"""
NetProbe — SYN (half-open) scanner.

Sends a raw TCP SYN packet and inspects the reply flags to determine
port state without completing the three-way handshake.  Requires
root / admin privileges on Linux.  On macOS (or when not root) the
scanner prints a warning and falls back gracefully.

**Note:** Raw-socket SYN scanning is only fully supported on Linux
because macOS strips TCP/IP headers from raw-socket reads.  The class
still provides a usable API so the rest of NetProbe can call it without
platform checks.
"""

import logging
import os
import platform
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PortState, ScanResult

logger = logging.getLogger("netprobe.scanner.syn_scanner")


def _is_root() -> bool:
    """Return *True* when the process has root / admin privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows — check ctypes
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[union-attr]
        except Exception:
            return False


def _checksum(data: bytes) -> int:
    """Compute the standard Internet checksum (RFC 1071).

    Parameters
    ----------
    data : bytes
        Raw header bytes.

    Returns
    -------
    int
        16-bit one's-complement checksum.
    """
    if len(data) % 2:
        data += b"\x00"

    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w

    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class SYNScanner:
    """Half-open SYN port scanner using raw sockets.

    Parameters
    ----------
    timeout : float
        Seconds to wait for a SYN-ACK / RST response.
    retries : int
        Number of extra SYN retransmissions on timeout.
    """

    def __init__(self, timeout: float = 1.5, retries: int = 1) -> None:
        self.timeout = timeout
        self.retries = retries
        self._lock = threading.Lock()

    # ──────────────────────────────────────────
    # Packet construction helpers
    # ──────────────────────────────────────────
    @staticmethod
    def _build_ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
        """Build a minimal 20-byte IPv4 header.

        Parameters
        ----------
        src_ip, dst_ip : str
            Dotted-quad addresses.
        payload_len : int
            Length of the TCP segment following this header.

        Returns
        -------
        bytes
            20-byte IP header with correct checksum.
        """
        version_ihl = (4 << 4) | 5   # IPv4, IHL=5 (20 bytes)
        tos = 0
        total_length = 20 + payload_len
        identification = random.randint(1, 65535)
        flags_offset = 0x4000  # Don't Fragment
        ttl = 64
        protocol = 6  # TCP
        header_checksum = 0  # placeholder
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)

        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, tos, total_length,
            identification, flags_offset,
            ttl, protocol, header_checksum,
            src, dst,
        )

        # Compute and insert checksum
        header_checksum = _checksum(header)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, tos, total_length,
            identification, flags_offset,
            ttl, protocol, header_checksum,
            src, dst,
        )
        return header

    @staticmethod
    def _build_tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
        """Construct a TCP SYN segment (20 bytes) with a correct checksum.

        Parameters
        ----------
        src_ip, dst_ip : str
            Dotted-quad addresses (needed for pseudo-header).
        src_port, dst_port : int
            TCP port numbers.

        Returns
        -------
        bytes
            20-byte TCP SYN segment.
        """
        seq = random.randint(0, 0xFFFFFFFF)
        ack = 0
        data_offset = (5 << 4)  # 5 × 4 = 20 bytes, no options
        flags = 0x02            # SYN
        window = 65535
        checksum = 0            # placeholder
        urgent = 0

        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port,
            seq, ack,
            data_offset, flags,
            window, checksum, urgent,
        )

        # Pseudo-header for TCP checksum
        pseudo = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0,      # reserved
            6,      # TCP protocol number
            len(tcp_header),
        )

        checksum = _checksum(pseudo + tcp_header)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port,
            seq, ack,
            data_offset, flags,
            window, checksum, urgent,
        )
        return tcp_header

    # ──────────────────────────────────────────
    # Response parsing
    # ──────────────────────────────────────────
    @staticmethod
    def _parse_tcp_flags(packet: bytes) -> Tuple[int, int]:
        """Extract (source_port, tcp_flags) from an IP+TCP raw packet.

        Parameters
        ----------
        packet : bytes
            Raw IP packet (at least 40 bytes).

        Returns
        -------
        tuple[int, int]
            Source port and bitmask of TCP flags.
        """
        if len(packet) < 40:
            return 0, 0

        # IP header length
        ihl = (packet[0] & 0x0F) * 4
        tcp_header = packet[ihl:ihl + 20]
        if len(tcp_header) < 20:
            return 0, 0

        src_port, dst_port, seq, ack_num, offset_flags = struct.unpack(
            "!HHIIB", tcp_header[:13],
        )
        flags = tcp_header[13]
        return src_port, flags

    # ──────────────────────────────────────────
    # Source IP detection
    # ──────────────────────────────────────────
    @staticmethod
    def _get_source_ip(target_ip: str) -> str:
        """Determine the local IP address used to reach *target_ip*.

        Parameters
        ----------
        target_ip : str
            The remote host we want to reach.

        Returns
        -------
        str
            Local IP address.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((target_ip, 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    # ──────────────────────────────────────────
    # Single-port SYN scan
    # ──────────────────────────────────────────
    def scan_port(self, target_ip: str, port: int, timeout: Optional[float] = None) -> ScanResult:
        """Send a SYN to *target_ip:port* and classify the response.

        Parameters
        ----------
        target_ip : str
            IPv4 address.
        port : int
            Destination port.
        timeout : float | None
            Override instance timeout.

        Returns
        -------
        ScanResult
        """
        _timeout = timeout if timeout is not None else self.timeout

        if not _is_root():
            logger.warning("SYN scan requires root — returning FILTERED for %s:%d", target_ip, port)
            return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.FILTERED)

        if platform.system() != "Linux":
            logger.warning("SYN scan raw sockets fully supported only on Linux")
            return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.FILTERED)

        src_ip = self._get_source_ip(target_ip)
        src_port = random.randint(1024, 65535)

        try:
            # Build packet
            tcp_seg = self._build_tcp_syn(src_ip, target_ip, src_port, port)
            ip_hdr = self._build_ip_header(src_ip, target_ip, len(tcp_seg))
            packet = ip_hdr + tcp_seg

            # Send
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            send_sock.sendto(packet, (target_ip, 0))
            send_sock.close()

            # Receive
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.settimeout(_timeout)

            start = time.monotonic()
            while time.monotonic() - start < _timeout:
                try:
                    data, addr = recv_sock.recvfrom(65535)
                except socket.timeout:
                    recv_sock.close()
                    return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.FILTERED)

                if addr[0] != target_ip:
                    continue

                resp_port, flags = self._parse_tcp_flags(data)
                if resp_port != port:
                    continue

                recv_sock.close()

                # SYN-ACK => open  (flags 0x12 = SYN+ACK)
                if flags & 0x12 == 0x12:
                    return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.OPEN)
                # RST => closed  (flags 0x04 = RST)
                if flags & 0x04:
                    return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.CLOSED)

            recv_sock.close()
            return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.FILTERED)

        except PermissionError:
            logger.error("Permission denied creating raw socket")
            return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.FILTERED)
        except OSError as exc:
            logger.error("OSError during SYN scan on %s:%d — %s", target_ip, port, exc)
            return ScanResult(ip=target_ip, port=port, protocol="tcp", state=PortState.FILTERED)

    # ──────────────────────────────────────────
    # Bulk SYN scan
    # ──────────────────────────────────────────
    def scan_all_ports(
        self,
        target_ip: str,
        ports: List[int],
        threads: int = 500,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[ScanResult]:
        """Scan many ports via SYN.

        Falls back to a warning and returns all-FILTERED when not running
        as root or not on Linux.

        Parameters
        ----------
        target_ip : str
            IPv4 address.
        ports : list[int]
            Ports to probe.
        threads : int
            Max concurrent workers.
        timeout : float | None
            Per-port timeout.
        progress_callback : callable | None
            ``callback(completed, total)``.

        Returns
        -------
        list[ScanResult]
        """
        if not _is_root():
            logger.warning(
                "SYN scanning requires root privileges. "
                "Run with sudo or use TCP Connect scan (-sT) instead."
            )
            results = [
                ScanResult(ip=target_ip, port=p, protocol="tcp", state=PortState.FILTERED)
                for p in ports
            ]
            return results

        if platform.system() != "Linux":
            logger.warning(
                "SYN scanning with raw sockets is fully supported only on Linux. "
                "On macOS use TCP Connect scan (-sT) instead."
            )
            results = [
                ScanResult(ip=target_ip, port=p, protocol="tcp", state=PortState.FILTERED)
                for p in ports
            ]
            return results

        _timeout = timeout if timeout is not None else self.timeout
        results: List[ScanResult] = []
        completed = 0
        total = len(ports)

        with ThreadPoolExecutor(max_workers=min(threads, total)) as executor:
            future_map = {}
            for port in ports:
                future = executor.submit(self.scan_port, target_ip, port, _timeout)
                future_map[future] = port

            for future in as_completed(future_map):
                try:
                    result = future.result()
                except Exception as exc:
                    port_num = future_map[future]
                    logger.error("SYN scan error %s:%d — %s", target_ip, port_num, exc)
                    result = ScanResult(
                        ip=target_ip, port=port_num, protocol="tcp", state=PortState.FILTERED,
                    )

                with self._lock:
                    results.append(result)
                    completed += 1

                if progress_callback:
                    progress_callback(completed, total)

        results.sort(key=lambda r: r.port)
        return results
