"""
NetProbe — UDP scanner.

Sends a UDP datagram to each target port and classifies the result:

* **Response received** → ``OPEN``
* **ICMP Port Unreachable** → ``CLOSED``
* **No response (timeout)** → ``OPEN|FILTERED``

Protocol-specific payloads are used for well-known UDP services (DNS,
SNMP, NTP, DHCP) to increase the chance of eliciting a response.
"""

import logging
import os
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PortState, ScanResult

logger = logging.getLogger("netprobe.scanner.udp_scanner")


# ──────────────────────────────────────────────
# Protocol-specific UDP payloads
# ──────────────────────────────────────────────

def _dns_query() -> bytes:
    """Minimal DNS query for ``version.bind`` (TXT, CHAOS class)."""
    # Transaction ID
    tid = b"\xaa\xbb"
    # Flags: standard query
    flags = b"\x01\x00"
    # Questions: 1, Answers/Auth/Additional: 0
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    # QNAME: version.bind
    qname = (
        b"\x07version\x04bind\x00"
    )
    # QTYPE=TXT (16), QCLASS=CH (3)
    qtype_class = b"\x00\x10\x00\x03"
    return tid + flags + counts + qname + qtype_class


def _snmpv1_get() -> bytes:
    """Minimal SNMPv1 GET request for sysDescr.0."""
    # ASN.1 BER-encoded SNMPv1 GET sysDescr.0 with community "public"
    return bytes([
        0x30, 0x26,                               # SEQUENCE, length 38
        0x02, 0x01, 0x00,                          # version: 0 (SNMPv1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # community: "public"
        0xa0, 0x19,                                # GET-REQUEST, length 25
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,        # request-id: 1
        0x02, 0x01, 0x00,                          # error-status: 0
        0x02, 0x01, 0x00,                          # error-index: 0
        0x30, 0x0b,                                # variable bindings
        0x30, 0x09,
        0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, # OID: 1.3.6.1.2.1.1.1.0
        0x05, 0x00,                                # value: NULL
    ])


def _ntp_request() -> bytes:
    """Minimal NTP v3 client request."""
    # LI=0, VN=3, Mode=3 (client)
    packet = b"\x1b" + b"\x00" * 47
    return packet


def _dhcp_discover() -> bytes:
    """Minimal DHCP DISCOVER message."""
    msg = bytearray(244)
    msg[0] = 1    # op: BOOTREQUEST
    msg[1] = 1    # htype: Ethernet
    msg[2] = 6    # hlen: 6
    msg[3] = 0    # hops
    # xid
    msg[4:8] = struct.pack("!I", 0x12345678)
    # flags: broadcast
    msg[10:12] = struct.pack("!H", 0x8000)
    # magic cookie
    msg[236:240] = b"\x63\x82\x53\x63"
    # Option 53: DHCP Discover
    msg[240] = 53
    msg[241] = 1
    msg[242] = 1
    # End
    msg[243] = 255
    return bytes(msg)


# Map port → payload builder
UDP_PAYLOADS: Dict[int, bytes] = {
    53:  _dns_query(),
    161: _snmpv1_get(),
    123: _ntp_request(),
    67:  _dhcp_discover(),
}


class UDPScanner:
    """UDP port scanner with protocol-specific payloads.

    Parameters
    ----------
    timeout : float
        Seconds to wait for a response before classifying as open|filtered.
    retries : int
        Extra retransmissions per port.
    """

    def __init__(self, timeout: float = 2.0, retries: int = 1) -> None:
        self.timeout = timeout
        self.retries = retries
        self._lock = threading.Lock()

    def scan_port(self, target_ip: str, port: int, timeout: Optional[float] = None) -> ScanResult:
        """Send a UDP datagram and classify the response.

        Parameters
        ----------
        target_ip : str
            IPv4 address.
        port : int
            Destination UDP port.
        timeout : float | None
            Override.

        Returns
        -------
        ScanResult
        """
        _timeout = timeout if timeout is not None else self.timeout
        payload = UDP_PAYLOADS.get(port, b"")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_timeout)
        try:
            sock.sendto(payload, (target_ip, port))
            try:
                data, addr = sock.recvfrom(1024)
                # Got a response → port is open
                return ScanResult(ip=target_ip, port=port, protocol="udp", state=PortState.OPEN)
            except socket.timeout:
                # No response → open|filtered
                return ScanResult(ip=target_ip, port=port, protocol="udp", state=PortState.OPEN_FILTERED)
            except ConnectionRefusedError:
                # ICMP port unreachable surfaced by OS → closed
                return ScanResult(ip=target_ip, port=port, protocol="udp", state=PortState.CLOSED)
            except OSError as exc:
                # Some OSes raise OSError for ICMP unreachable
                if exc.errno in (111, 10054):  # ECONNREFUSED on Linux / Windows
                    return ScanResult(ip=target_ip, port=port, protocol="udp", state=PortState.CLOSED)
                logger.debug("OSError on recv for %s:%d — %s", target_ip, port, exc)
                return ScanResult(ip=target_ip, port=port, protocol="udp", state=PortState.OPEN_FILTERED)
        except OSError as exc:
            logger.debug("OSError sending to %s:%d — %s", target_ip, port, exc)
            return ScanResult(ip=target_ip, port=port, protocol="udp", state=PortState.FILTERED)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def scan_single(
        self,
        target_ip: str,
        port: int,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
    ) -> ScanResult:
        """Scan a single UDP port with retry logic.

        Parameters
        ----------
        target_ip : str
        port : int
        timeout : float | None
        retries : int | None

        Returns
        -------
        ScanResult
        """
        _retries = retries if retries is not None else self.retries
        result = self.scan_port(target_ip, port, timeout)

        attempt = 0
        while result.state == PortState.OPEN_FILTERED and attempt < _retries:
            attempt += 1
            logger.debug("UDP retry %d/%d for %s:%d", attempt, _retries, target_ip, port)
            time.sleep(0.2)
            result = self.scan_port(target_ip, port, timeout)

        return result

    def scan_all_ports(
        self,
        target_ip: str,
        ports: List[int],
        threads: int = 500,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[ScanResult]:
        """Scan *ports* via UDP with a thread pool.

        Parameters
        ----------
        target_ip : str
        ports : list[int]
        threads : int
        timeout : float | None
        progress_callback : callable | None

        Returns
        -------
        list[ScanResult]
        """
        _timeout = timeout if timeout is not None else self.timeout
        results: List[ScanResult] = []
        completed = 0
        total = len(ports)

        with ThreadPoolExecutor(max_workers=min(threads, total or 1)) as executor:
            future_map = {}
            for port in ports:
                future = executor.submit(self.scan_single, target_ip, port, _timeout, self.retries)
                future_map[future] = port

            for future in as_completed(future_map):
                try:
                    result = future.result()
                except Exception as exc:
                    p = future_map[future]
                    logger.error("UDP error %s:%d — %s", target_ip, p, exc)
                    result = ScanResult(ip=target_ip, port=p, protocol="udp", state=PortState.OPEN_FILTERED)
                with self._lock:
                    results.append(result)
                    completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        results.sort(key=lambda r: r.port)
        return results
