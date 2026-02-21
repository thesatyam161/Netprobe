"""
NetProbe — TCP Connect scanner.

Performs a full TCP three-way handshake for each target port using
``socket.connect_ex``.  Scanning is parallelised via
``concurrent.futures.ThreadPoolExecutor`` with thread-safe result
collection.
"""

import errno
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PortState, ScanResult

logger = logging.getLogger("netprobe.scanner.tcp_scanner")


class TCPScanner:
    """Full-connect TCP port scanner.

    Parameters
    ----------
    timeout : float
        Socket connect timeout in seconds.
    retries : int
        Number of retries per port if the first attempt is inconclusive.
    rate_limit : int
        Maximum connections per second (0 = unlimited).
    """

    def __init__(
        self,
        timeout: float = 1.0,
        retries: int = 1,
        rate_limit: int = 0,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self._lock = threading.Lock()
        self._rate_semaphore: Optional[threading.Semaphore] = None

    # ──────────────────────────────────────────
    # Single-port scan (no retries)
    # ──────────────────────────────────────────
    def scan_port(self, target_ip: str, port: int, timeout: Optional[float] = None) -> ScanResult:
        """Attempt a TCP connect to *target_ip:port*.

        Parameters
        ----------
        target_ip : str
            IPv4 address.
        port : int
            Destination port.
        timeout : float | None
            Override the instance default timeout.

        Returns
        -------
        ScanResult
        """
        _timeout = timeout if timeout is not None else self.timeout
        state = PortState.FILTERED  # default / fallback

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_timeout)
        try:
            result_code = sock.connect_ex((target_ip, port))
            if result_code == 0:
                state = PortState.OPEN
            elif result_code == errno.ECONNREFUSED:
                state = PortState.CLOSED
            else:
                state = PortState.FILTERED
        except socket.timeout:
            state = PortState.FILTERED
        except ConnectionRefusedError:
            state = PortState.CLOSED
        except OSError as exc:
            # "Too many open files" or other OS-level errors
            if exc.errno == errno.EMFILE:
                logger.warning("Too many open files — throttling")
                time.sleep(0.5)
                state = PortState.FILTERED
            else:
                logger.debug("OSError scanning %s:%d — %s", target_ip, port, exc)
                state = PortState.FILTERED
        finally:
            try:
                sock.close()
            except OSError:
                pass

        return ScanResult(
            ip=target_ip,
            port=port,
            protocol="tcp",
            state=state,
        )

    # ──────────────────────────────────────────
    # Single-port scan with retry logic
    # ──────────────────────────────────────────
    def scan_single(
        self,
        target_ip: str,
        port: int,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
    ) -> ScanResult:
        """Scan a single port with retry logic.

        If the first attempt yields ``FILTERED`` the scan is retried up to
        *retries* additional times before accepting the result.

        Parameters
        ----------
        target_ip : str
            IPv4 address.
        port : int
            Destination port.
        timeout : float | None
            Override instance default.
        retries : int | None
            Override instance default.

        Returns
        -------
        ScanResult
        """
        _retries = retries if retries is not None else self.retries
        _timeout = timeout if timeout is not None else self.timeout

        result = self.scan_port(target_ip, port, _timeout)

        # Retry only for ambiguous results
        attempt = 0
        while result.state == PortState.FILTERED and attempt < _retries:
            attempt += 1
            logger.debug("Retry %d/%d for %s:%d", attempt, _retries, target_ip, port)
            time.sleep(0.1)  # brief back-off
            result = self.scan_port(target_ip, port, _timeout)

        return result

    # ──────────────────────────────────────────
    # Bulk scan with thread pool
    # ──────────────────────────────────────────
    def scan_all_ports(
        self,
        target_ip: str,
        ports: List[int],
        threads: int = 1000,
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[ScanResult]:
        """Scan *ports* on *target_ip* using a thread pool.

        Parameters
        ----------
        target_ip : str
            IPv4 address.
        ports : list[int]
            Ports to scan.
        threads : int
            Max worker threads.
        timeout : float | None
            Per-port timeout override.
        progress_callback : callable | None
            ``callback(completed, total)`` invoked after each port finishes.

        Returns
        -------
        list[ScanResult]
            One result per port, sorted by port number.
        """
        _timeout = timeout if timeout is not None else self.timeout
        results: List[ScanResult] = []
        completed = 0
        total = len(ports)

        # Rate-limiting: simple sleep between submissions
        delay = 1.0 / self.rate_limit if self.rate_limit > 0 else 0

        with ThreadPoolExecutor(max_workers=min(threads, total)) as executor:
            future_map = {}
            for port in ports:
                future = executor.submit(self.scan_single, target_ip, port, _timeout, self.retries)
                future_map[future] = port
                if delay:
                    time.sleep(delay)

            for future in as_completed(future_map):
                try:
                    result = future.result()
                except Exception as exc:
                    port = future_map[future]
                    logger.error("Unexpected error scanning %s:%d — %s", target_ip, port, exc)
                    result = ScanResult(
                        ip=target_ip,
                        port=port,
                        protocol="tcp",
                        state=PortState.FILTERED,
                    )

                with self._lock:
                    results.append(result)
                    completed += 1

                if progress_callback:
                    progress_callback(completed, total)

        results.sort(key=lambda r: r.port)
        return results
