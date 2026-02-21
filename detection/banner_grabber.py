"""
NetProbe — Banner grabber.

Connects to an open port and attempts to elicit a service banner using
protocol-specific strategies (HTTP, HTTPS, SSH, FTP, SMTP, MySQL,
Redis, PostgreSQL, VNC, and a generic fallback).
"""

import logging
import os
import re
import socket
import ssl
import sys
import threading
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import BANNER_MAX_LENGTH, BANNER_TIMEOUT, BannerResult

logger = logging.getLogger("netprobe.detection.banner_grabber")


class BannerGrabber:
    """Grab service banners with protocol-aware strategies.

    The class is thread-safe — each call opens its own socket.

    Parameters
    ----------
    timeout : float
        Socket read timeout for banner grabs.
    max_length : int
        Maximum banner bytes to keep.
    """

    def __init__(
        self,
        timeout: float = BANNER_TIMEOUT,
        max_length: int = BANNER_MAX_LENGTH,
    ) -> None:
        self.timeout = timeout
        self.max_length = max_length
        self._lock = threading.Lock()

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────
    def grab_banner(
        self,
        ip: str,
        port: int,
        service_name: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> BannerResult:
        """Attempt to grab a banner from *ip:port*.

        Parameters
        ----------
        ip : str
            Target IPv4 address.
        port : int
            Open port number.
        service_name : str | None
            Hint for choosing the right protocol handler.
        timeout : float | None
            Override instance timeout.

        Returns
        -------
        BannerResult
        """
        _timeout = timeout if timeout is not None else self.timeout
        svc = (service_name or "").lower()

        try:
            if port == 443 or svc in ("https", "https-alt"):
                return self._grab_https(ip, port, _timeout)
            if port in (80, 8080, 8443, 8000, 8008, 8888) or svc.startswith("http"):
                return self._grab_http(ip, port, _timeout)
            if port == 22 or svc == "ssh":
                return self._grab_ssh(ip, port, _timeout)
            if port == 21 or svc == "ftp":
                return self._grab_ftp(ip, port, _timeout)
            if port in (25, 587, 465) or svc in ("smtp", "submission", "smtps"):
                return self._grab_smtp(ip, port, _timeout)
            if port == 3306 or svc == "mysql":
                return self._grab_mysql(ip, port, _timeout)
            if port == 6379 or svc == "redis":
                return self._grab_redis(ip, port, _timeout)
            if port == 5432 or svc == "postgresql":
                return self._grab_postgresql(ip, port, _timeout)
            if port in (5900, 5901) or svc == "vnc":
                return self._grab_vnc(ip, port, _timeout)
            # Generic fallback
            return self._grab_generic(ip, port, _timeout)

        except Exception as exc:
            logger.debug("Banner grab failed for %s:%d — %s", ip, port, exc)
            return BannerResult(raw_banner="", service_name=service_name)

    def extract_version(self, banner: str, service: str) -> Optional[str]:
        """Extract a version string from *banner* text.

        Parameters
        ----------
        banner : str
            Raw banner text.
        service : str
            Service hint (``"ssh"``, ``"http"``, etc.).

        Returns
        -------
        str | None
            Extracted version or *None*.
        """
        if not banner:
            return None

        patterns: Dict[str, str] = {
            "ssh":        r"(SSH-[\d.]+-\S+)",
            "http":       r"(?:Server|server):\s*(\S+)",
            "https":      r"(?:Server|server):\s*(\S+)",
            "ftp":        r"(\d{3}\s.*)",
            "smtp":       r"(\d{3}\s.*)",
            "mysql":      r"([\d.]+[a-zA-Z\-]*)",
            "redis":      r"redis_version:([\d.]+)",
            "postgresql": r"([\d.]+)",
            "vnc":        r"(RFB\s[\d.]+)",
            "nginx":      r"nginx/([\d.]+)",
            "apache":     r"Apache/([\d.]+)",
            "openssh":    r"OpenSSH[_ ]([\d.p]+)",
        }

        svc = service.lower()
        regex = patterns.get(svc)
        if regex:
            m = re.search(regex, banner)
            if m:
                return m.group(1).strip()

        # Fallback: try every pattern
        for name, regex in patterns.items():
            m = re.search(regex, banner)
            if m:
                return m.group(1).strip()

        return None

    # ──────────────────────────────────────────
    # Protocol handlers
    # ──────────────────────────────────────────
    def _grab_http(self, ip: str, port: int, timeout: float) -> BannerResult:
        """GET / and parse Server + X-Powered-By headers."""
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: NetProbe/1.0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")

        raw = self._tcp_exchange(ip, port, request, timeout)
        banner = self._safe_decode(raw)

        extra: Dict[str, str] = {}
        # Status line
        status_match = re.search(r"(HTTP/[\d.]+\s+\d+\s+[^\r\n]*)", banner)
        if status_match:
            extra["status"] = status_match.group(1)
        # Server
        server_match = re.search(r"[Ss]erver:\s*([^\r\n]+)", banner)
        svc_name = None
        if server_match:
            svc_name = server_match.group(1).strip()
            extra["server"] = svc_name
        # X-Powered-By
        powered = re.search(r"X-Powered-By:\s*([^\r\n]+)", banner, re.IGNORECASE)
        if powered:
            extra["x_powered_by"] = powered.group(1).strip()

        version = self.extract_version(banner, "http")
        return BannerResult(
            raw_banner=banner[:self.max_length],
            service_name=svc_name or "http",
            version=version,
            extra_info=extra,
        )

    def _grab_https(self, ip: str, port: int, timeout: float) -> BannerResult:
        """TLS-wrap, GET /, and also extract cert info."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: NetProbe/1.0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")

        extra: Dict[str, str] = {}
        banner = ""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            wrapped = ctx.wrap_socket(sock, server_hostname=ip)
            wrapped.connect((ip, port))

            # Certificate info
            cert = wrapped.getpeercert(binary_form=False)
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                extra["ssl_cn"] = subject.get("commonName", "")
                extra["ssl_issuer"] = str(cert.get("issuer", ""))
                extra["ssl_not_after"] = cert.get("notAfter", "")

            der_cert = wrapped.getpeercert(binary_form=True)
            if der_cert:
                extra["ssl_cert_size"] = str(len(der_cert))

            wrapped.sendall(request)
            raw = b""
            while True:
                try:
                    chunk = wrapped.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) >= self.max_length:
                        break
                except socket.timeout:
                    break

            banner = self._safe_decode(raw)

            server_match = re.search(r"[Ss]erver:\s*([^\r\n]+)", banner)
            svc_name = server_match.group(1).strip() if server_match else "https"

            version = self.extract_version(banner, "https")
            return BannerResult(
                raw_banner=banner[:self.max_length],
                service_name=svc_name,
                version=version,
                extra_info=extra,
            )
        except Exception as exc:
            logger.debug("HTTPS banner grab %s:%d — %s", ip, port, exc)
            return BannerResult(raw_banner=str(exc)[:200], service_name="https", extra_info=extra)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _grab_ssh(self, ip: str, port: int, timeout: float) -> BannerResult:
        """Passive read — SSH servers send their version string first."""
        raw = self._tcp_exchange(ip, port, b"", timeout, passive=True)
        banner = self._safe_decode(raw).strip()
        version = self.extract_version(banner, "ssh")
        return BannerResult(raw_banner=banner[:self.max_length], service_name="ssh", version=version)

    def _grab_ftp(self, ip: str, port: int, timeout: float) -> BannerResult:
        """Passive read — FTP servers send 220 greeting."""
        raw = self._tcp_exchange(ip, port, b"", timeout, passive=True)
        banner = self._safe_decode(raw).strip()
        version = self.extract_version(banner, "ftp")
        return BannerResult(raw_banner=banner[:self.max_length], service_name="ftp", version=version)

    def _grab_smtp(self, ip: str, port: int, timeout: float) -> BannerResult:
        """Passive read for 220, then send EHLO."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            greeting = self._safe_decode(sock.recv(1024)).strip()

            # Send EHLO
            sock.sendall(b"EHLO scanner\r\n")
            ehlo_resp = self._safe_decode(sock.recv(2048)).strip()

            sock.sendall(b"QUIT\r\n")

            banner = greeting + "\n" + ehlo_resp
            version = self.extract_version(banner, "smtp")
            return BannerResult(
                raw_banner=banner[:self.max_length],
                service_name="smtp",
                version=version,
                extra_info={"ehlo_response": ehlo_resp[:500]},
            )
        except Exception as exc:
            logger.debug("SMTP banner %s:%d — %s", ip, port, exc)
            return BannerResult(raw_banner=str(exc)[:200], service_name="smtp")
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _grab_mysql(self, ip: str, port: int, timeout: float) -> BannerResult:
        """Passive read — MySQL sends a greeting packet with version."""
        raw = self._tcp_exchange(ip, port, b"", timeout, passive=True)
        banner = self._safe_decode(raw)

        # MySQL greeting: after 4 header bytes comes the protocol version
        # byte, then a null-terminated version string.
        version = None
        if len(raw) > 5:
            try:
                # Skip 4-byte packet header + 1-byte protocol version
                ver_end = raw.index(b"\x00", 5)
                version = raw[5:ver_end].decode("utf-8", errors="replace")
            except (ValueError, IndexError):
                version = self.extract_version(banner, "mysql")

        return BannerResult(
            raw_banner=banner[:self.max_length],
            service_name="mysql",
            version=version,
        )

    def _grab_redis(self, ip: str, port: int, timeout: float) -> BannerResult:
        """PING, then INFO server to pull version."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        extra: Dict[str, str] = {}
        try:
            sock.connect((ip, port))

            # PING
            sock.sendall(b"PING\r\n")
            pong = self._safe_decode(sock.recv(128)).strip()
            extra["ping_response"] = pong

            # INFO server
            sock.sendall(b"INFO server\r\n")
            info_raw = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    info_raw += chunk
                    if len(info_raw) > 4096:
                        break
                except socket.timeout:
                    break

            info = self._safe_decode(info_raw)
            version = None
            m = re.search(r"redis_version:([\d.]+)", info)
            if m:
                version = m.group(1)

            banner = pong + "\n" + info
            return BannerResult(
                raw_banner=banner[:self.max_length],
                service_name="redis",
                version=version,
                extra_info=extra,
            )
        except Exception as exc:
            logger.debug("Redis banner %s:%d — %s", ip, port, exc)
            return BannerResult(raw_banner=str(exc)[:200], service_name="redis", extra_info=extra)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _grab_postgresql(self, ip: str, port: int, timeout: float) -> BannerResult:
        """Send a startup message; parse the error for version info."""
        # PostgreSQL startup: length(int32) + protocol(int32) + params
        # Protocol 3.0 = 196608
        # Send user=probe\0 database=probe\0 \0
        params = b"user\x00probe\x00database\x00probe\x00\x00"
        length = 4 + 4 + len(params)
        startup = struct._pack("!II", length, 196608) if False else b""

        # Manual struct pack
        import struct as _struct
        startup = _struct.pack("!II", length, 196608) + params

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            sock.sendall(startup)

            raw = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 2048:
                        break
                except socket.timeout:
                    break

            banner = self._safe_decode(raw)
            version = self.extract_version(banner, "postgresql")
            return BannerResult(
                raw_banner=banner[:self.max_length],
                service_name="postgresql",
                version=version,
            )
        except Exception as exc:
            logger.debug("PostgreSQL banner %s:%d — %s", ip, port, exc)
            return BannerResult(raw_banner=str(exc)[:200], service_name="postgresql")
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _grab_vnc(self, ip: str, port: int, timeout: float) -> BannerResult:
        """Passive read — VNC sends 'RFB 003.xxx' immediately."""
        raw = self._tcp_exchange(ip, port, b"", timeout, passive=True)
        banner = self._safe_decode(raw).strip()
        version = self.extract_version(banner, "vnc")
        return BannerResult(raw_banner=banner[:self.max_length], service_name="vnc", version=version)

    def _grab_generic(self, ip: str, port: int, timeout: float) -> BannerResult:
        """Send CRLF and read whatever comes back."""
        raw = self._tcp_exchange(ip, port, b"\r\n", timeout)
        banner = self._safe_decode(raw).strip()
        return BannerResult(raw_banner=banner[:self.max_length])

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────
    def _tcp_exchange(
        self,
        ip: str,
        port: int,
        payload: bytes,
        timeout: float,
        passive: bool = False,
    ) -> bytes:
        """Open a TCP socket, optionally send *payload*, and read response.

        Parameters
        ----------
        ip : str
        port : int
        payload : bytes
        timeout : float
        passive : bool
            If *True* read first without sending (server-speaks-first).

        Returns
        -------
        bytes
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))

            if passive or not payload:
                # Read whatever the server sends
                try:
                    data = sock.recv(self.max_length)
                    return data
                except socket.timeout:
                    return b""

            sock.sendall(payload)
            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= self.max_length:
                        break
                except socket.timeout:
                    break
            return data
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            logger.debug("TCP exchange %s:%d — %s", ip, port, exc)
            return b""
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _safe_decode(data: bytes) -> str:
        """Decode bytes to string, replacing non-UTF-8 characters."""
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            try:
                return data.decode("latin-1", errors="replace")
            except Exception:
                return repr(data)
