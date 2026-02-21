"""
NetProbe — Vulnerability detector.

Flags open ports that pose common security risks and matches service
banners against known CVE patterns loaded from
``data/vuln_signatures.json``.
"""

import json
import logging
import os
import re
import sys
from typing import Dict, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ScanResult, PortState, Severity, VulnFlag

logger = logging.getLogger("netprobe.detection.vuln_detector")

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_VULN_FILE = os.path.join(_DATA_DIR, "vuln_signatures.json")


# ──────────────────────────────────────────────
# Category-based port sets
# ──────────────────────────────────────────────
_UNENCRYPTED_PORTS: Dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    69: "TFTP",
    161: "SNMP",
}

_EXPOSED_DB_PORTS: Dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    1433: "MSSQL",
    1521: "Oracle",
    5984: "CouchDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    2375: "Docker API",
}

_REMOTE_ACCESS_PORTS: Dict[int, str] = {
    3389: "RDP",
    5900: "VNC",
    22: "SSH",
    23: "Telnet",
    5985: "WinRM",
}

_LEGACY_PORTS: Dict[int, str] = {
    23: "Telnet",
    513: "rlogin",
    514: "rsh",
    21: "FTP",
    512: "rexec",
}

# "Standard" port for each service — anything else is non-standard
_STANDARD_PORTS: Dict[str, Set[int]] = {
    "ssh":    {22},
    "http":   {80, 8080, 8000, 8008, 8888},
    "https":  {443, 8443},
    "ftp":    {21},
    "smtp":   {25, 465, 587},
    "mysql":  {3306},
    "redis":  {6379},
    "dns":    {53},
    "rdp":    {3389},
    "vnc":    {5900, 5901},
}


class VulnDetector:
    """Evaluate scan results for common vulnerability indicators.

    Loads regex patterns from ``data/vuln_signatures.json`` at
    construction time.
    """

    def __init__(self, signatures_path: Optional[str] = None) -> None:
        self._sig_path = signatures_path or _VULN_FILE
        self._signatures: List[Dict] = []
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Read the JSON signatures file."""
        try:
            with open(self._sig_path, "r", encoding="utf-8") as fh:
                self._signatures = json.load(fh)
            logger.debug("Loaded %d vuln signatures from %s", len(self._signatures), self._sig_path)
        except FileNotFoundError:
            logger.warning("Vuln signatures not found at %s", self._sig_path)
        except json.JSONDecodeError as exc:
            logger.error("Malformed vuln signatures: %s", exc)

    def check_vulnerabilities(self, result: ScanResult) -> List[VulnFlag]:
        """Analyse a single *ScanResult* and return applicable flags.

        Only *OPEN* ports are checked (closed / filtered ports are
        irrelevant).

        Parameters
        ----------
        result : ScanResult

        Returns
        -------
        list[VulnFlag]
        """
        if result.state != PortState.OPEN:
            return []

        flags: List[VulnFlag] = []

        # ── Category checks ──────────────────
        port = result.port

        if port in _UNENCRYPTED_PORTS:
            svc = _UNENCRYPTED_PORTS[port]
            flags.append(VulnFlag(
                flag_type="UNENCRYPTED",
                severity=Severity.MEDIUM,
                description=f"{svc} (port {port}) transmits data in cleartext",
                remediation=f"Use the encrypted alternative of {svc} or tunnel through TLS/VPN",
            ))

        if port in _EXPOSED_DB_PORTS:
            svc = _EXPOSED_DB_PORTS[port]
            flags.append(VulnFlag(
                flag_type="EXPOSED_DATABASE",
                severity=Severity.HIGH,
                description=f"{svc} database (port {port}) is exposed on the network",
                remediation=f"Restrict {svc} to localhost/VPN, enable authentication, and use TLS",
            ))

        if port in _REMOTE_ACCESS_PORTS:
            svc = _REMOTE_ACCESS_PORTS[port]
            flags.append(VulnFlag(
                flag_type="REMOTE_ACCESS",
                severity=Severity.MEDIUM if svc == "SSH" else Severity.HIGH,
                description=f"{svc} remote access (port {port}) is exposed",
                remediation=f"Restrict {svc} access via firewall, use MFA, disable if unused",
            ))

        if port in _LEGACY_PORTS:
            svc = _LEGACY_PORTS[port]
            flags.append(VulnFlag(
                flag_type="LEGACY_PROTOCOL",
                severity=Severity.HIGH,
                description=f"Legacy protocol {svc} (port {port}) lacks modern security controls",
                remediation=f"Replace {svc} with SSH or another encrypted alternative",
            ))

        # ── Non-standard port check ──────────
        if result.service:
            svc_lower = result.service.lower()
            for svc_name, std_ports in _STANDARD_PORTS.items():
                if svc_lower.startswith(svc_name) and port not in std_ports:
                    flags.append(VulnFlag(
                        flag_type="NON_STANDARD_PORT",
                        severity=Severity.INFO,
                        description=(
                            f"Service '{result.service}' running on non-standard port {port} "
                            f"(expected {std_ports})"
                        ),
                        remediation="Verify this is intentional; non-standard ports can indicate shadow services",
                    ))
                    break

        # ── Version / banner regex checks ────
        banner_text = ""
        if result.banner:
            banner_text += result.banner
        if result.version:
            banner_text += " " + result.version

        if banner_text.strip():
            for sig in self._signatures:
                pattern = sig.get("pattern", "")
                if not pattern:
                    continue
                try:
                    if re.search(pattern, banner_text, re.IGNORECASE):
                        sev_str = sig.get("severity", "INFO")
                        try:
                            severity = Severity(sev_str)
                        except ValueError:
                            severity = Severity.INFO

                        flags.append(VulnFlag(
                            flag_type="VERSION_VULNERABLE",
                            severity=severity,
                            description=sig.get("description", "Matched known vulnerable pattern"),
                            cve_id=sig.get("cve"),
                            remediation=sig.get("remediation"),
                        ))
                except re.error as exc:
                    logger.debug("Invalid regex in vuln sig: %s — %s", pattern, exc)

        return flags
