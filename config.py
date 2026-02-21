"""
NetProbe — Configuration, constants, and data models.

All tunables, default values, ANSI escape codes, protocol probes, and
shared dataclasses / enums live here so every other module can import
from a single source of truth.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime
from enum import Enum

# ──────────────────────────────────────────────
# Version
# ──────────────────────────────────────────────
VERSION = "1.0.0"
APP_NAME = "NetProbe"

# ──────────────────────────────────────────────
# Scan defaults
# ──────────────────────────────────────────────
DEFAULT_THREADS = 1000
DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 1
MAX_THREADS = 5000
BANNER_TIMEOUT = 2.0
BANNER_MAX_LENGTH = 1024
DEFAULT_RATE_LIMIT = 0  # 0 = unlimited (packets / second)

# ──────────────────────────────────────────────
# ANSI colour codes
# ──────────────────────────────────────────────

class Colors:
    """ANSI escape sequences for terminal colouring."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    # Background
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"

    @classmethod
    def disable(cls) -> None:
        """Strip every colour attribute so output is plain text."""
        for attr in list(vars(cls)):
            if not attr.startswith("_") and attr != "disable" and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")


# ──────────────────────────────────────────────
# Legal disclaimer
# ──────────────────────────────────────────────
LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║                        LEGAL DISCLAIMER                        ║
╠══════════════════════════════════════════════════════════════════╣
║  NetProbe is provided for AUTHORIZED security testing and      ║
║  network administration ONLY.  Scanning networks or hosts      ║
║  without explicit permission is ILLEGAL and may violate         ║
║  local, state, and/or federal laws.                             ║
║                                                                  ║
║  The author assumes NO liability for misuse of this tool.       ║
║  YOU are solely responsible for your actions.                   ║
║                                                                  ║
║  By using this tool you acknowledge that you have AUTHORIZATION ║
║  to scan the target(s).                                         ║
╚══════════════════════════════════════════════════════════════════╝
"""

BANNER_ART = f"""
{Colors.CYAN}{Colors.BOLD}
  ███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
  ██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{Colors.RESET}
  {Colors.DIM}v{VERSION} — Multi-Threaded Network Port Scanner{Colors.RESET}
"""

# ──────────────────────────────────────────────
# Protocol probes (bytes sent to elicit banners)
# ──────────────────────────────────────────────
PROTOCOL_PROBES: Dict[str, bytes] = {
    "http":       b"GET / HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n",
    "https":      b"GET / HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n",
    "ftp":        b"",             # passive — server talks first
    "ssh":        b"",             # passive — server talks first
    "smtp":       b"",             # passive — server talks first
    "pop3":       b"",             # passive — server talks first
    "imap":       b"",             # passive — server talks first
    "mysql":      b"",             # passive — server talks first
    "redis":      b"PING\r\n",
    "vnc":        b"",             # passive — server talks first
    "postgresql":  b"",            # handled specially in banner grabber
    "generic":    b"\r\n",
}

# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────

class PortState(Enum):
    """Possible states for a scanned port."""
    OPEN          = "open"
    CLOSED        = "closed"
    FILTERED      = "filtered"
    OPEN_FILTERED = "open|filtered"


class Severity(Enum):
    """Vulnerability severity levels."""
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ScanType(Enum):
    """Supported scan techniques."""
    TCP_CONNECT = "TCP Connect"
    TCP_SYN     = "TCP SYN"
    UDP         = "UDP"


# ──────────────────────────────────────────────
# Data-classes
# ──────────────────────────────────────────────

@dataclass
class ScanConfig:
    """Holds every setting for a scan run."""
    targets: List[str]
    ports: List[int]
    scan_type: ScanType
    threads: int
    timeout: float
    retries: int
    service_detection: bool
    banner_grabbing: bool
    output_json: Optional[str]
    output_csv: Optional[str]
    output_txt: Optional[str]
    verbose: bool
    no_color: bool
    rate_limit: int = DEFAULT_RATE_LIMIT


@dataclass
class ServiceInfo:
    """Information about a network service."""
    name: str
    description: str
    default_port: int


@dataclass
class BannerResult:
    """Result of a banner-grab attempt."""
    raw_banner: str
    service_name: Optional[str] = None
    version: Optional[str] = None
    extra_info: dict = field(default_factory=dict)


@dataclass
class VulnFlag:
    """A single vulnerability indicator."""
    flag_type: str
    severity: Severity
    description: str
    cve_id: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class ScanResult:
    """Scan result for one (ip, port) combination."""
    ip: str
    port: int
    protocol: str
    state: PortState
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None
    vulnerability_flags: List[VulnFlag] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanReport:
    """Aggregated report for a complete scan."""
    scan_config: ScanConfig
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_ports_scanned: int
    results: List[ScanResult] = field(default_factory=list)

    @property
    def open_ports(self) -> int:
        return sum(1 for r in self.results if r.state == PortState.OPEN)

    @property
    def closed_ports(self) -> int:
        return sum(1 for r in self.results if r.state == PortState.CLOSED)

    @property
    def filtered_ports(self) -> int:
        return sum(1 for r in self.results if r.state == PortState.FILTERED)
