"""
NetProbe — Report generator.

Produces scan output in four formats:

1. **Console** — colour-coded ASCII table with progress bar.
2. **JSON** — machine-readable, pretty-printed.
3. **CSV** — spreadsheet-friendly.
4. **TXT** — human-readable plain-text report.
"""

import csv
import io
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    Colors,
    PortState,
    ScanConfig,
    ScanReport,
    ScanResult,
    Severity,
    VulnFlag,
)

logger = logging.getLogger("netprobe.reporting.report_generator")


def _severity_color(severity: Severity) -> str:
    """Return ANSI colour for a severity level."""
    mapping = {
        Severity.INFO:     Colors.CYAN,
        Severity.LOW:      Colors.GREEN,
        Severity.MEDIUM:   Colors.YELLOW,
        Severity.HIGH:     Colors.RED,
        Severity.CRITICAL: f"{Colors.BOLD}{Colors.RED}",
    }
    return mapping.get(severity, Colors.WHITE)


def _state_color(state: PortState) -> str:
    """Return ANSI colour for a port state."""
    mapping = {
        PortState.OPEN:          Colors.GREEN,
        PortState.CLOSED:        Colors.RED,
        PortState.FILTERED:      Colors.YELLOW,
        PortState.OPEN_FILTERED: Colors.YELLOW,
    }
    return mapping.get(state, Colors.WHITE)


class ReportGenerator:
    """Multi-format scan report generator.

    Parameters
    ----------
    no_color : bool
        If *True*, strip ANSI sequences from console output.
    """

    def __init__(self, no_color: bool = False) -> None:
        self.no_color = no_color
        if no_color:
            Colors.disable()

    # ──────────────────────────────────────────
    # Console output
    # ──────────────────────────────────────────
    def print_console(
        self,
        results: List[ScanResult],
        scan_config: ScanConfig,
        duration: float,
        target_ip: str = "",
    ) -> None:
        """Print a colour-coded scan report to stdout.

        Parameters
        ----------
        results : list[ScanResult]
            Scan results (typically only OPEN ports).
        scan_config : ScanConfig
            Settings used for the scan.
        duration : float
            Total scan seconds.
        target_ip : str
            The target that was scanned.
        """
        open_results = [r for r in results if r.state == PortState.OPEN]

        # ── Header ───────────────────────────
        print()
        print(f"{Colors.BOLD}{'═' * 72}{Colors.RESET}")
        print(f"{Colors.BOLD}  Scan Report for {Colors.CYAN}{target_ip or 'target'}{Colors.RESET}")
        print(f"{Colors.BOLD}{'═' * 72}{Colors.RESET}")
        print(f"  Scan type   : {Colors.CYAN}{scan_config.scan_type.value}{Colors.RESET}")
        print(f"  Ports       : {Colors.CYAN}{len(scan_config.ports)}{Colors.RESET}")
        print(f"  Threads     : {Colors.CYAN}{scan_config.threads}{Colors.RESET}")
        print(f"  Duration    : {Colors.CYAN}{duration:.2f}s{Colors.RESET}")
        print()

        if not open_results:
            print(f"  {Colors.YELLOW}No open ports discovered.{Colors.RESET}")
            print(f"{Colors.BOLD}{'═' * 72}{Colors.RESET}")
            return

        # ── Table header ─────────────────────
        hdr = f"  {'PORT':<10} {'STATE':<14} {'SERVICE':<18} {'VERSION':<22} {'FLAGS'}"
        print(f"{Colors.BOLD}{hdr}{Colors.RESET}")
        print(f"  {'─' * 10} {'─' * 14} {'─' * 18} {'─' * 22} {'─' * 20}")

        # ── Rows ─────────────────────────────
        for r in open_results:
            sc = _state_color(r.state)
            port_str = f"{r.port}/{r.protocol}"
            state_str = f"{sc}{r.state.value}{Colors.RESET}"
            svc_str = r.service or ""
            ver_str = r.version or ""

            flag_parts: List[str] = []
            for vf in r.vulnerability_flags:
                fc = _severity_color(vf.severity)
                flag_parts.append(f"{fc}{vf.flag_type}{Colors.RESET}")
            flags_str = ", ".join(flag_parts) if flag_parts else ""

            print(f"  {port_str:<10} {state_str:<24} {svc_str:<18} {ver_str:<22} {flags_str}")

        # ── Vulnerability detail list ────────
        vuln_results = [r for r in open_results if r.vulnerability_flags]
        if vuln_results:
            print()
            print(f"{Colors.BOLD}  ┌─ Vulnerability Details {'─' * 46}┐{Colors.RESET}")
            for r in vuln_results:
                for vf in r.vulnerability_flags:
                    fc = _severity_color(vf.severity)
                    cve = f" ({vf.cve_id})" if vf.cve_id else ""
                    print(f"  │ {fc}[{vf.severity.value}]{Colors.RESET} Port {r.port}: {vf.description}{cve}")
                    if vf.remediation:
                        print(f"  │   {Colors.DIM}→ {vf.remediation}{Colors.RESET}")
            print(f"{Colors.BOLD}  └{'─' * 70}┘{Colors.RESET}")

        # ── Summary ──────────────────────────
        total = len(results)
        n_open = sum(1 for r in results if r.state == PortState.OPEN)
        n_closed = sum(1 for r in results if r.state == PortState.CLOSED)
        n_filtered = sum(1 for r in results if r.state in (PortState.FILTERED, PortState.OPEN_FILTERED))

        print()
        print(f"{Colors.BOLD}  ┌─ Summary {'─' * 60}┐{Colors.RESET}")
        print(f"  │  Total ports scanned : {total}")
        print(f"  │  Open                : {Colors.GREEN}{n_open}{Colors.RESET}")
        print(f"  │  Closed              : {Colors.RED}{n_closed}{Colors.RESET}")
        print(f"  │  Filtered            : {Colors.YELLOW}{n_filtered}{Colors.RESET}")
        print(f"  │  Scan duration       : {duration:.2f}s")
        print(f"{Colors.BOLD}  └{'─' * 70}┘{Colors.RESET}")
        print()

    # ──────────────────────────────────────────
    # JSON output
    # ──────────────────────────────────────────
    def generate_json(
        self,
        results: List[ScanResult],
        scan_config: ScanConfig,
        filepath: str,
        duration: float = 0.0,
    ) -> None:
        """Write scan results as a JSON file.

        Parameters
        ----------
        results : list[ScanResult]
        scan_config : ScanConfig
        filepath : str
            Output file path.
        duration : float
        """
        data = {
            "scan_metadata": {
                "scan_type": scan_config.scan_type.value,
                "targets": scan_config.targets,
                "total_ports": len(scan_config.ports),
                "threads": scan_config.threads,
                "timeout": scan_config.timeout,
                "retries": scan_config.retries,
                "service_detection": scan_config.service_detection,
                "banner_grabbing": scan_config.banner_grabbing,
                "duration_seconds": round(duration, 3),
                "timestamp": datetime.now().isoformat(),
            },
            "summary": {
                "total_scanned": len(results),
                "open": sum(1 for r in results if r.state == PortState.OPEN),
                "closed": sum(1 for r in results if r.state == PortState.CLOSED),
                "filtered": sum(1 for r in results if r.state in (PortState.FILTERED, PortState.OPEN_FILTERED)),
            },
            "results": [self._result_to_dict(r) for r in results],
        }

        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.info("JSON report saved to %s", filepath)

    # ──────────────────────────────────────────
    # CSV output
    # ──────────────────────────────────────────
    def generate_csv(
        self,
        results: List[ScanResult],
        scan_config: ScanConfig,
        filepath: str,
    ) -> None:
        """Write scan results as a CSV file.

        Parameters
        ----------
        results : list[ScanResult]
        scan_config : ScanConfig
        filepath : str
        """
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "ip", "port", "protocol", "state", "service",
                "banner", "version", "vulnerability_flags", "severity", "timestamp",
            ])
            for r in results:
                vuln_str = "; ".join(
                    f"{vf.flag_type}({vf.severity.value}): {vf.description}"
                    for vf in r.vulnerability_flags
                ) if r.vulnerability_flags else ""

                max_sev = ""
                if r.vulnerability_flags:
                    sev_order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                                 Severity.HIGH: 3, Severity.CRITICAL: 4}
                    max_sev = max(r.vulnerability_flags,
                                  key=lambda v: sev_order.get(v.severity, 0)).severity.value

                writer.writerow([
                    r.ip, r.port, r.protocol, r.state.value,
                    r.service or "",
                    (r.banner or "").replace("\n", " ").replace("\r", "")[:500],
                    r.version or "",
                    vuln_str,
                    max_sev,
                    r.timestamp.isoformat() if r.timestamp else "",
                ])
        logger.info("CSV report saved to %s", filepath)

    # ──────────────────────────────────────────
    # TXT output
    # ──────────────────────────────────────────
    def generate_txt(
        self,
        results: List[ScanResult],
        scan_config: ScanConfig,
        filepath: str,
        duration: float = 0.0,
    ) -> None:
        """Write a human-readable plain-text report.

        Parameters
        ----------
        results : list[ScanResult]
        scan_config : ScanConfig
        filepath : str
        duration : float
        """
        buf = io.StringIO()
        buf.write("=" * 72 + "\n")
        buf.write("  NetProbe Scan Report\n")
        buf.write("=" * 72 + "\n\n")

        # Config
        buf.write("--- Scan Configuration ---\n")
        buf.write(f"  Scan type  : {scan_config.scan_type.value}\n")
        buf.write(f"  Targets    : {', '.join(scan_config.targets)}\n")
        buf.write(f"  Ports      : {len(scan_config.ports)}\n")
        buf.write(f"  Threads    : {scan_config.threads}\n")
        buf.write(f"  Timeout    : {scan_config.timeout}s\n")
        buf.write(f"  Duration   : {duration:.2f}s\n")
        buf.write(f"  Timestamp  : {datetime.now().isoformat()}\n\n")

        # Results table
        buf.write("--- Results ---\n")
        buf.write(f"  {'PORT':<12} {'STATE':<14} {'SERVICE':<18} {'VERSION':<22}\n")
        buf.write(f"  {'─' * 12} {'─' * 14} {'─' * 18} {'─' * 22}\n")
        open_results = [r for r in results if r.state == PortState.OPEN]
        for r in open_results:
            buf.write(
                f"  {r.port}/{r.protocol:<8} {r.state.value:<14} "
                f"{(r.service or ''):<18} {(r.version or ''):<22}\n"
            )

        if not open_results:
            buf.write("  No open ports discovered.\n")

        # Vulnerability summary
        vuln_results = [r for r in open_results if r.vulnerability_flags]
        if vuln_results:
            buf.write("\n--- Vulnerability Summary ---\n")
            for r in vuln_results:
                for vf in r.vulnerability_flags:
                    cve = f" ({vf.cve_id})" if vf.cve_id else ""
                    buf.write(f"  [{vf.severity.value}] Port {r.port}: {vf.description}{cve}\n")
                    if vf.remediation:
                        buf.write(f"          → {vf.remediation}\n")

        # Statistics
        total = len(results)
        n_open = sum(1 for r in results if r.state == PortState.OPEN)
        n_closed = sum(1 for r in results if r.state == PortState.CLOSED)
        n_filtered = total - n_open - n_closed

        buf.write("\n--- Statistics ---\n")
        buf.write(f"  Total scanned : {total}\n")
        buf.write(f"  Open          : {n_open}\n")
        buf.write(f"  Closed        : {n_closed}\n")
        buf.write(f"  Filtered      : {n_filtered}\n")
        buf.write("=" * 72 + "\n")

        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(buf.getvalue())
        logger.info("TXT report saved to %s", filepath)

    # ──────────────────────────────────────────
    # Progress bar
    # ──────────────────────────────────────────
    @staticmethod
    def print_progress(current: int, total: int, start_time: float) -> None:
        """Render an in-place progress bar on the terminal.

        Parameters
        ----------
        current : int
            Completed items.
        total : int
            Total items.
        start_time : float
            ``time.time()`` when the scan began.
        """
        if total == 0:
            return

        pct = current / total
        bar_len = 40
        filled = int(bar_len * pct)
        bar = "█" * filled + "░" * (bar_len - filled)

        elapsed = time.time() - start_time
        if current > 0 and pct < 1.0:
            eta = (elapsed / current) * (total - current)
            eta_str = f"ETA: {eta:.0f}s"
        elif pct >= 1.0:
            eta_str = "done"
        else:
            eta_str = "ETA: --"

        line = f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} {pct * 100:5.1f}% | {current}/{total} ports | {eta_str}  "
        sys.stdout.write(line)
        sys.stdout.flush()

        if current >= total:
            sys.stdout.write("\n")

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────
    @staticmethod
    def _result_to_dict(r: ScanResult) -> dict:
        """Convert a ScanResult to a JSON-serialisable dict."""
        return {
            "ip": r.ip,
            "port": r.port,
            "protocol": r.protocol,
            "state": r.state.value,
            "service": r.service,
            "banner": r.banner,
            "version": r.version,
            "vulnerability_flags": [
                {
                    "flag_type": vf.flag_type,
                    "severity": vf.severity.value,
                    "description": vf.description,
                    "cve_id": vf.cve_id,
                    "remediation": vf.remediation,
                }
                for vf in r.vulnerability_flags
            ],
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
