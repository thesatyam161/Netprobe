#!/usr/bin/env python3
"""
NetProbe — Multi-threaded network port scanner.

Entry point.  Parses CLI arguments, orchestrates the scan pipeline, and
produces reports.

Usage examples
--------------
    python main.py --target 192.168.1.1 -p 1-1024
    python main.py --target 10.0.0.0/24 --top-ports 100 -sT --threads 500
    python main.py --target example.com -p 22,80,443 --service-detection
    python main.py --target 192.168.1.1 -p 1-65535 --output-json scan.json
"""

import argparse
import os
import sys
import time
from datetime import datetime
from typing import List

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    APP_NAME,
    BANNER_ART,
    Colors,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRIES,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    LEGAL_DISCLAIMER,
    MAX_THREADS,
    VERSION,
    PortState,
    ScanConfig,
    ScanType,
    ScanResult,
)
from utils.logger import setup_logger
from scanner.port_parser import parse_ports, get_top_ports
from scanner.tcp_scanner import TCPScanner
from scanner.syn_scanner import SYNScanner
from scanner.udp_scanner import UDPScanner
from network.target_parser import parse_target, parse_target_file
from detection.service_mapper import ServiceMapper
from detection.banner_grabber import BannerGrabber
from detection.vuln_detector import VulnDetector
from reporting.report_generator import ReportGenerator


def build_parser() -> argparse.ArgumentParser:
    """Create and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description=f"{APP_NAME} v{VERSION} — Multi-threaded network port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --target 192.168.1.1 -p 1-1024\n"
            "  python main.py --target 10.0.0.0/24 --top-ports 100 -sT\n"
            "  python main.py --target example.com -p 22,80,443 --service-detection\n"
            "  python main.py -iL targets.txt -p 80,443 --output-json results.json\n"
        ),
    )

    # Target specification
    target_group = parser.add_argument_group("Target specification")
    target_group.add_argument(
        "--target", "-t", dest="target", type=str, default=None,
        help="Target host(s): IP, CIDR, range, hostname, or comma-separated list",
    )
    target_group.add_argument(
        "--input-list", "-iL", dest="input_list", type=str, default=None,
        help="Read targets from a file (one per line)",
    )

    # Port specification
    port_group = parser.add_argument_group("Port specification")
    port_group.add_argument(
        "--ports", "-p", dest="ports", type=str, default=None,
        help="Ports to scan: e.g. 22,80,443 or 1-1024 or 80,8000-9000",
    )
    port_group.add_argument(
        "--top-ports", dest="top_ports", type=int, default=None,
        help="Scan the top N most common ports",
    )

    # Scan type
    scan_group = parser.add_argument_group("Scan type")
    scan_type = scan_group.add_mutually_exclusive_group()
    scan_type.add_argument(
        "-sT", dest="scan_type", action="store_const", const="T",
        help="TCP Connect scan (default)", default="T",
    )
    scan_type.add_argument(
        "-sS", dest="scan_type", action="store_const", const="S",
        help="TCP SYN scan (requires root, Linux only)",
    )
    scan_type.add_argument(
        "-sU", dest="scan_type", action="store_const", const="U",
        help="UDP scan",
    )

    # Performance
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument(
        "--threads", "-T", dest="threads", type=int, default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS}, max: {MAX_THREADS})",
    )
    perf_group.add_argument(
        "--timeout", dest="timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Per-port timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    perf_group.add_argument(
        "--retries", dest="retries", type=int, default=DEFAULT_RETRIES,
        help=f"Retries for filtered/ambiguous ports (default: {DEFAULT_RETRIES})",
    )
    perf_group.add_argument(
        "--rate-limit", dest="rate_limit", type=int, default=DEFAULT_RATE_LIMIT,
        help="Max connections per second, 0 = unlimited (default: 0)",
    )

    # Detection
    detect_group = parser.add_argument_group("Service & vulnerability detection")
    detect_group.add_argument(
        "--service-detection", "-sV", dest="service_detection", action="store_true",
        default=False,
        help="Enable service/version detection on open ports",
    )
    detect_group.add_argument(
        "--no-banner", dest="no_banner", action="store_true", default=False,
        help="Skip banner grabbing (faster scan)",
    )

    # Output
    out_group = parser.add_argument_group("Output")
    out_group.add_argument(
        "--output-json", "-oJ", dest="output_json", type=str, default=None,
        help="Save results to a JSON file",
    )
    out_group.add_argument(
        "--output-csv", "-oC", dest="output_csv", type=str, default=None,
        help="Save results to a CSV file",
    )
    out_group.add_argument(
        "--output-txt", "-oT", dest="output_txt", type=str, default=None,
        help="Save results to a TXT file",
    )
    out_group.add_argument(
        "--no-color", dest="no_color", action="store_true", default=False,
        help="Disable coloured output",
    )

    # Misc
    misc_group = parser.add_argument_group("Miscellaneous")
    misc_group.add_argument(
        "--verbose", "-v", dest="verbose", action="store_true", default=False,
        help="Verbose / debug output",
    )
    misc_group.add_argument(
        "--version", "-V", action="version", version=f"{APP_NAME} {VERSION}",
    )

    return parser


def resolve_targets(args: argparse.Namespace) -> List[str]:
    """Resolve CLI target arguments into a flat list of IPs."""
    targets: List[str] = []
    if args.target:
        targets.extend(parse_target(args.target))
    if args.input_list:
        targets.extend(parse_target_file(args.input_list))
    if not targets:
        print(f"{Colors.RED}[!] No targets specified. Use --target or --input-list.{Colors.RESET}",
              file=sys.stderr)
        sys.exit(1)
    # Deduplicate
    seen: set = set()
    unique: List[str] = []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def resolve_ports(args: argparse.Namespace) -> List[int]:
    """Resolve CLI port arguments into a sorted list of port ints."""
    if args.ports:
        return parse_ports(args.ports)
    if args.top_ports:
        return get_top_ports(args.top_ports)
    # Default: top 100
    return get_top_ports(100)


def main() -> None:
    """NetProbe entry point."""
    parser = build_parser()
    args = parser.parse_args()

    # ── Colour control ───────────────────────
    if args.no_color:
        Colors.disable()

    # ── Banner + disclaimer ──────────────────
    print(BANNER_ART)
    print(LEGAL_DISCLAIMER)

    # ── Logger ───────────────────────────────
    logger = setup_logger(verbose=args.verbose, use_colour=not args.no_color)

    # ── Targets ──────────────────────────────
    try:
        targets = resolve_targets(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"{Colors.RED}[!] Target error: {exc}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    logger.info("Resolved %d target(s)", len(targets))

    # ── Ports ────────────────────────────────
    try:
        ports = resolve_ports(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"{Colors.RED}[!] Port error: {exc}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    logger.info("Scanning %d port(s)", len(ports))

    # ── Threads cap ──────────────────────────
    threads = min(args.threads, MAX_THREADS)

    # ── Scan type ────────────────────────────
    scan_type_map = {"T": ScanType.TCP_CONNECT, "S": ScanType.TCP_SYN, "U": ScanType.UDP}
    scan_type = scan_type_map.get(args.scan_type, ScanType.TCP_CONNECT)

    # ── Config ───────────────────────────────
    config = ScanConfig(
        targets=targets,
        ports=ports,
        scan_type=scan_type,
        threads=threads,
        timeout=args.timeout,
        retries=args.retries,
        service_detection=args.service_detection,
        banner_grabbing=not args.no_banner,
        output_json=args.output_json,
        output_csv=args.output_csv,
        output_txt=args.output_txt,
        verbose=args.verbose,
        no_color=args.no_color,
        rate_limit=args.rate_limit,
    )

    # ── Instantiate components ───────────────
    if scan_type == ScanType.TCP_SYN:
        scanner = SYNScanner(timeout=config.timeout, retries=config.retries)
    elif scan_type == ScanType.UDP:
        scanner = UDPScanner(timeout=config.timeout, retries=config.retries)
    else:
        scanner = TCPScanner(timeout=config.timeout, retries=config.retries, rate_limit=config.rate_limit)

    service_mapper = ServiceMapper()
    banner_grabber = BannerGrabber()
    vuln_detector = VulnDetector()
    reporter = ReportGenerator(no_color=config.no_color)

    # ── Scan loop ────────────────────────────
    all_results: List[ScanResult] = []
    scan_start = time.time()

    try:
        for idx, target_ip in enumerate(targets):
            print(
                f"\n{Colors.BOLD}{Colors.CYAN}"
                f"[*] Scanning target {idx + 1}/{len(targets)}: {target_ip}"
                f"{Colors.RESET}"
            )

            progress_start = time.time()

            def progress_cb(done: int, total: int, _ps=progress_start) -> None:
                reporter.print_progress(done, total, _ps)

            results = scanner.scan_all_ports(
                target_ip=target_ip,
                ports=ports,
                threads=threads,
                timeout=config.timeout,
                progress_callback=progress_cb,
            )

            # ── Service detection ────────────
            if config.service_detection:
                for r in results:
                    if r.state == PortState.OPEN:
                        svc_info = service_mapper.get_service(r.port, r.protocol)
                        r.service = svc_info.name

            # ── Banner grabbing ──────────────
            if config.banner_grabbing:
                open_results = [r for r in results if r.state == PortState.OPEN]
                if open_results:
                    print(f"  {Colors.CYAN}[*] Grabbing banners for {len(open_results)} open port(s)…{Colors.RESET}")
                for r in open_results:
                    svc_name = r.service or service_mapper.get_service(r.port, r.protocol).name
                    if not r.service:
                        r.service = svc_name
                    banner_result = banner_grabber.grab_banner(r.ip, r.port, svc_name)
                    if banner_result.raw_banner:
                        r.banner = banner_result.raw_banner
                    if banner_result.version:
                        r.version = banner_result.version
                    elif banner_result.raw_banner:
                        r.version = banner_grabber.extract_version(
                            banner_result.raw_banner, svc_name,
                        )

            # ── Vulnerability detection ──────
            for r in results:
                if r.state == PortState.OPEN:
                    if not r.service:
                        r.service = service_mapper.get_service(r.port, r.protocol).name
                    vulns = vuln_detector.check_vulnerabilities(r)
                    r.vulnerability_flags = vulns

            all_results.extend(results)

            # ── Per-target console report ────
            scan_duration = time.time() - progress_start
            reporter.print_console(results, config, scan_duration, target_ip=target_ip)

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user. Partial results:{Colors.RESET}")
        elapsed = time.time() - scan_start
        reporter.print_console(all_results, config, elapsed, target_ip="(interrupted)")

    # ── Total duration ───────────────────────
    total_duration = time.time() - scan_start

    # ── File reports ─────────────────────────
    if config.output_json:
        reporter.generate_json(all_results, config, config.output_json, total_duration)
        print(f"  {Colors.GREEN}[✓] JSON report → {config.output_json}{Colors.RESET}")

    if config.output_csv:
        reporter.generate_csv(all_results, config, config.output_csv)
        print(f"  {Colors.GREEN}[✓] CSV report  → {config.output_csv}{Colors.RESET}")

    if config.output_txt:
        reporter.generate_txt(all_results, config, config.output_txt, total_duration)
        print(f"  {Colors.GREEN}[✓] TXT report  → {config.output_txt}{Colors.RESET}")

    # ── Final summary ────────────────────────
    n_open = sum(1 for r in all_results if r.state == PortState.OPEN)
    print(
        f"\n{Colors.BOLD}"
        f"  Scan complete: {len(all_results)} port(s) scanned across "
        f"{len(targets)} target(s) in {total_duration:.2f}s "
        f"— {Colors.GREEN}{n_open} open{Colors.RESET}"
        f"{Colors.BOLD} port(s) found.{Colors.RESET}\n"
    )


if __name__ == "__main__":
    main()
