"""
NetProbe — Target parser.

Validate, resolve, and expand target specifications into a flat list of
IPv4 addresses that can be fed to the scanner.
"""

import ipaddress
import logging
import socket
from typing import List

logger = logging.getLogger("netprobe.network.target_parser")


def validate_ip(ip: str) -> bool:
    """Return *True* if *ip* is a valid IPv4 or IPv6 address.

    Parameters
    ----------
    ip : str
        The candidate IP string.

    Returns
    -------
    bool
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> str:
    """Resolve a hostname to its first IPv4 address.

    Parameters
    ----------
    hostname : str
        DNS name to resolve (e.g. ``example.com``).

    Returns
    -------
    str
        Resolved IPv4 address string.

    Raises
    ------
    ValueError
        If DNS resolution fails.
    """
    try:
        ip = socket.gethostbyname(hostname)
        logger.debug("Resolved %s → %s", hostname, ip)
        return ip
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {exc}") from exc


def expand_cidr(cidr: str) -> List[str]:
    """Expand a CIDR notation to individual host addresses.

    Parameters
    ----------
    cidr : str
        CIDR string, e.g. ``192.168.1.0/24``.

    Returns
    -------
    list[str]
        List of host IP address strings (network and broadcast excluded
        for /31 and smaller prefixes).
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # For /32 (single host) just return that address
        if network.prefixlen == 32:
            return [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR notation '{cidr}': {exc}") from exc


def expand_range(range_str: str) -> List[str]:
    """Expand a dash-range like ``192.168.1.1-254`` into individual IPs.

    The last octet is treated as a range.  E.g.
    ``10.0.0.100-110``  →  ``10.0.0.100, 10.0.0.101, …, 10.0.0.110``

    Parameters
    ----------
    range_str : str
        Dash-range specification.

    Returns
    -------
    list[str]

    Raises
    ------
    ValueError
        If the format is invalid.
    """
    try:
        base, end_str = range_str.rsplit("-", 1)
        end_val = int(end_str)

        # Find last octet in base
        parts = base.rsplit(".", 1)
        if len(parts) != 2:
            raise ValueError("Expected base.start-end format")

        prefix = parts[0]
        start_val = int(parts[1])

        if not (0 <= start_val <= 255 and 0 <= end_val <= 255):
            raise ValueError("Octet values must be 0-255")
        if start_val > end_val:
            raise ValueError("Start must be <= end")

        ips: List[str] = []
        for octet in range(start_val, end_val + 1):
            ip_str = f"{prefix}.{octet}"
            if validate_ip(ip_str):
                ips.append(ip_str)
            else:
                raise ValueError(f"Generated invalid IP: {ip_str}")
        return ips
    except (ValueError, IndexError) as exc:
        raise ValueError(f"Invalid range specification '{range_str}': {exc}") from exc


def _parse_single_target(target_str: str) -> List[str]:
    """Parse **one** target token (no commas) into a list of IPs.

    Handles: single IP, CIDR, dash-range, or hostname.
    """
    target_str = target_str.strip()
    if not target_str:
        return []

    # CIDR?
    if "/" in target_str:
        return expand_cidr(target_str)

    # Dash-range?  e.g. 192.168.1.1-254
    if "-" in target_str:
        return expand_range(target_str)

    # Plain IP?
    if validate_ip(target_str):
        return [target_str]

    # Assume hostname
    resolved = resolve_hostname(target_str)
    return [resolved]


def parse_target(target_str: str) -> List[str]:
    """Parse a target specification into a list of IP addresses.

    Supports comma-separated values where each token may be a single IP,
    a CIDR block, a dash-range, or a hostname.

    Parameters
    ----------
    target_str : str
        Target specification string.

    Returns
    -------
    list[str]
        Deduplicated list of IPv4 addresses.

    Raises
    ------
    ValueError
        If any token cannot be parsed.

    Examples
    --------
    >>> parse_target("192.168.1.1")
    ['192.168.1.1']
    >>> parse_target("10.0.0.0/30")
    ['10.0.0.1', '10.0.0.2']
    """
    tokens = [t.strip() for t in target_str.split(",") if t.strip()]
    if not tokens:
        raise ValueError("No targets specified")

    all_ips: List[str] = []
    for token in tokens:
        all_ips.extend(_parse_single_target(token))

    # Deduplicate but preserve order
    seen: set = set()
    unique: List[str] = []
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def parse_target_file(filepath: str) -> List[str]:
    """Read targets from a file (one per line).

    Blank lines and lines starting with ``#`` are skipped.

    Parameters
    ----------
    filepath : str
        Path to the target-list file.

    Returns
    -------
    list[str]
        Deduplicated list of IP addresses.

    Raises
    ------
    FileNotFoundError
        If *filepath* does not exist.
    ValueError
        If a line cannot be parsed.
    """
    all_ips: List[str] = []
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    all_ips.extend(parse_target(line))
                except ValueError as exc:
                    raise ValueError(
                        f"Error on line {lineno} of '{filepath}': {exc}"
                    ) from exc
    except FileNotFoundError:
        raise FileNotFoundError(f"Target file not found: '{filepath}'")

    # Deduplicate
    seen: set = set()
    unique: List[str] = []
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique
