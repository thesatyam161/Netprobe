"""
NetProbe — Port specification parser.

Converts user-supplied port strings (``"80"``, ``"22,80,443"``,
``"1-1024"``, ``"22,80,8000-9000"``) into sorted, deduplicated lists
of port numbers.  Also provides access to the *top-N ports* list shipped
in ``data/top_ports.json``.
"""

import json
import logging
import os
from typing import List

logger = logging.getLogger("netprobe.scanner.port_parser")

# Resolve path to the bundled data directory
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_TOP_PORTS_FILE = os.path.join(_DATA_DIR, "top_ports.json")


def validate_port(port: int) -> bool:
    """Return *True* if *port* is within the valid TCP/UDP range (1-65535).

    Parameters
    ----------
    port : int
        Port number to validate.

    Returns
    -------
    bool
    """
    return isinstance(port, int) and 1 <= port <= 65535


def parse_ports(port_spec: str) -> List[int]:
    """Parse a port specification string into a sorted, unique list of ints.

    Supported formats
    -----------------
    * Single port:  ``"80"``
    * Comma list:   ``"80,443,8080"``
    * Range:        ``"1-1024"``
    * Mixed:        ``"22,80,443,8000-9000"``

    Parameters
    ----------
    port_spec : str
        User-supplied port specification.

    Returns
    -------
    list[int]
        Sorted list of unique, valid port numbers.

    Raises
    ------
    ValueError
        If the specification contains invalid values.

    Examples
    --------
    >>> parse_ports("22,80,443")
    [22, 80, 443]
    >>> parse_ports("8000-8005")
    [8000, 8001, 8002, 8003, 8004, 8005]
    """
    if not port_spec or not port_spec.strip():
        raise ValueError("Empty port specification")

    ports: set = set()
    tokens = [t.strip() for t in port_spec.split(",") if t.strip()]

    for token in tokens:
        if "-" in token:
            # Range: "start-end"
            parts = token.split("-", 1)
            if len(parts) != 2:
                raise ValueError(f"Invalid port range: '{token}'")
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                raise ValueError(f"Non-integer in port range: '{token}'")

            if not validate_port(start):
                raise ValueError(f"Port out of range (1-65535): {start}")
            if not validate_port(end):
                raise ValueError(f"Port out of range (1-65535): {end}")
            if start > end:
                raise ValueError(f"Invalid range — start ({start}) > end ({end})")

            ports.update(range(start, end + 1))
        else:
            # Single port
            try:
                p = int(token)
            except ValueError:
                raise ValueError(f"Non-integer port value: '{token}'")
            if not validate_port(p):
                raise ValueError(f"Port out of range (1-65535): {p}")
            ports.add(p)

    if not ports:
        raise ValueError("No valid ports parsed from specification")

    result = sorted(ports)
    logger.debug("Parsed %d ports from spec '%s'", len(result), port_spec)
    return result


def get_top_ports(n: int = 100) -> List[int]:
    """Return the top *n* most commonly scanned ports.

    Port data is loaded from ``data/top_ports.json``.

    Parameters
    ----------
    n : int
        Number of ports to return (max = length of the data file).

    Returns
    -------
    list[int]
        Top *n* port numbers.

    Raises
    ------
    FileNotFoundError
        If the top-ports data file is missing.
    ValueError
        If *n* < 1.
    """
    if n < 1:
        raise ValueError("n must be >= 1")

    try:
        with open(_TOP_PORTS_FILE, "r", encoding="utf-8") as fh:
            all_ports: List[int] = json.load(fh)
    except FileNotFoundError:
        raise FileNotFoundError(f"Top-ports data file not found: {_TOP_PORTS_FILE}")

    # Deduplicate while preserving order (the JSON may have duplicates)
    seen: set = set()
    unique: List[int] = []
    for p in all_ports:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique[:n]
