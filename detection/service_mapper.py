"""
NetProbe — Service mapper.

Maps (port, protocol) pairs to human-readable service names using the
bundled ``data/services_db.json`` database.
"""

import json
import logging
import os
import sys
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ServiceInfo

logger = logging.getLogger("netprobe.detection.service_mapper")

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_SERVICES_FILE = os.path.join(_DATA_DIR, "services_db.json")


class ServiceMapper:
    """Look up service info for a given port and protocol.

    The database is loaded lazily on first use and cached for the
    lifetime of the instance.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or _SERVICES_FILE
        self._db: Optional[Dict] = None

    def _load(self) -> None:
        """Load the service database from disk."""
        if self._db is not None:
            return
        try:
            with open(self._db_path, "r", encoding="utf-8") as fh:
                self._db = json.load(fh)
            logger.debug("Loaded service DB from %s", self._db_path)
        except FileNotFoundError:
            logger.warning("Service DB not found at %s — all lookups will return 'unknown'", self._db_path)
            self._db = {"tcp": {}, "udp": {}}
        except json.JSONDecodeError as exc:
            logger.error("Malformed services DB: %s", exc)
            self._db = {"tcp": {}, "udp": {}}

    def get_service(self, port: int, protocol: str = "tcp") -> ServiceInfo:
        """Return service information for *port* / *protocol*.

        Parameters
        ----------
        port : int
            Port number.
        protocol : str
            ``"tcp"`` or ``"udp"``.

        Returns
        -------
        ServiceInfo
            Populated with name, description, and default_port.
            Falls back to ``"unknown"`` if the port is not in the database.
        """
        self._load()
        assert self._db is not None

        proto_map = self._db.get(protocol.lower(), {})
        entry = proto_map.get(str(port))

        if entry:
            return ServiceInfo(
                name=entry.get("name", "unknown"),
                description=entry.get("description", ""),
                default_port=port,
            )

        return ServiceInfo(name="unknown", description="", default_port=port)

    def get_probe(self, port: int, protocol: str = "tcp") -> bytes:
        """Return a probe payload appropriate for *port* / *protocol*.

        Parameters
        ----------
        port : int
        protocol : str

        Returns
        -------
        bytes
            Protocol-specific probe (may be empty for passive-read
            services).
        """
        self._load()
        assert self._db is not None

        proto_map = self._db.get(protocol.lower(), {})
        entry = proto_map.get(str(port))

        if entry and "probe" in entry:
            raw = entry["probe"]
            # The JSON stores probes as escaped strings
            try:
                return raw.encode("utf-8").decode("unicode_escape").encode("latin-1")
            except Exception:
                return raw.encode("utf-8")

        # Fallback: simple CRLF
        return b"\r\n"
