"""Unit tests for ``reporting.report_generator``."""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PortState, ScanConfig, ScanResult, ScanType, Severity, VulnFlag
from reporting.report_generator import ReportGenerator


def _sample_config() -> ScanConfig:
    """Return a minimal ScanConfig for test purposes."""
    return ScanConfig(
        targets=["127.0.0.1"],
        ports=[22, 80, 443],
        scan_type=ScanType.TCP_CONNECT,
        threads=100,
        timeout=1.0,
        retries=1,
        service_detection=True,
        banner_grabbing=True,
        output_json=None,
        output_csv=None,
        output_txt=None,
        verbose=False,
        no_color=True,
    )


def _sample_results() -> list:
    """Return a small list of ScanResult objects."""
    return [
        ScanResult(
            ip="127.0.0.1", port=22, protocol="tcp", state=PortState.OPEN,
            service="ssh", banner="SSH-2.0-OpenSSH_8.9", version="OpenSSH_8.9",
            vulnerability_flags=[
                VulnFlag(
                    flag_type="REMOTE_ACCESS",
                    severity=Severity.MEDIUM,
                    description="SSH remote access exposed",
                    remediation="Restrict via firewall",
                ),
            ],
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
        ),
        ScanResult(
            ip="127.0.0.1", port=80, protocol="tcp", state=PortState.OPEN,
            service="http", banner="HTTP/1.1 200 OK\r\nServer: nginx/1.22",
            version="nginx/1.22",
            timestamp=datetime(2024, 1, 15, 12, 0, 1),
        ),
        ScanResult(
            ip="127.0.0.1", port=443, protocol="tcp", state=PortState.CLOSED,
            timestamp=datetime(2024, 1, 15, 12, 0, 2),
        ),
    ]


class TestReportGenerator(unittest.TestCase):
    """Tests for the ReportGenerator class."""

    def setUp(self) -> None:
        self.reporter = ReportGenerator(no_color=True)
        self.config = _sample_config()
        self.results = _sample_results()

    # ── JSON output ──────────────────────────

    def test_json_output_structure(self) -> None:
        """JSON should contain scan_metadata, summary, and results."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            self.reporter.generate_json(self.results, self.config, path, duration=1.5)
            with open(path, "r") as fh:
                data = json.load(fh)

            self.assertIn("scan_metadata", data)
            self.assertIn("summary", data)
            self.assertIn("results", data)

            self.assertEqual(data["summary"]["total_scanned"], 3)
            self.assertEqual(data["summary"]["open"], 2)
            self.assertEqual(data["summary"]["closed"], 1)

            self.assertEqual(len(data["results"]), 3)
            # Check first result fields
            r0 = data["results"][0]
            self.assertEqual(r0["port"], 22)
            self.assertEqual(r0["state"], "open")
            self.assertEqual(r0["service"], "ssh")
            self.assertIn("vulnerability_flags", r0)
            self.assertEqual(len(r0["vulnerability_flags"]), 1)
        finally:
            os.unlink(path)

    def test_json_serialization(self) -> None:
        """JSON file should be valid and pretty-printed."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            self.reporter.generate_json(self.results, self.config, path)
            with open(path, "r") as fh:
                content = fh.read()
            # Pretty printed = has newlines and indentation
            self.assertIn("\n", content)
            self.assertIn("  ", content)
            # Valid JSON
            json.loads(content)
        finally:
            os.unlink(path)

    # ── CSV output ───────────────────────────

    def test_csv_output_columns(self) -> None:
        """CSV should have correct headers and row count."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            path = f.name

        try:
            self.reporter.generate_csv(self.results, self.config, path)
            with open(path, "r") as fh:
                lines = fh.readlines()

            self.assertGreater(len(lines), 0)
            header = lines[0].strip()
            self.assertIn("ip", header)
            self.assertIn("port", header)
            self.assertIn("protocol", header)
            self.assertIn("state", header)
            self.assertIn("service", header)
            self.assertIn("banner", header)
            self.assertIn("version", header)
            self.assertIn("vulnerability_flags", header)
            self.assertIn("severity", header)
            self.assertIn("timestamp", header)

            # 1 header + 3 data rows
            self.assertEqual(len(lines), 4)
        finally:
            os.unlink(path)

    # ── TXT output ───────────────────────────

    def test_txt_output_format(self) -> None:
        """TXT report should contain key sections."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            path = f.name

        try:
            self.reporter.generate_txt(self.results, self.config, path, duration=2.0)
            with open(path, "r") as fh:
                content = fh.read()

            self.assertIn("NetProbe Scan Report", content)
            self.assertIn("Scan Configuration", content)
            self.assertIn("Results", content)
            self.assertIn("Statistics", content)
            self.assertIn("Total scanned", content)
            self.assertIn("Open", content)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
