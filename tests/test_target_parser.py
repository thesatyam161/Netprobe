"""Unit tests for ``network.target_parser``."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.target_parser import (
    expand_cidr,
    expand_range,
    parse_target,
    parse_target_file,
    resolve_hostname,
    validate_ip,
)


class TestTargetParser(unittest.TestCase):
    """Tests for target specification parsing."""

    # ── validate_ip ──────────────────────────

    def test_valid_ipv4(self) -> None:
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("255.255.255.255"))

    def test_invalid_ip(self) -> None:
        self.assertFalse(validate_ip("999.999.999.999"))
        self.assertFalse(validate_ip("not_an_ip"))
        self.assertFalse(validate_ip(""))

    # ── parse_target (single IP) ─────────────

    def test_single_ip(self) -> None:
        result = parse_target("192.168.1.1")
        self.assertEqual(result, ["192.168.1.1"])

    # ── CIDR ─────────────────────────────────

    def test_cidr_24(self) -> None:
        result = expand_cidr("192.168.1.0/24")
        self.assertEqual(len(result), 254)  # excludes network + broadcast
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.254", result)

    def test_cidr_32(self) -> None:
        result = expand_cidr("10.0.0.5/32")
        self.assertEqual(result, ["10.0.0.5"])

    def test_cidr_invalid(self) -> None:
        with self.assertRaises(ValueError):
            expand_cidr("invalid/24")

    # ── Range ────────────────────────────────

    def test_ip_range(self) -> None:
        result = expand_range("10.0.0.1-5")
        self.assertEqual(len(result), 5)
        self.assertEqual(result[0], "10.0.0.1")
        self.assertEqual(result[-1], "10.0.0.5")

    def test_range_single(self) -> None:
        result = expand_range("10.0.0.10-10")
        self.assertEqual(result, ["10.0.0.10"])

    def test_range_invalid_reversed(self) -> None:
        with self.assertRaises(ValueError):
            expand_range("10.0.0.10-5")

    # ── Hostname resolution ──────────────────

    @patch("network.target_parser.socket.gethostbyname")
    def test_hostname_resolution(self, mock_resolve: unittest.mock.MagicMock) -> None:
        mock_resolve.return_value = "93.184.216.34"
        result = parse_target("example.com")
        self.assertEqual(result, ["93.184.216.34"])
        mock_resolve.assert_called_once_with("example.com")

    @patch("network.target_parser.socket.gethostbyname")
    def test_hostname_resolution_failure(self, mock_resolve: unittest.mock.MagicMock) -> None:
        import socket as _socket
        mock_resolve.side_effect = _socket.gaierror("Name or service not known")
        with self.assertRaises(ValueError):
            parse_target("nonexistent.invalid")

    # ── Comma-separated ──────────────────────

    def test_comma_separated(self) -> None:
        result = parse_target("192.168.1.1,192.168.1.2")
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2"])

    def test_deduplication(self) -> None:
        result = parse_target("10.0.0.1,10.0.0.1,10.0.0.1")
        self.assertEqual(result, ["10.0.0.1"])

    # ── parse_target_file ────────────────────

    def test_target_file(self) -> None:
        content = "192.168.1.1\n# comment\n\n10.0.0.1\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            path = f.name
        try:
            result = parse_target_file(path)
            self.assertEqual(result, ["192.168.1.1", "10.0.0.1"])
        finally:
            os.unlink(path)

    def test_target_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            parse_target_file("/nonexistent/path/targets.txt")

    # ── Empty inputs ─────────────────────────

    def test_empty_target(self) -> None:
        with self.assertRaises(ValueError):
            parse_target("")


if __name__ == "__main__":
    unittest.main()
