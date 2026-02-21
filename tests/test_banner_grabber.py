"""Unit tests for ``detection.banner_grabber``."""

import os
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.banner_grabber import BannerGrabber


class TestBannerGrabber(unittest.TestCase):
    """Tests for the BannerGrabber class."""

    def setUp(self) -> None:
        self.grabber = BannerGrabber(timeout=1.0, max_length=1024)

    # ── HTTP banner ──────────────────────────

    @patch("detection.banner_grabber.socket.socket")
    def test_http_banner(self, mock_socket_cls: MagicMock) -> None:
        """HTTP banner should parse Server header."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.54\r\n"
            b"X-Powered-By: PHP/8.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        sock_inst.recv.side_effect = [response, b""]

        result = self.grabber.grab_banner("127.0.0.1", 80, "http")
        self.assertIn("Apache", result.raw_banner)
        self.assertIsNotNone(result.version)

    # ── SSH banner ───────────────────────────

    @patch("detection.banner_grabber.socket.socket")
    def test_ssh_banner(self, mock_socket_cls: MagicMock) -> None:
        """SSH banner should return the version string."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

        result = self.grabber.grab_banner("127.0.0.1", 22, "ssh")
        self.assertIn("SSH-2.0", result.raw_banner)
        self.assertIsNotNone(result.version)
        self.assertIn("OpenSSH", result.version)

    # ── FTP banner ───────────────────────────

    @patch("detection.banner_grabber.socket.socket")
    def test_ftp_banner(self, mock_socket_cls: MagicMock) -> None:
        """FTP banner should capture 220 greeting."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"220 (vsFTPd 3.0.5)\r\n"

        result = self.grabber.grab_banner("127.0.0.1", 21, "ftp")
        self.assertIn("220", result.raw_banner)

    # ── Timeout handling ─────────────────────

    @patch("detection.banner_grabber.socket.socket")
    def test_timeout_handling(self, mock_socket_cls: MagicMock) -> None:
        """Socket timeout should return empty banner gracefully."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect.side_effect = socket.timeout("timed out")

        result = self.grabber.grab_banner("127.0.0.1", 9999, "generic")
        self.assertEqual(result.raw_banner, "")

    # ── Binary data handling ─────────────────

    @patch("detection.banner_grabber.socket.socket")
    def test_binary_data_handling(self, mock_socket_cls: MagicMock) -> None:
        """Binary data should be decoded without raising."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"\x00\x01\xff\xfe\x80binary"

        result = self.grabber.grab_banner("127.0.0.1", 12345, "generic")
        self.assertIsInstance(result.raw_banner, str)

    # ── Version extraction ───────────────────

    def test_version_extraction_ssh(self) -> None:
        version = self.grabber.extract_version(
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu", "ssh"
        )
        self.assertIsNotNone(version)
        self.assertIn("SSH-2.0", version)

    def test_version_extraction_http(self) -> None:
        version = self.grabber.extract_version(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.22.1\r\n", "http"
        )
        self.assertIsNotNone(version)
        self.assertIn("nginx", version)

    def test_version_extraction_no_match(self) -> None:
        version = self.grabber.extract_version("random garbage", "unknown")
        self.assertIsNone(version)

    # ── Truncation ───────────────────────────

    @patch("detection.banner_grabber.socket.socket")
    def test_banner_truncation(self, mock_socket_cls: MagicMock) -> None:
        """Banners exceeding max_length should be truncated."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.recv.side_effect = [b"A" * 5000, b""]

        grabber = BannerGrabber(timeout=1.0, max_length=256)
        result = grabber.grab_banner("127.0.0.1", 9999, "generic")
        self.assertLessEqual(len(result.raw_banner), 256)


if __name__ == "__main__":
    unittest.main()
