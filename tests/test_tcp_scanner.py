"""Unit tests for ``scanner.tcp_scanner``."""

import errno
import os
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PortState
from scanner.tcp_scanner import TCPScanner


class TestTCPScanner(unittest.TestCase):
    """Tests for the TCPScanner class."""

    def setUp(self) -> None:
        self.scanner = TCPScanner(timeout=0.5, retries=1, rate_limit=0)

    # ── scan_port ────────────────────────────

    @patch("scanner.tcp_scanner.socket.socket")
    def test_scan_open_port(self, mock_socket_cls: MagicMock) -> None:
        """connect_ex returning 0 → OPEN."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.return_value = 0

        result = self.scanner.scan_port("127.0.0.1", 80)
        self.assertEqual(result.state, PortState.OPEN)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.ip, "127.0.0.1")
        self.assertEqual(result.protocol, "tcp")
        sock_inst.close.assert_called_once()

    @patch("scanner.tcp_scanner.socket.socket")
    def test_scan_closed_port(self, mock_socket_cls: MagicMock) -> None:
        """connect_ex returning ECONNREFUSED → CLOSED."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.return_value = errno.ECONNREFUSED

        result = self.scanner.scan_port("127.0.0.1", 9999)
        self.assertEqual(result.state, PortState.CLOSED)

    @patch("scanner.tcp_scanner.socket.socket")
    def test_scan_timeout(self, mock_socket_cls: MagicMock) -> None:
        """connect_ex raising socket.timeout → FILTERED."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.side_effect = socket.timeout("timed out")

        result = self.scanner.scan_port("127.0.0.1", 12345)
        self.assertEqual(result.state, PortState.FILTERED)

    @patch("scanner.tcp_scanner.socket.socket")
    def test_scan_connection_refused(self, mock_socket_cls: MagicMock) -> None:
        """connect_ex raising ConnectionRefusedError → CLOSED."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.side_effect = ConnectionRefusedError()

        result = self.scanner.scan_port("127.0.0.1", 1234)
        self.assertEqual(result.state, PortState.CLOSED)

    # ── scan_single (retries) ────────────────

    @patch("scanner.tcp_scanner.socket.socket")
    def test_scan_with_retries(self, mock_socket_cls: MagicMock) -> None:
        """Filtered on first try, open on retry."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        # First call → timeout (FILTERED), second call → open
        sock_inst.connect_ex.side_effect = [socket.timeout("t"), 0]

        scanner = TCPScanner(timeout=0.1, retries=1)
        # Need fresh sockets per call, so we must handle that
        sock_instances = [MagicMock(), MagicMock()]
        sock_instances[0].connect_ex.side_effect = socket.timeout("t")
        sock_instances[1].connect_ex.return_value = 0
        mock_socket_cls.side_effect = sock_instances

        result = scanner.scan_single("127.0.0.1", 80, timeout=0.1, retries=1)
        # After retry it should be OPEN
        self.assertEqual(result.state, PortState.OPEN)

    # ── scan_all_ports (threading) ───────────

    @patch("scanner.tcp_scanner.socket.socket")
    def test_scan_all_ports_threading(self, mock_socket_cls: MagicMock) -> None:
        """Verify ThreadPoolExecutor is used and results are collected."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.return_value = 0

        results = self.scanner.scan_all_ports(
            target_ip="127.0.0.1",
            ports=[80, 443, 8080],
            threads=2,
        )
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.state == PortState.OPEN for r in results))
        # Sorted by port
        self.assertEqual([r.port for r in results], [80, 443, 8080])

    @patch("scanner.tcp_scanner.socket.socket")
    def test_scan_all_ports_progress(self, mock_socket_cls: MagicMock) -> None:
        """Verify progress callback is invoked."""
        sock_inst = MagicMock()
        mock_socket_cls.return_value = sock_inst
        sock_inst.connect_ex.return_value = 0

        progress_calls = []

        def progress_cb(done: int, total: int) -> None:
            progress_calls.append((done, total))

        self.scanner.scan_all_ports(
            target_ip="127.0.0.1",
            ports=[22, 80],
            threads=1,
            progress_callback=progress_cb,
        )
        self.assertEqual(len(progress_calls), 2)
        # Final call should have done == total
        self.assertEqual(progress_calls[-1][0], progress_calls[-1][1])


if __name__ == "__main__":
    unittest.main()
