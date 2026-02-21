"""Unit tests for ``scanner.port_parser``."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.port_parser import parse_ports, validate_port, get_top_ports


class TestPortParser(unittest.TestCase):
    """Tests for port specification parsing."""

    def test_single_port(self) -> None:
        self.assertEqual(parse_ports("80"), [80])

    def test_port_list(self) -> None:
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_port_range(self) -> None:
        result = parse_ports("1-10")
        self.assertEqual(result, list(range(1, 11)))

    def test_mixed_ports(self) -> None:
        result = parse_ports("22,80,443,8000-8005")
        expected = sorted({22, 80, 443, 8000, 8001, 8002, 8003, 8004, 8005})
        self.assertEqual(result, expected)

    def test_all_ports(self) -> None:
        result = parse_ports("1-65535")
        self.assertEqual(len(result), 65535)
        self.assertEqual(result[0], 1)
        self.assertEqual(result[-1], 65535)

    def test_duplicate_removal(self) -> None:
        result = parse_ports("80,80,443,443")
        self.assertEqual(result, [80, 443])

    def test_invalid_port_zero(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_invalid_port_too_high(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("65536")

    def test_invalid_port_string(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("abc")

    def test_invalid_range_reversed(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("1024-22")

    def test_empty_spec(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("")

    def test_validate_port_valid(self) -> None:
        self.assertTrue(validate_port(1))
        self.assertTrue(validate_port(80))
        self.assertTrue(validate_port(65535))

    def test_validate_port_invalid(self) -> None:
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(65536))
        self.assertFalse(validate_port(-1))

    def test_top_ports(self) -> None:
        top = get_top_ports(10)
        self.assertEqual(len(top), 10)
        # Should contain well-known ports
        self.assertIn(80, top)
        self.assertIn(443, top)

    def test_top_ports_all(self) -> None:
        top = get_top_ports(100)
        self.assertLessEqual(len(top), 100)
        self.assertGreater(len(top), 0)


if __name__ == "__main__":
    unittest.main()
