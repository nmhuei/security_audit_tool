"""tests/test_port_scanner.py – Unit tests for scanner/port_scanner.py"""
from __future__ import annotations
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.port_scanner import (
    scan_open_ports, _check_port, _grab_banner,
    COMMON_PORTS, PORT_RISK,
)


class TestCheckPort(unittest.TestCase):
    def test_closed_port_returns_none(self):
        result = _check_port("127.0.0.1", 19998, 0.1)
        self.assertIsNone(result)

    def test_open_port_returns_port_number(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        _, port = srv.getsockname()
        srv.listen(1)
        t = threading.Thread(target=lambda: srv.accept(), daemon=True)
        t.start()
        result = _check_port("127.0.0.1", port, 1.0)
        srv.close()
        self.assertEqual(result, port)

    def test_invalid_host_returns_none(self):
        result = _check_port("256.256.256.256", 80, 0.1)
        self.assertIsNone(result)


class TestPortRisk(unittest.TestCase):
    def test_critical_ports_have_critical_severity(self):
        critical_ports = [23, 6379, 27017, 9200]
        for port in critical_ports:
            if port in PORT_RISK:
                _, sev = PORT_RISK[port]
                self.assertIn(sev, ("CRITICAL", "HIGH"),
                              f"Port {port} should be HIGH or CRITICAL")

    def test_database_ports_at_least_medium(self):
        db_ports = [3306, 5432, 1433]
        for port in db_ports:
            if port in PORT_RISK:
                _, sev = PORT_RISK[port]
                self.assertNotEqual(sev, "LOW",
                                    f"DB port {port} should not be LOW severity")

    def test_telnet_critical(self):
        self.assertIn(23, PORT_RISK)
        _, sev = PORT_RISK[23]
        self.assertEqual(sev, "CRITICAL")

    def test_docker_tcp_critical(self):
        self.assertIn(2375, PORT_RISK)
        _, sev = PORT_RISK[2375]
        self.assertEqual(sev, "CRITICAL")

    def test_all_severities_valid(self):
        for port, (svc, sev) in PORT_RISK.items():
            self.assertIn(sev, ("LOW","MEDIUM","HIGH","CRITICAL"),
                          f"Port {port} has invalid severity: {sev}")


class TestGrabBanner(unittest.TestCase):
    def test_returns_empty_for_non_banner_port(self):
        """Ports not in BANNER_PORTS should return empty string."""
        result = _grab_banner("127.0.0.1", 9999, 0.1)
        self.assertEqual(result, "")

    def test_banner_truncated_to_200(self):
        """Banner should never exceed 200 chars."""
        with patch("socket.socket") as mock_sock:
            instance = MagicMock()
            instance.recv.return_value = b"X" * 500
            mock_sock.return_value = instance
            instance.connect_ex.return_value = 0
            # _grab_banner connects for port 80
            result = _grab_banner("127.0.0.1", 80, 0.1)
        self.assertLessEqual(len(result), 200)

    def test_connection_error_returns_empty(self):
        with patch("socket.socket") as mock_sock:
            instance = MagicMock()
            instance.connect.side_effect = OSError("refused")
            mock_sock.return_value = instance
            result = _grab_banner("127.0.0.1", 80, 0.1)
        self.assertEqual(result, "")


class TestScanOpenPorts(unittest.TestCase):
    def _open_server(self):
        """Start a real local TCP server, return (server, port)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        _, port = srv.getsockname()
        srv.listen(5)
        t = threading.Thread(target=lambda: srv.accept(), daemon=True)
        t.start()
        return srv, port

    def test_open_port_detected(self):
        srv, port = self._open_server()
        try:
            findings = scan_open_ports(host="127.0.0.1", ports=[port],
                                       timeout=1.0, grab_banners=False)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].evidence["port"], port)
        finally:
            srv.close()

    def test_closed_port_not_reported(self):
        findings = scan_open_ports(host="127.0.0.1", ports=[19997],
                                   timeout=0.2, grab_banners=False)
        self.assertEqual(len(findings), 0)

    def test_finding_has_required_evidence(self):
        srv, port = self._open_server()
        try:
            findings = scan_open_ports(host="127.0.0.1", ports=[port],
                                       timeout=1.0, grab_banners=False)
            if findings:
                ev = findings[0].evidence
                self.assertIn("port", ev)
                self.assertIn("host", ev)
                self.assertIn("service", ev)
        finally:
            srv.close()

    def test_multiple_ports_all_found(self):
        srv1, p1 = self._open_server()
        srv2, p2 = self._open_server()
        try:
            findings = scan_open_ports(host="127.0.0.1", ports=[p1, p2, 19996],
                                       timeout=1.0, grab_banners=False)
            found_ports = {f.evidence["port"] for f in findings}
            self.assertIn(p1, found_ports)
            self.assertIn(p2, found_ports)
            self.assertNotIn(19996, found_ports)
        finally:
            srv1.close()
            srv2.close()

    def test_risky_port_gets_correct_severity(self):
        srv, port = self._open_server()
        try:
            # Temporarily make the port appear as redis (6379)
            with patch("scanner.port_scanner.PORT_RISK",
                       {port: ("TestRedis", "CRITICAL")}):
                findings = scan_open_ports(host="127.0.0.1", ports=[port],
                                           timeout=1.0, grab_banners=False)
            if findings:
                self.assertEqual(findings[0].severity, "CRITICAL")
        finally:
            srv.close()

    def test_unknown_port_gets_low(self):
        srv, port = self._open_server()
        try:
            with patch("scanner.port_scanner.PORT_RISK", {}):
                findings = scan_open_ports(host="127.0.0.1", ports=[port],
                                           timeout=1.0, grab_banners=False)
            if findings:
                self.assertEqual(findings[0].severity, "LOW")
        finally:
            srv.close()

    def test_common_ports_list_coverage(self):
        """COMMON_PORTS should contain standard risky ports."""
        for p in [21, 22, 23, 80, 443, 3306, 6379, 27017]:
            self.assertIn(p, COMMON_PORTS)

    def test_deduplication_of_ports(self):
        """Duplicate ports in input should not cause duplicate findings."""
        srv, port = self._open_server()
        try:
            findings = scan_open_ports(host="127.0.0.1",
                                       ports=[port, port, port],
                                       timeout=1.0, grab_banners=False)
            self.assertLessEqual(len(findings), 1)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
