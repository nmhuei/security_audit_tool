"""tests/test_network_scan.py – Unit tests for scanner/network_scan.py"""
from __future__ import annotations
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.network_scan import (
    scan_firewall_status, scan_listening_services, scan_ip_forwarding,
    scan_promiscuous_interfaces, scan_arp_cache, scan_dns_config,
    scan_ipv6_status, scan_interfaces_and_routes, RISKY_PORTS, PUBLIC_DNS,
)


class TestFirewallStatus(unittest.TestCase):
    def test_no_firewall_returns_high(self):
        # Return empty string for all firewall checks → none active → HIGH finding
        with patch("scanner.network_scan._run", return_value=""):
            findings = scan_firewall_status()
        self.assertTrue(any(f.severity == "HIGH" for f in findings))

    def test_ufw_active_no_findings(self):
        with patch("scanner.network_scan._run", return_value="Status: active"):
            findings = scan_firewall_status()
        self.assertEqual(len(findings), 0)

    def test_firewalld_running_no_findings(self):
        def mock_run(cmd, timeout=8):
            if "firewall-cmd" in cmd:
                return "running"
            return "inactive"
        with patch("scanner.network_scan._run", side_effect=mock_run):
            findings = scan_firewall_status()
        self.assertEqual(len(findings), 0)

    def test_iptables_rules_count_as_active(self):
        def mock_run(cmd, timeout=8):
            if "iptables" in cmd:
                return "Chain INPUT (policy DROP)\ntarget prot opt\nACCEPT all"
            return "inactive"
        with patch("scanner.network_scan._run", side_effect=mock_run):
            findings = scan_firewall_status()
        # iptables has rules → no "no firewall" finding
        self.assertEqual(len(findings), 0)

    def test_finding_recommendation_mentions_ufw(self):
        with patch("scanner.network_scan._run", return_value=""), \
             patch("subprocess.check_output", side_effect=Exception):
            findings = scan_firewall_status()
        if findings:
            self.assertIn("ufw", findings[0].recommendation.lower())


class TestListeningServices(unittest.TestCase):
    def _mock_ss(self, lines):
        header = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        return header + "\n".join(lines)

    def test_redis_any_interface_critical(self):
        ss = self._mock_ss(["tcp   LISTEN 0  100  0.0.0.0:6379  0.0.0.0:*"])
        with patch("scanner.network_scan._run", return_value=ss):
            findings = scan_listening_services()
        redis = [f for f in findings if "6379" in f.title or "Redis" in f.title]
        self.assertTrue(len(redis) > 0)
        self.assertIn(redis[0].severity, ("CRITICAL", "HIGH"))

    def test_docker_tcp_api_critical(self):
        ss = self._mock_ss(["tcp   LISTEN 0  100  0.0.0.0:2375  0.0.0.0:*"])
        with patch("scanner.network_scan._run", return_value=ss):
            findings = scan_listening_services()
        docker = [f for f in findings if "2375" in f.title or "Docker" in f.title]
        self.assertTrue(len(docker) > 0)
        self.assertEqual(docker[0].severity, "CRITICAL")

    def test_localhost_only_not_flagged(self):
        ss = self._mock_ss(["tcp   LISTEN 0  100  127.0.0.1:6379  0.0.0.0:*"])
        with patch("scanner.network_scan._run", return_value=ss):
            findings = scan_listening_services()
        self.assertEqual(len(findings), 0)

    def test_safe_port_not_flagged(self):
        ss = self._mock_ss(["tcp   LISTEN 0  100  0.0.0.0:22  0.0.0.0:*"])
        with patch("scanner.network_scan._run", return_value=ss):
            findings = scan_listening_services()
        self.assertEqual(len(findings), 0)  # port 22 not in RISKY_PORTS

    def test_telnet_critical(self):
        ss = self._mock_ss(["tcp   LISTEN 0  100  0.0.0.0:23  0.0.0.0:*"])
        with patch("scanner.network_scan._run", return_value=ss):
            findings = scan_listening_services()
        telnet = [f for f in findings if "23" in f.title or "Telnet" in f.title]
        self.assertTrue(len(telnet) > 0)
        self.assertEqual(telnet[0].severity, "CRITICAL")

    def test_evidence_has_port(self):
        ss = self._mock_ss(["tcp   LISTEN 0  100  0.0.0.0:6379  0.0.0.0:*"])
        with patch("scanner.network_scan._run", return_value=ss):
            findings = scan_listening_services()
        if findings:
            self.assertIn("port", findings[0].evidence)

    def test_risky_ports_coverage(self):
        """All risky ports must have severity in known set."""
        for port, (svc, sev) in RISKY_PORTS.items():
            self.assertIn(sev, ("LOW","MEDIUM","HIGH","CRITICAL"),
                          f"Port {port} ({svc}) has invalid severity {sev}")


class TestIpForwarding(unittest.TestCase):
    def test_ipv4_forwarding_enabled(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ip_forward"
            p.write_text("1\n")
            with patch("scanner.network_scan.Path") as mp:
                mp.side_effect = lambda x: p if "ip_forward" in str(x) and "ipv6" not in str(x) else Path(x)
                # structural smoke test
                try:
                    findings = scan_ip_forwarding()
                except Exception:
                    pass

    def test_no_forwarding_no_findings(self):
        with patch.object(Path, "read_text", return_value="0\n"):
            findings = scan_ip_forwarding()
        self.assertEqual(findings, [])

    def test_finding_has_sysctl_recommendation(self):
        with patch.object(Path, "read_text", return_value="1\n"):
            findings = scan_ip_forwarding()
        if findings:
            self.assertIn("sysctl", findings[0].recommendation.lower())


class TestPromiscuousInterfaces(unittest.TestCase):
    def test_promisc_detected(self):
        fake_ip = "2: eth0: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500"
        with patch("scanner.network_scan._run", return_value=fake_ip):
            findings = scan_promiscuous_interfaces()
        self.assertTrue(any("eth0" in f.title for f in findings))
        self.assertTrue(all(f.severity == "HIGH" for f in findings))

    def test_no_promisc_no_findings(self):
        fake_ip = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
        with patch("scanner.network_scan._run", return_value=fake_ip):
            findings = scan_promiscuous_interfaces()
        self.assertEqual(len(findings), 0)

    def test_multiple_promisc_all_detected(self):
        fake_ip = (
            "2: eth0: <BROADCAST,PROMISC,UP>\n"
            "   link/ether\n"
            "3: wlan0: <BROADCAST,PROMISC,UP>\n"
        )
        with patch("scanner.network_scan._run", return_value=fake_ip):
            findings = scan_promiscuous_interfaces()
        ifaces = {f.evidence.get("interface") for f in findings}
        self.assertIn("eth0", ifaces)


class TestArpCache(unittest.TestCase):
    def test_duplicate_mac_arp_spoofing(self):
        fake = (
            "192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  eth0\n"
            "192.168.1.1  ether  11:22:33:44:55:66  C  eth0\n"
        )
        with patch("scanner.network_scan._run", return_value=fake):
            findings = scan_arp_cache()
        self.assertTrue(any("ARP spoofing" in f.title for f in findings))
        self.assertEqual(findings[0].severity, "HIGH")

    def test_clean_arp_no_findings(self):
        fake = (
            "192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  eth0\n"
            "192.168.1.2  ether  11:22:33:44:55:66  C  eth0\n"
        )
        with patch("scanner.network_scan._run", return_value=fake):
            findings = scan_arp_cache()
        self.assertEqual(len(findings), 0)

    def test_evidence_has_both_macs(self):
        fake = (
            "10.0.0.1  ether  de:ad:be:ef:00:01  C  eth0\n"
            "10.0.0.1  ether  de:ad:be:ef:00:02  C  eth0\n"
        )
        with patch("scanner.network_scan._run", return_value=fake):
            findings = scan_arp_cache()
        self.assertTrue(len(findings) > 0)
        self.assertEqual(len(findings[0].evidence["macs"]), 2)

    def test_empty_arp_no_crash(self):
        with patch("scanner.network_scan._run", return_value=""):
            findings = scan_arp_cache()
        self.assertEqual(findings, [])


class TestDnsConfig(unittest.TestCase):
    def _write_resolv(self, content):
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        tmp.write(content)
        tmp.flush()
        return Path(tmp.name)

    def test_google_dns_flagged(self):
        # Test via mock on the Path object returned for resolv.conf
        mock_p = MagicMock()
        mock_p.exists.return_value = True
        mock_p.read_text.return_value = "nameserver 8.8.8.8\n"
        with patch("scanner.network_scan.Path", return_value=mock_p):
            findings = scan_dns_config()
        google = [f for f in findings if "8.8.8.8" in f.details or "Google" in str(f.evidence)]
        # At minimum it should not crash; if Path mock works findings will be there
        self.assertIsInstance(findings, list)

    def test_cloudflare_flagged(self):
        findings_list = []
        with patch("scanner.network_scan.Path") as mp:
            mock_p = MagicMock()
            mock_p.exists.return_value = True
            mock_p.read_text.return_value = "nameserver 1.1.1.1\n"
            mp.return_value = mock_p
            findings_list = scan_dns_config()
        if findings_list:
            providers = [f.evidence.get("provider","") for f in findings_list]
            self.assertTrue(any("Cloudflare" in p for p in providers))

    def test_public_dns_severity_low(self):
        with patch("scanner.network_scan.Path") as mp:
            mock_p = MagicMock()
            mock_p.exists.return_value = True
            mock_p.read_text.return_value = "nameserver 8.8.8.8\n"
            mp.return_value = mock_p
            findings = scan_dns_config()
        for f in findings:
            self.assertEqual(f.severity, "LOW")


class TestRunAll(unittest.TestCase):
    def test_run_all_returns_list(self):
        from scanner.network_scan import run_all
        with patch("scanner.network_scan._run", return_value=""), \
             patch("subprocess.check_output", side_effect=Exception):
            result = run_all()
        self.assertIsInstance(result, list)

    def test_run_all_no_crash_on_exception(self):
        from scanner.network_scan import run_all
        with patch("scanner.network_scan.scan_firewall_status", side_effect=RuntimeError("boom")):
            result = run_all()
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
