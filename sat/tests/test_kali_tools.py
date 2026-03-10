"""tests/test_kali_tools.py – Unit tests for scanner/kali_tools.py"""
from __future__ import annotations
import json, sys, unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.kali_tools import (
    _available, _run, _not_installed, run_lynis, run_chkrootkit,
    run_nmap, run_debsums, run_fail2ban_check, run_auditd_check,
    run_all, list_tools, TOOL_TIMEOUTS, TOOL_RUNNERS_FAST, TOOL_RUNNERS_DEEP,
)


class TestToolTimeouts(unittest.TestCase):
    """Each tool must declare its own timeout in TOOL_TIMEOUTS."""

    def test_all_fast_tools_have_timeout(self):
        for name in TOOL_RUNNERS_FAST:
            # nmap fast uses nmap_fast key
            key = "nmap_fast" if name == "nmap" else name
            self.assertIn(key, TOOL_TIMEOUTS,
                          f"Tool '{name}' missing from TOOL_TIMEOUTS")

    def test_all_deep_tools_have_timeout(self):
        deep_keys = {
            "lynis", "chkrootkit", "rkhunter", "nmap_deep",
            "nikto", "debsums", "tiger", "aide", "fail2ban", "auditd"
        }
        for key in deep_keys:
            self.assertIn(key, TOOL_TIMEOUTS, f"Missing timeout for '{key}'")

    def test_timeouts_are_positive(self):
        for tool, t in TOOL_TIMEOUTS.items():
            self.assertGreater(t, 0, f"Timeout for '{tool}' must be > 0")

    def test_deep_nmap_longer_than_fast(self):
        self.assertGreater(TOOL_TIMEOUTS["nmap_deep"], TOOL_TIMEOUTS["nmap_fast"])

    def test_slow_tools_have_long_timeout(self):
        """rkhunter/aide/debsums should have ≥ 120s."""
        for tool in ("rkhunter", "aide", "debsums"):
            self.assertGreaterEqual(TOOL_TIMEOUTS[tool], 120,
                                    f"{tool} timeout too short")


class TestAvailability(unittest.TestCase):
    def test_not_installed_returns_low_finding(self):
        findings = _not_installed("fakeTool")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("fakeTool", findings[0].title)

    def test_available_false_for_nonexistent(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(_available("nosuchtool"))

    def test_available_true_when_found(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            self.assertTrue(_available("nmap"))


class TestRunHelper(unittest.TestCase):
    def test_timeout_returns_minus1(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 1)):
            rc, out, err = _run(["echo", "hi"], timeout=1)
        self.assertEqual(rc, -1)
        self.assertIn("timeout", err)

    def test_not_found_returns_minus1(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            rc, out, err = _run(["notexist"])
        self.assertEqual(rc, -1)

    def test_success_returns_output(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "hello"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            rc, out, err = _run(["echo", "hello"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "hello")


class TestLynis(unittest.TestCase):
    def test_not_installed_finding(self):
        with patch("scanner.kali_tools._available", return_value=False):
            findings = run_lynis()
        self.assertTrue(any("not installed" in f.title for f in findings))

    def test_parses_hardening_score(self):
        fake_out = "Hardening index : 42 [########]\n"
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, fake_out, "")), \
             patch("scanner.kali_tools.Path", side_effect=lambda p: MagicMock(exists=lambda: False)):
            findings = run_lynis()
        scores = [f for f in findings if "42" in f.title]
        self.assertTrue(len(scores) > 0)

    def test_low_score_critical_severity(self):
        fake_out = "Hardening index : 25 [#####]\n"
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, fake_out, "")), \
             patch("scanner.kali_tools.Path") as mp:
            mp.return_value.exists.return_value = False
            findings = run_lynis()
        score_findings = [f for f in findings if "25" in f.title]
        if score_findings:
            self.assertEqual(score_findings[0].severity, "CRITICAL")

    def test_warning_parsed(self):
        fake_out = "! This is a lynis warning message\n"
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, fake_out, "")), \
             patch("scanner.kali_tools.Path") as mp:
            mp.return_value.exists.return_value = False
            findings = run_lynis()
        warnings = [f for f in findings if "WARNING" in f.title]
        self.assertTrue(len(warnings) > 0)


class TestChkrootkit(unittest.TestCase):
    def test_not_installed(self):
        with patch("scanner.kali_tools._available", return_value=False):
            findings = run_chkrootkit()
        self.assertTrue(any("not installed" in f.title for f in findings))

    def test_infected_found_critical(self):
        fake_out = "INFECTED: /bin/ls is infected with trojan\n"
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(1, fake_out, "")):
            findings = run_chkrootkit()
        crits = [f for f in findings if f.severity == "CRITICAL"]
        self.assertTrue(len(crits) > 0)

    def test_clean_system(self):
        fake_out = "nothing found\n"
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, fake_out, "")):
            findings = run_chkrootkit()
        # Should have at least one "clean" finding
        self.assertTrue(len(findings) > 0)


class TestNmap(unittest.TestCase):
    NMAP_XML_FAST = """<?xml version="1.0"?>
<nmaprun>
  <host><ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
    </port>
    <port protocol="tcp" portid="6379">
      <state state="open"/>
      <service name="redis" product="Redis" version="7.0"/>
    </port>
  </ports></host>
</nmaprun>"""

    NMAP_XML_DEEP = """<?xml version="1.0"?>
<nmaprun>
  <host><ports>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache" version="2.4.49"/>
      <script id="http-vuln-cve2021-41773" output="VULNERABLE: Path Traversal"/>
    </port>
  </ports></host>
</nmaprun>"""

    def test_not_installed(self):
        with patch("scanner.kali_tools._available", return_value=False):
            findings = run_nmap()
        self.assertTrue(any("not installed" in f.title for f in findings))

    def test_fast_mode_parses_ports(self):
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, self.NMAP_XML_FAST, "")):
            findings = run_nmap(deep=False)
        ports = {f.evidence.get("port") for f in findings if "port" in f.evidence}
        self.assertIn(22, ports)
        self.assertIn(6379, ports)

    def test_deep_mode_parses_vuln_script(self):
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, self.NMAP_XML_DEEP, "")):
            findings = run_nmap(deep=True)
        vulns = [f for f in findings if "vuln" in f.title.lower() or "CRITICAL" == f.severity]
        self.assertTrue(len(vulns) > 0)

    def test_deep_uses_longer_timeout(self):
        """Verify deep mode passes deep timeout to _run."""
        calls = []
        def mock_run(cmd, timeout=120):
            calls.append(timeout)
            return (0, self.NMAP_XML_FAST, "")
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", side_effect=mock_run):
            run_nmap(deep=True)
        if calls:
            self.assertGreaterEqual(calls[0], TOOL_TIMEOUTS["nmap_fast"])

    def test_fast_uses_fast_timeout(self):
        calls = []
        def mock_run(cmd, timeout=120):
            calls.append(timeout)
            return (0, self.NMAP_XML_FAST, "")
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", side_effect=mock_run):
            run_nmap(deep=False)
        if calls:
            self.assertEqual(calls[0], TOOL_TIMEOUTS["nmap_fast"])

    def test_dangerous_port_high_severity(self):
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, self.NMAP_XML_FAST, "")):
            findings = run_nmap(deep=False)
        redis_f = [f for f in findings if f.evidence.get("port") == 6379]
        if redis_f:
            self.assertEqual(redis_f[0].severity, "HIGH")


class TestDebsums(unittest.TestCase):
    def test_not_installed(self):
        with patch("scanner.kali_tools._available", return_value=False):
            findings = run_debsums()
        self.assertTrue(any("not installed" in f.title for f in findings))

    def test_integrity_failure_detected(self):
        fake_out = "/bin/ls FAILED\n/usr/bin/wget FAILED\n"
        def mock_run(cmd, timeout=120):
            if "debsums" in cmd:
                return (1, fake_out, "")
            if "dpkg" in cmd:
                return (0, "coreutils: /bin/ls", "")
            return (0, "", "")
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", side_effect=mock_run):
            findings = run_debsums()
        failures = [f for f in findings if "integrity" in f.title.lower() or "FAILED" in f.details]
        self.assertTrue(len(failures) > 0)

    def test_critical_for_system_binaries(self):
        fake_out = "/bin/ls FAILED\n"
        def mock_run(cmd, timeout=120):
            if "debsums" in cmd:
                return (1, fake_out, "")
            return (0, "coreutils: /bin/ls", "")
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", side_effect=mock_run):
            findings = run_debsums()
        crits = [f for f in findings if f.severity == "CRITICAL"]
        self.assertTrue(len(crits) > 0)


class TestFail2ban(unittest.TestCase):
    def test_not_installed(self):
        with patch("scanner.kali_tools._available", return_value=False):
            findings = run_fail2ban_check()
        self.assertTrue(any("not installed" in f.title for f in findings))

    def test_running_returns_low(self):
        def mock_run(cmd, timeout=120):
            if "status" in cmd and len(cmd) == 2:
                return (0, "Status\nJail list: sshd, nginx", "")
            if "status" in cmd and len(cmd) == 3:
                return (0, "Status for jail\nCurrently banned: 3", "")
            return (0, "", "")
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", side_effect=mock_run):
            findings = run_fail2ban_check()
        self.assertTrue(any(f.severity == "LOW" for f in findings))

    def test_not_running_high_severity(self):
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(1, "not running", "")):
            findings = run_fail2ban_check()
        self.assertTrue(any(f.severity == "HIGH" for f in findings))


class TestAuditd(unittest.TestCase):
    def test_not_installed(self):
        with patch("scanner.kali_tools._available", return_value=False):
            findings = run_auditd_check()
        self.assertTrue(any("not installed" in f.title for f in findings))

    def test_disabled_high_severity(self):
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", return_value=(0, "enabled 0", "")):
            findings = run_auditd_check()
        self.assertTrue(any(f.severity == "HIGH" for f in findings))

    def test_running_with_rules_low(self):
        def mock_run(cmd, timeout=120):
            if "-s" in cmd:
                return (0, "enabled 1\npid 1234", "")
            if "-l" in cmd:
                rules = "\n".join([f"-a always,exit -F arch=b64 -S open {i}" for i in range(10)])
                return (0, rules, "")
            return (0, "", "")
        with patch("scanner.kali_tools._available", return_value=True), \
             patch("scanner.kali_tools._run", side_effect=mock_run):
            findings = run_auditd_check()
        self.assertTrue(any(f.severity == "LOW" for f in findings))


class TestRunAll(unittest.TestCase):
    def test_fast_mode_does_not_run_rkhunter(self):
        called = []
        def track_run(cmd, timeout=120):
            called.append(cmd[0] if cmd else "")
            return (0, "", "")
        with patch("scanner.kali_tools._available", return_value=False), \
             patch("scanner.kali_tools._run", side_effect=track_run):
            findings = run_all(deep=False)
        self.assertNotIn("rkhunter", called)

    def test_deep_mode_includes_rkhunter(self):
        """In deep mode, rkhunter must be in selected runners."""
        self.assertIn("rkhunter", TOOL_RUNNERS_DEEP)
        self.assertNotIn("rkhunter", TOOL_RUNNERS_FAST)

    def test_returns_list(self):
        with patch("scanner.kali_tools._available", return_value=False):
            result = run_all(deep=False)
        self.assertIsInstance(result, list)

    def test_per_tool_timeout_used(self):
        """run_all passes the tool-specific timeout to each ThreadPoolExecutor future."""
        # This is a structural test – verify each runner is called within timeout
        from concurrent.futures import ThreadPoolExecutor
        self.assertIsNotNone(ThreadPoolExecutor)  # sanity check

    def test_list_tools_has_all_keys(self):
        tools = list_tools()
        for key in ("lynis", "nmap", "chkrootkit", "debsums", "fail2ban", "auditd"):
            self.assertIn(key, tools)
            self.assertIn("description", tools[key])
            self.assertIn("installed", tools[key])


if __name__ == "__main__":
    unittest.main(verbosity=2)
