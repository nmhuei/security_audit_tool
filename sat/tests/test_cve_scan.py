"""tests/test_cve_scan.py – Unit tests for scanner/cve_scan.py"""
from __future__ import annotations
import json, sys, unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.cve_scan import (
    scan_kernel_cves, scan_libc_version, scan_with_trivy,
    _batch_osv, _installed_pip_packages, KERNEL_CVES,
)


class TestKernelCves(unittest.TestCase):
    def test_ancient_kernel_many_cves(self):
        with patch("platform.release", return_value="4.4.0-200-generic"):
            findings = scan_kernel_cves()
        self.assertGreater(len(findings), 3)

    def test_very_new_kernel_fewer_cves(self):
        with patch("platform.release", return_value="6.9.0-generic"):
            findings = scan_kernel_cves()
        self.assertIsInstance(findings, list)

    def test_critical_cves_are_critical(self):
        with patch("platform.release", return_value="4.4.0-generic"):
            findings = scan_kernel_cves()
        crits = [f for f in findings if f.severity == "CRITICAL"]
        self.assertTrue(len(crits) > 0)

    def test_finding_has_cve_id(self):
        with patch("platform.release", return_value="4.4.0-generic"):
            findings = scan_kernel_cves()
        for f in findings[:3]:
            self.assertIn("CVE-", f.title)

    def test_malformed_version_empty(self):
        with patch("platform.release", return_value="not-a-version-string"):
            findings = scan_kernel_cves()
        self.assertEqual(findings, [])

    def test_kernel_cves_list_nonempty(self):
        self.assertGreater(len(KERNEL_CVES), 5)

    def test_all_cve_entries_have_required_fields(self):
        for entry in KERNEL_CVES:
            self.assertIn("cve",  entry, f"Missing 'cve' in entry: {entry}")
            self.assertIn("desc", entry, f"Missing 'desc' in entry: {entry}")
            self.assertIn("max",  entry, f"Missing 'max' in entry: {entry}")
            self.assertIn("sev",  entry, f"Missing 'sev' in entry: {entry}")
            self.assertIn(entry["sev"], ("LOW","MEDIUM","HIGH","CRITICAL"))

    def test_recommendation_mentions_kernel_update(self):
        with patch("platform.release", return_value="4.4.0-generic"):
            findings = scan_kernel_cves()
        if findings:
            rec = findings[0].recommendation.lower()
            self.assertTrue("update" in rec or "upgrade" in rec or "dist-upgrade" in rec)


class TestLibcVersion(unittest.TestCase):
    def test_old_glibc_high(self):
        fake_out = "ldd (Ubuntu GLIBC 2.27-3ubuntu1) 2.27\n"
        with patch("subprocess.check_output", return_value=fake_out):
            findings = scan_libc_version()
        highs = [f for f in findings if f.severity in ("HIGH","CRITICAL")]
        self.assertTrue(len(highs) > 0)

    def test_modern_glibc_no_findings(self):
        fake_out = "ldd (Ubuntu GLIBC 2.37-0ubuntu2) 2.37\n"
        with patch("subprocess.check_output", return_value=fake_out):
            findings = scan_libc_version()
        self.assertEqual(len(findings), 0)

    def test_error_no_crash(self):
        with patch("subprocess.check_output", side_effect=Exception("fail")):
            findings = scan_libc_version()
        self.assertEqual(findings, [])


class TestTrivy(unittest.TestCase):
    def test_not_available_returns_empty(self):
        with patch("scanner.cve_scan._trivy_available", return_value=False):
            findings = scan_with_trivy()
        self.assertEqual(findings, [])

    def test_parses_trivy_output(self):
        fake_json = json.dumps({
            "Results": [{
                "Target": "/usr/bin/test",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "libssl",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1",
                    "Title": "Buffer overflow",
                    "Severity": "CRITICAL",
                    "CVSS": {},
                }]
            }]
        })
        with patch("scanner.cve_scan._trivy_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = fake_json
            findings = scan_with_trivy()
        self.assertTrue(any("CVE-2024-0001" in f.title for f in findings))

    def test_nonzero_return_above_1_empty(self):
        with patch("scanner.cve_scan._trivy_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 2
            mock_run.return_value.stdout = ""
            findings = scan_with_trivy()
        self.assertEqual(findings, [])


class TestBatchOsv(unittest.TestCase):
    def test_empty_input_returns_empty(self):
        findings = _batch_osv([], "PyPI")
        self.assertEqual(findings, [])

    def test_parses_vulnerability(self):
        fake_resp = json.dumps({"results": [{
            "vulns": [{
                "id": "GHSA-0000-0000-0000",
                "aliases": ["CVE-2024-1234"],
                "summary": "Remote code execution",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            }]
        }]}).encode()

        ctx = MagicMock()
        ctx.__enter__ = lambda s: s
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.read.return_value = fake_resp

        with patch("scanner.cve_scan.urlopen", return_value=ctx), \
             patch("time.sleep"):
            findings = _batch_osv([{"name": "requests", "version": "2.0.0"}], "PyPI")

        self.assertTrue(any("CVE-2024-1234" in f.title for f in findings))

    def test_rate_limit_retry(self):
        """429 should trigger retry, not immediate failure."""
        from urllib.error import URLError
        call_count = [0]

        def fake_urlopen(req, timeout):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise URLError("429 Too Many Requests")
            ctx = MagicMock()
            ctx.__enter__ = lambda s: s
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.read.return_value = json.dumps({"results": []}).encode()
            return ctx

        with patch("scanner.cve_scan.urlopen", side_effect=fake_urlopen), \
             patch("time.sleep"):
            findings = _batch_osv([{"name": "requests", "version": "2.0.0"}], "PyPI")

        self.assertGreaterEqual(call_count[0], 2, "Should retry on 429")
        self.assertIsInstance(findings, list)

    def test_rate_limit_batches_have_pause(self):
        """Multiple batches should have sleep between them."""
        sleep_calls = []

        ctx = MagicMock()
        ctx.__enter__ = lambda s: s
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.read.return_value = json.dumps({"results": []}).encode()

        with patch("scanner.cve_scan.urlopen", return_value=ctx), \
             patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            # 60 packages → 2 batches of 50+10 → 1 inter-batch sleep
            pkgs = [{"name": f"pkg{i}", "version": "1.0.0"} for i in range(60)]
            _batch_osv(pkgs, "PyPI")

        self.assertTrue(len(sleep_calls) >= 1, "Should sleep between batches")

    def test_network_error_graceful(self):
        from urllib.error import URLError
        with patch("scanner.cve_scan.urlopen", side_effect=URLError("Network unreachable")), \
             patch("time.sleep"):
            findings = _batch_osv([{"name": "requests", "version": "2.0.0"}], "PyPI")
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
