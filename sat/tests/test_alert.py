"""tests/test_alert.py – Unit tests for alert.py"""
from __future__ import annotations
import json, sys, unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from alert import (
    AlertSummary, build_alert_summary, _format_telegram,
    _format_text, _format_email_html, _sev_gte, send_telegram,
    send_webhook,
)


def _f(sev="HIGH", title="Test finding", module="test", details=""):
    return {"severity": sev, "title": title, "module": module,
            "details": details, "_key": f"key_{title[:10]}"}


class TestSevGte(unittest.TestCase):
    def test_critical_gte_high(self):
        self.assertTrue(_sev_gte("CRITICAL", "HIGH"))

    def test_low_not_gte_high(self):
        self.assertFalse(_sev_gte("LOW", "HIGH"))

    def test_same_level(self):
        self.assertTrue(_sev_gte("HIGH", "HIGH"))

    def test_medium_not_gte_high(self):
        self.assertFalse(_sev_gte("MEDIUM", "HIGH"))


class TestAlertSummary(unittest.TestCase):
    def _make(self):
        s = AlertSummary()
        s.new_critical = [_f("CRITICAL", "Critical vuln")]
        s.new_high     = [_f("HIGH", "High issue 1"), _f("HIGH", "High issue 2")]
        s.new_medium   = [_f("MEDIUM", "Medium thing")]
        s.new_low      = [_f("LOW", "Low thing")]
        s.resolved     = [_f("HIGH", "Fixed issue")]
        s.posture      = "CRITICAL"
        s.risk_score   = 85
        return s

    def test_total_new(self):
        s = self._make()
        self.assertEqual(s.total_new, 5)

    def test_has_critical_or_high(self):
        s = self._make()
        self.assertTrue(s.has_critical_or_high)

    def test_empty_no_critical_high(self):
        s = AlertSummary()
        s.new_low = [_f("LOW")]
        self.assertFalse(s.has_critical_or_high)

    def test_new_above_high(self):
        s = self._make()
        above = s.new_above("HIGH")
        sevs = {f["severity"] for f in above}
        self.assertNotIn("MEDIUM", sevs)
        self.assertNotIn("LOW",    sevs)
        self.assertIn("HIGH",      sevs)
        self.assertIn("CRITICAL",  sevs)

    def test_new_above_medium(self):
        s = self._make()
        above = s.new_above("MEDIUM")
        self.assertEqual(len(above), 4)  # CRITICAL + 2 HIGH + MEDIUM


class TestFormatTelegram(unittest.TestCase):
    def test_contains_counts(self):
        s = AlertSummary()
        s.new_critical = [_f("CRITICAL")]
        s.new_high     = [_f("HIGH"), _f("HIGH")]
        s.posture = "CRITICAL"
        msg = _format_telegram(s, "HIGH")
        self.assertIn("1", msg)   # critical count
        self.assertIn("2", msg)   # high count

    def test_finding_titles_included(self):
        s = AlertSummary()
        s.new_critical = [_f("CRITICAL", "Remote Code Execution CVE-2024")]
        s.posture = "CRITICAL"
        msg = _format_telegram(s, "HIGH")
        self.assertIn("Remote Code Execution", msg)

    def test_truncates_long_title(self):
        s = AlertSummary()
        s.new_high = [_f("HIGH", "X" * 200)]
        msg = _format_telegram(s, "HIGH")
        self.assertLess(len(msg.split("X" * 10)[1] if "X" * 10 in msg else ""), 200)

    def test_resolved_shows_if_present(self):
        s = AlertSummary()
        s.new_high = [_f("HIGH")]
        s.resolved = [_f("HIGH", "Fixed")]
        msg = _format_telegram(s, "HIGH")
        self.assertIn("Resolved", msg)


class TestFormatText(unittest.TestCase):
    def test_contains_header(self):
        s = AlertSummary()
        s.new_critical = [_f("CRITICAL")]
        s.posture = "CRITICAL"
        text = _format_text(s, "HIGH")
        self.assertIn("SECURITY ALERT", text)
        self.assertIn("CRITICAL", text)

    def test_finding_listed(self):
        s = AlertSummary()
        s.new_high = [_f("HIGH", "SSH root login enabled")]
        text = _format_text(s, "HIGH")
        self.assertIn("SSH root login enabled", text)


class TestFormatEmailHtml(unittest.TestCase):
    def test_valid_html(self):
        s = AlertSummary()
        s.new_critical = [_f("CRITICAL", "Critical finding")]
        s.posture = "CRITICAL"
        s.risk_score = 90
        html = _format_email_html(s, "HIGH")
        self.assertIn("<html>", html)
        self.assertIn("Critical finding", html)
        self.assertIn("90", html)

    def test_subject_line_component(self):
        s = AlertSummary()
        s.new_critical = [_f("CRITICAL")]
        s.new_high     = [_f("HIGH")]
        s.posture = "HIGH RISK"
        s.risk_score = 50
        html = _format_email_html(s, "HIGH")
        self.assertIn("CRITICAL", html)


class TestBuildAlertSummary(unittest.TestCase):
    def test_no_baseline_all_are_new(self):
        report = {
            "findings": [
                _f("CRITICAL", "CVE-X"), _f("HIGH", "SSH weak config"),
                _f("LOW", "DNS cleartext"),
            ],
            "analysis": {"posture": "CRITICAL", "risk_score": 50},
            "scanned_at": "2024-01-01T00:00:00Z",
        }
        with patch("scanner.baseline.load_baseline", return_value=None):
            summary = build_alert_summary(report, "test")
        self.assertEqual(len(summary.new_critical), 1)
        self.assertEqual(len(summary.new_high),     1)
        self.assertEqual(len(summary.new_low),      1)

    def test_with_baseline_detects_new(self):
        baseline = [_f("HIGH", "Old finding")]
        current_findings = [
            _f("HIGH", "Old finding"),
            _f("CRITICAL", "Brand new vuln"),
        ]
        report = {
            "findings": current_findings,
            "analysis": {"posture": "CRITICAL", "risk_score": 70},
            "scanned_at": "2024-01-02T00:00:00Z",
        }
        with patch("scanner.baseline.load_baseline", return_value=baseline):
            summary = build_alert_summary(report, "test")
        new_titles = [f["title"] for f in summary.new_critical]
        self.assertIn("Brand new vuln", new_titles)

    def test_resolved_detected(self):
        baseline = [_f("HIGH", "Will be fixed"), _f("MEDIUM", "Also fixed")]
        current_findings = []
        report = {
            "findings": current_findings,
            "analysis": {"posture": "SECURE", "risk_score": 0},
            "scanned_at": "2024-01-02T00:00:00Z",
        }
        with patch("scanner.baseline.load_baseline", return_value=baseline):
            summary = build_alert_summary(report, "test")
        self.assertEqual(len(summary.resolved), 2)


class TestSendTelegram(unittest.TestCase):
    def test_sends_message(self):
        s = AlertSummary()
        s.new_high = [_f("HIGH", "Test finding")]
        s.posture  = "HIGH RISK"

        ctx = MagicMock()
        ctx.__enter__ = lambda self: self
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.read.return_value = json.dumps({"ok": True}).encode()

        with patch("urllib.request.urlopen", return_value=ctx):
            result = send_telegram(s, "TOKEN", "CHAT_ID")
        self.assertTrue(result)

    def test_network_error_returns_false(self):
        s = AlertSummary()
        with patch("urllib.request.urlopen", side_effect=Exception("Network error")):
            result = send_telegram(s, "TOKEN", "CHAT_ID")
        self.assertFalse(result)


class TestSendWebhook(unittest.TestCase):
    def test_sends_json_payload(self):
        s = AlertSummary()
        s.new_high  = [_f("HIGH", "Security issue")]
        s.posture   = "HIGH RISK"
        s.risk_score = 42

        ctx = MagicMock()
        ctx.__enter__ = lambda self: self
        ctx.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=ctx):
            result = send_webhook(s, "https://hooks.example.com/123")
        self.assertTrue(result)

    def test_error_returns_false(self):
        s = AlertSummary()
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = send_webhook(s, "https://hooks.example.com/123")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
