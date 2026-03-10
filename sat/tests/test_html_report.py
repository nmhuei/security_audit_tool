"""tests/test_html_report.py – Unit tests for reporter/html_report.py (incl. diff/drift)"""
from __future__ import annotations
import sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from reporter.html_report import generate_html, _badge, _diff_badge, _e, SEV_COLOR
from ai.analyzer import analyze
from scanner.baseline import diff_findings, drift_summary


def _f(module="test", title="Finding", details="details", severity="HIGH",
       rec="Fix", evidence=None):
    from scanner.common import Finding
    return Finding(module, title, details, severity, rec, evidence or {}).to_dict()


class TestBadgeHelpers(unittest.TestCase):
    def test_badge_has_color(self):
        badge = _badge("CRITICAL")
        self.assertIn("#ff2244", badge)   # CRITICAL color
        self.assertIn("CRITICAL", badge)

    def test_badge_all_severities(self):
        for sev in ("LOW","MEDIUM","HIGH","CRITICAL"):
            b = _badge(sev)
            self.assertIn(sev, b)
            self.assertIn(SEV_COLOR[sev], b)

    def test_diff_badge_new(self):
        b = _diff_badge("NEW")
        self.assertIn("NEW",  b)
        self.assertIn("#ff2244", b)   # red for new

    def test_diff_badge_resolved(self):
        b = _diff_badge("RESOLVED")
        self.assertIn("RESOLVED", b)
        self.assertIn("#00cc66", b)   # green for resolved

    def test_diff_badge_changed(self):
        b = _diff_badge("CHANGED")
        self.assertIn("CHANGED", b)
        self.assertIn("#ffaa00", b)   # orange for changed

    def test_escape_helper(self):
        self.assertEqual(_e("<script>"), "&lt;script&gt;")
        self.assertEqual(_e('"test"'),   "&quot;test&quot;")


class TestGenerateHtml(unittest.TestCase):
    def _report(self, findings=None):
        if findings is None:
            findings = [
            _f("ssh",  "Root login enabled",     "/etc/ssh",   "HIGH"),
            _f("cve",  "CVE-2022-0001 in libssl","libssl 1.0", "CRITICAL"),
            _f("net",  "Redis on 0.0.0.0:6379",  "port 6379",  "HIGH"),
            _f("fs",   "World-writable /tmp",     "/tmp",       "MEDIUM"),
            ]
        return {
            "scanned_at": "2024-01-01T00:00:00Z",
            "scope": "local_machine_only",
            "findings": findings,
            "analysis": analyze(findings),
        }

    def test_generates_valid_html(self):
        html = generate_html(self._report())
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<html",            html)
        self.assertIn("</html>",          html)

    def test_contains_finding_titles(self):
        html = generate_html(self._report())
        self.assertIn("Root login enabled",     html)
        self.assertIn("CVE-2022-0001",           html)

    def test_contains_posture(self):
        html = generate_html(self._report())
        self.assertTrue(
            any(p in html for p in ("CRITICAL","HIGH RISK","MEDIUM RISK","LOW RISK","SECURE"))
        )

    def test_empty_scan_shows_secure(self):
        html = generate_html(self._report(findings=[]))
        # Posture is SECURE for empty scan
        self.assertIn("SECURE", html.upper())

    def test_writes_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            p = Path(tmp.name)
        try:
            generate_html(self._report(), output_path=p)
            self.assertTrue(p.exists())
            self.assertGreater(p.stat().st_size, 1000)
            content = p.read_text()
            self.assertIn("<!DOCTYPE html>", content)
        finally:
            p.unlink(missing_ok=True)

    def test_severity_colors_in_html(self):
        html = generate_html(self._report())
        for sev, color in SEV_COLOR.items():
            self.assertIn(color, html, f"Color for {sev} not found in HTML")

    def test_module_names_in_report(self):
        html = generate_html(self._report())
        for mod in ("ssh", "cve", "net", "fs"):
            self.assertIn(mod, html)


class TestHtmlReportWithDiff(unittest.TestCase):
    """Test that diff/drift data is correctly visualized in HTML."""

    def _make_drift_report(self):
        v1 = [
            _f("cve", "CVE-2022-0001 in libssl", "libssl 1.0", "CRITICAL"),
            _f("ssh", "Root login enabled",       "/etc/ssh",   "HIGH"),
        ]
        v2 = [
            _f("ssh", "Root login enabled",         "/etc/ssh",  "HIGH"),    # unchanged
            _f("net", "Redis exposed on 0.0.0.0",   "port 6379", "CRITICAL"), # new
        ]
        diff  = diff_findings(v2, v1)
        drift = drift_summary(diff)

        analysis          = analyze(v2)
        analysis["drift"] = drift

        report = {
            "scanned_at": "2024-01-02T00:00:00Z",
            "findings":   v2,
            "analysis":   analysis,
        }
        return report, diff, drift

    def test_drift_section_present(self):
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        self.assertIn("DRIFT", html.upper())

    def test_new_findings_shown_in_red(self):
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        # NEW badge should use red color
        self.assertIn("NEW", html)
        self.assertIn("#ff2244", html)

    def test_resolved_findings_shown_in_green(self):
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        self.assertIn("RESOLVED", html)
        self.assertIn("#00cc66", html)

    def test_new_count_in_html(self):
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        # drift.new_count should be 1
        self.assertIn(str(drift["new_count"]), html)

    def test_resolved_count_in_html(self):
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        self.assertIn(str(drift["resolved_count"]), html)

    def test_resolved_section_with_strikethrough(self):
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        # Resolved findings are shown with line-through style
        self.assertIn("line-through", html)

    def test_row_background_color_new(self):
        """New findings rows should have red tinted background."""
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        self.assertIn("rgba(255,34,68,0.08)", html)

    def test_row_background_color_resolved_or_summary(self):
        """Resolved section should have green styling (line-through, green color, or dark bg)."""
        report, diff, drift = self._make_drift_report()
        html = generate_html(report, diff=diff)
        # Resolved findings have green (#00cc66) color and line-through style
        self.assertTrue(
            "line-through" in html or "#00cc66" in html or "rgba(0,204,102" in html,
            "Expected green/resolved styling in HTML"
        )

    def test_no_diff_no_drift_section(self):
        """Without diff param, no DRIFT section should appear."""
        report = {
            "scanned_at": "2024-01-01T00:00:00Z",
            "findings": [_f()],
            "analysis": analyze([_f()]),
        }
        html = generate_html(report)  # no diff kwarg
        self.assertNotIn("BASELINE DRIFT", html)

    def test_ai_insight_rendered(self):
        html = generate_html(
            {"scanned_at": "2024-01-01T00:00:00Z",
             "findings": [], "analysis": analyze([])},
            ai_insight="Risk is elevated due to Redis exposure.",
        )
        self.assertIn("Redis exposure", html)
        self.assertIn("AI", html.upper())

    def test_severity_changed_orange_row(self):
        """Changed findings should have orange tinted row."""
        v1 = [_f("ssh", "SSH weak config", "details", "LOW")]
        v2 = [_f("ssh", "SSH weak config", "details", "HIGH")]  # severity increased
        diff  = diff_findings(v2, v1)
        drift = drift_summary(diff)
        analysis          = analyze(v2)
        analysis["drift"] = drift
        report = {"scanned_at": "2024-01-02T00:00:00Z",
                  "findings": v2, "analysis": analysis}
        html = generate_html(report, diff=diff)
        # CHANGED badge or orange background
        self.assertTrue("CHANGED" in html or "rgba(255,170,0" in html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
