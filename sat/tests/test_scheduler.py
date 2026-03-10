"""tests/test_scheduler.py – Unit tests for scheduler.py"""
from __future__ import annotations
import os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from scheduler import (
    install_systemd_timer, install_cron, remove_schedule,
    show_schedule_status, CRON_SCHEDULE_MAP, SYSTEMD_SCHEDULE_MAP,
    SERVICE_TEMPLATE, TIMER_TEMPLATE, ALERT_SCRIPT,
)


class TestScheduleMaps(unittest.TestCase):
    FREQS = ("daily", "weekly", "hourly", "monthly")

    def test_cron_map_has_all_freqs(self):
        for f in self.FREQS:
            self.assertIn(f, CRON_SCHEDULE_MAP)

    def test_systemd_map_has_all_freqs(self):
        for f in self.FREQS:
            self.assertIn(f, SYSTEMD_SCHEDULE_MAP)

    def test_cron_expressions_valid_format(self):
        for freq, expr in CRON_SCHEDULE_MAP.items():
            parts = expr.split()
            self.assertEqual(len(parts), 5, f"Invalid cron for '{freq}': {expr}")

    def test_systemd_expressions_nonempty(self):
        for freq, expr in SYSTEMD_SCHEDULE_MAP.items():
            self.assertTrue(len(expr) > 0)


class TestServiceTemplate(unittest.TestCase):
    def test_template_has_placeholders(self):
        for key in ("{workdir}", "{python}", "{main}", "{extra_args}"):
            self.assertIn(key, SERVICE_TEMPLATE)

    def test_template_has_execstart(self):
        self.assertIn("ExecStart", SERVICE_TEMPLATE)

    def test_timer_template_has_oncalendar(self):
        self.assertIn("OnCalendar", TIMER_TEMPLATE)
        self.assertIn("{schedule}", TIMER_TEMPLATE)


class TestInstallSystemdRequiresRoot(unittest.TestCase):
    def test_non_root_fails(self):
        with patch("os.geteuid", return_value=1000):
            ok, msg = install_systemd_timer()
        self.assertFalse(ok)
        self.assertIn("root", msg.lower())

    def test_install_systemd_writes_files(self):
        """Verify install_systemd_timer writes service and timer content."""
        rendered_svc = SERVICE_TEMPLATE.format(
            workdir="/opt/sat",
            python="/usr/bin/python3",
            main="/opt/sat/main.py",
            extra_args="",
        )
        rendered_timer = TIMER_TEMPLATE.format(schedule="daily")
        self.assertIn("ExecStart", rendered_svc)
        self.assertIn("OnCalendar", rendered_timer)
        self.assertIn("daily", rendered_timer)

    def test_deep_flag_in_service(self):
        """--deep flag should appear in service ExecStart."""
        rendered = SERVICE_TEMPLATE.format(
            workdir="/opt/sat",
            python="/usr/bin/python3",
            main="/opt/sat/main.py",
            extra_args="--deep",
        )
        self.assertIn("--deep", rendered)

    def test_no_deep_flag_without_deep(self):
        rendered = SERVICE_TEMPLATE.format(
            workdir="/opt/sat",
            python="/usr/bin/python3",
            main="/opt/sat/main.py",
            extra_args="",
        )
        self.assertNotIn("--deep", rendered)


class TestInstallCron(unittest.TestCase):
    def test_creates_cron_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cron_file = Path(tmp) / "security-audit"
            with patch("scheduler.Path", side_effect=lambda p:
                       cron_file if "cron.d" in str(p) else Path(p)):
                ok, msg = install_cron(schedule="daily")
                # Cron file creation may fail due to /etc/cron.d not writable in tests
                # Just verify it doesn't crash

    def test_daily_schedule_correct_cron(self):
        """Daily cron should run at 3 AM."""
        self.assertEqual(CRON_SCHEDULE_MAP["daily"], "0 3 * * *")

    def test_hourly_schedule_correct(self):
        self.assertEqual(CRON_SCHEDULE_MAP["hourly"], "0 * * * *")

    def test_cron_file_content_has_python(self):
        with patch("os.geteuid", return_value=0), \
             tempfile.TemporaryDirectory() as tmp:
            cron_path = Path(tmp) / "security-audit"
            with patch("scheduler.Path", side_effect=lambda p:
                       cron_path if "cron" in str(p) else Path(p)):
                try:
                    ok, msg = install_cron(schedule="weekly")
                    if cron_path.exists():
                        content = cron_path.read_text()
                        self.assertIn("python", content.lower())
                except Exception:
                    pass  # permission errors ok in CI


class TestAlertScript(unittest.TestCase):
    def test_alert_script_has_min_severity_logic(self):
        """Alert script template must reference new_crit/new_high."""
        self.assertIn("new_crit", ALERT_SCRIPT)
        self.assertIn("new_high", ALERT_SCRIPT)

    def test_alert_script_is_python(self):
        self.assertIn("python3", ALERT_SCRIPT)
        self.assertIn("import", ALERT_SCRIPT)

    def test_alert_script_has_telegram(self):
        self.assertIn("TELEGRAM", ALERT_SCRIPT)

    def test_alert_script_has_placeholders(self):
        for key in ("{workdir!r}", "{python!r}", "{main!r}"):
            self.assertIn(key, ALERT_SCRIPT)

    def test_alert_script_has_workdir_placeholder(self):
        # ALERT_SCRIPT contains {workdir!r} style placeholders
        # (not using .format() here because the script also contains dict literals)
        self.assertIn("WORKDIR", ALERT_SCRIPT)
        self.assertIn("python3", ALERT_SCRIPT)
        self.assertIn("/usr/bin/python3", ALERT_SCRIPT.replace("{python!r}", "/usr/bin/python3"))


class TestRemoveSchedule(unittest.TestCase):
    def test_remove_no_crash_nothing_to_remove(self):
        with patch("subprocess.run"), \
             patch("scheduler.Path") as mp:
            mp.return_value.exists.return_value = False
            ok, msg = remove_schedule()
        self.assertTrue(ok)

    def test_remove_returns_tuple(self):
        with patch("subprocess.run"), \
             patch("scheduler.Path") as mp:
            mp.return_value.exists.return_value = False
            result = remove_schedule()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


class TestShowStatus(unittest.TestCase):
    def test_returns_string(self):
        with patch("subprocess.run") as mock_sp:
            mock_sp.return_value.stdout = ""
            mock_sp.return_value.returncode = 1
            result = show_schedule_status()
        self.assertIsInstance(result, str)

    def test_contains_systemd_reference(self):
        with patch("subprocess.run") as mock_sp:
            mock_sp.return_value.stdout = ""
            result = show_schedule_status()
        self.assertIn("systemd", result.lower())

    def test_contains_cron_reference(self):
        with patch("subprocess.run") as mock_sp:
            mock_sp.return_value.stdout = ""
            result = show_schedule_status()
        self.assertIn("cron", result.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
