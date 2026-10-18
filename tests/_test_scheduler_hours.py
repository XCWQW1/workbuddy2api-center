"""后台排程时段可配置：默认保持 09:00/21:00、22:00、01:00，面板保存后立即生效。

不联网：调度器只做时段计算，不启动线程。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))
from _isolated_dirs import isolated_data_dirs  # noqa: E402

_TMP = isolated_data_dirs("wb-scheduler-hours-")

import wb_scheduler  # noqa: E402
import wb_settings  # noqa: E402


class FakePool(object):
    def __init__(self, directory):
        self.dir = directory
        self.accounts = []


class SchedulerHoursSettingsTests(unittest.TestCase):
    def setUp(self):
        self.directory = os.environ["ACCOUNTS_DIR"]
        with wb_settings._lock:
            data = wb_settings.load(self.directory)
            data.pop("scheduler_hours", None)
            wb_settings.save(self.directory, data)

    def test_defaults_match_the_shipped_schedule(self):
        self.assertEqual(wb_settings.scheduler_hours(self.directory), {
            "checkin": [9, 21],
            "travel": [9, 21],
            "keepalive": [22],
            "cat": [1],
        })

    def test_values_are_stored_sorted_and_deduplicated(self):
        saved = wb_settings.set_scheduler_hours(self.directory, {
            "checkin": ["21", 9, 9], "travel": [9, 21],
            "keepalive": [], "cat": [1],
        })
        self.assertEqual(saved["checkin"], [9, 21])
        self.assertEqual(saved["keepalive"], [])
        self.assertEqual(wb_settings.scheduler_hours(self.directory), saved)

    def test_out_of_range_hours_are_refused(self):
        with self.assertRaises(ValueError):
            wb_settings.set_scheduler_hours(self.directory, {"checkin": [24]})
        with self.assertRaises(ValueError):
            wb_settings.set_scheduler_hours(self.directory, {"checkin": ["soon"]})
        with self.assertRaises(ValueError):
            wb_settings.set_scheduler_hours(self.directory, "9,21")

    def test_a_broken_group_falls_back_to_the_default(self):
        with wb_settings._lock:
            data = wb_settings.load(self.directory)
            data["scheduler_hours"] = {"checkin": "abc", "cat": []}
            wb_settings.save(self.directory, data)
        hours = wb_settings.scheduler_hours(self.directory)
        self.assertEqual(hours["checkin"], [9, 21])
        self.assertEqual(hours["cat"], [])
        self.assertEqual(hours["keepalive"], [22])


class SchedulerHoursTests(unittest.TestCase):
    def test_scheduler_reads_the_saved_schedule(self):
        directory = os.environ["ACCOUNTS_DIR"]
        wb_settings.set_scheduler_hours(directory, {
            "checkin": [8, 20], "travel": [9], "keepalive": [], "cat": [3],
        })
        scheduler = wb_scheduler.Scheduler(FakePool(directory))
        self.assertEqual(scheduler.checkin_hours, [8, 20])
        self.assertEqual(scheduler.travel_hours, [9])
        self.assertEqual(scheduler.keepalive_hours, [])
        self.assertEqual(scheduler.cat_hours, [3])
        self.assertEqual(scheduler.all_hours, [3, 8, 9, 20])
        status = scheduler.status()
        self.assertIn("08:00/20:00", status["mode_cn"])
        self.assertIn("09:00", status["mode_cn"])
        self.assertIn("关闭", status["mode_cn"])

    def test_apply_schedule_takes_effect_without_a_restart(self):
        scheduler = wb_scheduler.Scheduler(FakePool(os.environ["ACCOUNTS_DIR"]))
        scheduler.apply_schedule({"checkin": [7], "travel": [6],
                                  "keepalive": [23], "cat": [0]})
        self.assertEqual(scheduler.all_hours, [0, 6, 7, 23])
        self.assertEqual(scheduler.next_run_time is not None, True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
