"""定时任务的随机间隔：默认 5 秒，下限 2 秒，上限 600 秒。

调度器在处理下一个账号前等待 uniform(2, 上限)。本套件不联网：
账号是桩对象，sleep 与 uniform 都被替换。
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))
from _isolated_dirs import isolated_data_dirs  # noqa: E402

_TMP = isolated_data_dirs("wb-task-jitter-")

import wb_scheduler  # noqa: E402
import wb_settings  # noqa: E402


class FakeAccount(object):
    enabled = True
    expires_at = 0
    realm = "intl"
    uid = "jitter-account"

    def can_daily_chat(self):
        return False


class FakePool(object):
    def __init__(self, directory):
        self.dir = directory
        self.accounts = [FakeAccount(), FakeAccount()]


class TaskJitterSettingsTests(unittest.TestCase):
    def setUp(self):
        self.directory = os.environ["ACCOUNTS_DIR"]
        with wb_settings._lock:
            data = wb_settings.load(self.directory)
            data.pop("task_jitter_max", None)
            wb_settings.save(self.directory, data)

    def test_default_is_five_seconds(self):
        self.assertEqual(wb_settings.task_jitter_max(self.directory), 5)

    def test_minimum_is_two_seconds(self):
        self.assertEqual(wb_settings.set_task_jitter_max(self.directory, 1), 2)
        self.assertEqual(wb_settings.task_jitter_max(self.directory), 2)

    def test_value_is_stored_and_bounded(self):
        self.assertEqual(wb_settings.set_task_jitter_max(self.directory, 9), 9)
        self.assertEqual(wb_settings.task_jitter_max(self.directory), 9)
        self.assertEqual(wb_settings.set_task_jitter_max(self.directory, 9999), 600)

    def test_garbage_falls_back_to_default(self):
        with wb_settings._lock:
            data = wb_settings.load(self.directory)
            data["task_jitter_max"] = "soon"
            wb_settings.save(self.directory, data)
        self.assertEqual(wb_settings.task_jitter_max(self.directory), 5)


class SchedulerJitterTests(unittest.TestCase):
    def test_cycle_waits_between_accounts_with_the_configured_upper_bound(self):
        wb_settings.set_task_jitter_max(os.environ["ACCOUNTS_DIR"], 9)
        scheduler = wb_scheduler.Scheduler(FakePool(os.environ["ACCOUNTS_DIR"]))
        uniform_calls = []
        with mock.patch.object(wb_scheduler.random, "uniform",
                               side_effect=lambda low, high: uniform_calls.append((low, high)) or 2.5), \
             mock.patch.object(wb_scheduler.time, "sleep") as sleep:
            scheduler._run_cycle("测试")
        # 两个账号之间只等一次：第一个账号不等待。
        self.assertEqual(uniform_calls, [(2, 9)])
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2.5])


if __name__ == "__main__":
    unittest.main(verbosity=2)
