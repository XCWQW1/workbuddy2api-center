import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RUN_ALL = os.path.join(HERE, "run_all.py")

# 该套件会打印中文摘要，被测的就是父进程自己的 print。只跑一个套件，
# 保持子进程粒度，不跑整轮。
NON_ASCII_SUITE = "accounts_logic"


class RunAllEncodingTests(unittest.TestCase):
    def _run(self, io_encoding):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = io_encoding
        return subprocess.run([sys.executable, RUN_ALL, NON_ASCII_SUITE],
                              cwd=ROOT, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=300)

    def test_survives_a_cp1252_console(self):
        """cp1252 下退出码必须为 0，输出也不含 UnicodeEncodeError。"""
        result = self._run("cp1252")
        output = result.stdout.decode("utf-8", "replace")
        self.assertEqual(result.returncode, 0,
                         "run_all.py failed under a cp1252 console:\n" + output)
        self.assertNotIn("UnicodeEncodeError", output)

    def test_survives_utf8_console(self):
        result = self._run("utf-8")
        self.assertEqual(result.returncode, 0,
                         result.stdout.decode("utf-8", "replace"))

    def test_reports_the_selected_suite(self):
        """防止运行被静默短路。"""
        result = self._run("cp1252")
        output = result.stdout.decode("utf-8", "replace")
        self.assertIn(NON_ASCII_SUITE, output)
        self.assertIn("1 passed", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
