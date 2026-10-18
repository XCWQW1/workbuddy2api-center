# VS Code 渠道的出站身分：UA 与版本头必须来自同一组值。
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
sys.path.insert(0, APP)
sys.path.insert(0, ROOT)

import wb_identity  # noqa: E402


class VSCodeIdentityTest(unittest.TestCase):
    def test_headers_follow_the_codebuddy_plugin_shape(self):
        headers = wb_identity.build_identity_headers(
            "vscode", "intl", "uid-1", "token-1")
        self.assertEqual(headers["X-IDE-Type"], "VSCode")
        self.assertEqual(headers["X-IDE-Version"], "1.142.0")
        self.assertEqual(headers["X-Product-Version"], "4.12.39997873")
        self.assertEqual(
            headers["User-Agent"],
            "VSCode/%s CodeBuddy/%s" % (
                headers["X-IDE-Version"], headers["X-Product-Version"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
