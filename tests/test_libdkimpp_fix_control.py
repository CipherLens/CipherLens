from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


class LibdkimppFixControlTest(unittest.TestCase):
    def test_public_key_patch_applies(self):
        repo_value = os.environ.get("LIBDKIMPP_ROOT")
        if not repo_value:
            self.skipTest("LIBDKIMPP_ROOT is not configured")

        repo = Path(repo_value)
        patch = Path(
            "caller_audit/fix_controls/"
            "libdkimpp_public_key_full_consumption.patch"
        ).resolve()

        self.assertTrue(repo.is_dir())
        self.assertTrue(patch.is_file())

        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "apply",
                "--check",
                str(patch),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
