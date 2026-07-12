from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


class FixControlPatchTest(unittest.TestCase):
    def test_mlspp_patch_applies(self):
        repo_value = os.environ.get("MLSPP_ROOT")
        if not repo_value:
            self.skipTest("MLSPP_ROOT is not configured")

        repo = Path(repo_value)
        patch = Path(
            "caller_audit/fix_controls/"
            "mlspp_rsa_full_consumption.patch"
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

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
