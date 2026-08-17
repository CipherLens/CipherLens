from __future__ import annotations

import unittest

import yaml

from transfer_signature.canonical import canonical_evaluation_bytes, canonical_signature_bytes
from transfer_signature.profile import canonical_profile_bytes

from tests.transfer_signature.common import CASES, ROOT, TS_GOLDEN, load_yaml


class CanonicalSerializationTests(unittest.TestCase):
    def test_signature_bytes_are_stable_and_match_snapshots(self):
        for case in CASES:
            path = TS_GOLDEN / case / "expected.ts.yaml"
            value = load_yaml(path)
            first = canonical_signature_bytes(value, ROOT)
            self.assertEqual(first, canonical_signature_bytes(yaml.safe_load(first), ROOT))
            self.assertEqual(path.read_bytes(), first)

    def test_profile_and_evaluation_bytes_are_stable(self):
        for case in CASES:
            for label in ("eligible", "ineligible", "indeterminate"):
                profile_path = TS_GOLDEN / case / f"{label}.profile.yaml"
                evaluation_path = TS_GOLDEN / case / f"{label}.evaluation.yaml"
                self.assertEqual(profile_path.read_bytes(), canonical_profile_bytes(load_yaml(profile_path), ROOT))
                self.assertEqual(evaluation_path.read_bytes(), canonical_evaluation_bytes(load_yaml(evaluation_path)))


if __name__ == "__main__":
    unittest.main()
