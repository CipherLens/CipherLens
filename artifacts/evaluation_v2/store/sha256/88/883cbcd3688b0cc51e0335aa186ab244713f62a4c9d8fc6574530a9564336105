from __future__ import annotations

from copy import deepcopy
import unittest

from transfer_signature.canonical import validate_evaluation, validate_signature
from transfer_signature.profile import validate_profile

from tests.transfer_signature.common import CASES, ROOT, TS_GOLDEN, load_yaml


class TransferSignatureSchemaTests(unittest.TestCase):
    def test_all_golden_artifacts_validate(self):
        for case in CASES:
            directory = TS_GOLDEN / case
            self.assertEqual([], validate_signature(load_yaml(directory / "expected.ts.yaml"), ROOT))
            for label in ("eligible", "ineligible", "indeterminate"):
                self.assertEqual([], validate_profile(load_yaml(directory / f"{label}.profile.yaml"), ROOT))
                self.assertEqual([], validate_evaluation(load_yaml(directory / f"{label}.evaluation.yaml")))

    def test_recursive_unknown_field_is_rejected(self):
        value = load_yaml(TS_GOLDEN / CASES[0] / "expected.ts.yaml")
        value["required_capabilities"][0]["parameters"]["surprise"] = "x"
        errors = validate_signature(value, ROOT)
        self.assertTrue(any("surprise: unknown field" in item for item in errors), errors)

    def test_target_api_and_candidate_binding_fields_are_forbidden(self):
        for field in ("target_api", "CandidateBinding"):
            value = load_yaml(TS_GOLDEN / CASES[0] / "expected.ts.yaml")
            value["provenance"]["producer"][field] = "forbidden"
            errors = validate_signature(value, ROOT)
            with self.subTest(field=field):
                self.assertTrue(any("forbidden TS field" in item for item in errors), errors)

    def test_expected_relation_and_score_cannot_be_smuggled_into_ts(self):
        value = load_yaml(TS_GOLDEN / CASES[0] / "expected.ts.yaml")
        value["expected_relation"] = {}
        value["required_capabilities"][0]["score"] = 99
        errors = validate_signature(value, ROOT)
        self.assertTrue(any("expected_relation" in item for item in errors), errors)
        self.assertTrue(any("score" in item for item in errors), errors)


if __name__ == "__main__":
    unittest.main()
