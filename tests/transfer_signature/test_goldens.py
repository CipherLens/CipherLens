from __future__ import annotations

import unittest

from transfer_signature.evaluate import evaluate_transfer_signature

from tests.transfer_signature.common import CASES, ROOT, TS_GOLDEN, derive_case, load_yaml


class GoldenEvaluationTests(unittest.TestCase):
    def test_three_by_three_profiles_match_expected_evaluations(self):
        expected = {
            "eligible": "ELIGIBLE",
            "ineligible": "INELIGIBLE",
            "indeterminate": "INDETERMINATE",
        }
        for case in CASES:
            signature, contract, _ = derive_case(case)
            for label, eligibility in expected.items():
                profile = load_yaml(TS_GOLDEN / case / f"{label}.profile.yaml")
                actual = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
                with self.subTest(case=case, label=label):
                    self.assertEqual(eligibility, actual["eligibility"])
                    self.assertEqual(load_yaml(TS_GOLDEN / case / f"{label}.evaluation.yaml"), actual)

    def test_evaluation_never_uses_contract_verdict_vocabulary_at_top_level(self):
        for case in CASES:
            for label in ("eligible", "ineligible", "indeterminate"):
                value = load_yaml(TS_GOLDEN / case / f"{label}.evaluation.yaml")
                self.assertNotIn(value["eligibility"], {"SATISFIED", "VIOLATED", "UNKNOWN"})


if __name__ == "__main__":
    unittest.main()
