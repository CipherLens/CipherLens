from __future__ import annotations

from copy import deepcopy
import unittest

from transfer_signature.evaluate import evaluate_transfer_signature

from tests.transfer_signature.common import ROOT, derive_case, golden_profile


class DeterministicEvaluatorTests(unittest.TestCase):
    def test_verified_false_is_mismatch_but_unknown_is_not(self):
        signature, contract, _ = derive_case("mbedtls_poc_0004")
        false_profile = golden_profile("mbedtls_poc_0004", "eligible")
        operation = next(item for item in false_profile["facts"] if item["fact_type"] == "operation_role")
        operation["assertion"] = "FALSE"
        result = evaluate_transfer_signature(signature, false_profile, contract, repo_root=ROOT)
        self.assertEqual("INELIGIBLE", result["eligibility"])
        self.assertIn("REQUIRED_CAPABILITY_MISMATCH", result["reason_codes"])

        unknown_profile = golden_profile("mbedtls_poc_0004", "eligible")
        operation = next(item for item in unknown_profile["facts"] if item["fact_type"] == "operation_role")
        operation["assertion"] = "UNKNOWN"
        result = evaluate_transfer_signature(signature, unknown_profile, contract, repo_root=ROOT)
        self.assertEqual("INDETERMINATE", result["eligibility"])

    def test_inferred_and_proposed_true_cannot_match(self):
        signature, contract, _ = derive_case("mbedtls_poc_0020")
        for status in ("INFERRED", "PROPOSED"):
            profile = golden_profile("mbedtls_poc_0020", "eligible")
            fact = next(item for item in profile["facts"] if item["fact_type"] == "operation_role")
            fact["epistemic_status"] = status
            result = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
            with self.subTest(status=status):
                self.assertEqual("INDETERMINATE", result["eligibility"])
                constraint = next(item for item in result["constraint_results"] if item["constraint_id"] == fact["fact_id"][2:])
                self.assertEqual("UNKNOWN", constraint["result"])

    def test_correct_role_on_wrong_subject_does_not_match(self):
        signature, contract, _ = derive_case("mbedtls_poc_0004")
        profile = golden_profile("mbedtls_poc_0004", "eligible")
        fact = next(item for item in profile["facts"] if item["fact_type"] == "operation_role")
        fact["subject_ref"] = "SYNTHETIC_CIPHER_INPUT"
        result = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
        self.assertEqual("INDETERMINATE", result["eligibility"])
        operation_result = next(item for item in result["constraint_results"] if item["constraint_id"] == fact["fact_id"][2:])
        self.assertEqual("UNKNOWN", operation_result["result"])
        self.assertEqual([], operation_result["matched_fact_refs"])

    def test_correct_fact_type_with_incompatible_parameters_does_not_match(self):
        signature, contract, _ = derive_case("mbedtls_poc_0020")
        profile = golden_profile("mbedtls_poc_0020", "eligible")
        fact = next(item for item in profile["facts"] if item["fact_type"] == "operation_role")
        fact["parameters"]["role"] = "VERIFY"
        result = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
        self.assertEqual("INDETERMINATE", result["eligibility"])
        operation_result = next(item for item in result["constraint_results"] if item["constraint_id"] == fact["fact_id"][2:])
        self.assertEqual("NO_COMPATIBLE_FACT", operation_result["reason_code"])

    def test_multi_subject_execution_shape_matches_only_compatible_participants(self):
        signature, contract, _ = derive_case("mbedtls_poc_0005")
        profile = golden_profile("mbedtls_poc_0005", "eligible")
        constraint = next(item for item in signature["required_capabilities"] if item["type"] == "supports_execution_shape")
        constraint["parameters"]["continuity"] = "multi_subject"
        fact = next(item for item in profile["facts"] if item["fact_type"] == "execution_shape")
        fact["parameters"]["continuity"] = "multi_subject"
        fact["parameters"]["participant_refs"] = [
            "SYNTHETIC_UPDATE",
            "SYNTHETIC_STATE_SURFACE",
            "SYNTHETIC_UPDATE",
        ]
        result = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
        self.assertEqual("ELIGIBLE", result["eligibility"])

    def test_determinate_ineligible_dominates_unknown(self):
        signature, contract, _ = derive_case("mbedtls_poc_0020")
        profile = golden_profile("mbedtls_poc_0020", "ineligible")
        channel = next(item for item in profile["facts"] if item["fact_type"] == "observable_channel")
        channel["epistemic_status"] = "INFERRED"
        result = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
        self.assertEqual("INELIGIBLE", result["eligibility"])
        self.assertIn("EXCLUDED_SEMANTIC_MATCH", result["reason_codes"])

    def test_verified_unavailable_observable_is_ineligible(self):
        signature, contract, _ = derive_case("mbedtls_poc_0020")
        profile = golden_profile("mbedtls_poc_0020", "eligible")
        channel = next(item for item in profile["facts"] if item["fact_type"] == "observable_channel")
        channel["assertion"] = "FALSE"
        result = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
        self.assertEqual("INELIGIBLE", result["eligibility"])
        self.assertIn("REQUIRED_OBSERVABILITY_MISMATCH", result["reason_codes"])


if __name__ == "__main__":
    unittest.main()
