from __future__ import annotations

from copy import deepcopy
import unittest

from transfer_signature.profile import validate_profile

from tests.transfer_signature.common import CASES, ROOT, golden_profile


class TargetSemanticProfileTests(unittest.TestCase):
    def test_api_group_surface_and_multi_subjects_are_valid(self):
        value = golden_profile("mbedtls_poc_0004", "eligible")
        self.assertEqual([], validate_profile(value, ROOT))
        self.assertTrue(any(item["subject_kind"] == "API_GROUP" for item in value["subjects"]))
        self.assertGreater(len(value["subjects"]), 1)
        self.assertTrue(all("subject_ref" in item for item in value["facts"]))

    def test_wrong_subject_ref_is_rejected(self):
        value = golden_profile(CASES[0], "eligible")
        value["facts"][0]["subject_ref"] = "MISSING_SUBJECT"
        errors = validate_profile(value, ROOT)
        self.assertTrue(any("dangling subject reference" in item for item in errors), errors)

    def test_conflicting_verified_facts_are_profile_error(self):
        value = golden_profile(CASES[0], "eligible")
        opposite = deepcopy(value["facts"][0])
        opposite["fact_id"] = "F_CONFLICTING_FACT"
        opposite["assertion"] = "FALSE" if opposite["assertion"] == "TRUE" else "TRUE"
        value["facts"].append(opposite)
        errors = validate_profile(value, ROOT)
        self.assertTrue(any("conflicting VERIFIED facts" in item for item in errors), errors)

    def test_llm_cannot_establish_verified_fact(self):
        value = golden_profile(CASES[0], "eligible")
        value["evidence"][0]["kind"] = "llm_proposal"
        errors = validate_profile(value, ROOT)
        self.assertTrue(any("LLM evidence cannot establish VERIFIED" in item for item in errors), errors)

    def test_api_card_only_cannot_establish_verified_fact(self):
        value = golden_profile(CASES[0], "eligible")
        value["evidence"][0]["kind"] = "api_card"
        errors = validate_profile(value, ROOT)
        self.assertTrue(any("requires deterministic evidence" in item for item in errors), errors)


if __name__ == "__main__":
    unittest.main()
