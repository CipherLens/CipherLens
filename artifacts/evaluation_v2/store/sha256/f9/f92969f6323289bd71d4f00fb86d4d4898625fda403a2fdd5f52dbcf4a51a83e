from __future__ import annotations

from copy import deepcopy
import unittest

from candidate_binding.canonical import candidate_binding_digest, canonical_candidate_binding_bytes, canonical_validation_bytes, expected_binding_id
from candidate_binding.construct import construct_candidate_binding
from candidate_binding.model import ConstructionRejected
from candidate_binding.validate import validate_candidate_binding, validate_validation_artifact
from tests.candidate_binding.common import rebuild, valid_case


class CandidateSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binding, cls.context, cls.validation = valid_case("mbedtls_poc_0004")

    def test_valid_binding_and_validation_are_closed(self):
        self.assertEqual([], validate_candidate_binding(self.binding))
        self.assertEqual([], validate_validation_artifact(self.validation))
        canonical_validation_bytes(self.validation)

    def test_unknown_forbidden_score_verdict_and_digest_rejected(self):
        cases = []
        unknown = deepcopy(self.binding); unknown["unknown"] = True; cases.append((unknown, "unknown field"))
        for key in ("llm_confidence", "ranking_score", "verdict"):
            value = deepcopy(self.binding); value[key] = "VIOLATED"; cases.append((value, "forbidden"))
        digest = deepcopy(self.binding); digest["source_contract_digest"] = "BAD"; digest["binding_id"] = expected_binding_id(digest); cases.append((digest, "SHA-256"))
        for value, expected in cases:
            with self.subTest(expected=expected): self.assertTrue(any(expected in x for x in validate_candidate_binding(value)))

    def test_absolute_artifact_duplicate_ids_enum_and_dangling_shape(self):
        absolute = deepcopy(self.binding); absolute["input_bindings"][0]["artifact_ref"] = "/tmp/data"; absolute = rebuild(absolute)
        self.assertTrue(any("repo-relative" in x for x in validate_candidate_binding(absolute)))
        duplicate = deepcopy(self.binding); duplicate["input_bindings"][1]["input_binding_id"] = duplicate["input_bindings"][0]["input_binding_id"]; duplicate = rebuild(duplicate)
        self.assertTrue(any("duplicate input_binding_id" in x for x in validate_candidate_binding(duplicate)))
        enum = deepcopy(self.binding); enum["observation_bindings"][0]["phase"] = "SOMETIME"; enum = rebuild(enum)
        self.assertTrue(any("unknown value" in x for x in validate_candidate_binding(enum)))

    def test_canonical_order_and_semantic_identity(self):
        shuffled = deepcopy(self.binding)
        shuffled["subject_bindings"].reverse(); shuffled["input_bindings"].reverse(); shuffled["construction"]["verified_fact_refs"].reverse()
        self.assertEqual(canonical_candidate_binding_bytes(self.binding), canonical_candidate_binding_bytes(shuffled))
        self.assertEqual(candidate_binding_digest(self.binding), candidate_binding_digest(shuffled))
        changed = deepcopy(self.binding); changed["input_bindings"][0]["encoding"] = "RAW"; changed = rebuild(changed)
        self.assertNotEqual(self.binding["binding_id"], changed["binding_id"])

    def test_noneligible_constructor_gate(self):
        mappings = {
            key: deepcopy(self.binding[key]) for key in (
                "subject_bindings", "operation_bindings", "input_bindings", "intervention_bindings",
                "continuity_bindings", "observation_bindings", "correlation_bindings"
            )
        }
        mappings["verified_fact_refs"] = self.binding["construction"]["verified_fact_refs"]
        mappings["evidence_refs"] = self.binding["construction"]["evidence_refs"]
        evaluation = deepcopy(self.context.eligibility_evaluation); evaluation["eligibility"] = "INDETERMINATE"; evaluation["reason_codes"] = ["UNRESOLVED_CONSTRAINTS"]
        with self.assertRaises(ConstructionRejected):
            construct_candidate_binding(contract=self.context.contract, transfer_signature=self.context.transfer_signature,
                template_manifest=self.context.template_manifest, target_profile=self.context.target_profile,
                eligibility_evaluation=evaluation, mappings=mappings)

    def test_frankenstein_binding_gets_new_identity(self):
        a, _, _ = valid_case("mbedtls_poc_0020"); b, _, _ = valid_case("mbedtls_poc_0004"); c, _, _ = valid_case("mbedtls_poc_0005")
        hybrid = deepcopy(a)
        hybrid["operation_bindings"][0]["target_operation_kind"] = b["operation_bindings"][0]["target_operation_kind"] + "_FROM_B"
        hybrid["subject_bindings"][0]["target_type_ref"] = c["subject_bindings"][0]["target_type_ref"] + ":FROM_C"
        hybrid = rebuild(hybrid)
        self.assertNotIn(hybrid["binding_id"], {a["binding_id"], b["binding_id"], c["binding_id"]})


if __name__ == "__main__": unittest.main()
