from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from candidate_binding.model import ValidationContext
from candidate_binding.registry import validate_with_registry
from tests.candidate_binding.common import rebuild, valid_case
from transfer_signature.canonical import canonical_evaluation_bytes
from transfer_signature.profile import profile_digest


def check(validation: dict, kind: str) -> dict:
    return next(x for x in validation["check_results"] if x["validator_type"] == kind)


class DeterministicValidatorTests(unittest.TestCase):
    def setUp(self):
        self.binding, self.context, self.validation = valid_case("mbedtls_poc_0005")

    def assess(self, binding: dict, context=None) -> dict:
        return validate_with_registry(rebuild(binding), context or self.context)

    def test_golden_valid_invalid_incomplete_for_all_families(self):
        for name in ("mbedtls_poc_0020", "mbedtls_poc_0004", "mbedtls_poc_0005"):
            binding, context, validation = valid_case(name)
            self.assertEqual("VALID", validation["status"])
            invalid = deepcopy(binding); invalid["subject_bindings"][0]["target_subject_ref"] = context.target_profile["subjects"][-1]["subject_ref"]
            self.assertEqual("INVALID", self.assess(invalid, context)["status"])
            incomplete = deepcopy(binding); incomplete["operation_bindings"][0]["verified_fact_refs"] = ["F_MISSING_REQUIRED_VERIFIED_EVIDENCE"]
            self.assertEqual("INCOMPLETE", self.assess(incomplete, context)["status"])

    def test_reference_scope_and_eligibility_failures(self):
        mismatch = deepcopy(self.binding); mismatch["source_contract_digest"] = "0" * 64
        self.assertEqual("FAIL", check(self.assess(mismatch), "REFERENCE_INTEGRITY")["result"])
        scope = deepcopy(self.binding); scope["target_scope"]["surface_ref"] = "synthetic:wrong"
        self.assertEqual("FAIL", check(self.assess(scope), "TARGET_SCOPE")["result"])
        evaluation = deepcopy(self.context.eligibility_evaluation); evaluation["eligibility"] = "INDETERMINATE"; evaluation["reason_codes"] = ["UNRESOLVED_CONSTRAINTS"]
        ctx = ValidationContext(self.context.contract, self.context.transfer_signature, self.context.template_manifest, self.context.target_profile, evaluation)
        candidate = deepcopy(self.binding); candidate["eligibility_evaluation_digest"] = hashlib.sha256(canonical_evaluation_bytes(evaluation)).hexdigest()
        self.assertEqual("FAIL", check(self.assess(candidate, ctx), "ELIGIBILITY_GATE")["result"])

    def test_subject_operation_receiver_and_sequence_failures(self):
        wrong_subject = deepcopy(self.binding); wrong_subject["subject_bindings"][0]["target_subject_ref"] = "SYNTHETIC_UPDATE"
        self.assertEqual("FAIL", check(self.assess(wrong_subject), "SUBJECT_BINDING")["result"])
        wrong_kind = deepcopy(self.binding); wrong_kind["subject_bindings"][0]["subject_kind"] = "API"
        self.assertEqual("FAIL", check(self.assess(wrong_kind), "SUBJECT_BINDING")["result"])
        wrong_role = deepcopy(self.binding); wrong_role["operation_bindings"][0]["operation_role"] = "PARSE"
        self.assertEqual("FAIL", check(self.assess(wrong_role), "OPERATION_BINDING")["result"])
        receiver = deepcopy(self.binding); receiver["operation_bindings"][0]["receiver_subject_binding_ref"] = "MISSING"
        self.assertEqual("FAIL", check(self.assess(receiver), "OPERATION_BINDING")["result"])
        sequence = deepcopy(self.binding); sequence["operation_bindings"][1]["sequence_index"] = sequence["operation_bindings"][0]["sequence_index"]
        self.assertEqual("FAIL", check(self.assess(sequence), "OPERATION_BINDING")["result"])

    def test_input_and_intervention_failures(self):
        parameter = deepcopy(self.binding); parameter["input_bindings"][0]["target_parameter_ref"] = "unknown"
        self.assertEqual("FAIL", check(self.assess(parameter), "INPUT_BINDING")["result"])
        representation = deepcopy(self.binding); representation["input_bindings"][0]["representation_kind"] = "ARTIFACT_REF"
        self.assertEqual("FAIL", check(self.assess(representation), "INPUT_BINDING")["result"])
        missing = deepcopy(self.binding); missing["intervention_bindings"] = []
        self.assertEqual("FAIL", check(self.assess(missing), "INTERVENTION_BINDING")["result"])
        phase = deepcopy(self.binding); phase["intervention_bindings"][0]["application_phase"] = "AT_OPERATION"
        self.assertEqual("FAIL", check(self.assess(phase), "INTERVENTION_BINDING")["result"])

    def test_continuity_observation_and_correlation_failures(self):
        continuity = deepcopy(self.binding); continuity["continuity_bindings"][0]["subject_binding_refs"].append("MISSING")
        self.assertEqual("FAIL", check(self.assess(continuity), "CONTINUITY")["result"])
        missing_obs = deepcopy(self.binding); missing_obs["observation_bindings"] = missing_obs["observation_bindings"][1:]
        self.assertEqual("FAIL", check(self.assess(missing_obs), "OBSERVABILITY")["result"])
        subject = deepcopy(self.binding); subject["observation_bindings"][0]["target_subject_binding_ref"] = "MISSING"
        self.assertEqual("FAIL", check(self.assess(subject), "OBSERVABILITY")["result"])
        acquisition = deepcopy(self.binding); acquisition["observation_bindings"][0]["acquisition_kind"] = "RETURN_VALUE"
        self.assertEqual("FAIL", check(self.assess(acquisition), "OBSERVABILITY")["result"])
        phase = deepcopy(self.binding); phase["observation_bindings"][0]["phase"] = "BEFORE_STEP"
        self.assertEqual("FAIL", check(self.assess(phase), "OBSERVABILITY")["result"])
        correlation = deepcopy(self.binding); correlation["observation_bindings"][0]["correlation_group_refs"] = ["MISSING"]
        self.assertEqual("FAIL", check(self.assess(correlation), "OBSERVABILITY")["result"])

    def test_missing_template_slot_and_unverified_facts(self):
        missing = deepcopy(self.binding); missing["operation_bindings"] = missing["operation_bindings"][1:]
        self.assertEqual("FAIL", check(self.assess(missing), "COMPLETENESS")["result"])
        for status in ("INFERRED", "PROPOSED"):
            profile = deepcopy(self.context.target_profile)
            fact = deepcopy(next(x for x in profile["facts"] if x["fact_type"] == "operation_role"))
            fact["fact_id"] = f"F_EXTRA_{status}"
            fact["epistemic_status"] = status
            profile["facts"].append(fact)
            ctx = ValidationContext(self.context.contract, self.context.transfer_signature, self.context.template_manifest, profile, self.context.eligibility_evaluation)
            candidate = deepcopy(self.binding); candidate["target_profile_digest"] = profile_digest(profile); candidate["operation_bindings"][0]["verified_fact_refs"] = [fact["fact_id"]]
            result = self.assess(candidate, ctx)
            with self.subTest(status=status):
                self.assertEqual("INCOMPLETE", check(result, "OPERATION_BINDING")["result"])


if __name__ == "__main__": unittest.main()
