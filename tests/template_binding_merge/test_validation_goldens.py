from __future__ import annotations

from copy import deepcopy
import unittest

from template_binding_merge.completion import programmatic_complete
from template_binding_merge.model import ValidationContext, ValidatorType
from template_binding_merge.registry import validate_merged_source
from tests.template_binding_merge.common import FAMILIES, ROOT, built, context, proposal_hole


EXPECTED_MERGE_IDS = {
    "mbedtls_poc_0020": "merge:7b65c1ad3c4041e23e5217a3f9a2e101c17793e65ee5064fbe96093dab6ccfe7",
    "mbedtls_poc_0004": "merge:fa22f7e15910dee145b235117ba44469f51674ecbdf2d8e48f065529e53807fc",
    "mbedtls_poc_0005": "merge:6274cb130bd7651f4a3c89d5655e96e733d11dab4cfab62a1ed5383a985f2cc0",
}


class ValidationStatusTests(unittest.TestCase):
    def test_incomplete_means_only_declared_required_hole(self) -> None:
        gated, merge, rendered = built()
        validation = validate_merged_source(context(gated, merge, rendered))
        nonpass = [x for x in validation["check_results"] if x["result"] != "PASS"]
        self.assertEqual("INCOMPLETE", validation["status"])
        self.assertEqual("PROGRAMMATIC_COMPLETION", validation["routing"])
        self.assertEqual(["COMPLETENESS"], [x["validator_type"] for x in nonpass])

    def test_invalid_precedes_incomplete(self) -> None:
        gated, merge, rendered = built()
        changed = b"X" + rendered.source_bytes[1:]
        validation = validate_merged_source(
            ValidationContext(gated, merge, changed, rendered.source_map, rendered.bound_source)
        )
        self.assertEqual("INVALID", validation["status"])
        self.assertEqual("WHOLE_BINDING_SWITCH", validation["routing"])
        self.assertEqual("INCOMPLETE", _check(validation, "COMPLETENESS")["result"])

    def test_valid_only_after_all_checks_pass(self) -> None:
        gated, merge, base = built()
        completed = programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
        validation = validate_merged_source(context(gated, merge, completed))
        self.assertEqual("VALID", validation["status"])
        self.assertEqual("EXECUTION_HANDOFF", validation["routing"])
        self.assertTrue(all(x["result"] == "PASS" for x in validation["check_results"]))

    def test_proposal_hole_routes_to_constrained_adaptation(self) -> None:
        gated, merge, base = built(additional_holes=[proposal_hole()])
        completed = programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
        validation = validate_merged_source(context(gated, merge, completed))
        self.assertEqual("INCOMPLETE", validation["status"])
        self.assertEqual("CONSTRAINED_ADAPTATION", validation["routing"])

    def test_registry_contains_exactly_frozen_eighteen_checks(self) -> None:
        gated, merge, rendered = built()
        validation = validate_merged_source(context(gated, merge, rendered))
        self.assertEqual(
            {item.value for item in ValidatorType},
            {item["validator_type"] for item in validation["check_results"]},
        )
        self.assertEqual(18, len(validation["check_results"]))


class ThreeGoldenFamilyTests(unittest.TestCase):
    def test_three_family_merge_ids_are_frozen(self) -> None:
        for family, expected in EXPECTED_MERGE_IDS.items():
            with self.subTest(family=family):
                _, merge, _ = built(family)
                self.assertEqual(expected, merge["merge_id"])

    def test_all_three_families_complete_to_valid(self) -> None:
        for family in FAMILIES:
            with self.subTest(family=family):
                gated, merge, base = built(family)
                completed = programmatic_complete(
                    merge, base.source_bytes, base.source_map, base.bound_source, ROOT
                )
                validation = validate_merged_source(context(gated, merge, completed))
                self.assertEqual("VALID", validation["status"])
                self.assertEqual([], completed.bound_source["unresolved_hole_refs"])

    def test_0020_preserves_parse_and_pointer_delta_observation(self) -> None:
        _, merge, _ = built("mbedtls_poc_0020")
        operations = [x for x in merge["slot_bindings"] if x["candidate_element_kind"] == "OPERATION"]
        acquisitions = {x["acquisition_kind"] for x in merge["observation_capture_bindings"]}
        self.assertEqual(5, len(operations))
        self.assertIn("POINTER_DELTA", acquisitions)
        self.assertEqual("SAME_RUN", merge["correlation_realizations"][0]["correlation_kind"])

    def test_0004_preserves_stateful_before_after_evidence(self) -> None:
        _, merge, _ = built("mbedtls_poc_0004")
        observations = {x["observation_binding_ref"] for x in merge["observation_capture_bindings"]}
        self.assertIn("OBSERVATION_1_OUTPUT_LENGTH_BEFORE", observations)
        self.assertIn("OBSERVATION_2_OUTPUT_LENGTH_AFTER", observations)
        context_identity = next(x for x in merge["identity_realizations"] if x["identity_group_ref"] == "identity:cipher_context")
        self.assertEqual(1, len({context_identity["storage_ref"]}))

    def test_0005_preserves_update_zero_reuse_sequence(self) -> None:
        _, merge, _ = built("mbedtls_poc_0005")
        order = next(
            x["ordered_refs"] for x in merge["structural_obligations"]
            if x["obligation_type"] == "OPERATION_SEQUENCE_PRESERVED"
        )
        self.assertEqual(
            ["OPERATION_0_STORE_INITIAL", "OPERATION_1_STORE_ZERO", "OPERATION_2_STORE_REUSE"],
            order,
        )
        self.assertEqual("SAME_SUBJECT", merge["correlation_realizations"][0]["correlation_kind"])


def _check(validation: dict, kind: str) -> dict:
    return next(item for item in validation["check_results"] if item["validator_type"] == kind)


if __name__ == "__main__":
    unittest.main()
