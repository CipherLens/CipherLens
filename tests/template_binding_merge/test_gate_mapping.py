from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import unittest

from template_binding_merge.gate import validate_merge_gate
from template_binding_merge.model import MergeGateError, ValidationContext
from template_binding_merge.registry import validate_merged_source
from template_binding_merge.render import render_base_source
from tests.template_binding_merge.common import ROOT, built, inputs, reidentify


class MergeGateTests(unittest.TestCase):
    def test_wrong_template_digest_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        bundle = replace(bundle, trigger_template_digest="0" * 64)
        with self.assertRaises(MergeGateError):
            validate_merge_gate(bundle, manifest, binding, validation, ROOT)

    def test_wrong_source_artifact_digest_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        bundle = replace(bundle, source_artifact_digest="0" * 64)
        with self.assertRaises(MergeGateError):
            validate_merge_gate(bundle, manifest, binding, validation, ROOT)

    def test_wrong_interface_digest_binding_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        validation = deepcopy(validation)
        check = next(x for x in validation["check_results"] if x["validator_type"] == "REFERENCE_INTEGRITY")
        check["evidence_refs"] = ["0" * 64]
        with self.assertRaises(MergeGateError):
            validate_merge_gate(bundle, manifest, binding, validation, ROOT)

    def test_wrong_candidate_binding_digest_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        validation = deepcopy(validation)
        validation["candidate_binding_digest"] = "0" * 64
        with self.assertRaises(MergeGateError):
            validate_merge_gate(bundle, manifest, binding, validation, ROOT)

    def test_wrong_validation_binding_ref_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        validation = deepcopy(validation)
        validation["candidate_binding_ref"] = "binding:wrong-validation-subject"
        with self.assertRaises(MergeGateError):
            validate_merge_gate(bundle, manifest, binding, validation, ROOT)

    def test_non_valid_candidate_binding_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        validation = deepcopy(validation)
        validation["status"] = "INCOMPLETE"
        with self.assertRaises(MergeGateError):
            validate_merge_gate(bundle, manifest, binding, validation, ROOT)

    def test_target_scope_mismatch_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        expected = dict(binding["target_scope"])
        expected["version"] = "other"
        with self.assertRaises(MergeGateError):
            validate_merge_gate(
                bundle, manifest, binding, validation, ROOT, expected_target_scope=expected
            )

    def test_unresolvable_artifact_fails_closed(self) -> None:
        bundle, manifest, binding, validation = inputs()
        bundle = replace(bundle, source_artifact_ref="missing/template.c")
        with self.assertRaises(MergeGateError):
            validate_merge_gate(bundle, manifest, binding, validation, ROOT)


class MappingTests(unittest.TestCase):
    def _validate_mutation(self, merge: dict) -> dict:
        gated, _, _ = built()
        rendered = render_base_source(merge, ROOT)
        return validate_merged_source(
            ValidationContext(gated, merge, rendered.source_bytes, rendered.source_map, rendered.bound_source)
        )

    def test_missing_required_slot_is_invalid(self) -> None:
        _, merge, _ = built()
        manifest_required = {
            x["slot_ref"] for x in built()[0].template_manifest["slots"] if x["required"]
        }
        victim = next(
            item for item in merge["slot_bindings"]
            if item["candidate_element_kind"] == "INPUT" and item["template_slot_ref"] in manifest_required
        )
        merge["slot_bindings"].remove(victim)
        merge = reidentify(merge)
        result = self._validate_mutation(merge)
        self.assertEqual("INVALID", result["status"])
        self.assertEqual("FAIL", _check(result, "SLOT_COVERAGE")["result"])

    def test_dangling_template_slot_is_invalid(self) -> None:
        _, merge, _ = built()
        victim = next(x for x in merge["slot_bindings"] if x["candidate_element_kind"] == "INPUT")
        victim["template_slot_ref"] = "slot:input:dangling"
        merge = reidentify(merge)
        self.assertEqual("INVALID", self._validate_mutation(merge)["status"])

    def test_duplicate_mapping_violates_one_multiplicity(self) -> None:
        _, merge, _ = built()
        victim = next(x for x in merge["slot_bindings"] if x["candidate_element_kind"] == "OPERATION")
        duplicate = deepcopy(victim)
        duplicate["mapping_id"] = "mapping:deliberate-duplicate"
        duplicate["occurrence_index"] = 1
        merge["slot_bindings"].append(duplicate)
        merge = reidentify(merge)
        result = self._validate_mutation(merge)
        self.assertEqual("FAIL", _check(result, "SLOT_MULTIPLICITY")["result"])

    def test_wrong_candidate_element_kind_is_invalid(self) -> None:
        _, merge, _ = built()
        victim = next(x for x in merge["slot_bindings"] if x["candidate_element_kind"] == "INPUT")
        victim["candidate_element_kind"] = "SUBJECT"
        merge = reidentify(merge)
        result = self._validate_mutation(merge)
        self.assertEqual("INVALID", result["status"])
        self.assertEqual("FAIL", _check(result, "INPUT_PRESERVATION")["result"])

    def test_atomic_mappings_have_unique_occurrences(self) -> None:
        _, merge, _ = built()
        pairs = [(x["template_slot_ref"], x["occurrence_index"]) for x in merge["slot_bindings"]]
        self.assertEqual(len(pairs), len(set(pairs)))
        self.assertTrue(all(isinstance(x["candidate_element_ref"], str) for x in merge["slot_bindings"]))


def _check(validation: dict, kind: str) -> dict:
    return next(item for item in validation["check_results"] if item["validator_type"] == kind)


if __name__ == "__main__":
    unittest.main()
