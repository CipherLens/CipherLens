from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from template_binding_merge.canonical import (
    expected_bound_source_id,
    expected_source_map_id,
    source_map_digest,
)
from template_binding_merge.model import ValidationContext
from template_binding_merge.registry import validate_merged_source
from template_binding_merge.render import render_base_source
from tests.template_binding_merge.common import ROOT, built, context, reidentify


class StructuralPreservationTests(unittest.TestCase):
    def _result(self, gated: object, merge: dict) -> dict:
        rendered = render_base_source(merge, ROOT)
        return validate_merged_source(context(gated, merge, rendered))

    def test_operation_reorder_is_invalid(self) -> None:
        gated, merge, _ = built()
        obligation = _obligation(merge, "OPERATION_SEQUENCE_PRESERVED")
        obligation["ordered_refs"].reverse()
        merge = reidentify(merge)
        result = self._result(gated, merge)
        self.assertEqual("INVALID", result["status"])
        self.assertEqual("FAIL", _check(result, "ORDER_PRESERVATION")["result"])

    def test_intervention_movement_is_invalid(self) -> None:
        gated, merge, _ = built()
        obligation = _obligation(merge, "INTERVENTION_PHASE_PRESERVED")
        obligation["typed_refs"][0] = obligation["typed_refs"][0].replace("BEFORE_OPERATION", "FOLLOWUP_SEQUENCE")
        if obligation["typed_refs"][0].endswith("FOLLOWUP_SEQUENCE") is False:
            obligation["typed_refs"][0] += ":MOVED"
        merge = reidentify(merge)
        self.assertEqual("INVALID", self._result(gated, merge)["status"])

    def test_identity_storage_break_is_invalid(self) -> None:
        gated, merge, _ = built()
        merge["identity_realizations"][0]["storage_ref"] = "storage:replacement"
        merge = reidentify(merge)
        result = self._result(gated, merge)
        self.assertEqual("FAIL", _check(result, "STATE_CONTINUITY_PRESERVATION")["result"])

    def test_correlation_break_is_invalid(self) -> None:
        gated, merge, _ = built()
        merge["correlation_realizations"][0]["correlation_kind"] = "SAME_STEP"
        merge = reidentify(merge)
        result = self._result(gated, merge)
        self.assertEqual("FAIL", _check(result, "CORRELATION_PRESERVATION")["result"])

    def test_followup_break_is_invalid(self) -> None:
        gated, merge, _ = built("mbedtls_poc_0005")
        obligation = _obligation(merge, "FOLLOWUP_SEQUENCE_PRESERVED")
        obligation["ordered_refs"] = list(reversed(obligation["ordered_refs"]))
        merge = reidentify(merge)
        self.assertEqual("INVALID", self._result(gated, merge)["status"])

    def test_api_substitution_is_invalid(self) -> None:
        gated, merge, _ = built()
        operation = next(x for x in merge["slot_bindings"] if x["candidate_element_kind"] == "OPERATION")
        operation["target_semantic_ref"] = "api:substituted"
        merge = reidentify(merge)
        self.assertEqual("INVALID", self._result(gated, merge)["status"])

    def test_object_substitution_is_invalid(self) -> None:
        gated, merge, _ = built()
        merge["subject_realizations"][0]["target_subject_ref"] = "object:substituted"
        merge = reidentify(merge)
        self.assertEqual("INVALID", self._result(gated, merge)["status"])

    def test_observation_replacement_is_invalid(self) -> None:
        gated, merge, _ = built()
        merge["observation_capture_bindings"][0]["semantic_source_ref"] = "observable:substituted"
        merge = reidentify(merge)
        self.assertEqual("INVALID", self._result(gated, merge)["status"])

    def test_observation_deletion_is_invalid(self) -> None:
        gated, merge, _ = built()
        del merge["observation_capture_bindings"][0]
        merge = reidentify(merge)
        self.assertEqual("INVALID", self._result(gated, merge)["status"])


class SourceMapTests(unittest.TestCase):
    def test_renderer_and_source_map_are_deterministic(self) -> None:
        gated, merge, first = built()
        second = render_base_source(merge, ROOT)
        self.assertEqual(first.source_bytes, second.source_bytes)
        self.assertEqual(first.source_map, second.source_map)
        self.assertEqual(first.bound_source, second.bound_source)

    def test_protected_region_digests_match_exact_bytes(self) -> None:
        _, _, rendered = built()
        for region in rendered.source_map["regions"]:
            if not region["protected"]:
                continue
            source_range = region["source_range"]
            payload = rendered.source_bytes[source_range["byte_start"]:source_range["byte_end"]]
            self.assertEqual(region["canonical_digest"], hashlib.sha256(payload).hexdigest())

    def test_declared_hole_has_one_unprotected_range(self) -> None:
        _, merge, rendered = built()
        hole = merge["adaptation_holes"][0]
        regions = [x for x in rendered.source_map["regions"] if hole["hole_id"] in x["adaptation_hole_refs"]]
        self.assertEqual(1, len(regions))
        self.assertFalse(regions[0]["protected"])
        self.assertEqual("ADAPTATION_HOLE", regions[0]["region_kind"])

    def test_operation_records_preserve_order(self) -> None:
        _, merge, rendered = built()
        expected = _obligation(merge, "OPERATION_SEQUENCE_PRESERVED")["ordered_refs"]
        actual = [x["operation_binding_ref"] for x in rendered.source_map["ordered_operation_records"]]
        self.assertEqual(expected, actual)

    def test_observation_records_exactly_cover_captures(self) -> None:
        _, merge, rendered = built()
        expected = {x["observation_binding_ref"] for x in merge["observation_capture_bindings"]}
        actual = {x["observation_binding_ref"] for x in rendered.source_map["observation_capture_records"]}
        self.assertEqual(expected, actual)

    def test_identity_records_exactly_cover_storage(self) -> None:
        _, merge, rendered = built()
        expected = {(x["identity_group_ref"], x["storage_ref"]) for x in merge["identity_realizations"]}
        actual = {(x["identity_group_ref"], x["storage_ref"]) for x in rendered.source_map["identity_storage_records"]}
        self.assertEqual(expected, actual)

    def test_protected_source_mutation_is_invalid(self) -> None:
        gated, merge, rendered = built()
        changed = bytearray(rendered.source_bytes)
        changed[0] = (changed[0] + 1) % 255
        validation = validate_merged_source(
            ValidationContext(gated, merge, bytes(changed), rendered.source_map, rendered.bound_source)
        )
        self.assertEqual("INVALID", validation["status"])

    def test_undeclared_range_append_is_invalid(self) -> None:
        gated, merge, rendered = built()
        validation = validate_merged_source(
            ValidationContext(
                gated, merge, rendered.source_bytes + b"/* undeclared */", rendered.source_map,
                rendered.bound_source,
            )
        )
        self.assertEqual("INVALID", validation["status"])

    def test_source_map_api_record_substitution_is_invalid_even_when_rehashed(self) -> None:
        gated, merge, rendered = built()
        source_map = deepcopy(rendered.source_map)
        source_map["ordered_operation_records"][0]["target_symbol_ref"] = "api:substituted"
        source_map, bound_source = _rebind_map(source_map, rendered.bound_source)
        validation = validate_merged_source(
            ValidationContext(gated, merge, rendered.source_bytes, source_map, bound_source)
        )
        self.assertEqual("FAIL", _check(validation, "SOURCE_BINDING_CONSISTENCY")["result"])

    def test_source_map_observation_deletion_is_invalid_even_when_rehashed(self) -> None:
        gated, merge, rendered = built()
        source_map = deepcopy(rendered.source_map)
        del source_map["observation_capture_records"][0]
        source_map, bound_source = _rebind_map(source_map, rendered.bound_source)
        validation = validate_merged_source(
            ValidationContext(gated, merge, rendered.source_bytes, source_map, bound_source)
        )
        self.assertEqual("FAIL", _check(validation, "SOURCE_BINDING_CONSISTENCY")["result"])

    def test_source_map_identity_drift_is_invalid_even_when_rehashed(self) -> None:
        gated, merge, rendered = built()
        source_map = deepcopy(rendered.source_map)
        source_map["identity_storage_records"][0]["storage_ref"] = "storage:substituted"
        source_map, bound_source = _rebind_map(source_map, rendered.bound_source)
        validation = validate_merged_source(
            ValidationContext(gated, merge, rendered.source_bytes, source_map, bound_source)
        )
        self.assertEqual("FAIL", _check(validation, "SOURCE_BINDING_CONSISTENCY")["result"])


def _obligation(merge: dict, kind: str) -> dict:
    return next(item for item in merge["structural_obligations"] if item["obligation_type"] == kind)


def _check(validation: dict, kind: str) -> dict:
    return next(item for item in validation["check_results"] if item["validator_type"] == kind)


def _rebind_map(source_map: dict, bound_source: dict) -> tuple[dict, dict]:
    source_map["source_map_id"] = expected_source_map_id(source_map)
    envelope = deepcopy(bound_source)
    envelope["source_map_ref"] = source_map["source_map_id"]
    envelope["source_map_digest"] = source_map_digest(source_map)
    envelope["bound_source_id"] = expected_bound_source_id(envelope)
    return source_map, envelope


if __name__ == "__main__":
    unittest.main()
