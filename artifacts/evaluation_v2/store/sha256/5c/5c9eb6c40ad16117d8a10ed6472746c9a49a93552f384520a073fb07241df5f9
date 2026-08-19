from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from template_binding_merge.adaptation import apply_adaptation, build_adaptation_proposal
from template_binding_merge.canonical import expected_adaptation_proposal_id
from template_binding_merge.completion import programmatic_complete
from template_binding_merge.model import AdaptationRejected
from template_binding_merge.registry import validate_merged_source
from template_binding_merge.validate import validate_adaptation_proposal
from tests.template_binding_merge.common import ROOT, built, context, proposal_hole


REPLACEMENT = "/* exact syntax glue */"


def workflow() -> tuple[object, dict, object, dict]:
    gated, merge, base = built(additional_holes=[proposal_hole(REPLACEMENT)])
    completed = programmatic_complete(
        merge, base.source_bytes, base.source_map, base.bound_source, ROOT
    )
    edit = {
        "edit_id": "edit:proposal-declaration",
        "edit_type": "FILL_HOLE",
        "hole_ref": "hole:proposal-declaration",
        "base_source_digest": completed.bound_source["source_digest"],
        "expected_syntax_kind": "C_DECLARATION",
        "replacement": REPLACEMENT,
    }
    proposal = build_adaptation_proposal(
        merge,
        completed.bound_source,
        [edit],
        provider_id="provider:replay",
        provider_version="v0.1",
        request_digest="1" * 64,
    )
    return gated, merge, completed, proposal


class AdaptationTests(unittest.TestCase):
    def test_allowed_syntax_only_fill_becomes_valid(self) -> None:
        gated, merge, completed, proposal = workflow()
        adapted = apply_adaptation(
            merge, completed.source_bytes, completed.source_map, completed.bound_source,
            proposal, ROOT,
        )
        validation = validate_merged_source(context(gated, merge, adapted))
        self.assertEqual([], adapted.bound_source["unresolved_hole_refs"])
        self.assertEqual("VALID", validation["status"])

    def test_illegal_api_replacement_is_rejected(self) -> None:
        _, merge, completed, proposal = workflow()
        proposal = _edit_proposal(proposal, replacement="call_different_api()")
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, completed.source_bytes, completed.source_map, completed.bound_source, proposal, ROOT)

    def test_proposal_cannot_bypass_deterministic_completion_order(self) -> None:
        _, merge, base = built(additional_holes=[proposal_hole(REPLACEMENT)])
        edit = {
            "edit_id": "edit:proposal-declaration",
            "edit_type": "FILL_HOLE",
            "hole_ref": "hole:proposal-declaration",
            "base_source_digest": base.bound_source["source_digest"],
            "expected_syntax_kind": "C_DECLARATION",
            "replacement": REPLACEMENT,
        }
        proposal = build_adaptation_proposal(
            merge, base.bound_source, [edit], provider_id="provider:replay",
            provider_version="v0.1", request_digest="1" * 64,
        )
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, base.source_bytes, base.source_map, base.bound_source, proposal, ROOT)

    def test_illegal_object_replacement_is_rejected(self) -> None:
        _, merge, completed, proposal = workflow()
        proposal = _edit_proposal(proposal, replacement="replacement_object")
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, completed.source_bytes, completed.source_map, completed.bound_source, proposal, ROOT)

    def test_illegal_observable_replacement_is_rejected(self) -> None:
        _, merge, completed, proposal = workflow()
        proposal = _edit_proposal(proposal, replacement="capture_other_observable")
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, completed.source_bytes, completed.source_map, completed.bound_source, proposal, ROOT)

    def test_wrong_base_digest_is_rejected(self) -> None:
        _, merge, completed, proposal = workflow()
        proposal = _edit_proposal(proposal, base_source_digest="0" * 64)
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, completed.source_bytes, completed.source_map, completed.bound_source, proposal, ROOT)

    def test_wrong_hole_is_rejected(self) -> None:
        _, merge, completed, proposal = workflow()
        proposal = _edit_proposal(proposal, hole_ref="hole:undeclared")
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, completed.source_bytes, completed.source_map, completed.bound_source, proposal, ROOT)

    def test_wrong_syntax_kind_is_rejected(self) -> None:
        _, merge, completed, proposal = workflow()
        proposal = _edit_proposal(proposal, expected_syntax_kind="C_EXPRESSION")
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, completed.source_bytes, completed.source_map, completed.bound_source, proposal, ROOT)

    def test_protected_mutation_is_rejected_before_application(self) -> None:
        _, merge, completed, proposal = workflow()
        source = bytearray(completed.source_bytes)
        source[0] = (source[0] + 1) % 255
        with self.assertRaises(AdaptationRejected):
            apply_adaptation(merge, bytes(source), completed.source_map, completed.bound_source, proposal, ROOT)

    def test_provider_cannot_claim_verified_or_valid(self) -> None:
        _, _, _, proposal = workflow()
        for status in ("VERIFIED", "VALID", "SATISFIED", "VIOLATED"):
            with self.subTest(status=status):
                changed = deepcopy(proposal)
                changed["epistemic_status"] = status
                changed["proposal_id"] = expected_adaptation_proposal_id(changed)
                self.assertTrue(validate_adaptation_proposal(changed))

    def test_provider_cannot_add_candidate_binding_or_semantic_mapping(self) -> None:
        _, _, _, proposal = workflow()
        for field in ("candidate_binding", "slot_bindings"):
            with self.subTest(field=field):
                changed = deepcopy(proposal)
                changed[field] = []
                changed["proposal_id"] = expected_adaptation_proposal_id(changed)
                self.assertTrue(any("unknown field" in error for error in validate_adaptation_proposal(changed)))


class CompletionTests(unittest.TestCase):
    def test_completion_is_deterministic(self) -> None:
        _, merge, base = built()
        first = programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
        second = programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
        self.assertEqual(first, second)

    def test_completion_is_idempotent(self) -> None:
        _, merge, base = built()
        once = programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
        twice = programmatic_complete(merge, once.source_bytes, once.source_map, once.bound_source, ROOT)
        self.assertEqual(once, twice)

    def test_completion_does_not_modify_semantic_merge(self) -> None:
        _, merge, base = built()
        before = deepcopy(merge)
        programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
        self.assertEqual(before, merge)

    def test_completion_introduces_no_new_hole(self) -> None:
        _, merge, base = built()
        completed = programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
        declared = {x["hole_id"] for x in merge["adaptation_holes"]}
        mapped = {
            ref for region in completed.source_map["regions"]
            for ref in region["adaptation_hole_refs"]
        }
        self.assertEqual(declared, mapped)


def _edit_proposal(proposal: dict, **changes: str) -> dict:
    result = deepcopy(proposal)
    result["restricted_edits"][0].update(changes)
    result["proposal_id"] = expected_adaptation_proposal_id(result)
    return result


if __name__ == "__main__":
    unittest.main()
