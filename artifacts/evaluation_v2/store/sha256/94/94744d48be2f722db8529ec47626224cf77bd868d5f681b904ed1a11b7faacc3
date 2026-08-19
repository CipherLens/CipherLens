from __future__ import annotations

from copy import deepcopy
import unittest

from matcher.knowledge import KnowledgeSeed, SyntheticKnowledgeBackend
from matcher.model import MatcherCandidate, MatcherTelemetry, TargetScope
from matcher.query import build_recall_query
from matcher.recall import RecallResult, assemble_candidate_surfaces, wide_recall
from matcher.trace import matcher_trace_digest
from tests.matcher.common import case_request


class MatcherModelRecallTests(unittest.TestCase):
    def test_candidate_identity_ignores_evidence_and_retrieval_order(self) -> None:
        scope = TargetScope("synthetic-target", "1.0", "surface:test")
        left = MatcherCandidate.create(
            target_scope=scope,
            subject_refs=["SUBJECT_B", "SUBJECT_A"],
            symbol_refs=["SYMBOL_B", "SYMBOL_A"],
            surface_composition={"kind": "API_GROUP", "_binding_mappings": {"x": 1}},
            evidence_refs=["EVIDENCE_A"],
        )
        right = MatcherCandidate.create(
            target_scope=scope,
            subject_refs=["SUBJECT_A", "SUBJECT_B"],
            symbol_refs=["SYMBOL_A", "SYMBOL_B"],
            surface_composition={"kind": "API_GROUP", "_binding_mappings": {"x": 2}},
            evidence_refs=["EVIDENCE_B"],
        )
        self.assertEqual(left.candidate_id, right.candidate_id)

    def test_assignment_change_changes_candidate_identity(self) -> None:
        scope = TargetScope("synthetic-target", "1.0", "surface:test")
        first = MatcherCandidate.create(
            target_scope=scope,
            subject_refs=["SUBJECT_A"],
            symbol_refs=["SYMBOL_A"],
            surface_composition={"assignments": [{"role": "PARSE"}]},
        )
        second = MatcherCandidate.create(
            target_scope=scope,
            subject_refs=["SUBJECT_A"],
            symbol_refs=["SYMBOL_A"],
            surface_composition={"assignments": [{"role": "FINAL"}]},
        )
        self.assertNotEqual(first.candidate_id, second.candidate_id)

    def test_recall_query_is_stable_and_contains_controlled_relation_hints(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020")
        first = build_recall_query(
            request.contract, request.transfer_signature, request.template_manifest,
            family_metadata=request.family_metadata,
        )
        second = build_recall_query(
            request.contract, request.transfer_signature, request.template_manifest,
            family_metadata=request.family_metadata,
        )
        self.assertEqual(first.query_id, second.query_id)
        self.assertIn("full_consumption_on_success", first.controlled_relation_hints)
        self.assertNotIn(request.contract["expected_relation"]["summary"], first.controlled_relation_hints)
        self.assertTrue(first.template_slot_hints)
        self.assertTrue(first.template_slot_hints[0]["semantic_role_hint"])

    def test_wide_recall_keeps_rank_and_score_outside_candidate_identity(self) -> None:
        request, _, backend = case_request("mbedtls_poc_0004")
        query = build_recall_query(
            request.contract, request.transfer_signature, request.template_manifest
        )
        recall = wide_recall(backend, query, request.target_scope, limit=32)
        candidates, _ = assemble_candidate_surfaces(recall)
        record = recall.records[0]
        self.assertEqual(1, record.rank)
        self.assertEqual(0.99, record.score)
        self.assertNotIn("score", candidates[0].semantic_summary())

    def test_recall_budget_reports_truncation(self) -> None:
        request, _, backend = case_request("mbedtls_poc_0020")
        seed = backend._seeds[0]
        extra = deepcopy(seed)
        object.__setattr__(extra, "entity_ref", "seed:extra")
        many = SyntheticKnowledgeBackend(
            seeds=(seed, extra),
            evidence=tuple(backend._evidence.values()),
            subjects=backend._subjects,
        )
        query = build_recall_query(
            request.contract, request.transfer_signature, request.template_manifest
        )
        result = wide_recall(many, query, request.target_scope, limit=1)
        self.assertTrue(result.budget_exhausted)
        self.assertEqual(1, len(result.seeds))

    def test_multi_subject_surface_assembly(self) -> None:
        request, _, backend = case_request("mbedtls_poc_0005")
        query = build_recall_query(
            request.contract, request.transfer_signature, request.template_manifest
        )
        candidates, records = assemble_candidate_surfaces(
            wide_recall(backend, query, request.target_scope, limit=32)
        )
        self.assertGreater(len(candidates[0].subject_refs), 1)
        self.assertEqual("MULTI_SUBJECT_CALL_SURFACE", candidates[0].surface_composition["surface_kind"])
        self.assertEqual(candidates[0].candidate_id, records[0].candidate_ref)

    def test_incompatible_surface_composition_is_not_spliced(self) -> None:
        request, _, backend = case_request("mbedtls_poc_0020")
        first = backend._seeds[0]
        second = KnowledgeSeed(
            entity_ref="seed:conflict",
            entity_kind=first.entity_kind,
            target_scope=first.target_scope,
            subject_refs=first.subject_refs,
            symbol_refs=first.symbol_refs,
            evidence_refs=first.evidence_refs,
            surface_composition={"family": "incompatible"},
            metadata=first.metadata,
        )
        recall = RecallResult((first, second), (), False)
        with self.assertRaisesRegex(ValueError, "INCOMPATIBLE_SURFACE_COMPOSITION"):
            assemble_candidate_surfaces(recall)

    def test_telemetry_does_not_change_semantic_trace_digest(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020")
        from matcher.orchestrate import run_matcher

        trace = run_matcher(request).trace
        first = MatcherTelemetry(timestamps={"start": "1"}, host="a")
        second = MatcherTelemetry(timestamps={"start": "2"}, host="b")
        self.assertNotEqual(first, second)
        self.assertEqual(trace.digest(), matcher_trace_digest(trace.semantic_core))


if __name__ == "__main__":
    unittest.main()
