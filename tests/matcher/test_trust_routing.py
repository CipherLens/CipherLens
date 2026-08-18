from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import unittest

from binding_proposal.config import ProviderConfig
from binding_proposal.model import InvocationStatus, ProviderInvocationResult, ProviderKind
from binding_proposal.providers.replay import ReplayProposalProvider
from binding_proposal.router import ProviderRouter
from matcher.knowledge import EvidenceItem
from matcher.model import EvidenceClass, MatcherBudgets, MatcherRunOutcome
from matcher.orchestrate import run_matcher
from matcher.proposal import ProposalOrchestrator
from tests.matcher.common import (
    ROOT,
    case_request,
    golden_profile,
    payload_from_profile,
    synthetic_digest,
)


class PolicyRejectedReplayProvider(ReplayProposalProvider):
    def invoke(self, request):
        self.invocation_count += 1
        return ProviderInvocationResult(
            InvocationStatus.POLICY_REJECTED,
            ProviderKind.TEST_REPLAY,
            request.invocation_ref,
            "REPLAY_POLICY_REJECTED",
        )


class SequenceReplayProvider(ReplayProposalProvider):
    def __init__(self, fixtures):
        super().__init__(fixtures[0])
        self.fixtures = list(fixtures)

    def invoke(self, request):
        self.fixture = self.fixtures[min(self.invocation_count, len(self.fixtures) - 1)]
        return super().invoke(request)


def with_provider(request, provider):
    config = ProviderConfig(provider=ProviderKind.TEST_REPLAY)
    return replace(
        request,
        proposal_orchestrator=ProposalOrchestrator(
            provider=provider,
            router=ProviderRouter(provider, config=config),
        ),
    )


class MatcherTrustRoutingTests(unittest.TestCase):
    def test_rag_hit_cannot_create_verified_or_binding(self) -> None:
        request, _, _ = case_request(
            "mbedtls_poc_0020", evidence_class=EvidenceClass.RAG_HIT
        )
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.EVIDENCE_INSUFFICIENT, result.outcome)
        self.assertFalse(result.trace.semantic_core["binding_attempts"])
        self.assertTrue(
            all(
                record["resulting_epistemic_status"] == "INFERRED"
                for record in result.trace.semantic_core["fact_resolution_records"]
                if record["resulting_fact_ref"] is not None
            )
        )

    def test_api_card_free_text_cannot_create_verified(self) -> None:
        request, _, _ = case_request(
            "mbedtls_poc_0004", evidence_class=EvidenceClass.API_CARD
        )
        result = run_matcher(request)
        self.assertNotEqual(MatcherRunOutcome.MATCH_FOUND, result.outcome)
        self.assertFalse(result.trace.semantic_core["ranking_records"])

    def test_ts_ineligible_is_hard_reject_before_ranking(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020", profile_label="ineligible")
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.NO_ELIGIBLE_CANDIDATE, result.outcome)
        self.assertFalse(result.trace.semantic_core["ranking_records"])
        self.assertFalse(result.trace.semantic_core["binding_attempts"])

    def test_ts_indeterminate_enters_evidence_path_only(self) -> None:
        request, _, _ = case_request(
            "mbedtls_poc_0004",
            profile_label="indeterminate",
            evidence_class=EvidenceClass.RAG_HIT,
        )
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.EVIDENCE_INSUFFICIENT, result.outcome)
        self.assertFalse(result.trace.semantic_core["ranking_records"])
        self.assertTrue(
            any(x["eligibility"] == "INDETERMINATE" for x in result.trace.semantic_core["eligibility_records"])
        )

    def test_verified_fact_conflict_fails_closed(self) -> None:
        profile = golden_profile("mbedtls_poc_0020")
        duplicate = deepcopy(profile["facts"][0])
        duplicate["fact_id"] = "F_CONFLICT_DUPLICATE"
        duplicate["assertion"] = "FALSE" if duplicate["assertion"] == "TRUE" else "TRUE"
        profile["facts"].append(duplicate)
        request, _, _ = case_request(
            "mbedtls_poc_0020", profile_override=profile
        )
        result = run_matcher(request)
        self.assertNotEqual(MatcherRunOutcome.MATCH_FOUND, result.outcome)
        self.assertTrue(
            any(
                "PROFILE_VERIFIED_FACT_CONFLICT" in item["reason_codes"]
                for item in result.trace.semantic_core["rejection_records"]
            )
        )

    def test_observability_unresolvable_cannot_be_ranked(self) -> None:
        profile = golden_profile("mbedtls_poc_0020")
        payload = payload_from_profile(profile)
        moved_index = next(
            index
            for index, item in enumerate(payload["observation_proposals"])
            if item["source_ref"] == "CONSUMED_LENGTH"
        )
        resolver_claim = deepcopy(payload["observation_proposals"][moved_index])
        resolver_claim["source_ref"] = resolver_claim["related_refs"][0]
        payload["role_proposals"].append(resolver_claim)
        payload["observation_proposals"][moved_index]["target_ref"] = "SYNTHETIC_INPUT"
        request, _, _ = case_request("mbedtls_poc_0020", payload=payload)
        result = run_matcher(request)
        self.assertFalse(result.trace.semantic_core["ranking_records"])
        self.assertTrue(
            all(x["status"] == "UNRESOLVABLE" for x in result.trace.semantic_core["observability_records"])
        )

    def test_observability_incomplete_routes_to_evidence_insufficient(self) -> None:
        profile = golden_profile("mbedtls_poc_0004")
        payload = payload_from_profile(profile)
        moved_index = next(
            index
            for index, item in enumerate(payload["observation_proposals"])
            if item["related_refs"]
        )
        moved = payload["observation_proposals"].pop(moved_index)
        moved["source_ref"] = moved["related_refs"][0]
        payload["role_proposals"].append(moved)
        request, _, _ = case_request("mbedtls_poc_0004", payload=payload)
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.EVIDENCE_INSUFFICIENT, result.outcome)
        self.assertFalse(result.trace.semantic_core["ranking_records"])
        self.assertTrue(
            any(x["status"] == "INCOMPLETE" for x in result.trace.semantic_core["observability_records"])
        )

    def test_malformed_replay_proposal_is_provider_blocked_not_unknown(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020", payload="not-json")
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.PROVIDER_BLOCKED, result.outcome)
        self.assertNotIn("UNKNOWN", result.trace.semantic_core["run_outcome"])

    def test_policy_rejected_is_provider_blocked_without_transport(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0005")
        provider = PolicyRejectedReplayProvider(payload_from_profile(golden_profile("mbedtls_poc_0005")))
        result = run_matcher(with_provider(request, provider))
        self.assertEqual(MatcherRunOutcome.PROVIDER_BLOCKED, result.outcome)
        self.assertEqual(2, provider.invocation_count)
        self.assertTrue(
            all(x["invocation_status"] == "POLICY_REJECTED" for x in result.trace.semantic_core["provider_attempts"])
        )

    def test_multiple_proposals_are_append_only_and_change_assignment_candidate(self) -> None:
        profile = golden_profile("mbedtls_poc_0020")
        first = payload_from_profile(profile)
        second = deepcopy(first)
        second["operation_proposals"][0]["semantic_role"] = "FINAL"
        request, _, _ = case_request("mbedtls_poc_0020")
        provider = SequenceReplayProvider([first, second])
        result = run_matcher(with_provider(request, provider))
        proposal_refs = {x["proposal_ref"] for x in result.trace.semantic_core["proposal_records"]}
        derived_candidates = {
            x["candidate_id"]
            for x in result.trace.semantic_core["candidate_records"]
            if x.get("proposal_ref")
        }
        self.assertEqual(2, len(proposal_refs))
        self.assertEqual(2, len(derived_candidates))

    def test_identical_payload_from_distinct_invocations_has_distinct_proposal_id(self) -> None:
        payload = payload_from_profile(golden_profile("mbedtls_poc_0020"))
        request, _, _ = case_request("mbedtls_poc_0020")
        provider = SequenceReplayProvider([payload, payload])
        result = run_matcher(with_provider(request, provider))
        proposal_records = result.trace.semantic_core["proposal_records"]
        self.assertEqual(2, len(proposal_records))
        self.assertEqual(2, len({item["proposal_ref"] for item in proposal_records}))
        self.assertEqual(2, len({item["proposal_digest"] for item in proposal_records}))

    def test_invalid_binding_is_whole_rejected(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0004", binding_label="invalid")
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.CANDIDATES_EXHAUSTED, result.outcome)
        self.assertTrue(
            any(x.get("whole_binding_rejected") is True for x in result.trace.semantic_core["rejection_records"])
        )
        self.assertIsNone(result.candidate_binding)

    def test_incomplete_binding_never_becomes_valid(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0005", binding_label="incomplete")
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.EVIDENCE_INSUFFICIENT, result.outcome)
        self.assertIsNone(result.candidate_binding)
        self.assertTrue(
            any(x["status"] == "INCOMPLETE" for x in result.trace.semantic_core["validation_records"])
        )

    def test_evidence_round_budget_exhaustion_is_not_ineligible(self) -> None:
        profile = golden_profile("mbedtls_poc_0004", "indeterminate")
        scope = request_scope = case_request("mbedtls_poc_0004")[0].target_scope
        extra = EvidenceItem(
            evidence_ref="EMPTY_ENHANCEMENT_FIXTURE",
            source_type=EvidenceClass.FIXTURE,
            target_scope=request_scope,
            subject_refs=tuple(x["subject_ref"] for x in profile["subjects"]),
            symbol_refs=(),
            artifact_ref="tests/transfer_signature/fixtures/synthetic_target_evidence.md",
            artifact_digest=synthetic_digest(),
            initial_epistemic_status="HYPOTHESIS",
            fact_payloads=(),
        )
        request, _, _ = case_request(
            "mbedtls_poc_0004",
            profile_label="indeterminate",
            extra_evidence=(extra,),
            evidence_class=EvidenceClass.RAG_HIT,
        )
        result = run_matcher(request)
        self.assertEqual(MatcherRunOutcome.BUDGET_EXHAUSTED, result.outcome)
        self.assertNotEqual("INELIGIBLE", result.trace.semantic_core["run_outcome"])

    def test_binding_attempt_budget_exhaustion(self) -> None:
        profile = golden_profile("mbedtls_poc_0020")
        first = payload_from_profile(profile)
        second = deepcopy(first)
        second["operation_proposals"][0]["semantic_role"] = "FINAL"
        request, _, _ = case_request(
            "mbedtls_poc_0020",
            binding_label="invalid",
            budgets=MatcherBudgets(max_binding_attempts=1),
        )
        provider = SequenceReplayProvider([first, second])
        result = run_matcher(with_provider(request, provider))
        self.assertEqual(MatcherRunOutcome.BUDGET_EXHAUSTED, result.outcome)
        self.assertEqual(1, len(result.trace.semantic_core["binding_attempts"]))

    def test_same_candidate_evidence_refresh_has_profile_lineage(self) -> None:
        eligible = golden_profile("mbedtls_poc_0020", "eligible")
        initial = golden_profile("mbedtls_poc_0020", "indeterminate")
        scope = case_request("mbedtls_poc_0020")[0].target_scope
        extra = EvidenceItem(
            evidence_ref="ENHANCEMENT_FIXTURE",
            source_type=EvidenceClass.FIXTURE,
            target_scope=scope,
            subject_refs=tuple(x["subject_ref"] for x in eligible["subjects"]),
            symbol_refs=(),
            artifact_ref="tests/transfer_signature/fixtures/synthetic_target_evidence.md",
            artifact_digest=synthetic_digest(),
            initial_epistemic_status="HYPOTHESIS",
            fact_payloads=tuple(deepcopy(eligible["facts"])),
        )
        request, _, _ = case_request(
            "mbedtls_poc_0020",
            profile_override=initial,
            payload=payload_from_profile(eligible),
            extra_evidence=(extra,),
            evidence_class=EvidenceClass.RAG_HIT,
        )
        result = run_matcher(request)
        profiles = result.trace.semantic_core["profile_records"]
        self.assertGreaterEqual(len(profiles), 2)
        self.assertTrue(any(x["derived_from_profile_ref"] for x in profiles))
        assignment_candidates = {
            x["candidate_ref"] for x in result.trace.semantic_core["eligibility_records"]
        }
        self.assertEqual(1, len(assignment_candidates))

    def test_default_path_has_zero_external_calls_and_no_verdict_fields(self) -> None:
        request, replay, backend = case_request("mbedtls_poc_0005")
        result = run_matcher(request)
        self.assertEqual(0, backend.network_call_count)
        self.assertEqual(2, replay.invocation_count)
        rendered = str(result.trace.semantic_core)
        self.assertNotIn("SATISFIED", rendered)
        self.assertNotIn("VIOLATED", rendered)
        self.assertNotIn("Contract UNKNOWN", rendered)

    def test_invalid_input_returns_matcher_input_outcome_not_verdict(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020")
        broken = deepcopy(request.contract)
        broken["schema_version"] = "invalid"
        result = run_matcher(replace(request, contract=broken))
        self.assertEqual(MatcherRunOutcome.INPUT_INVALID, result.outcome)
        self.assertIsNone(result.candidate_binding)
        self.assertEqual("INPUT_INVALID", result.trace.semantic_core["run_outcome"])


if __name__ == "__main__":
    unittest.main()
