"""Canonical Contract-guided Matcher v0.1 orchestration."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from candidate_binding.canonical import candidate_binding_digest, validation_digest
from candidate_binding.construct import construct_candidate_binding
from candidate_binding.model import ValidationContext
from candidate_binding.registry import validate_with_registry
from contract_miner.schema import canonical_vc_bytes, validate_vc_or_raise
from matcher.knowledge import EvidenceClass, TargetKnowledgeBase
from matcher.model import (
    MatcherBudgets,
    MatcherCandidate,
    MatcherRunOutcome,
    MatcherTelemetry,
    ObservabilityStatus,
    TargetScope,
    semantic_digest,
)
from matcher.observability import evaluate_concrete_observability
from matcher.proposal import ProposalAttempt, ProposalOrchestrator
from matcher.query import build_recall_query
from matcher.rank import RankingInput, rank_attempts
from matcher.recall import assemble_candidate_surfaces, wide_recall
from matcher.resolve import DeterministicResolver, ProfileConflictError, ProfileRound
from matcher.trace import MatcherTrace, MatcherTraceBuilder
from transfer_signature.canonical import (
    canonical_evaluation_bytes,
    signature_digest,
    validate_signature_or_raise,
)
from transfer_signature.evaluate import evaluate_transfer_signature
from trigger_template_interface.canonical import manifest_digest
from trigger_template_interface.validate import validate_manifest_or_raise


@dataclass(frozen=True)
class MatcherRequest:
    contract: Mapping[str, Any]
    transfer_signature: Mapping[str, Any]
    template_manifest: Mapping[str, Any]
    target_scope: TargetScope
    knowledge: TargetKnowledgeBase
    proposal_orchestrator: ProposalOrchestrator
    repo_root: str | Path
    budgets: MatcherBudgets = MatcherBudgets()
    family_metadata: Mapping[str, Any] | None = None
    contract_artifact_ref: str = "matcher-input/contract.yaml"
    transfer_signature_artifact_ref: str = "matcher-input/transfer-signature.yaml"
    template_artifact_ref: str = "matcher-input/template-manifest.yaml"


@dataclass(frozen=True)
class MatcherResult:
    outcome: MatcherRunOutcome
    trace: MatcherTrace
    candidate_binding: Mapping[str, Any] | None
    candidate_binding_validation: Mapping[str, Any] | None
    reason_codes: tuple[str, ...]
    attempted_artifact_refs: tuple[str, ...]
    telemetry: MatcherTelemetry | None = None


@dataclass(frozen=True)
class _EligibleAttempt:
    candidate: MatcherCandidate
    proposal: Mapping[str, Any]
    profile_round: ProfileRound
    evaluation: Mapping[str, Any]
    observability: Any


def run_matcher(request: MatcherRequest) -> MatcherResult:
    """Return a Matcher outcome for both valid and failed orchestration."""

    try:
        validate_vc_or_raise(request.contract)
        validate_signature_or_raise(
            request.transfer_signature, repo_root=request.repo_root
        )
        validate_manifest_or_raise(request.template_manifest)
    except Exception as exc:
        return _terminal_failure_result(
            request,
            MatcherRunOutcome.INPUT_INVALID,
            ("MATCHER_INPUT_VALIDATION_FAILED", type(exc).__name__, str(exc)),
        )
    try:
        return _run_matcher_validated(request)
    except Exception as exc:
        return _terminal_failure_result(
            request,
            MatcherRunOutcome.INTERNAL_ERROR,
            ("MATCHER_INTERNAL_ERROR", type(exc).__name__, str(exc)),
        )


def _run_matcher_validated(request: MatcherRequest) -> MatcherResult:
    """Run without merge, execution, or Contract Verdict semantics."""

    validate_vc_or_raise(request.contract)
    validate_signature_or_raise(request.transfer_signature, repo_root=request.repo_root)
    validate_manifest_or_raise(request.template_manifest)
    contract_digest = hashlib.sha256(canonical_vc_bytes(request.contract)).hexdigest()
    ts_digest = signature_digest(request.transfer_signature, repo_root=request.repo_root)
    template_digest = manifest_digest(request.template_manifest)
    query = build_recall_query(
        request.contract,
        request.transfer_signature,
        request.template_manifest,
        family_metadata=request.family_metadata,
    )
    trace = MatcherTraceBuilder(
        source_references={
            "contract": {
                "artifact_ref": request.contract_artifact_ref,
                "artifact_digest": contract_digest,
                "semantic_ref": f"contract:{request.contract['contract_id']}",
            },
            "transfer_signature": {
                "artifact_ref": request.transfer_signature_artifact_ref,
                "artifact_digest": ts_digest,
                "semantic_ref": f"transfer-signature:{request.transfer_signature['signature_id']}",
            },
            "trigger_template": {
                "artifact_ref": request.template_artifact_ref,
                "artifact_digest": template_digest,
                "semantic_ref": request.template_manifest["trigger_template_ref"],
            },
        },
        target_scope=request.target_scope.to_dict(),
        recall_query_ref=query.query_id,
        recall_query_digest=query.digest(),
        retrieval_config={
            "backend": request.knowledge.backend_name,
            "max_recall_candidates": request.budgets.max_recall_candidates,
        },
    )
    recall = wide_recall(
        request.knowledge,
        query,
        request.target_scope,
        limit=request.budgets.max_recall_candidates,
    )
    trace.extend("retrieval_records", [item.to_dict() for item in recall.records])
    candidates, assemblies = assemble_candidate_surfaces(recall)
    trace.extend("assembly_records", [item.to_dict() for item in assemblies])
    trace.extend(
        "candidate_records",
        [
            {
                **candidate.semantic_summary(),
                "stage_status": candidate.stage_status.value,
                "evidence_refs": list(candidate.evidence_refs),
            }
            for candidate in candidates
        ],
    )

    resolver = DeterministicResolver(
        request.knowledge, repo_root=request.repo_root
    )
    eligible_attempts: list[_EligibleAttempt] = []
    provider_attempted = 0
    provider_succeeded = 0
    ineligible_count = 0
    evidence_gap = False
    budget_exhausted = recall.budget_exhausted
    attempted_refs: set[str] = {query.query_id}
    source_references = [
        {"artifact_ref": request.contract_artifact_ref, "artifact_digest": contract_digest},
        {"artifact_ref": request.transfer_signature_artifact_ref, "artifact_digest": ts_digest},
        {"artifact_ref": request.template_artifact_ref, "artifact_digest": template_digest},
    ]

    for base_candidate in candidates:
        candidate_evidence = [
            item
            for ref in base_candidate.evidence_refs
            if (item := request.knowledge.get_evidence(ref)) is not None
        ]
        seen_proposals: set[tuple[str, str]] = set()
        for attempt_number in range(1, request.budgets.max_proposals_per_candidate + 1):
            provider_attempted += 1
            proposal_attempt = request.proposal_orchestrator.propose(
                candidate=base_candidate,
                contract_summary=_contract_summary(request.contract),
                transfer_signature_summary=_signature_summary(request.transfer_signature),
                template_summary=_template_summary(request.template_manifest),
                evidence=candidate_evidence,
                attempt_number=attempt_number,
                source_references=source_references,
            )
            trace.add("provider_attempts", proposal_attempt.to_trace_dict())
            attempted_refs.add(proposal_attempt.attempt_id)
            if proposal_attempt.proposal is None:
                trace.add(
                    "rejection_records",
                    {
                        "candidate_ref": base_candidate.candidate_id,
                        "stage": "PROPOSAL_UNAVAILABLE",
                        "reason_codes": [
                            proposal_attempt.invocation_status,
                            proposal_attempt.reason_code,
                        ],
                    },
                )
                continue
            provider_succeeded += 1
            proposal = proposal_attempt.proposal
            proposal_key = (str(proposal["proposal_id"]), str(proposal_attempt.proposal_digest))
            trace.add(
                "proposal_records",
                {
                    "proposal_ref": proposal["proposal_id"],
                    "proposal_digest": proposal_attempt.proposal_digest,
                    "candidate_ref": base_candidate.candidate_id,
                    "epistemic_status": proposal["epistemic_status"],
                },
            )
            attempted_refs.add(str(proposal["proposal_id"]))
            if proposal_key in seen_proposals:
                continue
            seen_proposals.add(proposal_key)
            candidate = _candidate_for_assignment(base_candidate, proposal)
            trace.add(
                "candidate_records",
                {
                    **candidate.semantic_summary(),
                    "derived_from_candidate_ref": base_candidate.candidate_id,
                    "proposal_ref": proposal["proposal_id"],
                    "stage_status": "PROPOSED",
                },
            )
            try:
                profile_round = resolver.resolve(
                    candidate=candidate,
                    proposal=proposal,
                    round_index=0,
                )
            except ProfileConflictError:
                trace.add(
                    "rejection_records",
                    {
                        "candidate_ref": candidate.candidate_id,
                        "proposal_ref": proposal["proposal_id"],
                        "stage": "FACT_RESOLUTION",
                        "reason_codes": ["PROFILE_VERIFIED_FACT_CONFLICT"],
                    },
                )
                continue
            except ValueError as exc:
                evidence_gap = True
                trace.add(
                    "rejection_records",
                    {
                        "candidate_ref": candidate.candidate_id,
                        "proposal_ref": proposal["proposal_id"],
                        "stage": "FACT_RESOLUTION",
                        "reason_codes": [str(exc)],
                    },
                )
                continue

            evaluation = None
            for round_index in range(0, request.budgets.max_evidence_rounds + 1):
                _trace_profile_round(trace, profile_round)
                evaluation = evaluate_transfer_signature(
                    request.transfer_signature,
                    profile_round.profile,
                    request.contract,
                    repo_root=request.repo_root,
                )
                evaluation_digest = hashlib.sha256(
                    canonical_evaluation_bytes(evaluation)
                ).hexdigest()
                eligibility_ref = (
                    f"eligibility-evaluation:{evaluation['signature_id']}:"
                    f"{evaluation['profile_id']}"
                )
                trace.add(
                    "eligibility_records",
                    {
                        "eligibility_ref": eligibility_ref,
                        "eligibility_digest": evaluation_digest,
                        "candidate_ref": candidate.candidate_id,
                        "proposal_ref": proposal["proposal_id"],
                        "profile_ref": profile_round.profile_ref,
                        "eligibility": evaluation["eligibility"],
                        "reason_codes": evaluation["reason_codes"],
                    },
                )
                attempted_refs.add(eligibility_ref)
                if evaluation["eligibility"] != "INDETERMINATE":
                    break
                evidence_gap = True
                if round_index >= request.budgets.max_evidence_rounds:
                    budget_exhausted = True
                    break
                extra = _enhancement_evidence(
                    request.knowledge,
                    candidate,
                    excluded={
                        ref
                        for item in profile_round.profile.get("evidence", [])
                        for ref in [str(item["evidence_id"])]
                    },
                )
                if not extra:
                    break
                profile_round = resolver.resolve(
                    candidate=candidate,
                    proposal=proposal,
                    round_index=round_index + 1,
                    previous=profile_round,
                    additional_evidence_refs=extra,
                )

            assert evaluation is not None
            if evaluation["eligibility"] == "INELIGIBLE":
                ineligible_count += 1
                trace.add(
                    "rejection_records",
                    {
                        "candidate_ref": candidate.candidate_id,
                        "proposal_ref": proposal["proposal_id"],
                        "stage": "TS_HARD_FILTER",
                        "reason_codes": evaluation["reason_codes"],
                    },
                )
                continue
            if evaluation["eligibility"] == "INDETERMINATE":
                continue

            observability = evaluate_concrete_observability(
                candidate=candidate,
                proposal=proposal,
                profile=profile_round.profile,
                eligibility_evaluation=evaluation,
                transfer_signature=request.transfer_signature,
            )
            trace.add("observability_records", observability.to_dict())
            attempted_refs.add(observability.record_id)
            if observability.status is ObservabilityStatus.INCOMPLETE:
                evidence_gap = True
                trace.add(
                    "rejection_records",
                    {
                        "candidate_ref": candidate.candidate_id,
                        "proposal_ref": proposal["proposal_id"],
                        "stage": "CONCRETE_OBSERVABILITY",
                        "reason_codes": list(observability.reason_codes),
                        "missing_requirements": list(observability.missing_requirements),
                    },
                )
                continue
            if observability.status is ObservabilityStatus.UNRESOLVABLE:
                trace.add(
                    "rejection_records",
                    {
                        "candidate_ref": candidate.candidate_id,
                        "proposal_ref": proposal["proposal_id"],
                        "stage": "CONCRETE_OBSERVABILITY",
                        "reason_codes": list(observability.reason_codes),
                    },
                )
                continue
            eligible_attempts.append(
                _EligibleAttempt(candidate, proposal, profile_round, evaluation, observability)
            )

    ranking_inputs = [
        RankingInput(
            candidate=item.candidate,
            proposal_ref=str(item.proposal["proposal_id"]),
            profile=item.profile_round.profile,
            eligibility_evaluation=item.evaluation,
            observability=item.observability,
            template_manifest=request.template_manifest,
        )
        for item in eligible_attempts
    ]
    rankings = rank_attempts(ranking_inputs) if ranking_inputs else ()
    trace.extend("ranking_records", [item.to_dict() for item in rankings])
    attempt_by_key = {
        (item.candidate.candidate_id, str(item.proposal["proposal_id"])): item
        for item in eligible_attempts
    }
    binding_attempt_count = 0
    validation_incomplete = False
    for ranking in rankings:
        if binding_attempt_count >= request.budgets.max_binding_attempts:
            budget_exhausted = True
            break
        binding_attempt_count += 1
        item = attempt_by_key[(ranking.candidate_ref, ranking.proposal_ref)]
        mappings = item.candidate.surface_composition.get("_binding_mappings")
        if not isinstance(mappings, Mapping):
            validation_incomplete = True
            trace.add(
                "rejection_records",
                {
                    "candidate_ref": item.candidate.candidate_id,
                    "proposal_ref": item.proposal["proposal_id"],
                    "stage": "CANDIDATE_BINDING_CONSTRUCTION",
                    "reason_codes": ["EXPLICIT_BINDING_MAPPINGS_INCOMPLETE"],
                },
            )
            continue
        try:
            binding = construct_candidate_binding(
                contract=request.contract,
                transfer_signature=request.transfer_signature,
                template_manifest=request.template_manifest,
                target_profile=item.profile_round.profile,
                eligibility_evaluation=item.evaluation,
                mappings=mappings,
                producer="matcher.orchestrate",
                version="v0.1",
            )
        except Exception as exc:
            trace.add(
                "rejection_records",
                {
                    "candidate_ref": item.candidate.candidate_id,
                    "proposal_ref": item.proposal["proposal_id"],
                    "stage": "CANDIDATE_BINDING_CONSTRUCTION",
                    "reason_codes": [type(exc).__name__, str(exc)],
                },
            )
            continue
        binding_digest_value = candidate_binding_digest(binding)
        binding_ref = str(binding["binding_id"])
        trace.add(
            "binding_attempts",
            {
                "binding_ref": binding_ref,
                "binding_digest": binding_digest_value,
                "candidate_ref": item.candidate.candidate_id,
                "proposal_ref": item.proposal["proposal_id"],
                "ranking_ref": ranking.ranking_id,
            },
        )
        attempted_refs.add(binding_ref)
        context = ValidationContext(
            request.contract,
            request.transfer_signature,
            request.template_manifest,
            item.profile_round.profile,
            item.evaluation,
        )
        validation = validate_with_registry(binding, context)
        validation_digest_value = validation_digest(validation)
        validation_ref = str(validation["validation_id"])
        trace.add(
            "validation_records",
            {
                "validation_ref": validation_ref,
                "validation_digest": validation_digest_value,
                "binding_ref": binding_ref,
                "status": validation["status"],
                "reason_codes": validation["reason_codes"],
            },
        )
        attempted_refs.add(validation_ref)
        if validation["status"] == "VALID":
            final_trace = trace.finish(
                outcome=MatcherRunOutcome.MATCH_FOUND.value,
                reason_codes=("VALID_CANDIDATE_BINDING_SELECTED",),
                selected_binding_ref=binding_ref,
                selected_binding_digest=binding_digest_value,
                selected_validation_ref=validation_ref,
                selected_validation_digest=validation_digest_value,
            )
            return MatcherResult(
                MatcherRunOutcome.MATCH_FOUND,
                final_trace,
                binding,
                validation,
                ("VALID_CANDIDATE_BINDING_SELECTED",),
                tuple(sorted(attempted_refs)),
            )
        if validation["status"] == "INCOMPLETE":
            validation_incomplete = True
        trace.add(
            "rejection_records",
            {
                "candidate_ref": item.candidate.candidate_id,
                "proposal_ref": item.proposal["proposal_id"],
                "binding_ref": binding_ref,
                "stage": "CANDIDATE_BINDING_VALIDATION",
                "reason_codes": validation["reason_codes"],
                "whole_binding_rejected": True,
            },
        )

    if budget_exhausted:
        outcome = MatcherRunOutcome.BUDGET_EXHAUSTED
        reasons = ("MATCHER_RUNTIME_BUDGET_EXHAUSTED",)
    elif provider_attempted and not provider_succeeded:
        outcome = MatcherRunOutcome.PROVIDER_BLOCKED
        reasons = ("ALL_PROPOSAL_ATTEMPTS_UNAVAILABLE",)
    elif validation_incomplete or evidence_gap:
        outcome = MatcherRunOutcome.EVIDENCE_INSUFFICIENT
        reasons = ("DETERMINISTIC_EVIDENCE_INSUFFICIENT",)
    elif eligible_attempts and binding_attempt_count:
        outcome = MatcherRunOutcome.CANDIDATES_EXHAUSTED
        reasons = ("NO_VALID_COMPLETE_BINDING",)
    elif candidates and ineligible_count:
        outcome = MatcherRunOutcome.NO_ELIGIBLE_CANDIDATE
        reasons = ("ALL_EVALUATED_ASSIGNMENTS_INELIGIBLE",)
    else:
        outcome = MatcherRunOutcome.CANDIDATES_EXHAUSTED
        reasons = ("NO_COMPLETE_MATCHER_ATTEMPT_AVAILABLE",)
    final_trace = trace.finish(outcome=outcome.value, reason_codes=reasons)
    return MatcherResult(
        outcome,
        final_trace,
        None,
        None,
        reasons,
        tuple(sorted(attempted_refs)),
    )


def _candidate_for_assignment(
    candidate: MatcherCandidate, proposal: Mapping[str, Any]
) -> MatcherCandidate:
    assignments = []
    for list_name in (
        "role_proposals", "subject_proposals", "operation_proposals",
        "input_proposals", "intervention_proposals",
        "state_continuity_proposals", "observation_proposals",
    ):
        for item in proposal.get(list_name, []):
            assignments.append(
                {
                    "proposal_kind": list_name,
                    "source_ref": item["source_ref"],
                    "target_ref": item["target_ref"],
                    "semantic_role": item["semantic_role"],
                    "related_refs": sorted(item["related_refs"]),
                }
            )
    composition = deepcopy(dict(candidate.surface_composition))
    composition["assignments"] = sorted(
        assignments,
        key=lambda item: (
            item["proposal_kind"], item["source_ref"], item["target_ref"], item["semantic_role"]
        ),
    )
    return MatcherCandidate.create(
        target_scope=candidate.target_scope,
        subject_refs=candidate.subject_refs,
        symbol_refs=candidate.symbol_refs,
        surface_composition=composition,
        surface_relations=candidate.surface_relations,
        evidence_refs=candidate.evidence_refs,
        retrieval_records=candidate.retrieval_records,
    )


def _terminal_failure_result(
    request: MatcherRequest,
    outcome: MatcherRunOutcome,
    reasons: Sequence[str],
) -> MatcherResult:
    source = {
        "contract": {
            "artifact_ref": request.contract_artifact_ref,
            "artifact_digest": semantic_digest(request.contract),
            "semantic_ref": str(request.contract.get("contract_id", "unavailable")),
        },
        "transfer_signature": {
            "artifact_ref": request.transfer_signature_artifact_ref,
            "artifact_digest": semantic_digest(request.transfer_signature),
            "semantic_ref": str(request.transfer_signature.get("signature_id", "unavailable")),
        },
        "trigger_template": {
            "artifact_ref": request.template_artifact_ref,
            "artifact_digest": semantic_digest(request.template_manifest),
            "semantic_ref": str(request.template_manifest.get("trigger_template_ref", "unavailable")),
        },
    }
    builder = MatcherTraceBuilder(
        source_references=source,
        target_scope=request.target_scope.to_dict(),
        recall_query_ref="recall-query:unavailable",
        recall_query_digest="0" * 64,
        retrieval_config={"backend": request.knowledge.backend_name},
    )
    trace = builder.finish(outcome=outcome.value, reason_codes=reasons)
    return MatcherResult(
        outcome=outcome,
        trace=trace,
        candidate_binding=None,
        candidate_binding_validation=None,
        reason_codes=tuple(sorted(dict.fromkeys(reasons))),
        attempted_artifact_refs=(),
    )


def _trace_profile_round(trace: MatcherTraceBuilder, item: ProfileRound) -> None:
    trace.extend(
        "fact_resolution_records",
        [record.to_dict() for record in item.resolution_records],
    )
    trace.add(
        "profile_records",
        {
            "profile_ref": item.profile_ref,
            "profile_digest": item.profile_digest,
            "round_index": item.round_index,
            "derived_from_profile_ref": item.derived_from_profile_ref,
        },
    )


def _enhancement_evidence(
    knowledge: TargetKnowledgeBase,
    candidate: MatcherCandidate,
    *,
    excluded: set[str],
) -> tuple[str, ...]:
    trusted = (
        EvidenceClass.SOURCE,
        EvidenceClass.HEADER,
        EvidenceClass.OFFICIAL_DOCUMENT,
        EvidenceClass.STATIC_INSPECTION,
        EvidenceClass.TEST_ARTIFACT,
        EvidenceClass.FIXTURE,
    )
    found = set()
    for subject_ref in candidate.subject_refs:
        found.update(
            item.evidence_ref
            for item in knowledge.find_evidence(
                target_scope=candidate.target_scope,
                subject_ref=subject_ref,
                source_types=trusted,
            )
        )
    return tuple(sorted(found - excluded))


def _contract_summary(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "contract_id": contract["contract_id"],
        "contract_family": contract["contract_family"],
        "objects": deepcopy(contract["context"]["objects"]),
        "preconditions": deepcopy(contract["context"]["preconditions"]),
        "interventions": deepcopy(contract["intervention"]["actions"]),
        "steps": deepcopy(contract["execution"]["steps"]),
        "observables": deepcopy(contract["observable_evidence"]["observables"]),
    }


def _signature_summary(signature: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "signature_id": signature["signature_id"],
        "required_capabilities": deepcopy(signature["required_capabilities"]),
        "excluded_semantics": deepcopy(signature["excluded_semantics"]),
        "required_observability": deepcopy(signature["required_observability"]),
    }


def _template_summary(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "trigger_template_ref": manifest["trigger_template_ref"],
        "slots": [
            {
                "slot_ref": slot["slot_ref"],
                "slot_kind": slot["slot_kind"],
                "semantic_role_hint": slot.get("semantic_role_hint", ""),
                "required": slot["required"],
                "multiplicity": slot["multiplicity"],
            }
            for slot in manifest["slots"]
        ],
    }
