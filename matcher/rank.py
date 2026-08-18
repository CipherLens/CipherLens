"""Post-gate deterministic evidence ranking."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping, Sequence

from matcher.model import MatcherCandidate, ObservabilityRecord, RankingRecord, semantic_digest


@dataclass(frozen=True)
class RankingInput:
    candidate: MatcherCandidate
    proposal_ref: str
    profile: Mapping[str, Any]
    eligibility_evaluation: Mapping[str, Any]
    observability: ObservabilityRecord
    template_manifest: Mapping[str, Any]


FEATURE_NAMES = (
    "verified_required_fact_coverage",
    "required_template_slot_coverage",
    "concrete_observation_coverage",
    "continuity_correlation_completeness",
    "source_evidence_quality",
    "signature_type_certainty",
    "resolved_optional_fields",
    "inverse_adaptation_complexity",
    "legacy_affinity",
)


def rank_attempts(inputs: Sequence[RankingInput]) -> tuple[RankingRecord, ...]:
    prepared: list[RankingRecord] = []
    for item in inputs:
        if item.eligibility_evaluation.get("eligibility") != "ELIGIBLE":
            raise ValueError("RANKING_REQUIRES_ELIGIBLE")
        if item.observability.status.value != "RESOLVABLE":
            raise ValueError("RANKING_REQUIRES_RESOLVABLE")
        breakdown = _features(item)
        vector = tuple(breakdown[name] for name in FEATURE_NAMES)
        semantic = {
            "candidate_ref": item.candidate.candidate_id,
            "proposal_ref": item.proposal_ref,
            "feature_vector": list(vector),
            "feature_breakdown": breakdown,
        }
        prepared.append(
            RankingRecord(
                ranking_id="ranking:" + semantic_digest(semantic),
                candidate_ref=item.candidate.candidate_id,
                proposal_ref=item.proposal_ref,
                feature_vector=vector,
                feature_breakdown=breakdown,
            )
        )
    prepared.sort(key=lambda item: (tuple(-x for x in item.feature_vector), item.candidate_ref, item.proposal_ref))
    return tuple(replace(item, position=index) for index, item in enumerate(prepared, 1))


def _features(item: RankingInput) -> dict[str, int]:
    facts = list(item.profile.get("facts", []))
    verified = [fact for fact in facts if fact.get("epistemic_status") == "VERIFIED"]
    results = item.eligibility_evaluation.get("constraint_results", [])
    required_count = sum(
        1
        for result in results
        if result.get("constraint_class") in {"required_capability", "required_observability"}
    )
    required_match = sum(
        1
        for result in results
        if result.get("constraint_class") in {"required_capability", "required_observability"}
        and result.get("result") == "MATCH"
    )
    required_slots = [x for x in item.template_manifest.get("slots", []) if x.get("required")]
    mapping = item.candidate.surface_composition.get("_binding_mappings", {})
    used_slots = {
        value
        for key in (
            "subject_bindings", "operation_bindings", "input_bindings",
            "intervention_bindings", "observation_bindings",
        )
        for record in mapping.get(key, [])
        for field, value in record.items()
        if field in {
            "template_call_slot_ref", "template_input_slot_ref",
            "template_intervention_ref", "template_observation_ref",
        }
    }
    used_slots.update(
        ref
        for record in mapping.get("subject_bindings", [])
        for ref in record.get("template_object_slot_refs", [])
    )
    slot_coverage = _percent(
        sum(1 for slot in required_slots if slot.get("slot_ref") in used_slots),
        len(required_slots),
    )
    observation_count = sum(1 for x in item.observability.observable_assignments if "observable_ref" in x)
    expected_observation_count = max(1, len({x.get("observable_ref") for x in item.observability.observable_assignments if x.get("observable_ref")}))
    continuity = any(fact.get("fact_type") == "execution_shape" for fact in verified)
    correlation = any(fact.get("fact_type") == "observable_correlation" for fact in verified)
    high_quality = sum(
        1
        for evidence in item.profile.get("evidence", [])
        if evidence.get("kind") in {"source", "official_doc", "test", "test_fixture"}
    )
    signature_certainty = sum(
        1 for fact in verified if fact.get("fact_type") in {"operation_role", "object_role"}
    )
    unresolved_optional = int(item.candidate.surface_composition.get("unresolved_optional_fields", 0) or 0)
    complexity = int(item.candidate.surface_composition.get("adaptation_complexity", 0) or 0)
    legacy_affinity = int(item.candidate.surface_composition.get("legacy_affinity", 0) or 0)
    return {
        "verified_required_fact_coverage": _percent(required_match, required_count),
        "required_template_slot_coverage": slot_coverage,
        "concrete_observation_coverage": _percent(observation_count, expected_observation_count),
        "continuity_correlation_completeness": 100 if continuity and correlation else 50 if continuity or correlation else 0,
        "source_evidence_quality": min(100, high_quality * 25),
        "signature_type_certainty": min(100, signature_certainty * 20),
        "resolved_optional_fields": max(0, 100 - unresolved_optional * 10),
        "inverse_adaptation_complexity": max(0, 100 - complexity * 10),
        "legacy_affinity": max(0, min(100, legacy_affinity)),
    }


def _percent(numerator: int, denominator: int) -> int:
    return 100 if denominator == 0 else (100 * numerator) // denominator
