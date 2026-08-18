"""Concrete, assignment-level observability feasibility."""

from __future__ import annotations

from typing import Any, Mapping

from matcher.model import (
    MatcherCandidate,
    ObservabilityRecord,
    ObservabilityStatus,
    semantic_digest,
)


def evaluate_concrete_observability(
    *,
    candidate: MatcherCandidate,
    proposal: Mapping[str, Any],
    profile: Mapping[str, Any],
    eligibility_evaluation: Mapping[str, Any],
    transfer_signature: Mapping[str, Any],
) -> ObservabilityRecord:
    proposal_ref = str(proposal["proposal_id"])
    profile_ref = f"target-profile:{profile['profile_id']}"
    eligibility_ref = (
        f"eligibility-evaluation:{eligibility_evaluation['signature_id']}:"
        f"{eligibility_evaluation['profile_id']}"
    )
    required = {
        str(item["parameters"]["observable_ref"])
        for item in transfer_signature.get("required_observability", [])
        if item.get("type") == "contract_observable_resolvable"
    }
    required_correlations = [
        item
        for item in transfer_signature.get("required_observability", [])
        if item.get("type") == "observable_set_correlatable"
    ]
    verified_channels = {
        str(fact["parameters"]["observable_ref"]): fact
        for fact in profile.get("facts", [])
        if fact.get("fact_type") == "observable_channel"
        and fact.get("epistemic_status") == "VERIFIED"
        and fact.get("assertion") == "TRUE"
    }
    verified_correlations = [
        fact
        for fact in profile.get("facts", [])
        if fact.get("fact_type") == "observable_correlation"
        and fact.get("epistemic_status") == "VERIFIED"
        and fact.get("assertion") == "TRUE"
    ]
    proposed = {
        str(item.get("source_ref")): item
        for item in proposal.get("observation_proposals", [])
    }
    assignments: list[dict[str, Any]] = []
    missing: list[str] = []
    incompatible: list[str] = []
    facts: set[str] = set()
    evidence: set[str] = set()
    for observable_ref in sorted(required):
        fact = verified_channels.get(observable_ref)
        assignment = proposed.get(observable_ref)
        if fact is None:
            missing.append(f"VERIFIED_OBSERVABLE_CHANNEL:{observable_ref}")
            continue
        if assignment is None:
            missing.append(f"CONCRETE_OBSERVATION_ASSIGNMENT:{observable_ref}")
            continue
        if assignment.get("target_ref") != fact.get("subject_ref"):
            incompatible.append(f"OBSERVATION_OUTLET_SUBJECT_MISMATCH:{observable_ref}")
            continue
        facts.add(str(fact["fact_id"]))
        evidence.update(str(x) for x in fact.get("evidence_refs", []))
        assignments.append(
            {
                "observable_ref": observable_ref,
                "subject_ref": fact["subject_ref"],
                "outlet_ref": assignment["target_ref"],
                "operation_ref": next(
                    (
                        ref
                        for ref in assignment.get("related_refs", [])
                        if str(ref).startswith("operation:")
                    ),
                    "PROCESS_END",
                ),
                "phase": fact["parameters"]["phase"],
                "semantic_role": fact["parameters"]["semantic_role"],
                "value_type": fact["parameters"]["value_type"],
            }
        )
    for constraint in required_correlations:
        params = constraint["parameters"]
        match = next(
            (
                fact
                for fact in verified_correlations
                if fact["parameters"]["correlation_scope"] == params["correlation_scope"]
                and set(fact["parameters"]["observable_refs"]) == set(params["observable_refs"])
            ),
            None,
        )
        if match is None:
            missing.append(
                f"VERIFIED_OBSERVABLE_CORRELATION:{constraint['constraint_id']}"
            )
        else:
            facts.add(str(match["fact_id"]))
            evidence.update(str(x) for x in match.get("evidence_refs", []))
            assignments.append(
                {
                    "correlation_ref": constraint["constraint_id"],
                    "correlation_scope": params["correlation_scope"],
                    "observable_refs": sorted(params["observable_refs"]),
                    "participant_refs": sorted(match["parameters"].get("participant_refs", [])),
                }
            )

    if incompatible:
        status = ObservabilityStatus.UNRESOLVABLE
        reasons = ("VERIFIED_CONCRETE_ASSIGNMENT_INCOMPATIBLE",)
    elif missing:
        status = ObservabilityStatus.INCOMPLETE
        reasons = ("CONCRETE_OBSERVABILITY_EVIDENCE_INCOMPLETE",)
    else:
        status = ObservabilityStatus.RESOLVABLE
        reasons = ("CONCRETE_OBSERVABILITY_RESOLVED",)
    semantic = {
        "candidate_ref": candidate.candidate_id,
        "proposal_ref": proposal_ref,
        "profile_ref": profile_ref,
        "eligibility_ref": eligibility_ref,
        "status": status.value,
        "assignments": assignments,
        "facts": sorted(facts),
        "evidence": sorted(evidence),
        "missing": sorted(missing),
        "incompatible": sorted(incompatible),
        "reasons": list(reasons),
    }
    return ObservabilityRecord(
        record_id="observability:" + semantic_digest(semantic),
        candidate_ref=candidate.candidate_id,
        proposal_ref=proposal_ref,
        profile_ref=profile_ref,
        eligibility_ref=eligibility_ref,
        status=status,
        observable_assignments=tuple(assignments),
        verified_fact_refs=tuple(sorted(facts)),
        evidence_refs=tuple(sorted(evidence)),
        missing_requirements=tuple(sorted(missing + incompatible)),
        reason_codes=reasons,
    )
