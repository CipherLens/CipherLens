"""Validation layer for security-relevant cross-library inconsistencies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from analysis.fault_surface.exploitability_scorer import ExploitabilityScorer
from analysis.fault_surface.security_reproduction_runner import SecurityReproductionRunner
from analysis.fault_surface.verdict_engine import VerdictEngine


IMPACT_WEIGHTS = {
    "signature_validity_equivalence_break": 35,
    "key_usage_semantic_consistency_break": 30,
    "lifecycle_security_guarantee_inconsistency": 25,
    "cross_library_security_decision_mismatch": 10,
}


class CVECandidateValidator:
    """Run read-only validation over an existing security candidate."""

    schema = "cve_candidate_validation_v1"

    def validate(
        self,
        seed_context: Mapping[str, Any],
        security_candidate: Mapping[str, Any],
    ) -> dict[str, Any]:
        reproduction = SecurityReproductionRunner().replay(seed_context, security_candidate)
        security_impact = _security_impact_score(security_candidate, reproduction)
        exploitability = _exploitability_score(seed_context, security_candidate, reproduction)
        verdict = VerdictEngine().decide(reproduction, security_impact, exploitability)
        validation_result = {
            "schema": "validation_result_v1",
            "stage_a_reproduction_stability": reproduction["reproducibility_matrix"].get("reproducibility"),
            "stage_b_security_impact_score": security_impact.get("security_impact_score"),
            "stage_c_exploitability_score": exploitability.get("exploitability_score"),
            "final_verdict": verdict.get("final_verdict"),
            "mutation_executed": False,
            "pressure_injection_executed": False,
            "trigger_modification_executed": False,
            "runtime_executed_by_this_layer": False,
            "oracle_reevaluation_mode": "read_only_existing_trace",
            "candidate_queue_written": False,
            "claim_level": "validation_layer_result_not_disclosure_claim",
        }
        return {
            "schema": self.schema,
            "validation_result": validation_result,
            "reproducibility_matrix": reproduction.get("reproducibility_matrix", {}),
            "execution_trace_diff": reproduction.get("execution_trace_diff", {}),
            "security_impact_score": security_impact,
            "exploitability_score": exploitability,
            "final_verdict": verdict,
            "report_payloads": {
                "validation_result.yaml": validation_result,
                "reproducibility_matrix.yaml": reproduction.get("reproducibility_matrix", {}),
                "execution_trace_diff.yaml": reproduction.get("execution_trace_diff", {}),
                "security_impact_score.yaml": security_impact,
                "exploitability_score.yaml": exploitability,
                "final_verdict.yaml": verdict,
            },
            "candidate_queue_written": False,
        }


def validate(seed_context: Mapping[str, Any], security_candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Run read-only validation over an existing security candidate."""

    return CVECandidateValidator().validate(seed_context, security_candidate)


def _security_impact_score(
    security_candidate: Mapping[str, Any],
    reproduction: Mapping[str, Any],
) -> dict[str, Any]:
    flags = _collect_flags(security_candidate)
    score = sum(IMPACT_WEIGHTS.get(flag, 0) for flag in flags)
    trace_diff = reproduction.get("execution_trace_diff", {})
    if isinstance(trace_diff, Mapping) and trace_diff.get("has_output_difference"):
        score += IMPACT_WEIGHTS["cross_library_security_decision_mismatch"]
    score = min(100, score)
    return {
        "schema": "security_impact_score_v1",
        "security_impact_score": score,
        "threshold": 60,
        "security_impact_exists": score >= 60,
        "validated_dimensions": flags,
        "cross_library_mismatch_affects_security_decision": bool(
            isinstance(trace_diff, Mapping) and trace_diff.get("has_output_difference")
        ),
        "candidate_queue_written": False,
    }


def _exploitability_score(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
    reproduction: Mapping[str, Any],
) -> dict[str, Any]:
    base = ExploitabilityScorer().evaluate(_candidate_with_targets(seed_context, security_candidate))
    matrix = reproduction.get("reproducibility_matrix", {})
    stable = isinstance(matrix, Mapping) and matrix.get("reproducibility") == "stable"
    attacker_influence = _attacker_influence(seed_context, security_candidate)
    score = int(base.get("exploitability_score", 0) or 0)
    if not stable:
        score = min(score, 20)
    if not attacker_influence:
        score = min(score, 40)
    out = dict(base)
    out["schema"] = "exploitability_score_v2"
    out["exploitability_score"] = score
    out["exploitability_exists"] = score > 0 and stable and attacker_influence
    out["attacker_influence_evidence"] = attacker_influence
    out["reproducibility_required"] = "stable"
    out["candidate_queue_written"] = False
    return out


def _candidate_with_targets(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    out = dict(security_candidate)
    out.setdefault("target_libraries", seed_context.get("target_libraries") or seed_context.get("targets") or [])
    return out


def _collect_flags(security_candidate: Mapping[str, Any]) -> list[str]:
    flags = security_candidate.get("security_violation_flags")
    if not flags and isinstance(security_candidate.get("security_violation_summary"), Mapping):
        flags = security_candidate["security_violation_summary"].get("security_violation_flags")
    if not isinstance(flags, list):
        return []
    return [str(flag) for flag in flags]


def _attacker_influence(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
) -> bool:
    for source in (seed_context, security_candidate):
        for key in (
            "attacker_controlled_input",
            "untrusted_input",
            "public_api_surface",
            "trust_boundary_crossed",
            "verification_bypass_possible",
        ):
            if bool(source.get(key)):
                return True
    return False
