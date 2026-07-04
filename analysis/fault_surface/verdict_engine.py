"""Final validation verdict rules for fault-surface security observations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


DEFAULT_SECURITY_IMPACT_THRESHOLD = 60


class VerdictEngine:
    """Apply conservative validation rules over reproduction and scores."""

    schema = "verdict_engine_v1"

    def decide(
        self,
        reproduction: Mapping[str, Any],
        security_impact_score: Mapping[str, Any],
        exploitability_score: Mapping[str, Any],
        *,
        security_impact_threshold: int = DEFAULT_SECURITY_IMPACT_THRESHOLD,
    ) -> dict[str, Any]:
        matrix = reproduction.get("reproducibility_matrix", {})
        stable = isinstance(matrix, Mapping) and matrix.get("reproducibility") == "stable"
        impact = int(security_impact_score.get("security_impact_score", 0) or 0)
        exploitability = int(exploitability_score.get("exploitability_score", 0) or 0)
        if stable and impact >= security_impact_threshold and exploitability > 0:
            verdict = "CVE_CONFIRMED_CANDIDATE"
            reason = "stable_replay_security_impact_and_positive_exploitability"
        else:
            verdict = "NON_EXPLOITABLE_SECURITY_INCONSISTENCY"
            reason = _demotion_reason(stable, impact, exploitability, security_impact_threshold)
        return {
            "schema": "final_verdict_v1",
            "final_verdict": verdict,
            "reproducibility": matrix.get("reproducibility") if isinstance(matrix, Mapping) else "unknown",
            "security_impact_score": impact,
            "security_impact_threshold": security_impact_threshold,
            "exploitability_score": exploitability,
            "reason": reason,
            "candidate_queue_written": False,
            "claim_level": "validation_layer_verdict_requires_external_review",
        }


def decide(
    reproduction: Mapping[str, Any],
    security_impact_score: Mapping[str, Any],
    exploitability_score: Mapping[str, Any],
) -> dict[str, Any]:
    """Decide final validation label."""

    return VerdictEngine().decide(reproduction, security_impact_score, exploitability_score)


def _demotion_reason(stable: bool, impact: int, exploitability: int, threshold: int) -> str:
    if not stable:
        return "reproduction_not_stable"
    if impact < threshold:
        return "security_impact_below_threshold"
    if exploitability <= 0:
        return "exploitability_not_demonstrated"
    return "validation_rule_not_satisfied"
