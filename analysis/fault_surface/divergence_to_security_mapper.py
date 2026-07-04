"""Map execution divergence to security relevance."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SECURITY_RELEVANT_KINDS = {
    "error_path_divergence",
    "transition_divergence",
    "silent_failure",
    "state_divergence",
    "execution_path_mismatch",
}


def map_divergence_to_security(
    oracle_output: Mapping[str, Any],
    semantic_model: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify divergence as harmless, behavioral, or security-relevant."""

    report = _report(oracle_output)
    observations = _observations(report)
    active_dimensions = set(semantic_model.get("active_dimensions", []))
    mapped = []
    for observation in observations:
        kind = str(observation.get("kind", "unknown"))
        relevance = _relevance(kind, active_dimensions, report)
        mapped.append(
            {
                "source_kind": kind,
                "security_relevance": relevance,
                "score": _score_for_relevance(relevance),
                "active_semantic_dimensions": sorted(active_dimensions),
                "source_observation": observation,
            }
        )
    if not mapped:
        relevance = _score_only_relevance(report, active_dimensions)
        mapped.append(
            {
                "source_kind": "score_only_divergence",
                "security_relevance": relevance,
                "score": _score_for_relevance(relevance),
                "active_semantic_dimensions": sorted(active_dimensions),
                "source_observation": {
                    "divergence_score": _score(report, "divergence_score"),
                    "mismatch_score": _score(report, "mismatch_score"),
                    "instability_score": _score(report, "instability_score"),
                },
            }
        )
    total = min(100, sum(item["score"] for item in mapped))
    return {
        "schema": "divergence_to_security_mapping_v1",
        "mapped_observations": mapped,
        "security_divergence_score": total,
        "mapping_status": "ok",
    }


def _report(oracle_output: Mapping[str, Any]) -> Mapping[str, Any]:
    report = oracle_output.get("cross_library_divergence_report") or oracle_output.get("divergence_report")
    return report if isinstance(report, Mapping) else oracle_output


def _observations(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = report.get("observations")
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    return []


def _relevance(kind: str, active_dimensions: set[str], report: Mapping[str, Any]) -> str:
    if kind not in SECURITY_RELEVANT_KINDS:
        return "behavioral_divergence"
    if not active_dimensions:
        return "behavioral_divergence"
    if _score(report, "divergence_score") >= 50 or _score(report, "instability_score") >= 50:
        return "security_relevant_divergence"
    return "behavioral_divergence"


def _score_only_relevance(report: Mapping[str, Any], active_dimensions: set[str]) -> str:
    if _score(report, "divergence_score") <= 0:
        return "harmless_divergence"
    if active_dimensions and (_score(report, "mismatch_score") >= 50 or _score(report, "instability_score") >= 50):
        return "security_relevant_divergence"
    return "behavioral_divergence"


def _score_for_relevance(relevance: str) -> int:
    if relevance == "security_relevant_divergence":
        return 40
    if relevance == "behavioral_divergence":
        return 15
    return 0


def _score(report: Mapping[str, Any], key: str) -> int:
    try:
        return int(report.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0
