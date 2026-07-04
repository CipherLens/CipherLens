"""Security ground-truth validation for cross-library divergence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from analysis.fault_surface.crypto_semantic_model import build_crypto_semantic_model
from analysis.fault_surface.divergence_to_security_mapper import map_divergence_to_security


SECURITY_FLAG_BY_DIMENSION = {
    "key_lifecycle": "lifecycle_security_guarantee_inconsistency",
    "sign_verify_consistency": "signature_validity_equivalence_break",
    "encryption_correctness": "encryption_decryption_semantic_equivalence_break",
    "key_usage_semantics": "key_usage_semantic_consistency_break",
}


class SecurityGroundTruthValidator:
    """Validate whether execution divergence is security-relevant."""

    schema = "security_ground_truth_validator_v1"

    def evaluate(self, seed_context: Mapping[str, Any], oracle_output: Mapping[str, Any]) -> dict[str, Any]:
        semantic_model = build_crypto_semantic_model(seed_context, oracle_output)
        mapping = map_divergence_to_security(oracle_output, semantic_model)
        flags = _security_flags(semantic_model, mapping)
        breakpoints = _crypto_semantic_breakpoints(semantic_model, mapping, flags)
        report = {
            "schema": "security_divergence_report_v1",
            "security_divergence_score": mapping.get("security_divergence_score", 0),
            "security_violation_flags": flags,
            "security_violation_flag_count": len(flags),
            "decision": "security_relevant_inconsistency_candidate" if flags else "no_security_candidate",
            "candidate_queue_written": False,
            "claim_level": "security_relevance_validation_only",
        }
        summary = {
            "schema": "security_violation_summary_v1",
            "has_security_relevant_inconsistency": bool(flags),
            "security_violation_flags": flags,
            "candidate_queue_written": False,
            "next_action": "route_to_existing_oracle_campaign_triage" if flags else "keep_as_observation",
        }
        return {
            "schema": self.schema,
            "security_divergence_report": report,
            "crypto_semantic_breakpoints": breakpoints,
            "security_violation_summary": summary,
            "crypto_semantic_model": semantic_model,
            "divergence_security_mapping": mapping,
            "security_divergence_score": report["security_divergence_score"],
            "security_violation_flags": flags,
            "candidate_recommendation": report["decision"],
            "candidate_queue_written": False,
            "report_payloads": {
                "security_divergence_report.yaml": report,
                "crypto_semantic_breakpoints.yaml": breakpoints,
                "security_violation_summary.yaml": summary,
            },
        }


def evaluate(seed_context: Mapping[str, Any], oracle_output: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate security relevance for divergence output."""

    return SecurityGroundTruthValidator().evaluate(seed_context, oracle_output)


def _security_flags(semantic_model: Mapping[str, Any], mapping: Mapping[str, Any]) -> list[str]:
    relevant = [
        item
        for item in mapping.get("mapped_observations", [])
        if isinstance(item, Mapping) and item.get("security_relevance") == "security_relevant_divergence"
    ]
    if not relevant:
        return []
    flags = []
    for dimension in semantic_model.get("active_dimensions", []):
        flag = SECURITY_FLAG_BY_DIMENSION.get(str(dimension))
        if flag:
            flags.append(flag)
    return sorted(dict.fromkeys(flags))


def _crypto_semantic_breakpoints(
    semantic_model: Mapping[str, Any],
    mapping: Mapping[str, Any],
    flags: list[str],
) -> dict[str, Any]:
    rows = []
    for item in mapping.get("mapped_observations", []):
        if not isinstance(item, Mapping):
            continue
        if item.get("security_relevance") != "security_relevant_divergence":
            continue
        rows.append(
            {
                "breakpoint_id": f"crypto_semantic_breakpoint_{len(rows):03d}",
                "source_kind": item.get("source_kind"),
                "active_semantic_dimensions": item.get("active_semantic_dimensions", []),
                "security_flags": flags,
                "score": item.get("score", 0),
            }
        )
    return {
        "schema": "crypto_semantic_breakpoints_v1",
        "model_status": semantic_model.get("model_status"),
        "breakpoint_count": len(rows),
        "breakpoints": rows,
        "candidate_queue_written": False,
    }
