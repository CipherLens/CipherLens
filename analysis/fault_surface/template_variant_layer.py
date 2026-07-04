"""Invalid-but-possible template variant layer for high-recall planning."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


INVALID_BUT_POSSIBLE_FLOWS = (
    "sign_without_full_verify_chain",
    "hash_truncation_before_sign",
    "key_usage_without_explicit_init_check",
    "cross_library_key_interpretation_mismatch",
)


def inject_invalid_but_possible_flows(
    mutation_expansion: Mapping[str, Any],
    *,
    mode: str = "balanced",
) -> dict[str, Any]:
    """Attach dangerous variant intent without modifying normalized templates."""

    mutations = [
        item
        for item in mutation_expansion.get("mutations", [])
        if isinstance(item, Mapping)
    ]
    expanded: list[dict[str, Any]] = []
    for index, mutation in enumerate(mutations):
        for flow in INVALID_BUT_POSSIBLE_FLOWS:
            expanded.append(_expanded_candidate(index, mutation, flow, mode))

    return {
        "schema": "invalid_but_possible_template_variant_layer_v1",
        "mode": mode,
        "invalid_but_possible_flows": list(INVALID_BUT_POSSIBLE_FLOWS),
        "source_mutation_count": len(mutations),
        "expanded_candidate_count": len(expanded),
        "expanded_candidates": expanded,
        "normalized_templates_modified": False,
        "rendering_pipeline_changed": False,
        "runtime_executed": False,
        "candidate_queue_written": False,
        "layer_status": "ok" if expanded else "no_semantic_mutations_available",
    }


def _expanded_candidate(
    index: int,
    mutation: Mapping[str, Any],
    flow: str,
    mode: str,
) -> dict[str, Any]:
    return {
        "candidate_id": f"high_recall_variant_{index:03d}_{flow}",
        "source_mutation_id": mutation.get("mutation_id"),
        "flow": flow,
        "mode": mode,
        "variant_scope": "template_intent_extension",
        "existing_template_changed": False,
        "normalized_templates_extension_only": True,
        "requires_runtime": False,
        "requires_later_adapter_validation": True,
        "requires_later_oracle_validation": True,
        "reason": _reason(flow),
    }


def _reason(flow: str) -> str:
    return {
        "sign_without_full_verify_chain": "keeps signing paths where verification context is incomplete",
        "hash_truncation_before_sign": "retains digest-size ambiguity before a signing operation",
        "key_usage_without_explicit_init_check": "keeps key usage flows with unclear initialization guarantees",
        "cross_library_key_interpretation_mismatch": "retains cross-library key interpretation ambiguity",
    }[flow]
