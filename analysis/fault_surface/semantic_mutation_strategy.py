"""High-recall semantic mutation expansion for fault-surface planning."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SEMANTIC_MUTATION_TYPES = (
    "invalid_api_sequence_but_plausible",
    "partial_crypto_misuse_flow",
    "cross_library_ambiguous_usage",
    "weak_contract_violation_injection",
)


def semantic_mutation_expand(
    seed_context: Mapping[str, Any],
    filtered_signals: Mapping[str, Any],
    *,
    mode: str = "balanced",
) -> dict[str, Any]:
    """Expand retained early signals into semantic mutation plans only."""

    decisions = [
        item
        for item in filtered_signals.get("decisions", [])
        if isinstance(item, Mapping) and item.get("decision") in {"weak_accept", "defer", "accept"}
    ]
    mutations: list[dict[str, Any]] = []
    for signal_index, signal in enumerate(decisions):
        for mutation_type in SEMANTIC_MUTATION_TYPES:
            mutations.append(_mutation(seed_context, signal, signal_index, mutation_type, mode))

    return {
        "schema": "semantic_mutation_expansion_v1",
        "mode": mode,
        "seed_id": seed_context.get("seed_id") or seed_context.get("seed_candidate_id"),
        "family": seed_context.get("family") or seed_context.get("framework_family"),
        "mutation_scope": "execution_semantics",
        "input_only_mutation": False,
        "requires_execution_failure": False,
        "borderline_cases_retained": True,
        "uncertain_but_runnable_allowed": True,
        "source_signal_count": len(decisions),
        "mutation_count": len(mutations),
        "mutation_types": list(SEMANTIC_MUTATION_TYPES),
        "mutations": mutations,
        "candidate_queue_written": False,
        "plan_status": "ok" if mutations else "no_retained_signals_available",
    }


def _mutation(
    seed_context: Mapping[str, Any],
    signal: Mapping[str, Any],
    signal_index: int,
    mutation_type: str,
    mode: str,
) -> dict[str, Any]:
    signal_id = signal.get("signal_id") or f"signal_{signal_index:03d}"
    return {
        "mutation_id": f"semantic_{signal_index:03d}_{mutation_type}",
        "mutation_type": mutation_type,
        "source_signal_id": signal_id,
        "source_signal_type": signal.get("type", "unknown"),
        "source_signal_decision": signal.get("decision"),
        "family": seed_context.get("family") or seed_context.get("framework_family"),
        "target_libraries": _target_libraries(seed_context),
        "requires_execution_failure": False,
        "keeps_borderline_case": True,
        "allowed_before_final_validation": True,
        "priority": _priority(signal, mutation_type, mode),
        "intent": _intent(mutation_type),
    }


def _target_libraries(seed_context: Mapping[str, Any]) -> list[str]:
    value = seed_context.get("target_libraries") or seed_context.get("libraries") or seed_context.get("targets")
    if isinstance(value, list):
        return [str(item) for item in value]
    if value:
        return [str(value)]
    return []


def _priority(signal: Mapping[str, Any], mutation_type: str, mode: str) -> int:
    base = 50 if mode == "balanced" else 40
    if signal.get("decision") == "weak_accept":
        base += 15
    elif signal.get("decision") == "defer":
        base += 5
    if mutation_type in {"cross_library_ambiguous_usage", "weak_contract_violation_injection"}:
        base += 10
    return min(100, base)


def _intent(mutation_type: str) -> str:
    return {
        "invalid_api_sequence_but_plausible": "retain API order variants that are questionable but can be rendered",
        "partial_crypto_misuse_flow": "preserve incomplete cryptographic usage paths for later oracle validation",
        "cross_library_ambiguous_usage": "surface library-specific interpretation gaps from the same seed intent",
        "weak_contract_violation_injection": "exercise contract edges without requiring an immediate execution failure",
    }[mutation_type]
