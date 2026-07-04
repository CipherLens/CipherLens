"""High-recall early signal handling for fault-surface discovery.

This module does not replace the main oracle stack. It only changes how early
signals are retained before later runtime/oracle validation stages.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


WEAK_ACCEPT_TYPES = {"semantic", "state"}
LOW_CONFIDENCE_DEFER_THRESHOLD = 0.4


def early_signal_filter(signal: Mapping[str, Any] | Any) -> str:
    """Return the high-recall early decision for a single oracle signal."""

    signal_type = _signal_type(signal)
    confidence = _confidence(signal)
    if signal_type in WEAK_ACCEPT_TYPES:
        return "weak_accept"
    if confidence < LOW_CONFIDENCE_DEFER_THRESHOLD:
        return "defer"
    return "accept"


def generate_oracle_signals(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Collect existing seed/oracle observations as generic early signals."""

    signals: list[dict[str, Any]] = []
    for source_name in (
        "oracle_results",
        "differential_oracle",
        "cross_library_oracle",
        "reconciled_oracle_report",
        "semantic_divergence_points",
        "crypto_semantic_breakpoints",
        "runtime_results",
        "runtime_traces",
        "security_ground_truth_validation",
        "final_security_verdict",
    ):
        signals.extend(_signals_from_source(source_name, seed_context.get(source_name)))

    if not signals:
        signals.extend(_fallback_context_signals(seed_context))

    return {
        "schema": "fault_surface_early_oracle_signals_v1",
        "seed_id": seed_context.get("seed_id") or seed_context.get("seed_candidate_id"),
        "family": seed_context.get("family") or seed_context.get("framework_family"),
        "signal_count": len(signals),
        "signals": signals,
        "source_keys_scanned": [
            "oracle_results",
            "differential_oracle",
            "cross_library_oracle",
            "reconciled_oracle_report",
            "semantic_divergence_points",
            "crypto_semantic_breakpoints",
            "runtime_results",
            "runtime_traces",
            "security_ground_truth_validation",
            "final_security_verdict",
        ],
        "candidate_queue_written": False,
    }


def weak_filter(signals: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, mode: str = "balanced") -> dict[str, Any]:
    """Apply high-recall filtering without rejecting semantic/state signals."""

    rows = _signal_rows(signals)
    decisions = []
    counts = {"weak_accept": 0, "defer": 0, "accept": 0, "reject": 0}
    for index, signal in enumerate(rows):
        decision = early_signal_filter(signal)
        counts[decision] = counts.get(decision, 0) + 1
        decisions.append(
            {
                "signal_id": signal.get("signal_id") or signal.get("observation_id") or f"signal_{index:03d}",
                "source": signal.get("source", "unknown"),
                "type": _signal_type(signal),
                "confidence": _confidence(signal),
                "decision": decision,
                "early_rejected": False,
                "retention_reason": _retention_reason(signal, decision),
            }
        )
    retained = [item for item in decisions if item["decision"] in {"weak_accept", "defer", "accept"}]
    return {
        "schema": "high_recall_weak_signal_filter_v1",
        "mode": mode,
        "input_count": len(rows),
        "output_count": len(retained),
        "weak_accept_count": counts["weak_accept"],
        "defer_count": counts["defer"],
        "accept_count": counts["accept"],
        "reject_count": 0,
        "decisions": decisions,
        "early_reject_semantic_or_state": False,
        "final_validation_strictness_changed": False,
        "candidate_queue_written": False,
        "filter_status": "ok" if rows else "no_signals_available",
    }


def _signals_from_source(source_name: str, source: Any) -> list[dict[str, Any]]:
    if source is None:
        return []
    if isinstance(source, Mapping):
        rows = _extract_mapping_rows(source)
        if rows:
            return [_normalize_signal(row, source_name, index) for index, row in enumerate(rows)]
        if _looks_like_signal(source):
            return [_normalize_signal(source, source_name, 0)]
        return []
    if isinstance(source, list):
        return [
            _normalize_signal(item, source_name, index)
            for index, item in enumerate(source)
            if isinstance(item, Mapping)
        ]
    return []


def _extract_mapping_rows(source: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    for key in (
        "signals",
        "observations",
        "results",
        "points",
        "breakpoints",
        "items",
        "run_results",
        "analysis",
    ):
        value = source.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
    return []


def _fallback_context_signals(seed_context: Mapping[str, Any]) -> list[dict[str, Any]]:
    hints = []
    for key in ("classification", "oracle_classification", "recommendation", "result"):
        value = seed_context.get(key)
        if value:
            hints.append(str(value))
    if not hints:
        return []
    text = " ".join(hints).lower()
    signal_type = "state" if "state" in text or "lifecycle" in text else "semantic"
    return [
        {
            "signal_id": "context_hint_signal_000",
            "source": "seed_context_hint",
            "type": signal_type,
            "confidence": 0.5,
            "raw_classification": " ".join(hints),
        }
    ]


def _normalize_signal(signal: Mapping[str, Any], source_name: str, index: int) -> dict[str, Any]:
    normalized = dict(signal)
    normalized.setdefault("signal_id", signal.get("signal_id") or signal.get("observation_id") or f"{source_name}_{index:03d}")
    normalized.setdefault("source", source_name)
    normalized.setdefault("type", _signal_type(signal))
    normalized.setdefault("confidence", _confidence(signal))
    return normalized


def _signal_rows(signals: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(signals, Mapping):
        rows = signals.get("signals")
        if isinstance(rows, list):
            return [dict(item) for item in rows if isinstance(item, Mapping)]
        return [dict(signals)] if _looks_like_signal(signals) else []
    return [dict(item) for item in signals if isinstance(item, Mapping)]


def _looks_like_signal(value: Mapping[str, Any]) -> bool:
    return any(key in value for key in ("type", "signal_type", "kind", "classification", "confidence", "score"))


def _signal_type(signal: Mapping[str, Any] | Any) -> str:
    value = _get(signal, "type") or _get(signal, "signal_type") or _get(signal, "kind")
    if value:
        text = str(value).lower()
    else:
        text = " ".join(
            str(_get(signal, key, ""))
            for key in ("classification", "observation_id", "reason", "result")
        ).lower()
    if "state" in text or "lifecycle" in text:
        return "state"
    if "semantic" in text or "divergence" in text or "mismatch" in text or "safe_reject" in text:
        return "semantic"
    if "crash" in text or "sanitizer" in text or "timeout" in text:
        return "execution"
    return text or "unknown"


def _confidence(signal: Mapping[str, Any] | Any) -> float:
    for key in ("confidence", "confidence_score", "score", "semantic_divergence_score"):
        value = _get(signal, key)
        if value is None:
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            continue
        return numeric / 100.0 if numeric > 1 else numeric
    return 0.5


def _get(signal: Mapping[str, Any] | Any, key: str, default: Any = None) -> Any:
    if isinstance(signal, Mapping):
        return signal.get(key, default)
    return getattr(signal, key, default)


def _retention_reason(signal: Mapping[str, Any], decision: str) -> str:
    if decision == "weak_accept":
        return "semantic_or_state_signal_retained_for_later_validation"
    if decision == "defer":
        return "low_confidence_signal_deferred_instead_of_pruned"
    return "sufficient_confidence_for_early_stage_retention"
