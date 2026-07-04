"""Reconcile multi-oracle signals from unified runtime truth only."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


ORACLE_FIELDS = (
    "success",
    "return_code",
    "signature_validity",
    "key_usage_result",
    "lifecycle_state",
    "crash",
    "timeout",
    "sanitizer",
)


class OracleReconciliationEngine:
    """Evaluate oracle outputs using one unified truth source."""

    schema = "oracle_reconciliation_engine_v1"

    def evaluate(self, unified_runtime_truth: Mapping[str, Any]) -> dict[str, Any]:
        rows = [row for row in unified_runtime_truth.get("rows", []) if isinstance(row, Mapping)]
        usable = [row for row in rows if row.get("truth_status") == "authoritative"]
        field_values = _field_values(usable)
        crash_oracle = _flag_any(usable, "crash") or _flag_any(usable, "timeout")
        sanitizer_oracle = _flag_any(usable, "sanitizer")
        semantic_divergence = any(
            len({repr(value) for value in values.values() if value is not None}) > 1
            for values in field_values.values()
        )
        state_divergence = len({repr(v) for v in field_values.get("lifecycle_state", {}).values() if v is not None}) > 1
        final_decision = _final_decision(
            unified_runtime_truth,
            usable,
            crash_oracle,
            sanitizer_oracle,
            semantic_divergence,
            state_divergence,
        )
        report = {
            "schema": "reconciled_oracle_report_v1",
            "oracle_input": "unified_runtime_truth",
            "raw_split_truth_used_for_decision": False,
            "usable_library_count": len(usable),
            "crash_oracle": crash_oracle,
            "sanitizer_oracle": sanitizer_oracle,
            "semantic_oracle_divergence": semantic_divergence,
            "state_oracle_divergence": state_divergence,
            "field_values": field_values,
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "reconciled_oracle_report": report,
            "final_candidate_decision": final_decision,
            "candidate_queue_written": False,
        }


def evaluate(unified_runtime_truth: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate reconciled oracle result from unified truth only."""

    return OracleReconciliationEngine().evaluate(unified_runtime_truth)


def _field_values(rows: list[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {field: {} for field in ORACLE_FIELDS}
    for row in rows:
        library = str(row.get("library"))
        signature = row.get("outcome_signature") or {}
        if not isinstance(signature, Mapping):
            continue
        for field in ORACLE_FIELDS:
            if field in signature:
                out[field][library] = signature.get(field)
    return out


def _flag_any(rows: list[Mapping[str, Any]], field: str) -> bool:
    for row in rows:
        signature = row.get("outcome_signature") or {}
        if isinstance(signature, Mapping) and bool(signature.get(field)):
            return True
    return False


def _final_decision(
    unified_runtime_truth: Mapping[str, Any],
    usable: list[Mapping[str, Any]],
    crash_oracle: bool,
    sanitizer_oracle: bool,
    semantic_divergence: bool,
    state_divergence: bool,
) -> dict[str, Any]:
    if unified_runtime_truth.get("status") != "unified" or not usable:
        decision = "blocked_no_unified_runtime_truth"
        reason = "unified_truth_missing_or_unusable"
    elif crash_oracle or sanitizer_oracle or semantic_divergence or state_divergence:
        decision = "candidate_event_requires_campaign_triage"
        reason = "unified_truth_oracle_signal_present"
    else:
        decision = "no_candidate_from_unified_truth"
        reason = "unified_truth_has_consistent_non_failure_outcome"
    return {
        "schema": "final_candidate_decision_v1",
        "decision": decision,
        "reason": reason,
        "fallback_candidate_decision_used": False,
        "candidate_queue_written": False,
        "claim_level": "unified_truth_oracle_decision_only",
    }
