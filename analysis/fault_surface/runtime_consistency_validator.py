"""Consistency checks over a cross-library runtime truth matrix."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SECURITY_OUTCOME_FIELDS = (
    "success",
    "signature_validity",
    "key_usage_result",
    "lifecycle_state",
)


class RuntimeConsistencyValidator:
    """Determine whether runtime security outcomes agree across libraries."""

    schema = "runtime_consistency_validator_v1"

    def validate(self, runtime_truth_matrix: Mapping[str, Any]) -> dict[str, Any]:
        rows = [row for row in runtime_truth_matrix.get("rows", []) if isinstance(row, Mapping)]
        field_outcomes = {
            field: _field_values(rows, field)
            for field in SECURITY_OUTCOME_FIELDS
        }
        inconsistent_fields = [
            field
            for field, values in field_outcomes.items()
            if len({repr(value) for value in values.values() if value is not None}) > 1
        ]
        complete = bool(rows) and all(row.get("trace_found") and row.get("same_seed") for row in rows)
        consistency = "inconsistent" if complete and inconsistent_fields else "consistent"
        if not complete:
            consistency = "blocked_missing_runtime_truth"
        report = {
            "schema": "consistency_report_v1",
            "runtime_truth_status": runtime_truth_matrix.get("status"),
            "consistency": consistency,
            "complete_cross_library_replay": complete,
            "inconsistent_fields": inconsistent_fields,
            "field_outcomes": field_outcomes,
            "candidate_queue_written": False,
        }
        inconsistency_type = {
            "schema": "inconsistency_type_v1",
            "type": _inconsistency_type(inconsistent_fields, complete),
            "signature_validity_mismatch": "signature_validity" in inconsistent_fields,
            "key_usage_mismatch": "key_usage_result" in inconsistent_fields,
            "lifecycle_state_mismatch": "lifecycle_state" in inconsistent_fields,
            "success_mismatch": "success" in inconsistent_fields,
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "consistency_report": report,
            "inconsistency_type": inconsistency_type,
            "candidate_queue_written": False,
        }


def validate(runtime_truth_matrix: Mapping[str, Any]) -> dict[str, Any]:
    """Validate consistency over a runtime truth matrix."""

    return RuntimeConsistencyValidator().validate(runtime_truth_matrix)


def _field_values(rows: list[Mapping[str, Any]], field: str) -> dict[str, Any]:
    return {
        str(row.get("library")): row.get(field)
        for row in rows
        if row.get("trace_found")
    }


def _inconsistency_type(inconsistent_fields: list[str], complete: bool) -> str:
    if not complete:
        return "blocked_missing_runtime_truth"
    if not inconsistent_fields:
        return "none"
    if "signature_validity" in inconsistent_fields:
        return "signature_validity_mismatch"
    if "key_usage_result" in inconsistent_fields:
        return "key_usage_semantic_mismatch"
    if "lifecycle_state" in inconsistent_fields:
        return "lifecycle_state_mismatch"
    return "runtime_security_outcome_mismatch"
