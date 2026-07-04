"""Provenance and trust-weight views for unified runtime truth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class ExecutionProvenanceTracker:
    """Track source provenance for each unified runtime result."""

    schema = "execution_provenance_tracker_v1"

    def build(self, unified_truth_bundle: Mapping[str, Any]) -> dict[str, Any]:
        unified = unified_truth_bundle.get("unified_runtime_truth", {})
        provenance = unified_truth_bundle.get("execution_provenance_map", {})
        entries = [entry for entry in provenance.get("entries", []) if isinstance(entry, Mapping)]
        rows = [row for row in unified.get("rows", []) if isinstance(row, Mapping)]
        provenance_matrix = {
            "schema": "provenance_matrix_v1",
            "seed_id": unified.get("seed_id"),
            "rows": [
                {
                    "library": row.get("library"),
                    "authoritative_source": row.get("authoritative_source"),
                    "trust_weight": row.get("trust_weight"),
                    "available_sources": _available_sources(row.get("library"), entries),
                    "truth_status": row.get("truth_status"),
                }
                for row in rows
            ],
            "candidate_queue_written": False,
        }
        trust_weighted_execution_view = {
            "schema": "trust_weighted_execution_view_v1",
            "seed_id": unified.get("seed_id"),
            "oracle_input_policy": "unified_runtime_truth_only",
            "rows": [
                {
                    "library": row.get("library"),
                    "confidence_score": row.get("trust_weight", 0),
                    "outcome_signature": row.get("outcome_signature", {}),
                    "usable_for_oracle": row.get("truth_status") == "authoritative",
                }
                for row in rows
            ],
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "provenance_matrix": provenance_matrix,
            "trust_weighted_execution_view": trust_weighted_execution_view,
            "candidate_queue_written": False,
        }


def build(unified_truth_bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Build provenance reports from unified runtime truth."""

    return ExecutionProvenanceTracker().build(unified_truth_bundle)


def _available_sources(library: Any, entries: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "source_kind": entry.get("source_kind"),
            "trust_weight": entry.get("trust_weight"),
            "same_seed": entry.get("same_seed"),
        }
        for entry in entries
        if entry.get("library") == library
    ]
