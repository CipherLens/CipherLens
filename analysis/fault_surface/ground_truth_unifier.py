"""Unify split runtime evidence into one authoritative truth record."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any


SOURCE_TRUST = {
    "replay_execution": 100,
    "runtime_truth_matrix": 95,
    "asan_ubsan_trace": 80,
    "cached_execution": 60,
    "partial_log": 40,
    "unknown": 10,
}
OUTCOME_FIELDS = (
    "return_code",
    "success",
    "signature_validity",
    "signature_valid",
    "verification_result",
    "key_usage_result",
    "lifecycle_state",
    "accepted_or_rejected",
    "crash",
    "timeout",
    "sanitizer",
)


class GroundTruthUnifier:
    """Normalize, align, and reconcile runtime evidence into one source."""

    schema = "ground_truth_unifier_v1"

    def build(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        seed_id = str(seed_context.get("seed_id") or seed_context.get("seed_candidate_id") or "unknown_seed")
        evidence = _collect_evidence(seed_context, seed_id)
        grouped = _group_by_library(evidence)
        unified_rows, conflicts = _reconcile(grouped)
        unified_runtime_truth = {
            "schema": "unified_runtime_truth_v1",
            "seed_id": seed_id,
            "source_policy": "single_authoritative_execution_source",
            "oracle_input_policy": "use_unified_runtime_truth_only",
            "rows": unified_rows,
            "complete_library_count": sum(1 for row in unified_rows if row.get("truth_status") == "authoritative"),
            "status": "unified" if unified_rows else "blocked_no_runtime_evidence",
            "candidate_queue_written": False,
        }
        execution_provenance_map = {
            "schema": "execution_provenance_map_v1",
            "seed_id": seed_id,
            "entries": evidence,
            "source_trust": SOURCE_TRUST,
            "candidate_queue_written": False,
        }
        truth_conflict_resolution = {
            "schema": "truth_conflict_resolution_v1",
            "conflict_count": len(conflicts),
            "conflicts": conflicts,
            "resolution_rule": "highest_trust_source_wins_then_existing_order",
            "fallback_candidate_decision_allowed": False,
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "unified_runtime_truth": unified_runtime_truth,
            "execution_provenance_map": execution_provenance_map,
            "truth_conflict_resolution": truth_conflict_resolution,
            "candidate_queue_written": False,
        }


def build(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Build unified runtime truth from known evidence sources."""

    return GroundTruthUnifier().build(seed_context)


def _collect_evidence(seed_context: Mapping[str, Any], seed_id: str) -> list[dict[str, Any]]:
    sources = [
        ("runtime_truth_matrix", seed_context.get("runtime_truth_matrix")),
        ("replay_execution", seed_context.get("replay_execution_logs") or seed_context.get("replay_results")),
        ("asan_ubsan_trace", seed_context.get("asan_ubsan_traces") or seed_context.get("runtime_traces")),
        ("cached_execution", seed_context.get("cached_execution") or seed_context.get("runtime_results")),
        ("partial_log", seed_context.get("cross_library_outputs") or seed_context.get("oracle_results")),
        ("partial_log", seed_context.get("observations")),
    ]
    rows = []
    for source_kind, value in sources:
        for item in _as_rows(value):
            normalized = _normalize_row(item, source_kind, seed_id)
            if normalized:
                rows.append(normalized)
    return rows


def _as_rows(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        if isinstance(value.get("rows"), list):
            return [item for item in value["rows"] if isinstance(item, Mapping)]
        for key in ("results", "items", "run_results", "observations", "analysis", "traces"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, Mapping)]
        return [value]
    return []


def _normalize_row(item: Mapping[str, Any], source_kind: str, seed_id: str) -> dict[str, Any] | None:
    library = str(
        item.get("library")
        or item.get("target_library")
        or item.get("target")
        or item.get("target_name")
        or ""
    ).split("-", 1)[0].lower()
    if not library:
        return None
    item_seed = str(item.get("seed_id") or item.get("seed_candidate_id") or seed_id)
    signature = {field: item.get(field) for field in OUTCOME_FIELDS if field in item}
    return {
        "library": library,
        "seed_id": item_seed,
        "same_seed": item_seed == seed_id,
        "source_kind": source_kind,
        "trust_weight": int(SOURCE_TRUST.get(source_kind, SOURCE_TRUST["unknown"])),
        "timeline_index": int(item.get("timeline_index", item.get("sequence_index", 0)) or 0),
        "outcome_signature": signature,
        "raw_status": item.get("runtime_status") or item.get("status") or item.get("replay_status"),
    }


def _group_by_library(evidence: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in evidence:
        grouped[row["library"]].append(row)
    return grouped


def _reconcile(grouped: Mapping[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    unified = []
    conflicts = []
    for library, rows in sorted(grouped.items()):
        ordered = sorted(rows, key=lambda row: (row["trust_weight"], row["same_seed"]), reverse=True)
        chosen = ordered[0]
        signatures = {repr(sorted(row["outcome_signature"].items())) for row in ordered}
        if len(signatures) > 1:
            conflicts.append(
                {
                    "library": library,
                    "source_count": len(ordered),
                    "chosen_source": chosen["source_kind"],
                    "chosen_trust_weight": chosen["trust_weight"],
                    "conflicting_sources": [
                        {
                            "source_kind": row["source_kind"],
                            "trust_weight": row["trust_weight"],
                            "outcome_signature": row["outcome_signature"],
                        }
                        for row in ordered
                    ],
                }
            )
        unified.append(
            {
                "library": library,
                "seed_id": chosen["seed_id"],
                "same_seed": chosen["same_seed"],
                "authoritative_source": chosen["source_kind"],
                "trust_weight": chosen["trust_weight"],
                "timeline_index": chosen["timeline_index"],
                "outcome_signature": chosen["outcome_signature"],
                "truth_status": "authoritative" if chosen["same_seed"] else "blocked_seed_mismatch",
            }
        )
    return unified, conflicts
