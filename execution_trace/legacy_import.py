"""Demote legacy labels into non-authoritative compatibility evidence."""

from __future__ import annotations

from typing import Any, Mapping


FORBIDDEN_AUTHORITIES = frozenset({"SATISFIED", "VIOLATED", "UNKNOWN"})


def import_legacy_result(value: Mapping[str, Any]) -> dict[str, Any]:
    label = str(value.get("verdict") or value.get("candidate_label") or value.get("raw_observation_label") or value.get("status") or "unclassified")
    return {
        "schema_version": "cipherlens.legacy_execution_evidence.v0.1",
        "legacy_label": label,
        "authority": "NONE",
        "evidence_class": "LEGACY_COMPATIBILITY_LABEL",
        "may_decide_execution_verdict": False,
        "source_fields": sorted(str(key) for key in value),
    }
