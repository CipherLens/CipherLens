#!/usr/bin/env python3
"""Validate completed_slot_binding_v2 artifacts before renderer stages.

This consumer is intentionally schema-driven. It does not render source,
compile cases, run cases, call external services, or apply oracle dispatch.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path
from typing import Any

import yaml


REQUIRED_TOP_LEVEL_FIELDS = [
    "schema",
    "seed_id",
    "family",
    "target_library",
    "target_api",
    "source_api_boundary",
    "slots",
]

REQUIRED_SLOTS = [
    "parse_or_trigger_call",
    "return_code",
    "cleanup_call",
    "oracle_check",
]

HARNESS_MARKERS = [
    r"#\s*include\b",
    r"\bint\s+main\s*\(",
    r"\bvoid\s+main\s*\(",
    r"\bgcc\b",
    r"\bclang\b",
    r"\bcmake\b",
]


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"expected mapping YAML at {path}")
    return data


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def as_text(value: Any) -> str:
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=True)


def normalize_slots(slots: Any) -> dict[str, dict[str, Any]]:
    if isinstance(slots, dict):
        normalized: dict[str, dict[str, Any]] = {}
        for name, spec in slots.items():
            normalized[str(name)] = spec if isinstance(spec, dict) else {"binding": spec}
        return normalized

    if isinstance(slots, list):
        normalized = {}
        for item in slots:
            if not isinstance(item, dict):
                continue
            name = item.get("slot_name")
            if name:
                normalized[str(name)] = item
        return normalized

    return {}


def slot_binding_value(slot: dict[str, Any]) -> Any:
    for key in ("binding", "bound_value_or_reference", "value", "reference"):
        if key in slot:
            return slot.get(key)
    return None


def slot_evidence_value(slot: dict[str, Any]) -> Any:
    for key in ("evidence_source", "evidence", "evidence_reference"):
        if key in slot:
            return slot.get(key)
    return None


def check_schema(binding: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in REQUIRED_TOP_LEVEL_FIELDS if field not in binding]
    schema_ok = binding.get("schema") == "completed_slot_binding_v2"
    return {
        "check": "schema_validation",
        "status": "pass" if schema_ok and not missing else "fail",
        "evidence": {"schema": binding.get("schema"), "missing_fields": missing},
        "notes": "completed_slot_binding_v2 schema and required fields present",
    }


def check_required_slots(slots: dict[str, dict[str, Any]]) -> dict[str, Any]:
    missing = [slot for slot in REQUIRED_SLOTS if slot not in slots]
    unbound = [name for name, spec in slots.items() if not slot_binding_value(spec)]
    missing_evidence = [name for name, spec in slots.items() if not slot_evidence_value(spec)]
    status = "pass" if not missing and not unbound and not missing_evidence else "fail"
    return {
        "check": "required_slot_validation",
        "status": status,
        "evidence": {
            "required_slots": REQUIRED_SLOTS,
            "missing_required_slots": missing,
            "unbound_slots": unbound,
            "slots_missing_evidence_source": missing_evidence,
        },
        "notes": "all required slots must have binding and evidence_source",
    }


def check_target_api_evidence(binding: dict[str, Any]) -> dict[str, Any]:
    boundary = binding.get("source_api_boundary") or {}
    api_evidence = binding.get("api_evidence") or {}
    if not isinstance(api_evidence, dict):
        api_evidence = {}
    evidence_refs = [value for value in api_evidence.values() if value]
    target_ok = boundary.get("target_api_from_evidence_only") is True or boundary.get("target_api_from_allowed_candidates") is True
    return {
        "check": "target_api_evidence_validation",
        "status": "pass" if target_ok and evidence_refs else "fail",
        "evidence": {
            "target_api_from_evidence_only": boundary.get("target_api_from_evidence_only"),
            "target_api_from_allowed_candidates": boundary.get("target_api_from_allowed_candidates"),
            "api_evidence_refs": evidence_refs,
        },
        "notes": "target API must be evidence-backed by the binding artifact",
    }


def check_source_api_boundary(binding: dict[str, Any], slots: dict[str, dict[str, Any]]) -> dict[str, Any]:
    boundary = binding.get("source_api_boundary") or {}
    source_context_only = boundary.get("source_api_context_only") is True
    source_api_name = boundary.get("source_api_name")
    slot_text = as_text(slots)
    leaked_tokens: list[str] = []
    if source_api_name and re.search(rf"\b{re.escape(str(source_api_name))}\b", slot_text):
        leaked_tokens.append(str(source_api_name))
    return {
        "check": "source_api_boundary_validation",
        "status": "pass" if source_context_only and not leaked_tokens else "fail",
        "evidence": {
            "source_api_context_only": boundary.get("source_api_context_only"),
            "source_api_name": source_api_name,
            "leaked_source_api_tokens": leaked_tokens,
        },
        "notes": "source API may appear in context metadata but not inside target slot bindings",
    }


def check_oracle_hook(slots: dict[str, dict[str, Any]]) -> dict[str, Any]:
    oracle = slots.get("oracle_check") or {}
    binding_value = slot_binding_value(oracle)
    evidence_value = slot_evidence_value(oracle)
    return {
        "check": "oracle_hook_consistency_validation",
        "status": "pass" if binding_value and evidence_value else "fail",
        "evidence": {"oracle_binding": binding_value, "oracle_evidence": evidence_value},
        "notes": "oracle_check slot must describe an evidence-backed observation hook",
    }


def check_cleanup(slots: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cleanup = slots.get("cleanup_call") or {}
    binding_value = slot_binding_value(cleanup)
    evidence_value = slot_evidence_value(cleanup)
    return {
        "check": "cleanup_validation",
        "status": "pass" if binding_value and evidence_value else "fail",
        "evidence": {"cleanup_binding": binding_value, "cleanup_evidence": evidence_value},
        "notes": "cleanup_call slot must be bound and evidence-backed",
    }


def check_no_harness_code(binding: dict[str, Any]) -> dict[str, Any]:
    text = as_text(binding)
    matches = sorted({pattern for pattern in HARNESS_MARKERS if re.search(pattern, text, re.I)})
    return {
        "check": "no_source_generation_payload",
        "status": "pass" if not matches else "fail",
        "evidence": {"matched_harness_markers": matches},
        "notes": "completed slot bindings must not contain generated harness source",
    }


def validate(binding_path: Path) -> dict[str, Any]:
    binding = load_yaml(binding_path)
    slots = normalize_slots(binding.get("slots"))

    checks = [
        check_schema(binding),
        check_required_slots(slots),
        check_target_api_evidence(binding),
        check_source_api_boundary(binding, slots),
        check_oracle_hook(slots),
        check_cleanup(slots),
        check_no_harness_code(binding),
    ]
    failed = [check for check in checks if check["status"] != "pass"]

    if not failed:
        status = "adapter_validate_pass_with_guardrails"
        blocking_reason = ["renderer_profile_still_requires_separate_check_before_source_generation"]
    elif any(check["check"] == "schema_validation" for check in failed):
        status = "blocked_schema_invalid"
        blocking_reason = [check["check"] for check in failed]
    elif any(check["check"] == "required_slot_validation" for check in failed):
        status = "blocked_missing_required_slot"
        blocking_reason = [check["check"] for check in failed]
    elif any(check["check"] == "source_api_boundary_validation" for check in failed):
        status = "blocked_source_api_boundary"
        blocking_reason = [check["check"] for check in failed]
    elif any(check["check"] == "target_api_evidence_validation" for check in failed):
        status = "blocked_missing_target_api_evidence"
        blocking_reason = [check["check"] for check in failed]
    elif any(check["check"] == "oracle_hook_consistency_validation" for check in failed):
        status = "blocked_missing_oracle_hook"
        blocking_reason = [check["check"] for check in failed]
    else:
        status = "failed_validation_error"
        blocking_reason = [check["check"] for check in failed]

    return {
        "schema": "adapter_validate_result_v2",
        "executed": True,
        "items": [
            {
                "seed_id": binding.get("seed_id", ""),
                "family": binding.get("family", ""),
                "target_library": binding.get("target_library", ""),
                "target_api": binding.get("target_api", ""),
                "input_package": str(binding_path),
                "validation_checks": checks,
                "source_api_boundary_status": checks[3]["status"],
                "required_slots_status": checks[1]["status"],
                "target_api_evidence_status": checks[2]["status"],
                "cleanup_status": checks[5]["status"],
                "oracle_hook_status": checks[4]["status"],
                "adapter_validate_status": status,
                "blocking_reason": blocking_reason,
            }
        ],
        "summary": {
            "executed_count": 1,
            "passed_count": 1 if status == "adapter_validate_pass" else 0,
            "passed_with_guardrails_count": 1 if status == "adapter_validate_pass_with_guardrails" else 0,
            "blocked_count": 1 if status.startswith("blocked_") else 0,
            "failed_count": 1 if status == "failed_validation_error" else 0,
        },
    }


def import_smoke() -> bool:
    return importlib.util.find_spec("yaml") is not None


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a completed_slot_binding_v2 YAML artifact.")
    parser.add_argument("--completed-slot-binding", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    result = validate(args.completed_slot_binding)
    dump_yaml(args.out, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
