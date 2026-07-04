#!/usr/bin/env python3
"""Validate seed-driven completed slot bindings before renderer stages.

This bridge is intentionally narrow: it consumes artifact YAML, checks schema
and evidence guardrails, and writes YAML results. It does not render harnesses,
compile, run cases, or call external services.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml


REQUIRED_CHECKS = [
    "slot_schema_check",
    "target_api_evidence_check",
    "cleanup_check",
    "oracle_hook_field_check",
    "no_source_api_leakage_check",
]

HARNESS_MARKERS = [
    r"#\s*include\b",
    r"\bint\s+main\s*\(",
    r"\bvoid\s+main\s*\(",
    r"\bgcc\b",
    r"\bclang\b",
    r"\bcmake\b",
]

SOURCE_API_MARKERS = [
    r"\bmbedtls_[A-Za-z0-9_]+\b",
    r"\bwc_[A-Za-z0-9_]+\b",
    r"\bEVP_[A-Za-z0-9_]+\b",
]


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")


def as_text(value: Any) -> str:
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=True)


def has_harness_code(binding: dict[str, Any]) -> bool:
    text = as_text(binding)
    return any(re.search(pattern, text, re.I) for pattern in HARNESS_MARKERS)


def slot_values(binding: dict[str, Any]) -> str:
    return "\n".join(str(slot.get("bound_value_or_reference", "")) for slot in binding.get("slots", []))


def source_api_leaks(binding: dict[str, Any]) -> list[str]:
    values = slot_values(binding)
    leaks: list[str] = []
    for pattern in SOURCE_API_MARKERS:
        leaks.extend(re.findall(pattern, values, re.I))
    return sorted(set(leaks))


def validate_binding(binding_path: Path, package: dict[str, Any]) -> dict[str, Any]:
    binding = load_yaml(binding_path)
    checks: list[dict[str, Any]] = []

    schema_ok = binding.get("schema") == "completed_slot_bindings_v1"
    slots = binding.get("slots", [])
    unresolved = [slot.get("slot_name") for slot in slots if slot.get("unresolved")]
    required_names = {slot.get("slot_name") for slot in slots}
    missing_required = sorted(name for name in ["parse_or_trigger_call", "return_code", "cleanup_call", "oracle_check"] if name not in required_names)
    checks.append(
        {
            "check": "slot_schema_check",
            "status": "pass" if schema_ok and not unresolved and not missing_required else "fail",
            "notes": {
                "schema_ok": schema_ok,
                "unresolved_slots": unresolved,
                "missing_required_slots": missing_required,
            },
        }
    )

    boundary = binding.get("source_api_boundary", {})
    target_ok = boundary.get("target_api_from_allowed_candidates") is True
    checks.append(
        {
            "check": "target_api_evidence_check",
            "status": "pass" if target_ok else "fail",
            "notes": {
                "target_api_from_allowed_candidates": boundary.get("target_api_from_allowed_candidates"),
                "api_card_evidence": package.get("api_card_evidence", []),
            },
        }
    )

    cleanup_slots = [slot for slot in slots if slot.get("slot_name") == "cleanup_call"]
    cleanup_ok = bool(cleanup_slots) and not cleanup_slots[0].get("unresolved")
    checks.append(
        {
            "check": "cleanup_check",
            "status": "pass" if cleanup_ok else "fail",
            "notes": "cleanup slot present; RAII cleanup is acceptable for C++ targets when adapter validation records it"
            if cleanup_ok
            else "cleanup slot missing or unresolved",
        }
    )

    oracle_slots = [slot for slot in slots if slot.get("slot_name") == "oracle_check"]
    oracle_ok = bool(oracle_slots) and not oracle_slots[0].get("unresolved")
    checks.append(
        {
            "check": "oracle_hook_field_check",
            "status": "pass" if oracle_ok else "fail",
            "notes": package.get("oracle_kind") or binding.get("oracle_kind"),
        }
    )

    leaks = source_api_leaks(binding)
    checks.append(
        {
            "check": "no_source_api_leakage_check",
            "status": "pass" if not leaks else "fail",
            "notes": {"leaked_source_api_tokens": leaks},
        }
    )

    harness_found = has_harness_code(binding)
    checks.append(
        {
            "check": "no_harness_code_generated",
            "status": "pass" if not harness_found else "fail",
            "notes": "artifact-only validation; no harness source expected",
        }
    )

    failed = [check for check in checks if check["status"] != "pass"]
    if failed:
        status = "adapter_validate_failed_schema"
        if any(check["check"] == "no_source_api_leakage_check" for check in failed):
            status = "adapter_validate_failed_source_api_leakage"
        elif any(check["check"] == "slot_schema_check" for check in failed):
            status = "adapter_validate_failed_missing_slot"
        blocking = [check["check"] for check in failed]
    else:
        status = "adapter_validate_pass_with_guardrails"
        blocking = ["renderer_still_requires_separate_smoke_before_runtime"]

    return {
        "bridge_package_id": package.get("bridge_package_id"),
        "seed_id": package.get("seed_id"),
        "command_or_entrypoint": "tools/adapters/seed_adapter_validate_bridge.py",
        "exit_code": 0,
        "checks": checks,
        "adapter_validate_status": status,
        "blocking_reason": blocking,
    }


def run(bridge_package_path: Path, out_dir: Path) -> dict[str, Any]:
    package_doc = load_yaml(bridge_package_path)
    items = package_doc.get("items", [])
    results = []
    for package in items:
        binding_path = Path(package.get("completed_slot_binding_path", ""))
        if not binding_path.exists():
            results.append(
                {
                    "bridge_package_id": package.get("bridge_package_id"),
                    "seed_id": package.get("seed_id"),
                    "command_or_entrypoint": "tools/adapters/seed_adapter_validate_bridge.py",
                    "exit_code": 1,
                    "checks": [{"check": "input_exists", "status": "fail", "notes": str(binding_path)}],
                    "adapter_validate_status": "adapter_validate_blocked_input_invalid",
                    "blocking_reason": ["completed_slot_binding_path_missing"],
                }
            )
            continue
        results.append(validate_binding(binding_path, package))

    summary = {
        "executed_count": len(results),
        "pass_count": sum(1 for item in results if item["adapter_validate_status"] == "adapter_validate_pass"),
        "pass_with_guardrails_count": sum(
            1 for item in results if item["adapter_validate_status"] == "adapter_validate_pass_with_guardrails"
        ),
        "blocked_count": sum(1 for item in results if "blocked" in item["adapter_validate_status"]),
        "failed_count": sum(1 for item in results if "failed" in item["adapter_validate_status"]),
    }
    output = {
        "schema": "adapter_validate_bridge_smoke_result_v1",
        "executed": True,
        "bridge_added": True,
        "bridge_file": "tools/adapters/seed_adapter_validate_bridge.py",
        "items": results,
        "summary": summary,
    }
    dump_yaml(out_dir / "adapter_validate_bridge_smoke_result.yaml", output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate seed-driven completed slot bindings.")
    parser.add_argument("--bridge-package", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    run(args.bridge_package, args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
