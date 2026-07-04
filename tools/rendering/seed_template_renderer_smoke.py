#!/usr/bin/env python3
"""Bounded metadata renderer for seed-driven render packages.

This stage bridge writes renderer metadata and manifests only. It does not
generate C/C++ harness source, compile, run, or invoke oracle dispatch.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml


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


def slot_map(slots: list[dict[str, Any]]) -> dict[str, Any]:
    return {str(slot.get("name")): slot for slot in slots if slot.get("name")}


def source_api_leaks(values: Any) -> list[str]:
    text = yaml.safe_dump(values, sort_keys=False, allow_unicode=True)
    leaks: list[str] = []
    for pattern in SOURCE_API_MARKERS:
        leaks.extend(re.findall(pattern, text, re.I))
    return sorted(set(leaks))


def render_item(item: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    package_id = str(item.get("renderer_package_id"))
    package_dir = out_dir / "rendered_metadata" / package_id
    slots = slot_map(item.get("legacy_slot_bindings_equivalent", []))
    leaks = source_api_leaks(slots)

    metadata = {
        "schema": "rendered_case_metadata_v1",
        "renderer_package_id": package_id,
        "seed_id": item.get("seed_id"),
        "target_library": item.get("target_library"),
        "family": item.get("family"),
        "concrete_pattern": item.get("concrete_pattern"),
        "template_id": item.get("template_id"),
        "oracle_kind": item.get("oracle_kind"),
        "render_mode": "metadata_only_bounded_smoke",
        "target_api_reference": slots.get("parse_or_trigger_call", {}).get("value_or_reference"),
        "payload_reference": item.get("payload_reference"),
        "source_generated": False,
        "compile_executed": False,
        "runtime_executed": False,
    }
    compile_manifest = {
        "schema": "compile_input_manifest_v1",
        "renderer_package_id": package_id,
        "seed_id": item.get("seed_id"),
        "compile_input_available": False,
        "source_generated": False,
        "required_before_compile": [
            "real template renderer source generation",
            "human review of metadata-only render output",
        ],
    }
    oracle_manifest = {
        "schema": "oracle_hook_manifest_v1",
        "renderer_package_id": package_id,
        "seed_id": item.get("seed_id"),
        "family": item.get("family"),
        "oracle_kind": item.get("oracle_kind"),
        "expected_observation_fields": item.get("expected_observation_fields", []),
        "oracle_dispatcher_executed": False,
        "ready_after_runtime_observation": bool(item.get("expected_observation_fields")),
    }
    template_output = {
        "schema": "rendered_source_or_template_output_v1",
        "renderer_package_id": package_id,
        "output_kind": "metadata_only_template_binding_projection",
        "source_generated": False,
        "slot_projection": [
            {
                "slot_name": name,
                "value_or_reference": slot.get("value_or_reference"),
                "source": slot.get("source"),
            }
            for name, slot in sorted(slots.items())
        ],
    }

    metadata_path = package_dir / "rendered_case_metadata.yaml"
    compile_path = package_dir / "compile_input_manifest.yaml"
    oracle_path = package_dir / "oracle_hook_manifest.yaml"
    template_path = package_dir / "rendered_source_or_template_output.yaml"
    dump_yaml(metadata_path, metadata)
    dump_yaml(compile_path, compile_manifest)
    dump_yaml(oracle_path, oracle_manifest)
    dump_yaml(template_path, template_output)

    checks = [
        {
            "check": "renderer_input_schema",
            "status": "pass" if item.get("renderer_input_status") == "renderer_input_ready" else "fail",
            "notes": item.get("renderer_input_status"),
        },
        {
            "check": "source_api_boundary",
            "status": "pass" if not leaks else "fail",
            "notes": {"leaked_source_api_tokens": leaks},
        },
        {
            "check": "metadata_outputs_written",
            "status": "pass",
            "notes": "metadata-only bounded smoke outputs written",
        },
        {
            "check": "no_compile_or_runtime",
            "status": "pass",
            "notes": "compile/runtime/oracle dispatcher not executed",
        },
    ]
    failed = [check for check in checks if check["status"] != "pass"]
    status = "renderer_smoke_pass_with_guardrails" if not failed else "renderer_failed_source_api_leakage"
    blocking = ["compile_smoke_required_before_runtime"] if not failed else [check["check"] for check in failed]

    return {
        "renderer_package_id": package_id,
        "seed_id": item.get("seed_id"),
        "command_or_entrypoint": "tools/rendering/seed_template_renderer_smoke.py",
        "exit_code": 0 if not failed else 1,
        "rendered_outputs": [
            {"path": str(metadata_path), "output_type": "rendered_case_metadata", "exists": metadata_path.exists(), "notes": "metadata only"},
            {"path": str(template_path), "output_type": "rendered_source_or_template_output", "exists": template_path.exists(), "notes": "metadata projection, not source code"},
            {"path": str(compile_path), "output_type": "compile_input_manifest", "exists": compile_path.exists(), "notes": "compile not ready because no source generated"},
            {"path": str(oracle_path), "output_type": "oracle_hook_manifest", "exists": oracle_path.exists(), "notes": "oracle dispatcher not executed"},
        ],
        "renderer_checks": checks,
        "renderer_status": status,
        "blocking_reason": blocking,
    }


def run(renderer_package: Path, out_dir: Path) -> dict[str, Any]:
    package = load_yaml(renderer_package)
    results = [render_item(item, out_dir) for item in package.get("items", [])]
    output = {
        "schema": "renderer_smoke_result_v1",
        "executed": True,
        "items": results,
        "summary": {
            "executed_count": len(results),
            "rendered_count": sum(1 for item in results if item["renderer_status"] == "renderer_smoke_pass"),
            "rendered_with_guardrails_count": sum(
                1 for item in results if item["renderer_status"] == "renderer_smoke_pass_with_guardrails"
            ),
            "blocked_count": sum(1 for item in results if "blocked" in item["renderer_status"]),
            "failed_count": sum(1 for item in results if "failed" in item["renderer_status"]),
        },
    }
    dump_yaml(out_dir / "renderer_smoke_result.yaml", output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded seed-driven renderer metadata smoke.")
    parser.add_argument("--renderer-package", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    run(args.renderer_package, args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
