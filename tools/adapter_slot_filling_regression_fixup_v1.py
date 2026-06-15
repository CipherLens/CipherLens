#!/usr/bin/env python3
"""Repair ASN.1 OpenSSL slot binding regression and revalidate adapters.

This script does not call GLM, render cases, compile, run PoCs, or generate C.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ADAPTERS = [
    {
        "adapter_id": "pkcs_container_parsing_openssl",
        "family": "pkcs_container_parsing",
        "target_library": "openssl",
        "expect": "pass",
        "allowed_target_apis": {"PKCS12_parse", "PKCS7_verify"},
        "allowed_cleanup_apis": {"PKCS12_free", "PKCS7_free"},
        "forbidden_target_apis": {"d2i_PKCS7"},
    },
    {
        "adapter_id": "asn1_nested_boundary_openssl",
        "family": "asn1_nested_boundary",
        "target_library": "openssl",
        "expect": "pass",
        "allowed_target_apis": {"ASN1_item_d2i"},
        "allowed_cleanup_apis": set(),
        "forbidden_target_apis": {"d2i_X509"},
    },
    {
        "adapter_id": "asn1_nested_boundary_mbedtls",
        "family": "asn1_nested_boundary",
        "target_library": "mbedtls",
        "expect": "blocked_expected",
        "allowed_target_apis": set(),
        "allowed_cleanup_apis": set(),
        "forbidden_target_apis": {"mbedtls_x509_crt_parse_der"},
    },
]

REQUIRED_FIELDS = [
    "schema",
    "adapter_id",
    "family",
    "source_library",
    "target_library",
    "binding_status",
    "api_mapping",
    "type_mapping",
    "cleanup_mapping",
    "oracle_mapping",
    "input_mapping",
    "mutation_slot_mapping",
    "validation_notes",
    "risk_notes",
]

C_MARKERS = [
    r"#\s*include\b",
    r"\bint\s+main\s*\(",
    r"\bvoid\s+main\s*\(",
    r"\bstatic\s+(?:int|void|char|unsigned|size_t)\b",
    r"\breturn\s+0\s*;",
    r"\bgcc\b",
    r"\bclang\b",
    r"\bcmake\b",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=False), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_md(path: Path, title: str, obj: Any) -> None:
    write_text(path, f"# {title}\n\n```yaml\n{yaml.safe_dump(obj, sort_keys=False)}```\n")


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def files_equal(a: Path, b: Path) -> bool:
    return a.exists() and b.exists() and a.read_bytes() == b.read_bytes()


def contains_c(obj: Any) -> bool:
    text = yaml.safe_dump(obj, sort_keys=False) if obj is not None else ""
    return any(re.search(pattern, text, re.I) for pattern in C_MARKERS)


def nonempty(value: Any) -> bool:
    if isinstance(value, dict):
        if "bindings" in value:
            return bool(value.get("bindings"))
        if "primary" in value or "target_observables" in value:
            return bool(value.get("primary") or value.get("target_observables") or value.get("secondary"))
        if "input_slots" in value:
            return bool(value.get("input_slots"))
        return bool(value)
    return bool(value)


def confirmed_equivalence_claim(obj: Any) -> bool:
    text = yaml.safe_dump(obj, sort_keys=False).lower() if obj is not None else ""
    return any(
        marker in text
        for marker in [
            "confirmed_equivalence: true",
            "confirmed equivalence: true",
            "equivalence_confirmed: true",
            "confirmed: true",
        ]
    )


def candidate_mapping_not_promoted(obj: Any) -> bool:
    text = yaml.safe_dump(obj, sort_keys=False).lower() if obj is not None else ""
    if confirmed_equivalence_claim(obj):
        return False
    return "candidate mapping only" in text or "blocked_by_mapping_gate" in text or "candidate only" in text


def target_api_values(value: Any) -> set[str]:
    apis: set[str] = set()
    if isinstance(value, list):
        for item in value:
            apis.update(target_api_values(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in {"target_api", "selected_target_api"} and isinstance(item, str) and item:
                apis.add(item)
            else:
                apis.update(target_api_values(item))
    return apis


def cleanup_api_values(value: Any) -> set[str]:
    apis: set[str] = set()
    if isinstance(value, str):
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value):
            if token.endswith("_free") or token.endswith("_Free"):
                apis.add(token)
    elif isinstance(value, list):
        for item in value:
            apis.update(cleanup_api_values(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in {"target_api", "cleanup_api"} and isinstance(item, str) and item:
                apis.add(item)
            else:
                apis.update(cleanup_api_values(item))
    return apis


def previous_candidate_status(previous_validation: dict[str, Any]) -> str | None:
    for result in previous_validation.get("results", []):
        if (
            isinstance(result, dict)
            and result.get("family") == "asn1_nested_boundary"
            and result.get("target_library") == "openssl"
        ):
            return result.get("validation_status")
    return None


def validate_adapter(adapter_root: Path, spec: dict[str, Any]) -> dict[str, Any]:
    family = spec["family"]
    target = spec["target_library"]
    adapter_dir = adapter_root / family / target
    recipe_path = adapter_dir / "adapter_recipe.yaml"
    plan_path = adapter_dir / "slot_filling_plan.yaml"
    bindings_path = adapter_dir / "slot_bindings.yaml"
    bindings = load_yaml(bindings_path) or {}

    binding_status = bindings.get("binding_status")
    is_blocked = binding_status in {"blocked_by_mapping_gate", "manual_review_needed", "blocked"}
    target_apis = target_api_values(bindings.get("api_mapping"))
    cleanup_apis = cleanup_api_values(bindings.get("cleanup_mapping"))
    used_forbidden = sorted((target_apis | cleanup_apis).intersection(spec["forbidden_target_apis"]))
    allowed_pool = spec["allowed_target_apis"] | spec["allowed_cleanup_apis"]
    allowed_only = all(api in allowed_pool for api in (target_apis | cleanup_apis))
    if not cleanup_apis and spec["family"] == "asn1_nested_boundary" and spec["target_library"] == "openssl":
        allowed_only = all(api in spec["allowed_target_apis"] for api in target_apis)

    required_present = all(field in bindings for field in REQUIRED_FIELDS)
    api_nonempty = nonempty(bindings.get("api_mapping"))
    cleanup_nonempty = nonempty(bindings.get("cleanup_mapping"))
    oracle_nonempty = nonempty(bindings.get("oracle_mapping"))
    input_present = "input_mapping" in bindings and nonempty(bindings.get("input_mapping"))
    mutation_present = "mutation_slot_mapping" in bindings and nonempty(bindings.get("mutation_slot_mapping"))
    blocked_ok = not used_forbidden
    no_confirmed = not confirmed_equivalence_claim(bindings)
    no_c = not contains_c(bindings)
    candidate_ok = candidate_mapping_not_promoted(bindings)

    notes: list[str] = []
    if spec["expect"] == "blocked_expected":
        render_ready = False
        status = "blocked_expected" if is_blocked and blocked_ok and no_confirmed and no_c else "fail"
        if status == "fail":
            notes.append("blocked adapter is not safely represented as blocked placeholder")
    else:
        conditions = [
            recipe_path.exists(),
            plan_path.exists(),
            bindings_path.exists(),
            not is_blocked,
            required_present,
            api_nonempty,
            cleanup_nonempty,
            oracle_nonempty,
            input_present,
            mutation_present,
            blocked_ok,
            allowed_only,
            no_confirmed,
            no_c,
            candidate_ok,
        ]
        status = "pass" if all(conditions) else "fail"
        render_ready = status == "pass"
        if is_blocked:
            notes.append("adapter expected pass but binding_status is blocked")
        if not api_nonempty:
            notes.append("api_mapping empty")
        if not cleanup_nonempty:
            notes.append("cleanup_mapping empty")
        if not oracle_nonempty:
            notes.append("oracle_mapping empty")
        if not allowed_only:
            notes.append("target APIs outside allowed set")
        if used_forbidden:
            notes.append(f"forbidden APIs used: {', '.join(used_forbidden)}")

    return {
        "adapter_id": spec["adapter_id"],
        "family": family,
        "target_library": target,
        "adapter_recipe_exists": recipe_path.exists(),
        "slot_filling_plan_exists": plan_path.exists(),
        "slot_bindings_exists": bindings_path.exists(),
        "binding_status": binding_status,
        "render_ready": render_ready,
        "required_top_level_fields_present": required_present,
        "api_mapping_nonempty": api_nonempty,
        "cleanup_mapping_nonempty": cleanup_nonempty,
        "oracle_mapping_nonempty": oracle_nonempty,
        "input_mapping_present": input_present,
        "mutation_slot_mapping_present": mutation_present,
        "blocked_targets_respected": blocked_ok,
        "allowed_target_apis_only": allowed_only,
        "no_confirmed_equivalence_claim": no_confirmed,
        "no_c_generation_detected": no_c,
        "candidate_mapping_not_promoted": candidate_ok,
        "adapter_recipe_not_modified": True,
        "slot_filling_plan_not_modified": True,
        "selected_target_apis": sorted(target_apis),
        "cleanup_apis": sorted(cleanup_apis),
        "forbidden_apis_used": used_forbidden,
        "validation_status": status,
        "notes": notes,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate-bindings", required=True)
    p.add_argument("--target-bindings", required=True)
    p.add_argument("--adapter-root", required=True)
    p.add_argument("--previous-validation", required=True)
    p.add_argument("--validation-rules", required=True)
    p.add_argument("--mapping-gate", required=True)
    p.add_argument("--blocked-mappings", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--apply", choices=["true", "false"], default="false")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    for sub in ["input", "regression_analysis", "backup", "apply", "validation", "reports", "logs"]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    candidate = Path(args.candidate_bindings)
    target = Path(args.target_bindings)
    adapter_root = Path(args.adapter_root)
    previous_validation = load_yaml(Path(args.previous_validation)) or {}
    previous_apply_results = load_yaml(
        Path("artifacts/sprints/apply_pkcs_slot_bindings_and_adapter_validate_v1/validation/adapter_validate_results.yaml")
    ) or {}
    current = load_yaml(target) or {}
    cand = load_yaml(candidate) or {}

    pkcs_path = adapter_root / "pkcs_container_parsing" / "openssl" / "slot_bindings.yaml"
    mbedtls_path = adapter_root / "asn1_nested_boundary" / "mbedtls" / "slot_bindings.yaml"
    pkcs_sha_before = sha256_file(pkcs_path)
    mbedtls_sha_before = sha256_file(mbedtls_path)

    input_summary = {
        "schema": "regression_fixup_input_summary_v1",
        "generated_at": now_iso(),
        "scope": "only fix asn1_nested_boundary -> OpenSSL",
        "pkcs_should_remain_unchanged": True,
        "asn1_mbedtls_should_remain_blocked_expected": True,
        "no_glm_unless_no_candidate": True,
        "glm_called": False,
        "no_render_compile_run": True,
        "no_c_generation": True,
        "inputs": {
            "candidate_bindings": str(candidate),
            "target_bindings": str(target),
            "adapter_root": str(adapter_root),
            "previous_validation": args.previous_validation,
            "validation_rules": args.validation_rules,
            "mapping_gate": args.mapping_gate,
            "blocked_mappings": args.blocked_mappings,
        },
    }
    dump_yaml(out / "input" / "regression_fixup_input_summary.yaml", input_summary)
    write_md(out / "input" / "regression_fixup_input_summary.md", "Regression Fixup Input Summary", input_summary)

    prev_status = previous_candidate_status(previous_validation)
    candidate_exists = candidate.exists()
    current_status = current.get("binding_status")
    current_validation_status = None
    for result in previous_apply_results.get("results", []):
        if isinstance(result, dict) and result.get("adapter_id") == "asn1_nested_boundary_openssl":
            current_validation_status = result.get("validation_status")
            break

    if not candidate_exists:
        regression_type = "missing_candidate"
        should_apply = False
        reason = "previous candidate file missing"
    elif prev_status != "pass":
        regression_type = "candidate_invalid"
        should_apply = False
        reason = f"previous candidate validation status is {prev_status}"
    elif current_status == "blocked_by_mapping_gate":
        regression_type = "pass_candidate_not_applied"
        should_apply = not files_equal(candidate, target)
        reason = "previous pass candidate exists but adapter_recipes target is blocked placeholder"
    else:
        regression_type = "placeholder_overwrote_pass_candidate" if current_status != cand.get("binding_status") else "candidate_invalid"
        should_apply = not files_equal(candidate, target)
        reason = "target differs from previous pass candidate"

    analysis = {
        "adapter_id": "asn1_nested_boundary_openssl",
        "previous_candidate_file": str(candidate),
        "previous_candidate_exists": candidate_exists,
        "previous_candidate_binding_status": cand.get("binding_status"),
        "previous_candidate_validation_status": prev_status,
        "current_adapter_file": str(target),
        "current_adapter_binding_status": current_status,
        "current_adapter_validation_status": current_validation_status,
        "regression_type": regression_type,
        "should_apply_candidate": should_apply,
        "reason": reason,
    }
    dump_yaml(out / "regression_analysis" / "asn1_openssl_regression_analysis.yaml", analysis)
    write_md(out / "regression_analysis" / "asn1_openssl_regression_analysis.md", "ASN1 OpenSSL Regression Analysis", analysis)

    backup_path = out / "backup" / "asn1_nested_boundary_openssl_slot_bindings.before_apply.yaml"
    backup_attempted = args.apply == "true" and should_apply and target.exists()
    backup_written = False
    if backup_attempted:
        shutil.copyfile(target, backup_path)
        backup_written = True
    backup_summary = {
        "backup_attempted": backup_attempted,
        "backup_written": backup_written,
        "backup_path": str(backup_path) if backup_written else None,
        "source_target_file": str(target),
        "reason": reason if backup_attempted else f"backup not needed: {reason}",
    }
    dump_yaml(out / "backup" / "backup_summary.yaml", backup_summary)
    write_md(out / "backup" / "backup_summary.md", "Backup Summary", backup_summary)

    sha_before = sha256_file(target)
    before_text = target.read_text(encoding="utf-8") if target.exists() else ""
    applied = False
    if args.apply == "true" and should_apply:
        shutil.copyfile(candidate, target)
        applied = True
    sha_after = sha256_file(target)
    after_text = target.read_text(encoding="utf-8") if target.exists() else ""
    diff_path = out / "apply" / "asn1_openssl_slot_bindings_before_after.diff"
    diff = "".join(
        difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile="before/asn1_openssl_slot_bindings.yaml",
            tofile="after/asn1_openssl_slot_bindings.yaml",
        )
    )
    write_text(diff_path, diff)
    apply_summary = {
        "apply_attempted": args.apply == "true",
        "applied": applied,
        "target_file": str(target),
        "source_file": str(candidate),
        "backup_path": str(backup_path) if backup_written else None,
        "sha256_before": sha_before,
        "sha256_after": sha_after,
        "diff_path": str(diff_path),
        "notes": ["pass candidate applied"] if applied else [reason],
    }
    dump_yaml(out / "apply" / "apply_asn1_openssl_slot_bindings_summary.yaml", apply_summary)
    write_md(out / "apply" / "apply_asn1_openssl_slot_bindings_summary.md", "Apply ASN1 OpenSSL Slot Bindings Summary", apply_summary)

    results = [validate_adapter(adapter_root, spec) for spec in ADAPTERS]
    counts = {"pass": 0, "blocked_expected": 0, "fail": 0}
    for result in results:
        counts[result["validation_status"]] = counts.get(result["validation_status"], 0) + 1
    validation = {
        "schema": "adapter_validate_results_v1",
        "generated_at": now_iso(),
        "results": results,
        "summary": counts,
        "no_glm": True,
        "no_render_compile_run": True,
        "adapter_recipe_yaml_modified": False,
        "slot_filling_plan_yaml_modified": False,
    }
    dump_yaml(out / "validation" / "adapter_validate_results.yaml", validation)
    write_md(out / "validation" / "adapter_validate_results.md", "Adapter Validate Results", validation)

    render_ready = [
        {
            "adapter_id": r["adapter_id"],
            "family": r["family"],
            "target_library": r["target_library"],
            "reason": "validation pass; render may be planned next but not run in this sprint",
        }
        for r in results
        if r["render_ready"]
    ]
    blocked = [
        {
            "adapter_id": r["adapter_id"],
            "family": r["family"],
            "target_library": r["target_library"],
            "reason": "blocked placeholder preserved; render_ready=false",
        }
        for r in results
        if r["validation_status"] == "blocked_expected"
    ]
    not_ready = [
        {
            "adapter_id": r["adapter_id"],
            "family": r["family"],
            "target_library": r["target_library"],
            "reason": "; ".join(r["notes"]) or r["validation_status"],
        }
        for r in results
        if r["validation_status"] == "fail"
    ]
    readiness = {
        "schema": "render_readiness_summary_v1",
        "render_ready_adapters": render_ready,
        "blocked_adapters": blocked,
        "not_ready_adapters": not_ready,
        "summary": {
            **counts,
            "render_ready_count": len(render_ready),
        },
    }
    dump_yaml(out / "validation" / "render_readiness_summary.yaml", readiness)
    write_md(out / "validation" / "render_readiness_summary.md", "Render Readiness Summary", readiness)

    pkcs_sha_after = sha256_file(pkcs_path)
    mbedtls_sha_after = sha256_file(mbedtls_path)
    blocked_mbedtls = next(r for r in results if r["adapter_id"] == "asn1_nested_boundary_mbedtls")
    safety = {
        "schema": "regression_fixup_safety_checks_v1",
        "pkcs_unchanged": pkcs_sha_before == pkcs_sha_after,
        "pkcs_sha_before": pkcs_sha_before,
        "pkcs_sha_after": pkcs_sha_after,
        "asn1_mbedtls_unchanged": mbedtls_sha_before == mbedtls_sha_after,
        "asn1_mbedtls_sha_before": mbedtls_sha_before,
        "asn1_mbedtls_sha_after": mbedtls_sha_after,
        "adapter_recipe_yaml_modified": False,
        "slot_filling_plan_yaml_modified": False,
        "no_c_generation": all(r["no_c_generation_detected"] for r in results),
        "no_render_compile_run": True,
        "no_confirmed_equivalence_claim": all(r["no_confirmed_equivalence_claim"] for r in results),
        "blocked_target_not_render_ready": not blocked_mbedtls["render_ready"],
        "blocked_targets_respected": all(r["blocked_targets_respected"] for r in results),
    }
    dump_yaml(out / "validation" / "safety_checks.yaml", safety)
    write_md(out / "validation" / "safety_checks.md", "Safety Checks", safety)

    by_id = {r["adapter_id"]: r for r in results}
    if not candidate_exists:
        next_task = "adapter_slot_filling_fixup_asn1_openssl_v1"
        why = "previous pass candidate does not exist"
    elif by_id["asn1_nested_boundary_mbedtls"]["render_ready"]:
        next_task = "adapter_validation_blocking_policy_fixup_v1"
        why = "blocked mbedTLS adapter was incorrectly marked render-ready"
    elif by_id["asn1_nested_boundary_openssl"]["validation_status"] == "fail":
        next_task = "manual_asn1_openssl_slot_binding_review_v1"
        why = "asn1 OpenSSL still fails validation"
    elif (
        by_id["pkcs_container_parsing_openssl"]["validation_status"] == "pass"
        and by_id["asn1_nested_boundary_openssl"]["validation_status"] == "pass"
        and by_id["asn1_nested_boundary_mbedtls"]["validation_status"] == "blocked_expected"
    ):
        next_task = "render_plan_v1"
        why = "pkcs and asn1 OpenSSL pass; mbedTLS remains blocked_expected"
    else:
        next_task = "adapter_validate_triage_v1"
        why = "validation results need triage"
    next_action = {
        "schema": "next_action_after_regression_fixup_v1",
        "next_task_name": next_task,
        "why": why,
    }
    dump_yaml(out / "reports" / "next_action_after_regression_fixup.yaml", next_action)
    write_md(out / "reports" / "next_action_after_regression_fixup.md", "Next Action After Regression Fixup", next_action)

    report = {
        "schema": "adapter_slot_filling_regression_fixup_v1_report",
        "generated_at": now_iso(),
        "only_fixed_asn1_nested_boundary_openssl": True,
        "regression_reason": regression_type,
        "previous_pass_candidate_found": candidate_exists and prev_status == "pass",
        "old_placeholder_backed_up": backup_written,
        "pass_candidate_applied": applied,
        "adapter_validate_results": results,
        "render_ready_adapters": render_ready,
        "blocked_expected_adapters": blocked,
        "not_ready_adapters": not_ready,
        "run_poc": False,
        "render": False,
        "compile_run": False,
        "generated_c": False,
        "glm": False,
        "next_task_name": next_task,
        "safety_checks": safety,
    }
    dump_yaml(out / "reports" / "adapter_slot_filling_regression_fixup_v1_report.yaml", report)
    write_md(out / "reports" / "adapter_slot_filling_regression_fixup_v1_report.md", "Adapter Slot Filling Regression Fixup V1 Report", report)
    write_md(out / "README.md", "adapter_slot_filling_regression_fixup_v1", report)

    print(f"[OK] regression fixup artifacts written to {out}")
    print(f"[SUMMARY] applied: {applied}")
    print(f"[SUMMARY] validation: {counts}")
    print(f"[SUMMARY] next_task_name: {next_task}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
