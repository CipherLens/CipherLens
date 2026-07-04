#!/usr/bin/env python3
"""Apply fixed PKCS slot bindings and validate three concrete adapters.

No GLM, no render, no compile/run, no C generation.
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
        "allowed_trigger_apis": {"PKCS12_parse", "PKCS7_verify"},
        "allowed_cleanup_apis": {"PKCS12_free", "PKCS7_free"},
        "forbidden_apis": {"d2i_PKCS7"},
        "forbidden_terms": {"mbedtls"},
    },
    {
        "adapter_id": "asn1_nested_boundary_openssl",
        "family": "asn1_nested_boundary",
        "target_library": "openssl",
        "expect": "pass",
        "allowed_trigger_apis": {"ASN1_item_d2i"},
        "allowed_cleanup_apis": set(),
        "forbidden_apis": {"d2i_X509"},
        "forbidden_terms": set(),
    },
    {
        "adapter_id": "asn1_nested_boundary_mbedtls",
        "family": "asn1_nested_boundary",
        "target_library": "mbedtls",
        "expect": "blocked_expected",
        "allowed_trigger_apis": set(),
        "allowed_cleanup_apis": set(),
        "forbidden_apis": {"mbedtls_x509_crt_parse_der"},
        "forbidden_terms": set(),
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
    if not a.exists() or not b.exists():
        return False
    return a.read_bytes() == b.read_bytes()


def contains_c(obj: Any) -> bool:
    text = yaml.safe_dump(obj, sort_keys=False) if obj is not None else ""
    return any(re.search(pattern, text, re.I) for pattern in C_MARKERS)


def collect_api_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, str):
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value):
            if token.startswith(("PKCS", "ASN1", "d2i_", "mbedtls")):
                names.add(token)
    elif isinstance(value, list):
        for item in value:
            names.update(collect_api_names(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            names.update(collect_api_names(key))
            names.update(collect_api_names(item))
    return names


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


def candidate_promoted(obj: Any) -> bool:
    text = yaml.safe_dump(obj, sort_keys=False).lower() if obj is not None else ""
    if confirmed_equivalence_claim(obj):
        return True
    return "candidate mapping only" not in text and "blocked_by_mapping_gate" not in text


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
    trigger_apis = collect_api_names(bindings.get("api_mapping"))
    cleanup_apis = collect_api_names(bindings.get("cleanup_mapping"))
    used_forbidden = sorted((trigger_apis | cleanup_apis).intersection(spec["forbidden_apis"]))
    forbidden_terms_used = sorted(
        term for term in spec["forbidden_terms"] if term.lower() in yaml.safe_dump(bindings, sort_keys=False).lower()
    )
    allowed_target_apis_only = all(
        api in spec["allowed_trigger_apis"] or api in spec["allowed_cleanup_apis"]
        for api in (trigger_apis | cleanup_apis)
        if api not in {"PKCS12", "PKCS7"}
    )

    required_present = all(field in bindings for field in REQUIRED_FIELDS)
    api_nonempty = nonempty(bindings.get("api_mapping"))
    cleanup_nonempty = nonempty(bindings.get("cleanup_mapping"))
    oracle_nonempty = nonempty(bindings.get("oracle_mapping"))
    input_present = "input_mapping" in bindings and nonempty(bindings.get("input_mapping"))
    mutation_present = "mutation_slot_mapping" in bindings and nonempty(bindings.get("mutation_slot_mapping"))
    no_confirmed = not confirmed_equivalence_claim(bindings)
    no_c = not contains_c(bindings)
    blocked_ok = not used_forbidden and not forbidden_terms_used
    candidate_not_promoted = not candidate_promoted(bindings)

    notes: list[str] = []
    if spec["expect"] == "blocked_expected":
        render_ready = False
        if is_blocked and blocked_ok and no_confirmed and no_c:
            status = "blocked_expected"
        else:
            status = "fail"
            notes.append("blocked adapter is not safely represented as blocked placeholder")
    else:
        render_ready = False
        pass_conditions = [
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
            allowed_target_apis_only,
            no_confirmed,
            no_c,
            candidate_not_promoted,
        ]
        status = "pass" if all(pass_conditions) else "fail"
        render_ready = status == "pass"
        if is_blocked:
            notes.append("adapter expected pass but binding_status is blocked")
        if not api_nonempty:
            notes.append("api_mapping empty")
        if not cleanup_nonempty:
            notes.append("cleanup_mapping empty")
        if not oracle_nonempty:
            notes.append("oracle_mapping empty")
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
        "allowed_target_apis_only": allowed_target_apis_only,
        "no_confirmed_equivalence_claim": no_confirmed,
        "no_c_generation_detected": no_c,
        "candidate_mapping_not_promoted": candidate_not_promoted,
        "adapter_recipe_not_modified": True,
        "slot_filling_plan_not_modified": True,
        "selected_apis": sorted(trigger_apis),
        "cleanup_apis": sorted(cleanup_apis),
        "forbidden_apis_used": used_forbidden,
        "forbidden_terms_used": forbidden_terms_used,
        "validation_status": status,
        "notes": notes,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fixed-bindings", required=True)
    p.add_argument("--target-bindings", required=True)
    p.add_argument("--adapter-root", required=True)
    p.add_argument("--validation-rules", required=True)
    p.add_argument("--mapping-gate", required=True)
    p.add_argument("--blocked-mappings", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--apply", choices=["true", "false"], default="false")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    for sub in ["input", "pre_apply", "backup", "apply", "validator_inventory", "validation", "reports", "logs"]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    fixed = Path(args.fixed_bindings)
    target = Path(args.target_bindings)
    adapter_root = Path(args.adapter_root)
    fixup_report = load_yaml(Path("artifacts/sprints/adapter_slot_filling_fixup_v1/reports/adapter_slot_filling_fixup_v1_report.yaml")) or {}
    fixup_validation = load_yaml(Path("artifacts/sprints/adapter_slot_filling_fixup_v1/validation/pkcs_fixup_validation.yaml")) or {}
    write_summary = load_yaml(Path("artifacts/sprints/adapter_slot_filling_fixup_v1/write_summary/pkcs_fixup_write_summary.yaml")) or {}

    input_summary = {
        "schema": "apply_and_validate_input_summary_v1",
        "generated_at": now_iso(),
        "scope": "apply only pkcs fixed slot_bindings and validate three concrete adapters",
        "pkcs_fixed_bindings": str(fixed),
        "pkcs_target_bindings": str(target),
        "adapter_root": str(adapter_root),
        "validation_rules": args.validation_rules,
        "mapping_gate": args.mapping_gate,
        "blocked_mappings": args.blocked_mappings,
        "no_glm": True,
        "no_render_compile_run": True,
        "no_c_generation": True,
        "adapter_recipe_yaml_modified": False,
        "slot_filling_plan_yaml_modified": False,
        "blocked_placeholder_policy": "blocked adapters must remain render_ready=false",
    }
    dump_yaml(out / "input" / "apply_and_validate_input_summary.yaml", input_summary)
    write_md(out / "input" / "apply_and_validate_input_summary.md", "Apply And Validate Input Summary", input_summary)

    files_equal_before = files_equal(fixed, target)
    target_exists = target.exists()
    fixed_exists = fixed.exists()
    safe_prev = fixup_validation.get("validation_status") == "pass" and bool(write_summary.get("safe_to_apply"))
    should_apply = args.apply == "true" and fixed_exists and safe_prev and not files_equal_before
    reason = "ready_to_apply"
    if not fixed_exists:
        reason = "fixed_source_missing"
    elif not safe_prev:
        reason = "previous_fixup_not_safe_to_apply"
    elif files_equal_before:
        reason = "already_applied"
    elif args.apply != "true":
        reason = "apply_flag_false"
    pre_apply = {
        "pkcs_target_file": str(target),
        "pkcs_target_exists": target_exists,
        "pkcs_target_current_validation": "not_revalidated_before_apply",
        "fixed_source_file": str(fixed),
        "fixed_source_exists": fixed_exists,
        "fixed_source_validation": fixup_validation.get("validation_status"),
        "apply_script_exists": Path("artifacts/sprints/adapter_slot_filling_fixup_v1/write_summary/apply_fixed_slot_bindings.sh").exists(),
        "safe_to_apply_from_previous_report": safe_prev,
        "files_equal_before_apply": files_equal_before,
        "should_apply": should_apply,
        "reason": reason,
    }
    dump_yaml(out / "pre_apply" / "pre_apply_status.yaml", pre_apply)
    write_md(out / "pre_apply" / "pre_apply_status.md", "Pre Apply Status", pre_apply)

    backup_path = out / "backup" / "pkcs_container_parsing_openssl_slot_bindings.before_apply.yaml"
    backup_attempted = should_apply and target_exists
    backup_written = False
    if backup_attempted:
        shutil.copyfile(target, backup_path)
        backup_written = True
    backup_summary = {
        "backup_attempted": backup_attempted,
        "backup_written": backup_written,
        "backup_path": str(backup_path) if backup_written else None,
        "source_target_file": str(target),
        "reason": "target differs from fixed source and apply requested" if backup_attempted else reason,
    }
    dump_yaml(out / "backup" / "backup_summary.yaml", backup_summary)
    write_md(out / "backup" / "backup_summary.md", "Backup Summary", backup_summary)

    sha_before = sha256_file(target)
    before_text = target.read_text(encoding="utf-8") if target.exists() else ""
    applied = False
    if should_apply:
        shutil.copyfile(fixed, target)
        applied = True
    sha_after = sha256_file(target)
    after_text = target.read_text(encoding="utf-8") if target.exists() else ""
    diff = "".join(
        difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile="before/pkcs_slot_bindings.yaml",
            tofile="after/pkcs_slot_bindings.yaml",
        )
    )
    diff_path = out / "apply" / "pkcs_slot_bindings_before_after.diff"
    write_text(diff_path, diff)
    apply_summary = {
        "apply_attempted": args.apply == "true",
        "applied": applied,
        "target_file": str(target),
        "source_file": str(fixed),
        "backup_path": str(backup_path) if backup_written else None,
        "sha256_before": sha_before,
        "sha256_after": sha_after,
        "diff_path": str(diff_path),
        "notes": [reason] if not applied else ["fixed pkcs slot_bindings applied"],
    }
    dump_yaml(out / "apply" / "apply_pkcs_slot_bindings_summary.yaml", apply_summary)
    write_md(out / "apply" / "apply_pkcs_slot_bindings_summary.md", "Apply PKCS Slot Bindings Summary", apply_summary)

    rg_file = out / "validator_inventory" / "adapter_validate_related_rg.txt"
    tools_file = out / "validator_inventory" / "tooling_files.txt"
    rg_text = rg_file.read_text(encoding="utf-8") if rg_file.exists() else ""
    inventory = {
        "schema": "adapter_validate_tooling_inventory_v1",
        "existing_validator_found": "migration/adapter_validate.py" in rg_text or Path("migration/adapter_validate.py").exists(),
        "existing_validator_paths": [
            p for p in ["migration/adapter_validate.py"] if Path(p).exists()
        ],
        "existing_validator_cli": "python3 -m migration.adapter_validate --adapter-root <root> --out-root <out>",
        "existing_validator_used": False,
        "new_lightweight_validator_added": True,
        "new_validator_path": "tools/adapters/apply_pkcs_slot_bindings_and_adapter_validate_v1.py",
        "why_lightweight_validator": "existing adapter_validate validates adapter.yaml flows; this sprint validates slot_bindings.yaml policy without render/compile",
        "scope": "structure and policy validation only; no render/compile/run",
        "raw_search_files": [str(rg_file), str(tools_file)],
    }
    dump_yaml(out / "validator_inventory" / "adapter_validate_tooling_inventory.yaml", inventory)
    write_md(out / "validator_inventory" / "adapter_validate_tooling_inventory.md", "Adapter Validate Tooling Inventory", inventory)

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

    by_id = {r["adapter_id"]: r for r in results}
    if by_id["pkcs_container_parsing_openssl"]["validation_status"] == "fail":
        next_task = "manual_pkcs_slot_binding_review_v1"
        why = "pkcs OpenSSL validation failed"
    elif by_id["asn1_nested_boundary_openssl"]["validation_status"] == "fail":
        next_task = "adapter_slot_filling_regression_fixup_v1"
        why = "asn1 OpenSSL validation failed or regressed"
    elif by_id["asn1_nested_boundary_mbedtls"]["render_ready"]:
        next_task = "adapter_validation_blocking_policy_fixup_v1"
        why = "blocked mbedTLS adapter was incorrectly marked render-ready"
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
    next_action = {"schema": "next_action_after_adapter_validate_v1", "next_task_name": next_task, "why": why}
    dump_yaml(out / "reports" / "next_action_after_adapter_validate.yaml", next_action)
    write_md(out / "reports" / "next_action_after_adapter_validate.md", "Next Action After Adapter Validate", next_action)

    report = {
        "schema": "apply_pkcs_slot_bindings_and_adapter_validate_v1_report",
        "generated_at": now_iso(),
        "pkcs_fixed_slot_bindings_applied": applied,
        "old_file_backed_up": backup_written,
        "only_pkcs_slot_bindings_overwritten": applied,
        "adapter_recipe_yaml_modified": False,
        "slot_filling_plan_yaml_modified": False,
        "adapter_validate_results": results,
        "render_ready_adapters": render_ready,
        "blocked_expected_adapters": blocked,
        "not_ready_adapters": not_ready,
        "run_poc": False,
        "render": False,
        "compile_run": False,
        "generated_c": False,
        "glm": False,
        "pattern_bank_modified": False,
        "scheduler_seed_modified": False,
        "knowledge_raw_modified": False,
        "next_task_name": next_task,
    }
    dump_yaml(out / "reports" / "apply_pkcs_slot_bindings_and_adapter_validate_v1_report.yaml", report)
    write_md(out / "reports" / "apply_pkcs_slot_bindings_and_adapter_validate_v1_report.md", "Apply PKCS Slot Bindings And Adapter Validate V1 Report", report)
    write_md(out / "README.md", "apply_pkcs_slot_bindings_and_adapter_validate_v1", report)

    print(f"[OK] apply and validate artifacts written to {out}")
    print(f"[SUMMARY] applied: {applied}")
    print(f"[SUMMARY] validation: {counts}")
    print(f"[SUMMARY] next_task_name: {next_task}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
