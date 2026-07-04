#!/usr/bin/env python3
"""Generate recipe slot bindings for wolfSSL-family adapters.

This sprint script intentionally stops at YAML slot bindings. It does not
render C, compile harnesses, run PoCs, or update recipe/template inputs.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


TARGETS = [
    ("pkcs_container_parsing", "openssl"),
    ("asn1_nested_boundary", "openssl"),
    ("asn1_nested_boundary", "mbedtls"),
]

REQUIRED_TOP_LEVEL = [
    "adapter_id",
    "family",
    "source_library",
    "target_library",
    "api_mapping",
    "type_mapping",
    "cleanup_mapping",
    "oracle_mapping",
    "input_mapping",
    "mutation_slot_mapping",
    "validation_notes",
    "risk_notes",
]

C_GENERATION_MARKERS = [
    r"#\s*include\b",
    r"\bint\s+main\s*\(",
    r"\bvoid\s+main\s*\(",
    r"\bstatic\s+(?:int|void|char|unsigned|size_t)\b",
    r"\bgcc\b",
    r"\bclang\b",
    r"\bcmake\b",
    r"\bmake\b",
    r"\breturn\s+0\s*;",
]


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def adapter_id(family: str, target: str) -> str:
    return f"{family}.{target}.family_adapter_recipe_v1"


def slug(family: str, target: str) -> str:
    return f"{family}_{target}"


def run_capture(args: list[str], cwd: Path) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def extract_yaml(text: str) -> tuple[Any | None, str | None]:
    cleaned = text.strip()
    fence = re.search(r"```(?:yaml|yml)?\s*(.*?)```", cleaned, re.S | re.I)
    if fence:
        cleaned = fence.group(1).strip()
    try:
        return yaml.safe_load(cleaned), None
    except yaml.YAMLError as exc:
        return None, str(exc)


def contains_c_generation(obj: Any, raw_text: str = "") -> bool:
    joined = raw_text + "\n" + yaml.safe_dump(obj, sort_keys=False) if obj is not None else raw_text
    return any(re.search(pattern, joined, re.I) for pattern in C_GENERATION_MARKERS)


def list_target_apis(api_mapping: Any) -> list[str]:
    apis: list[str] = []
    if isinstance(api_mapping, dict):
        selected = api_mapping.get("selected_target_api") or api_mapping.get("target_api")
        if isinstance(selected, str):
            apis.append(selected)
        source_to_target = api_mapping.get("source_to_target")
        if isinstance(source_to_target, list):
            for item in source_to_target:
                if isinstance(item, dict):
                    for key in ("target_api", "target", "api"):
                        value = item.get(key)
                        if isinstance(value, str):
                            apis.append(value)
        for value in api_mapping.values():
            if isinstance(value, dict):
                nested = value.get("selected_target_api") or value.get("target_api")
                if isinstance(nested, str):
                    apis.append(nested)
    elif isinstance(api_mapping, list):
        for item in api_mapping:
            if isinstance(item, dict):
                for key in ("selected_target_api", "target_api", "target", "api"):
                    value = item.get(key)
                    if isinstance(value, str):
                        apis.append(value)
            elif isinstance(item, str):
                apis.append(item)
    return sorted(set(apis))


def get_blocked_records(blocked_doc: dict[str, Any], family: str, target: str) -> list[dict[str, Any]]:
    records = blocked_doc.get("blocked_targets", []) if isinstance(blocked_doc, dict) else []
    return [
        r
        for r in records
        if isinstance(r, dict)
        and r.get("family") == family
        and r.get("target_library") == target
    ]


def get_adapter_rules(rules_doc: dict[str, Any], aid: str) -> dict[str, Any]:
    rules = rules_doc.get("adapter_specific_rules", []) if isinstance(rules_doc, dict) else []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("adapter_id") == aid:
            return rule
    return {}


def blocked_placeholder(
    family: str,
    target: str,
    plan: dict[str, Any],
    blocked_records: list[dict[str, Any]],
    reason: str,
) -> dict[str, Any]:
    return {
        "schema": "adapter_slot_bindings_v1",
        "adapter_id": adapter_id(family, target),
        "family": family,
        "source_library": "wolfssl",
        "target_library": target,
        "binding_status": "blocked_by_mapping_gate",
        "mapping_gate": {
            "status": "blocked",
            "reason": reason,
            "blocked_records": blocked_records,
        },
        "api_mapping": {
            "selected_target_api": None,
            "source_to_target": [],
            "confirmed_equivalence": False,
            "notes": "No API binding generated because this requested target is blocked by the slot-filling plan/evidence gate.",
        },
        "type_mapping": {"bindings": []},
        "cleanup_mapping": {"bindings": [], "required": True},
        "oracle_mapping": {
            "bindings": [],
            "required": True,
            "source_oracles": (plan.get("slot_groups", {}).get("oracle_mapping", {}).get("source_oracles", [])),
            "target_observables": [],
        },
        "input_mapping": {"bindings": []},
        "mutation_slot_mapping": {
            "bindings": [
                {"slot_name": s, "target_binding": None, "status": "not_bound_blocked"}
                for s in plan.get("slot_groups", {}).get("mutation_slot_mapping", {}).get("mutation_slots", [])
            ],
            "allowed_mutation_policy": plan.get("slot_groups", {})
            .get("mutation_slot_mapping", {})
            .get("allowed_mutation_policy", ""),
        },
        "validation_notes": {
            "no_confirmed_equivalence_claim": True,
            "blocked_targets_respected": True,
            "no_c_generation": True,
            "cleanup_mapping_present": False,
            "oracle_mapping_present": False,
        },
        "risk_notes": [
            "Target was requested for artifact completeness, but binding is intentionally blocked.",
            "Manual review or stronger evidence is required before adapter generation.",
        ],
    }


def glm_unavailable_placeholder(
    family: str,
    target: str,
    plan: dict[str, Any],
    reason: str,
    call_error: str | None = None,
) -> dict[str, Any]:
    payload = {
        "schema": "adapter_slot_bindings_v1",
        "adapter_id": adapter_id(family, target),
        "family": family,
        "source_library": "wolfssl",
        "target_library": target,
        "binding_status": "glm_unavailable",
        "mapping_gate": {"status": "not_filled", "reason": reason},
        "api_mapping": {
            "selected_target_api": None,
            "source_to_target": [],
            "confirmed_equivalence": False,
        },
        "type_mapping": {"bindings": []},
        "cleanup_mapping": {"bindings": [], "required": True},
        "oracle_mapping": {
            "bindings": [],
            "required": True,
            "source_oracles": (plan.get("slot_groups", {}).get("oracle_mapping", {}).get("source_oracles", [])),
            "target_observables": [],
        },
        "input_mapping": {"bindings": []},
        "mutation_slot_mapping": {
            "bindings": [
                {"slot_name": s, "target_binding": None, "status": "not_bound_glm_unavailable"}
                for s in plan.get("slot_groups", {}).get("mutation_slot_mapping", {}).get("mutation_slots", [])
            ],
            "allowed_mutation_policy": plan.get("slot_groups", {})
            .get("mutation_slot_mapping", {})
            .get("allowed_mutation_policy", ""),
        },
        "validation_notes": {
            "no_confirmed_equivalence_claim": True,
            "blocked_targets_respected": True,
            "no_c_generation": True,
            "cleanup_mapping_present": False,
            "oracle_mapping_present": False,
        },
        "risk_notes": [
            "GLM was unavailable; this is a placeholder and not a validated adapter binding.",
        ],
    }
    if call_error:
        payload["glm_call_error"] = call_error
    return payload


def normalize_glm_payload(obj: Any, family: str, target: str, raw: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {
            "schema": "adapter_slot_bindings_v1",
            "adapter_id": adapter_id(family, target),
            "family": family,
            "source_library": "wolfssl",
            "target_library": target,
            "binding_status": "validation_failed",
            "api_mapping": {"selected_target_api": None, "source_to_target": [], "confirmed_equivalence": False},
            "type_mapping": {"bindings": []},
            "cleanup_mapping": {"bindings": [], "required": True},
            "oracle_mapping": {"bindings": [], "required": True, "target_observables": []},
            "input_mapping": {"bindings": []},
            "mutation_slot_mapping": {"bindings": []},
            "validation_notes": {
                "no_confirmed_equivalence_claim": True,
                "blocked_targets_respected": True,
                "no_c_generation": not contains_c_generation(None, raw),
            },
            "risk_notes": ["GLM output was not a YAML mapping."],
            "_raw_output_parse_error": "not_a_mapping",
        }
    if "slot_bindings" in obj and isinstance(obj["slot_bindings"], dict):
        obj = obj["slot_bindings"]
    obj = dict(obj)
    obj.setdefault("schema", "adapter_slot_bindings_v1")
    obj["adapter_id"] = adapter_id(family, target)
    obj["family"] = family
    obj["source_library"] = "wolfssl"
    obj["target_library"] = target
    obj.setdefault("binding_status", "filled_by_glm")
    obj.setdefault("api_mapping", {"selected_target_api": None, "source_to_target": [], "confirmed_equivalence": False})
    obj.setdefault("type_mapping", {"bindings": []})
    obj.setdefault("cleanup_mapping", {"bindings": []})
    obj.setdefault("oracle_mapping", {"bindings": []})
    obj.setdefault("input_mapping", {"bindings": []})
    obj.setdefault("mutation_slot_mapping", {"bindings": []})
    obj.setdefault("validation_notes", {})
    obj.setdefault("risk_notes", [])
    if isinstance(obj["api_mapping"], dict):
        obj["api_mapping"]["confirmed_equivalence"] = bool(obj["api_mapping"].get("confirmed_equivalence", False))
    return obj


def validate_binding(
    obj: dict[str, Any],
    plan: dict[str, Any],
    schema: dict[str, Any],
    rules: dict[str, Any],
    blocked_records: list[dict[str, Any]],
    raw_text: str = "",
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    for field in schema.get("required_top_level_fields", REQUIRED_TOP_LEVEL):
        if field not in obj:
            errors.append(f"missing required top-level field: {field}")

    if obj.get("adapter_id") != plan.get("adapter_id"):
        errors.append("adapter_id does not match slot plan")
    if obj.get("family") != plan.get("family"):
        errors.append("family does not match slot plan")
    if obj.get("target_library") != plan.get("target_library"):
        errors.append("target_library does not match slot plan")

    no_c_generation = not contains_c_generation(obj, raw_text)
    if not no_c_generation:
        errors.append("possible C generation markers detected")

    api_mapping = obj.get("api_mapping")
    selected_apis = list_target_apis(api_mapping)
    allowed = set(rules.get("allowed_target_apis") or plan.get("slot_groups", {}).get("api_mapping", {}).get("allowed_target_apis", []))
    forbidden = set(rules.get("forbidden_target_apis") or plan.get("slot_groups", {}).get("api_mapping", {}).get("forbidden_target_apis", []))

    if obj.get("binding_status") == "blocked_by_mapping_gate":
        if selected_apis:
            errors.append("blocked binding must not select target APIs")
    elif obj.get("binding_status") == "glm_unavailable":
        if selected_apis:
            errors.append("glm_unavailable placeholder must not select target APIs")
    else:
        if not selected_apis:
            errors.append("no selected target API in api_mapping")
        for api in selected_apis:
            if api not in allowed:
                errors.append(f"target API is not allowed by plan: {api}")
            if api in forbidden:
                errors.append(f"target API is forbidden by plan: {api}")

    if blocked_records:
        blocked_apis = {api for rec in blocked_records for api in rec.get("blocked_apis", [])}
        used_blocked = sorted(blocked_apis.intersection(selected_apis))
        if used_blocked:
            errors.append(f"blocked target API used: {', '.join(used_blocked)}")
        has_no_direct_block = any(rec.get("blocked_reason") == "no_direct_counterpart" for rec in blocked_records)
        all_allowed_apis_blocked = bool(allowed) and allowed.issubset(blocked_apis)
        if (
            obj.get("binding_status") not in ("blocked_by_mapping_gate", "glm_unavailable")
            and (has_no_direct_block or all_allowed_apis_blocked)
        ):
            errors.append("target family/library is blocked by mapping gate but binding_status is not blocked")

    confirmed = False
    if isinstance(api_mapping, dict):
        confirmed = bool(api_mapping.get("confirmed_equivalence"))
    if confirmed:
        errors.append("confirmed_equivalence claim is forbidden")

    cleanup_mapping = obj.get("cleanup_mapping", {})
    if isinstance(cleanup_mapping, dict) and "bindings" in cleanup_mapping:
        cleanup_bindings = cleanup_mapping.get("bindings")
    else:
        cleanup_bindings = cleanup_mapping
    cleanup_present = bool(cleanup_bindings)
    oracle_mapping = obj.get("oracle_mapping", {})
    if isinstance(oracle_mapping, dict) and "bindings" in oracle_mapping:
        oracle_bindings = oracle_mapping.get("bindings")
    else:
        oracle_bindings = oracle_mapping
    oracle_present = bool(oracle_bindings)

    if obj.get("binding_status") not in ("blocked_by_mapping_gate", "glm_unavailable"):
        if not cleanup_present:
            errors.append("cleanup_mapping is required but empty")
        if not oracle_present:
            errors.append("oracle_mapping is required but empty")

    validation_notes = obj.get("validation_notes")
    if isinstance(validation_notes, dict):
        no_claim_note = validation_notes.get("no_confirmed_equivalence_claim")
    elif isinstance(validation_notes, list):
        no_claim_note = any("no confirmed equivalence" in str(v).lower() for v in validation_notes)
    elif isinstance(validation_notes, str):
        no_claim_note = "no confirmed equivalence" in validation_notes.lower()
    else:
        no_claim_note = False
    if not no_claim_note:
        warnings.append("validation_notes does not explicitly include no_confirmed_equivalence_claim=true")

    if obj.get("schema") == "adapter_slot_filling_plan_v1":
        errors.append("GLM returned the slot filling plan rather than slot bindings")

    status = "pass"
    if obj.get("binding_status") == "glm_unavailable":
        status = "glm_unavailable"
    if obj.get("binding_status") == "blocked_by_mapping_gate":
        status = "blocked"
    if errors:
        status = "fail"

    return {
        "adapter_id": obj.get("adapter_id"),
        "family": obj.get("family"),
        "target_library": obj.get("target_library"),
        "binding_status": obj.get("binding_status"),
        "validation_status": status,
        "errors": errors,
        "warnings": warnings,
        "selected_target_apis": selected_apis,
        "required_fields_present": all(field in obj for field in schema.get("required_top_level_fields", REQUIRED_TOP_LEVEL)),
        "cleanup_mapping_present": cleanup_present,
        "oracle_mapping_present": oracle_present,
        "blocked_targets_respected": not any("blocked target API used" in e for e in errors),
        "no_c_generation_detected": no_c_generation,
        "no_confirmed_equivalence_claim": not confirmed,
    }


def make_prompt_bundle(
    family: str,
    target: str,
    plan: dict[str, Any],
    schema: dict[str, Any],
    recipe_text: str,
    context_text: str,
    rules_text: str,
    blocked_text: str,
) -> str:
    return f"""# Adapter Slot Filling Prompt Bundle

adapter_id: `{adapter_id(family, target)}`

Generate YAML only for `adapter_slot_bindings_v1`.

Hard rules:
- Do not generate C code, C snippets, harnesses, compiler commands, or renderable templates.
- Fill `slot_bindings` only; do not alter `adapter_recipe.yaml`.
- Use only target APIs allowed by the slot plan and validation rules.
- Do not use blocked or forbidden target APIs.
- Do not claim confirmed equivalence; candidate mappings must remain candidate-only.
- Preserve cleanup, oracle, input, and mutation-slot mappings as structured YAML.

Expected top-level YAML fields:
`adapter_id`, `family`, `source_library`, `target_library`, `binding_status`,
`mapping_gate`, `api_mapping`, `type_mapping`, `cleanup_mapping`,
`oracle_mapping`, `input_mapping`, `mutation_slot_mapping`,
`validation_notes`, `risk_notes`.

## Slot Filling Plan
```yaml
{yaml.safe_dump(plan, sort_keys=False)}
```

## Slot Bindings Schema
```yaml
{yaml.safe_dump(schema, sort_keys=False)}
```

## Adapter Recipe
```yaml
{recipe_text}
```

## Prompt Context
{context_text}

## Validation Rules
```yaml
{rules_text}
```

## Blocked Targets
```yaml
{blocked_text}
```
"""


def call_glm(prompt: str) -> tuple[str | None, str | None]:
    try:
        from utils.query_llm import get_glm_response
    except Exception as exc:  # pragma: no cover - environment dependent
        return None, f"import_error: {exc}"
    messages = [
        {
            "role": "system",
            "content": (
                "You fill adapter slot bindings as YAML only. "
                "Never emit C code, compiler commands, markdown explanation, or confirmed-equivalence claims."
            ),
        },
        {"role": "user", "content": prompt},
    ]
    try:
        return get_glm_response(messages), None
    except Exception as exc:  # pragma: no cover - network/API dependent
        return None, f"call_error: {type(exc).__name__}: {exc}"


def write_markdown_report(path: Path, title: str, obj: Any) -> None:
    write_text(path, f"# {title}\n\n```yaml\n{yaml.safe_dump(obj, sort_keys=False)}```\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slot-plan-root", required=True)
    parser.add_argument("--adapter-recipe-root", required=True)
    parser.add_argument("--family-template-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-slot-bindings", choices=["true", "false"], default="false")
    parser.add_argument("--glm-mode", choices=["auto", "off"], default="auto")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path.cwd()
    slot_plan_root = Path(args.slot_plan_root)
    adapter_recipe_root = Path(args.adapter_recipe_root)
    family_template_root = Path(args.family_template_root)
    out_dir = Path(args.out_dir)
    write_enabled = args.write_slot_bindings == "true"

    for sub in [
        "input",
        "glm_inventory",
        "prompt_bundles",
        "slot_bindings",
        "validation",
        "write_summary",
        "blocked",
        "reports",
        "logs",
    ]:
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    rc, rg_out, rg_err = run_capture(
        [
            "rg",
            "-n",
            "-i",
            "glm|llm|openai|dashscope|zhipu|slot_bindings|slot filling|adapter_slot|adapter_validate|validate_adapter|render_cases",
            "tools",
            "template_maker",
            "runner",
            "scripts",
            "adapter_recipes",
            "artifacts",
        ],
        repo,
    )
    write_text(out_dir / "glm_inventory" / "glm_slot_filling_related_rg.txt", rg_out + ("\n[stderr]\n" + rg_err if rg_err else ""))
    rc_find, find_out, find_err = run_capture(["find", "tools", "template_maker", "runner", "scripts", "-maxdepth", "4", "-type", "f"], repo)
    write_text(out_dir / "glm_inventory" / "tooling_files.txt", find_out + ("\n[stderr]\n" + find_err if find_err else ""))

    zhipuai_importable = False
    query_llm_importable = False
    try:
        import zhipuai  # noqa: F401

        zhipuai_importable = True
    except Exception:
        zhipuai_importable = False
    try:
        from utils import query_llm  # noqa: F401

        query_llm_importable = True
    except Exception:
        query_llm_importable = False

    glm_env_available = bool(os.environ.get("ZHIPUAI_API_KEY") or os.environ.get("GLM_API_KEY"))
    glm_can_call = args.glm_mode == "auto" and glm_env_available and query_llm_importable and zhipuai_importable

    blocked_doc = load_yaml(slot_plan_root / "blocked" / "blocked_slot_filling_targets.yaml") or {}
    rules_doc = load_yaml(slot_plan_root / "validation_rules" / "adapter_slot_binding_validation_rules.yaml") or {}
    blocked_text = (slot_plan_root / "blocked" / "blocked_slot_filling_targets.yaml").read_text(encoding="utf-8")
    rules_text = (slot_plan_root / "validation_rules" / "adapter_slot_binding_validation_rules.yaml").read_text(encoding="utf-8")

    input_items: list[dict[str, Any]] = []
    validations: list[dict[str, Any]] = []
    write_records: list[dict[str, Any]] = []
    glm_records: list[dict[str, Any]] = []
    blocked_records_summary: list[dict[str, Any]] = []

    for family, target in TARGETS:
        aid = adapter_id(family, target)
        plan_path = slot_plan_root / "slot_filling_plans" / family / target / "slot_filling_plan.yaml"
        schema_path = slot_plan_root / "schemas" / f"{family}_{target}_slot_bindings_schema.yaml"
        prompt_context_path = slot_plan_root / "prompt_contexts" / f"{family}_{target}_prompt_context.md"
        recipe_path = adapter_recipe_root / family / target / "adapter_recipe.yaml"

        plan = load_yaml(plan_path) or {}
        schema = load_yaml(schema_path) or {}
        recipe_text = recipe_path.read_text(encoding="utf-8") if recipe_path.exists() else ""
        context_text = prompt_context_path.read_text(encoding="utf-8") if prompt_context_path.exists() else ""
        adapter_rules = get_adapter_rules(rules_doc, aid)
        target_blocked_records = get_blocked_records(blocked_doc, family, target)
        plan_allowed_apis = set(
            plan.get("slot_groups", {}).get("api_mapping", {}).get("allowed_target_apis", [])
        )
        blocked_apis_for_target = {
            api for rec in target_blocked_records for api in rec.get("blocked_apis", [])
        }
        has_no_direct_block = any(
            rec.get("blocked_reason") == "no_direct_counterpart" for rec in target_blocked_records
        )
        target_is_blocked = bool(target_blocked_records) and (
            has_no_direct_block
            or (bool(plan_allowed_apis) and plan_allowed_apis.issubset(blocked_apis_for_target))
        )

        input_items.append(
            {
                "adapter_id": aid,
                "family": family,
                "target_library": target,
                "plan_path": str(plan_path),
                "schema_path": str(schema_path),
                "prompt_context_path": str(prompt_context_path),
                "adapter_recipe_path": str(recipe_path),
                "blocked_by_mapping_gate": target_is_blocked,
                "blocked_reasons": sorted({r.get("blocked_reason") for r in target_blocked_records}),
            }
        )
        if target_blocked_records:
            blocked_records_summary.extend(target_blocked_records)

        prompt = make_prompt_bundle(
            family, target, plan, schema, recipe_text, context_text, rules_text, blocked_text
        )
        prompt_path = out_dir / "prompt_bundles" / f"{slug(family, target)}_prompt_bundle.md"
        write_text(prompt_path, prompt)

        raw_glm = ""
        parse_error = None
        if target_is_blocked:
            binding = blocked_placeholder(
                family,
                target,
                plan,
                target_blocked_records,
                "target family/library requires manual review or is blocked by the mapping gate",
            )
            glm_status = "not_called_blocked"
        elif not glm_can_call:
            reason = "glm_mode_off" if args.glm_mode == "off" else "missing GLM/ZhipuAI environment or tooling"
            binding = glm_unavailable_placeholder(family, target, plan, reason)
            glm_status = "not_called_unavailable"
        else:
            raw_glm, call_error = call_glm(prompt)
            raw_path = out_dir / "logs" / f"{slug(family, target)}_glm_raw.txt"
            write_text(raw_path, raw_glm or f"[GLM unavailable]\n{call_error}\n")
            if call_error:
                binding = glm_unavailable_placeholder(family, target, plan, "GLM call failed", call_error)
                glm_status = "call_failed"
            else:
                parsed, parse_error = extract_yaml(raw_glm or "")
                binding = normalize_glm_payload(parsed, family, target, raw_glm or "")
                if parse_error:
                    binding["binding_status"] = "validation_failed"
                    binding["_raw_output_parse_error"] = parse_error
                glm_status = "called"

        if target_is_blocked and glm_can_call:
            write_text(out_dir / "logs" / f"{slug(family, target)}_glm_raw.txt", "[not called: target blocked by mapping gate]\n")

        glm_records.append(
            {
                "adapter_id": aid,
                "family": family,
                "target_library": target,
                "glm_status": glm_status,
                "raw_output_path": str(out_dir / "logs" / f"{slug(family, target)}_glm_raw.txt"),
                "parse_error": parse_error,
            }
        )

        validation = validate_binding(
            binding,
            plan,
            schema,
            adapter_rules,
            target_blocked_records,
            raw_text=raw_glm or "",
        )
        validations.append(validation)

        sprint_binding_path = out_dir / "slot_bindings" / family / target / "slot_bindings.yaml"
        dump_yaml(sprint_binding_path, binding)

        record = {
            "adapter_id": aid,
            "family": family,
            "target_library": target,
            "write_attempted": write_enabled,
            "source_path": str(sprint_binding_path),
            "target_path": str(adapter_recipe_root / family / target / "slot_bindings.yaml"),
            "written": False,
            "collision": False,
            "draft_only": False,
        }
        if write_enabled:
            target_path = adapter_recipe_root / family / target / "slot_bindings.yaml"
            if target_path.exists():
                draft_path = out_dir / "write_summary" / "draft_slot_bindings" / family / target / "slot_bindings.yaml"
                dump_yaml(draft_path, binding)
                record.update({"collision": True, "draft_only": True, "draft_path": str(draft_path)})
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(sprint_binding_path, target_path)
                record["written"] = True
        write_records.append(record)

    input_summary = {
        "schema": "adapter_slot_filling_input_summary_v1",
        "generated_at": now_iso(),
        "slot_plan_root": str(slot_plan_root),
        "adapter_recipe_root": str(adapter_recipe_root),
        "family_template_root": str(family_template_root),
        "targets": input_items,
        "forbidden_actions": [
            "no_poc_run",
            "no_compile_run",
            "no_render_cases",
            "no_c_generation",
            "no_adapter_recipe_yaml_modification",
            "no_family_template_modification",
            "no_knowledge_layer_modification",
            "no_git_add_commit_push",
        ],
    }
    dump_yaml(out_dir / "input" / "adapter_slot_filling_input_summary.yaml", input_summary)
    write_markdown_report(out_dir / "input" / "adapter_slot_filling_input_summary.md", "Adapter Slot Filling Input Summary", input_summary)

    glm_inventory = {
        "schema": "glm_slot_filling_tooling_inventory_v1",
        "generated_at": now_iso(),
        "existing_glm_tooling_found": query_llm_importable,
        "zhipuai_importable": zhipuai_importable,
        "zhipuai_api_key_set": bool(os.environ.get("ZHIPUAI_API_KEY")),
        "glm_api_key_set": bool(os.environ.get("GLM_API_KEY")),
        "glm_mode": args.glm_mode,
        "glm_can_call": glm_can_call,
        "method": "utils.query_llm.get_glm_response" if glm_can_call else "placeholder_without_glm",
        "raw_search_files": [
            str(out_dir / "glm_inventory" / "glm_slot_filling_related_rg.txt"),
            str(out_dir / "glm_inventory" / "tooling_files.txt"),
        ],
        "calls": glm_records,
    }
    dump_yaml(out_dir / "glm_inventory" / "glm_slot_filling_tooling_inventory.yaml", glm_inventory)
    write_markdown_report(out_dir / "glm_inventory" / "glm_slot_filling_tooling_inventory.md", "GLM Slot Filling Tooling Inventory", glm_inventory)

    status_counts: dict[str, int] = {}
    for item in validations:
        status_counts[item["validation_status"]] = status_counts.get(item["validation_status"], 0) + 1
    validation_summary = {
        "schema": "slot_binding_validation_results_v1",
        "generated_at": now_iso(),
        "total": len(validations),
        "status_counts": status_counts,
        "results": validations,
        "required_fields_present": all(v["required_fields_present"] for v in validations),
        "cleanup_mapping_present": all(v["cleanup_mapping_present"] for v in validations if v["validation_status"] == "pass"),
        "oracle_mapping_present": all(v["oracle_mapping_present"] for v in validations if v["validation_status"] == "pass"),
        "blocked_targets_respected": all(v["blocked_targets_respected"] for v in validations),
        "no_c_generation_detected": all(v["no_c_generation_detected"] for v in validations),
        "no_confirmed_equivalence_claim": all(v["no_confirmed_equivalence_claim"] for v in validations),
    }
    dump_yaml(out_dir / "validation" / "slot_binding_validation_results.yaml", validation_summary)
    write_markdown_report(out_dir / "validation" / "slot_binding_validation_results.md", "Slot Binding Validation Results", validation_summary)

    write_summary = {
        "schema": "slot_bindings_write_summary_v1",
        "generated_at": now_iso(),
        "write_enabled": write_enabled,
        "written_count": sum(1 for r in write_records if r["written"]),
        "collision_count": sum(1 for r in write_records if r["collision"]),
        "draft_only_count": sum(1 for r in write_records if r["draft_only"]),
        "adapter_recipe_yaml_modified": False,
        "slot_filling_plan_yaml_modified": False,
        "records": write_records,
    }
    dump_yaml(out_dir / "write_summary" / "slot_bindings_write_summary.yaml", write_summary)
    write_markdown_report(out_dir / "write_summary" / "slot_bindings_write_summary.md", "Slot Bindings Write Summary", write_summary)

    blocked_summary = {
        "schema": "blocked_targets_respected_v1",
        "generated_at": now_iso(),
        "respected": validation_summary["blocked_targets_respected"],
        "pkcs_container_parsing_mbedtls": "not requested for slot filling; blocked/no_direct_counterpart records preserved",
        "weak_evidence_mappings": "not promoted to confirmed equivalence; forbidden APIs rejected",
        "needs_manual_review_mappings": "asn1_nested_boundary.mbedtls written as blocked_by_mapping_gate placeholder",
        "blocked_records_seen": blocked_records_summary,
    }
    dump_yaml(out_dir / "blocked" / "blocked_targets_respected.yaml", blocked_summary)
    write_markdown_report(out_dir / "blocked" / "blocked_targets_respected.md", "Blocked Targets Respected", blocked_summary)

    if status_counts.get("fail"):
        next_task = "adapter_slot_filling_fixup_v1"
        why = "At least one generated binding failed structural or gate validation."
    elif status_counts.get("glm_unavailable"):
        next_task = "glm_configuration_or_manual_slot_review_v1"
        why = "At least one adapter could not be filled because GLM was unavailable."
    elif status_counts.get("blocked"):
        next_task = "manual_mapping_gate_review_v1"
        why = "At least one requested target is intentionally blocked by evidence/manual-review gate."
    else:
        next_task = "adapter_validate_v1"
        why = "All generated slot bindings passed local slot validation."

    next_action = {
        "schema": "next_action_after_adapter_slot_filling_v1",
        "generated_at": now_iso(),
        "next_task_name": next_task,
        "why": why,
        "do_not_run_yet": [
            "render_cases",
            "compile_run",
            "PoC execution",
        ],
    }
    dump_yaml(out_dir / "reports" / "next_action_after_adapter_slot_filling.yaml", next_action)
    write_markdown_report(out_dir / "reports" / "next_action_after_adapter_slot_filling.md", "Next Action After Adapter Slot Filling", next_action)

    report = {
        "schema": "adapter_slot_filling_v1_report",
        "generated_at": now_iso(),
        "input_summary": str(out_dir / "input" / "adapter_slot_filling_input_summary.yaml"),
        "glm_inventory": str(out_dir / "glm_inventory" / "glm_slot_filling_tooling_inventory.yaml"),
        "validation": validation_summary,
        "write_summary": write_summary,
        "blocked_targets": blocked_summary,
        "next_action": next_action,
        "actions_not_performed": {
            "run_poc": False,
            "compile_run": False,
            "glm": any(r["glm_status"] == "called" for r in glm_records),
            "render": False,
            "generated_c": False,
            "pattern_bank_modified": False,
            "scheduler_seed_modified": False,
            "knowledge_raw_modified": False,
            "git_add_commit_push": False,
        },
    }
    dump_yaml(out_dir / "reports" / "adapter_slot_filling_v1_report.yaml", report)
    write_markdown_report(out_dir / "reports" / "adapter_slot_filling_v1_report.md", "Adapter Slot Filling V1 Report", report)

    readme = f"""# adapter_slot_filling_v1

Generated at: `{now_iso()}`

This sprint fills or blocks structured `slot_bindings.yaml` artifacts only.
It does not generate C, render cases, compile, run PoCs, modify Pattern Bank,
or change family templates.

Key files:
- `input/adapter_slot_filling_input_summary.yaml`
- `glm_inventory/glm_slot_filling_tooling_inventory.yaml`
- `slot_bindings/*/*/slot_bindings.yaml`
- `validation/slot_binding_validation_results.yaml`
- `write_summary/slot_bindings_write_summary.yaml`
- `blocked/blocked_targets_respected.yaml`
- `reports/adapter_slot_filling_v1_report.yaml`
"""
    write_text(out_dir / "README.md", readme)

    print(f"[OK] adapter_slot_filling_v1 artifacts written to {out_dir}")
    print(f"[SUMMARY] validation status counts: {status_counts}")
    print(f"[SUMMARY] next_task_name: {next_task}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
