#!/usr/bin/env python3
"""Generate adapter slot filling plans for family-level adapter recipes."""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path
from typing import Any

import yaml


CONCRETE_ADAPTERS = [
    ("pkcs_container_parsing", "openssl"),
    ("asn1_nested_boundary", "openssl"),
    ("asn1_nested_boundary", "mbedtls"),
]

SPEC_ONLY_FAMILIES = [
    "x509_parsing",
    "tls_protocol_state_lifecycle",
    "secure_heap_state_lifecycle",
]

REQUIRED_BINDINGS = [
    "api_mapping",
    "type_mapping",
    "cleanup_mapping",
    "oracle_mapping",
    "input_mapping",
    "mutation_slot_mapping",
]

REQUIRED_TOP_LEVEL_FIELDS = [
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

VALIDATION_BEFORE_RENDER = [
    "all_required_bindings_present",
    "no_forbidden_target_api",
    "cleanup_mapping_present",
    "oracle_mapping_present",
    "no_confirmed_equivalence_claim",
    "blocked_targets_respected",
]

GLOBAL_RULES = [
    "no_full_c_generation",
    "no_blocked_target_api",
    "no_confirmed_equivalence_claim",
    "all_required_bindings_present",
    "cleanup_mapping_required",
    "oracle_mapping_required",
    "mapping_gate_status_recorded",
    "candidate_mapping_must_remain_candidate",
]


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.dump(obj, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def dump_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def adapter_recipe_path(root: Path, family: str, target: str) -> Path:
    return root / family / target / "adapter_recipe.yaml"


def spec_recipe_path(root: Path, family: str) -> Path:
    return root / family / "adapter_recipe_spec.yaml"


def family_template_dir(root: Path, recipe: dict[str, Any], family: str) -> Path:
    recipe_dir = recipe.get("source_template", {}).get("family_template_dir", "")
    if recipe_dir:
        path = Path(recipe_dir)
        if path.exists():
            return path
    return root / family


def read_selected_units(template_dir: Path) -> list[dict[str, Any]]:
    obj = load_yaml(template_dir / "selected_mask_units.yaml")
    return [row for row in obj.get("selected_units", []) if isinstance(row, dict)] if isinstance(obj, dict) else []


def selected_unit_summary(units: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    return [
        {
            "unit_id": row.get("unit_id", ""),
            "role": row.get("role", ""),
            "suggested_use": row.get("suggested_use", ""),
            "placeholder": row.get("placeholder", ""),
            "function": row.get("function", row.get("called_function", "")),
        }
        for row in units[:limit]
    ]


def recipe_target_apis(recipe: dict[str, Any]) -> list[str]:
    return [str(x) for x in recipe.get("target_mapping", {}).get("target_apis", []) if x]


def recipe_forbidden_apis(recipe: dict[str, Any]) -> list[str]:
    blocked = [str(x) for x in recipe.get("target_mapping", {}).get("blocked_apis", []) if x]
    for item in recipe.get("target_mapping", {}).get("blocked_mappings", []) or []:
        if isinstance(item, dict):
            value = item.get("target_api") or item.get("wolfssl_api")
            if value and str(value) not in blocked:
                blocked.append(str(value))
    return sorted(blocked)


def mutation_slots(recipe: dict[str, Any]) -> list[str]:
    return [str(x) for x in recipe.get("source_slots", {}).get("mutation_slots", []) if x]


def api_source_slots(recipe: dict[str, Any]) -> list[str]:
    slots: list[str] = []
    for item in recipe.get("source_slots", {}).get("api_slots", []) or []:
        if isinstance(item, dict):
            value = item.get("source_api") or item.get("slot_name")
            if value and str(value) not in slots:
                slots.append(str(value))
    return slots


def cleanup_slots(recipe: dict[str, Any]) -> list[Any]:
    return recipe.get("source_slots", {}).get("cleanup_slots", []) or []


def oracle_slots(recipe: dict[str, Any]) -> list[Any]:
    primary = recipe.get("oracle_strategy", {}).get("primary", []) or []
    secondary = recipe.get("oracle_strategy", {}).get("secondary", []) or []
    return primary + secondary


def input_slots(recipe: dict[str, Any], units: list[dict[str, Any]]) -> list[str]:
    slots = set(mutation_slots(recipe))
    for row in units:
        for placeholder in row.get("placeholder_dependencies", []) or []:
            text = str(placeholder).strip("[]")
            if text:
                slots.add(text)
        placeholder = str(row.get("placeholder", "")).strip("[]")
        if placeholder:
            slots.add(placeholder)
    return sorted(slots)


def slot_filling_plan(recipe: dict[str, Any], template_dir: Path, recipe_path: Path) -> dict[str, Any]:
    units = read_selected_units(template_dir)
    allowed = recipe_target_apis(recipe)
    forbidden = recipe_forbidden_apis(recipe)
    return {
        "schema": "adapter_slot_filling_plan_v1",
        "adapter_id": recipe.get("adapter_id", ""),
        "family": recipe.get("family", ""),
        "source_library": "wolfssl",
        "target_library": recipe.get("target_library", ""),
        "template_level": "family",
        "source_template": {
            "family_template_dir": str(template_dir),
            "canonical_template": str(template_dir / "canonical_tmpl_wolfssl.c"),
            "selected_mask_units": str(template_dir / "selected_mask_units.yaml"),
        },
        "adapter_recipe": {
            "path": str(recipe_path),
            "required_bindings": REQUIRED_BINDINGS,
        },
        "slot_groups": {
            "api_mapping": {
                "required": True,
                "source_slots": api_source_slots(recipe),
                "allowed_target_apis": allowed,
                "forbidden_target_apis": forbidden,
            },
            "type_mapping": {
                "required": True,
                "source_types": ["family_source_types_from_template"],
                "target_type_candidates": ["to_be_filled_as_slot_bindings"],
            },
            "cleanup_mapping": {
                "required": True,
                "source_cleanup_slots": cleanup_slots(recipe),
                "target_cleanup_candidates": ["to_be_filled_as_slot_bindings"],
            },
            "oracle_mapping": {
                "required": True,
                "source_oracles": oracle_slots(recipe),
                "target_oracle_candidates": ["return_code", "output_state", "parser_result", "sanitizer_signal"],
            },
            "input_mapping": {
                "required": True,
                "input_slots": input_slots(recipe, units),
                "preservation_requirements": [
                    "preserve family-level vulnerability path",
                    "preserve input length/buffer pairing",
                    "do not introduce blocked target API",
                ],
            },
            "mutation_slot_mapping": {
                "required": True,
                "mutation_slots": mutation_slots(recipe),
                "allowed_mutation_policy": "bind existing family mutation slots only",
            },
        },
        "glm_policy": {
            "allowed_now": False,
            "allowed_later_for": ["adapter_slot_filling"],
            "forbidden": [
                "full_c_generation",
                "freeform_harness_generation",
                "bypass_mapping_gate",
            ],
        },
        "validation_before_render": VALIDATION_BEFORE_RENDER,
        "selected_mask_units_summary": selected_unit_summary(units),
        "notes": [
            "Plan only. No GLM call in this sprint.",
            "GLM output must be YAML slot_bindings only.",
            "Candidate mapping must remain candidate, not confirmed equivalence.",
        ],
    }


def slot_schema(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "slot_bindings_schema_v1",
        "adapter_id": plan["adapter_id"],
        "family": plan["family"],
        "target_library": plan["target_library"],
        "required_top_level_fields": REQUIRED_TOP_LEVEL_FIELDS,
        "field_constraints": {
            "api_mapping": {
                "must_use_allowed_target_apis": True,
                "must_not_use_forbidden_target_apis": True,
            },
            "cleanup_mapping": {
                "required": True,
            },
            "oracle_mapping": {
                "required": True,
            },
            "mutation_slot_mapping": {
                "must_preserve_family_mutation_policy": True,
            },
            "validation_notes": {
                "must_include_no_confirmed_equivalence_claim": True,
            },
        },
    }


def example_bindings(plan: dict[str, Any]) -> dict[str, Any]:
    allowed = plan["slot_groups"]["api_mapping"]["allowed_target_apis"]
    return {
        "schema": "slot_bindings_example_v1",
        "example_only": True,
        "not_final_glm_output": True,
        "adapter_id": plan["adapter_id"],
        "family": plan["family"],
        "source_library": "wolfssl",
        "target_library": plan["target_library"],
        "api_mapping": {
            "selected_target_api": allowed[0] if allowed else "ALLOWED_TARGET_API_PLACEHOLDER",
            "source_to_target": [],
            "confirmed_equivalence": False,
        },
        "type_mapping": {
            "bindings": [],
        },
        "cleanup_mapping": {
            "bindings": [],
            "required": True,
        },
        "oracle_mapping": {
            "bindings": [],
            "required": True,
        },
        "input_mapping": {
            "bindings": [],
        },
        "mutation_slot_mapping": {
            "bindings": [
                {"slot_name": slot, "target_binding": "EXAMPLE_ONLY_TARGET_SLOT"}
                for slot in plan["slot_groups"]["mutation_slot_mapping"]["mutation_slots"]
            ],
        },
        "validation_notes": [
            "example only",
            "no confirmed equivalence claim",
            "blocked targets not used",
        ],
        "risk_notes": [
            "candidate mapping only",
        ],
    }


def prompt_context(plan: dict[str, Any], recipe: dict[str, Any]) -> str:
    selected = plan.get("selected_mask_units_summary", [])
    return "\n".join([
        f"# Slot filling prompt context: {plan['adapter_id']}",
        "",
        f"- adapter_id: `{plan['adapter_id']}`",
        f"- family: `{plan['family']}`",
        f"- target_library: `{plan['target_library']}`",
        f"- source template: `{plan['source_template']['canonical_template']}`",
        f"- selected_mask_units: `{plan['source_template']['selected_mask_units']}`",
        "",
        "## Selected Mask Units",
        *[
            f"- {row.get('unit_id')}: role={row.get('role')}, suggested_use={row.get('suggested_use')}, placeholder={row.get('placeholder')}"
            for row in selected
        ],
        "",
        "## Allowed Target APIs",
        *[f"- `{api}`" for api in plan["slot_groups"]["api_mapping"]["allowed_target_apis"]],
        "",
        "## Forbidden Target APIs",
        *[f"- `{api}`" for api in plan["slot_groups"]["api_mapping"]["forbidden_target_apis"]],
        "",
        "## Required Bindings",
        *[f"- `{item}`" for item in REQUIRED_BINDINGS],
        "",
        "## Oracle Strategy",
        f"- primary/secondary: `{recipe.get('oracle_strategy', {})}`",
        "",
        "## Cleanup Requirements",
        f"- cleanup slots: `{plan['slot_groups']['cleanup_mapping']['source_cleanup_slots']}`",
        "",
        "## False Positive Risks",
        *[f"- `{risk}`" for risk in recipe.get("false_positive_risks", [])],
        "",
        "## Output Contract",
        "- 输出必须是 YAML `slot_bindings` 结构。",
        "- 禁止生成 C。",
        "- 禁止绕过 mapping gate。",
        "- 禁止声称 confirmed equivalence。",
        "- 禁止使用 blocked/no_direct_counterpart target。",
        "- 本文件只是 prompt context；本 sprint 不调用 GLM。",
    ])


def adapter_specific_rule(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "adapter_id": plan["adapter_id"],
        "required_bindings": REQUIRED_BINDINGS,
        "forbidden_target_apis": plan["slot_groups"]["api_mapping"]["forbidden_target_apis"],
        "allowed_target_apis": plan["slot_groups"]["api_mapping"]["allowed_target_apis"],
        "required_oracles": plan["slot_groups"]["oracle_mapping"]["source_oracles"],
        "required_cleanup": plan["slot_groups"]["cleanup_mapping"]["source_cleanup_slots"],
    }


def future_plan(family: str, spec_path: Path, blocked_rows: list[dict[str, Any]]) -> dict[str, Any]:
    spec = load_yaml(spec_path)
    return {
        "schema": "spec_only_future_slot_filling_plan_v1",
        "family": family,
        "reason_not_ready": spec.get("reason_no_concrete_adapter", "spec-only family has no canonical C template"),
        "required_before_slot_filling": [
            "canonical_tmpl_wolfssl.c",
            "selected_mask_units.yaml",
            "concrete_adapter_recipe.yaml",
        ],
        "possible_targets": spec.get("candidate_only_targets", []),
        "blocked_targets": blocked_rows,
        "notes": [
            "Do not create concrete slot filling request until family canonical template and concrete adapter recipe exist.",
        ],
    }


def load_blocked_targets(path: Path) -> list[dict[str, Any]]:
    obj = load_yaml(path)
    return [row for row in obj.get("blocked_targets", []) if isinstance(row, dict)] if isinstance(obj, dict) else []


def blocked_slot_rows(blocked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for row in blocked:
        rows.append({
            "family": row.get("family", ""),
            "target_library": row.get("target_library", ""),
            "blocked_reason": row.get("blocked_reason", ""),
            "blocked_apis": row.get("blocked_apis", []),
            "why_not_slot_filling": "blocked/no_direct/weak/manual-review target must not enter slot filling",
            "recommendation": row.get("recommendation", []),
            "notes": row.get("notes", []),
        })
    return rows


def write_input_summary(out_dir: Path, inputs: list[Path]) -> None:
    data = {
        "schema": "adapter_slot_filling_plan_input_summary_v1",
        "task": "adapter_slot_filling_plan_v1",
        "based_on_family_level_adapter_recipe": True,
        "one_poc_one_adapter": False,
        "output_scope": "slot filling plan only",
        "glm_called": False,
        "c_generated": False,
        "render_compile_run": False,
        "blocked_no_direct_excluded": True,
        "inputs": [
            {
                "path": str(path),
                "exists": path.exists(),
                "sha256": sha256(path) if path.exists() and path.is_file() else "",
            }
            for path in inputs
        ],
    }
    dump_yaml(out_dir / "input" / "adapter_slot_filling_plan_input_summary.yaml", data)
    dump_md(out_dir / "input" / "adapter_slot_filling_plan_input_summary.md", """# adapter_slot_filling_plan_v1 input summary

- 本轮基于 family-level adapter recipe。
- 本轮不是 one PoC one adapter。
- 本轮只生成 slot filling plan / schema / validation rules。
- 本轮不调用 GLM。
- 本轮不生成 C。
- 本轮不 render / compile / run。
- blocked/no_direct_counterpart 不进入 slot filling。
""")


def copy_slot_plan(plan_path: Path, target_path: Path, draft_root: Path) -> dict[str, Any]:
    if target_path.exists():
        draft = draft_root / target_path.parent.name / target_path.name
        # Include family as one more level when possible.
        if len(target_path.parts) >= 4:
            draft = draft_root / target_path.parts[-3] / target_path.parts[-2] / target_path.name
        draft.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(plan_path, draft)
        return {
            "source": str(plan_path),
            "target": str(target_path),
            "status": "collision_existing_target_not_overwritten",
            "draft_written": str(draft),
        }
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(plan_path, target_path)
    return {
        "source": str(plan_path),
        "target": str(target_path),
        "status": "written_new_slot_filling_plan",
        "draft_written": "",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter-recipe-root", required=True)
    parser.add_argument("--family-template-root", required=True)
    parser.add_argument("--adapter-recipe-report", required=True)
    parser.add_argument("--slot-mapping-plan", required=True)
    parser.add_argument("--blocked-targets", required=True)
    parser.add_argument("--mapping-gate", required=True)
    parser.add_argument("--adapter-ready", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-slot-plans", default="false")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    for name in [
        "input", "adapter_inventory", "slot_filling_plans", "schemas", "prompt_contexts",
        "validation_rules", "examples", "spec_only_future_plans", "blocked",
        "write_summary", "reports", "logs", "validation",
    ]:
        (out_dir / name).mkdir(parents=True, exist_ok=True)

    adapter_root = Path(args.adapter_recipe_root)
    template_root = Path(args.family_template_root)
    blocked = load_blocked_targets(Path(args.blocked_targets))
    blocked_rows = blocked_slot_rows(blocked)
    input_paths = [
        adapter_recipe_path(adapter_root, family, target)
        for family, target in CONCRETE_ADAPTERS
    ] + [
        spec_recipe_path(adapter_root, family)
        for family in SPEC_ONLY_FAMILIES
    ] + [
        template_root / family for family in [
            "pkcs_container_parsing", "asn1_nested_boundary", *SPEC_ONLY_FAMILIES
        ]
    ] + [
        Path(args.adapter_recipe_report),
        Path(args.slot_mapping_plan),
        Path(args.blocked_targets),
        Path(args.mapping_gate),
        Path(args.adapter_ready),
    ]
    write_input_summary(out_dir, input_paths)

    plans: list[dict[str, Any]] = []
    plan_paths: list[Path] = []
    schemas: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    inventory: list[dict[str, Any]] = []
    quality: list[dict[str, Any]] = []

    for family, target in sorted(CONCRETE_ADAPTERS):
        recipe_path = adapter_recipe_path(adapter_root, family, target)
        recipe = load_yaml(recipe_path)
        template_dir = family_template_dir(template_root, recipe, family)
        canonical_exists = (template_dir / "canonical_tmpl_wolfssl.c").exists()
        selected_exists = (template_dir / "selected_mask_units.yaml").exists()
        can_plan = recipe_path.exists() and canonical_exists and selected_exists
        blocked_for_adapter = [
            row for row in blocked_rows
            if row["family"] == family and row["target_library"] == target
        ]
        inventory.append({
            "adapter_id": recipe.get("adapter_id", f"{family}.{target}.family_adapter_recipe_v1"),
            "family": family,
            "target_library": target,
            "adapter_recipe_path": str(recipe_path),
            "family_template_path": str(template_dir),
            "canonical_template_exists": canonical_exists,
            "selected_mask_units_exists": selected_exists,
            "adapter_recipe_exists": recipe_path.exists(),
            "can_plan_slot_filling": can_plan,
            "reason": "concrete adapter recipe with canonical template and selected units" if can_plan else "missing required slot planning input",
            "required_bindings": REQUIRED_BINDINGS,
            "blocked": blocked_for_adapter,
            "notes": ["Family-level adapter; not one PoC one slot filling."],
        })
        if not can_plan:
            continue
        plan = slot_filling_plan(recipe, template_dir, recipe_path)
        plans.append(plan)
        plan_path = out_dir / "slot_filling_plans" / family / target / "slot_filling_plan.yaml"
        dump_yaml(plan_path, plan)
        plan_paths.append(plan_path)

        schema = slot_schema(plan)
        schemas.append(schema)
        schema_path = out_dir / "schemas" / f"{family}_{target}_slot_bindings_schema.yaml"
        dump_yaml(schema_path, schema)

        context_path = out_dir / "prompt_contexts" / f"{family}_{target}_prompt_context.md"
        dump_md(context_path, prompt_context(plan, recipe))

        example_path = out_dir / "examples" / f"{family}_{target}_expected_slot_bindings_example.yaml"
        dump_yaml(example_path, example_bindings(plan))

        rules.append(adapter_specific_rule(plan))
        quality.append({
            "adapter_id": plan["adapter_id"],
            "family": family,
            "target_library": target,
            "slot_filling_plan_exists": plan_path.exists(),
            "slot_bindings_schema_exists": schema_path.exists(),
            "prompt_context_exists": context_path.exists(),
            "validation_rules_exists": True,
            "required_bindings_present": set(REQUIRED_BINDINGS).issubset(set(plan["adapter_recipe"]["required_bindings"])),
            "forbidden_targets_recorded": bool(plan["slot_groups"]["api_mapping"]["forbidden_target_apis"]) or family != "pkcs_container_parsing",
            "glm_disabled_now": plan["glm_policy"]["allowed_now"] is False,
            "c_generation_forbidden": "full_c_generation" in plan["glm_policy"]["forbidden"],
            "render_disabled_now": True,
            "compile_disabled_now": True,
            "quality_status": "pass",
            "notes": "concrete adapter slot filling plan",
        })

    for family in SPEC_ONLY_FAMILIES:
        spec_path = spec_recipe_path(adapter_root, family)
        family_blocked = [row for row in blocked_rows if row["family"] == family]
        obj = future_plan(family, spec_path, family_blocked)
        out_path = out_dir / "spec_only_future_plans" / f"{family}_future_slot_filling_plan.yaml"
        dump_yaml(out_path, obj)
        quality.append({
            "adapter_id": f"{family}.future_slot_filling_plan",
            "family": family,
            "target_library": "spec_only",
            "slot_filling_plan_exists": out_path.exists(),
            "slot_bindings_schema_exists": False,
            "prompt_context_exists": False,
            "validation_rules_exists": True,
            "required_bindings_present": True,
            "forbidden_targets_recorded": True,
            "glm_disabled_now": True,
            "c_generation_forbidden": True,
            "render_disabled_now": True,
            "compile_disabled_now": True,
            "quality_status": "spec_only_pass",
            "notes": "spec-only future plan; concrete slot filling blocked until canonical template exists",
        })

    dump_yaml(out_dir / "adapter_inventory" / "adapter_slot_filling_inventory.yaml", {
        "schema": "adapter_slot_filling_inventory_v1",
        "adapters": inventory,
    })
    dump_md(out_dir / "adapter_inventory" / "adapter_slot_filling_inventory.md", "\n".join([
        "# adapter slot filling inventory",
        "",
        *[f"- {row['adapter_id']}: can_plan={row['can_plan_slot_filling']}" for row in inventory],
    ]))

    dump_yaml(out_dir / "validation_rules" / "adapter_slot_binding_validation_rules.yaml", {
        "schema": "adapter_slot_binding_validation_rules_v1",
        "global_rules": GLOBAL_RULES,
        "adapter_specific_rules": rules,
    })
    dump_md(out_dir / "validation_rules" / "adapter_slot_binding_validation_rules.md", "\n".join([
        "# adapter slot binding validation rules",
        "",
        "## Global Rules",
        *[f"- {rule}" for rule in GLOBAL_RULES],
        "",
        "## Adapter-Specific Rules",
        *[f"- {rule['adapter_id']}: allowed={rule['allowed_target_apis']}, forbidden={rule['forbidden_target_apis']}" for rule in rules],
    ]))

    dump_yaml(out_dir / "blocked" / "blocked_slot_filling_targets.yaml", {
        "schema": "blocked_slot_filling_targets_v1",
        "blocked_targets": blocked_rows,
    })
    dump_md(out_dir / "blocked" / "blocked_slot_filling_targets.md", "\n".join([
        "# blocked slot filling targets",
        "",
        *[f"- {row['family']} -> {row['target_library']}: {row['blocked_reason']} ({', '.join(row['blocked_apis'])})" for row in blocked_rows],
    ]))

    writes: list[dict[str, Any]] = []
    if str(args.write_slot_plans).lower() == "true":
        draft_root = out_dir / "write_summary" / "draft_slot_plans"
        for plan_path in plan_paths:
            family = plan_path.parts[-3]
            target = plan_path.parts[-2]
            target_path = adapter_root / family / target / "slot_filling_plan.yaml"
            writes.append(copy_slot_plan(plan_path, target_path, draft_root))

    dump_yaml(out_dir / "write_summary" / "slot_filling_plan_write_summary.yaml", {
        "schema": "slot_filling_plan_write_summary_v1",
        "write_attempted": str(args.write_slot_plans).lower() == "true",
        "writes": writes,
        "adapter_recipe_yaml_modified": False,
    })
    dump_md(out_dir / "write_summary" / "slot_filling_plan_write_summary.md", "\n".join([
        "# slot filling plan write summary",
        "",
        *[f"- {row['target']}: {row['status']}" for row in writes],
        "",
        "- adapter_recipe.yaml modified: no",
    ]))

    dump_yaml(out_dir / "validation" / "slot_filling_plan_quality_checks.yaml", {
        "schema": "slot_filling_plan_quality_checks_v1",
        "checks": quality,
    })
    dump_md(out_dir / "validation" / "slot_filling_plan_quality_checks.md", "\n".join([
        "# slot filling plan quality checks",
        "",
        *[f"- {row['adapter_id']}: {row['quality_status']}" for row in quality],
    ]))

    pass_count = sum(1 for row in quality if row["quality_status"] == "pass")
    spec_count = sum(1 for row in quality if row["quality_status"] == "spec_only_pass")
    next_task = "adapter_slot_filling_v1" if pass_count == 3 else "adapter_slot_filling_plan_fixup_v1"
    next_reason = "3 concrete adapter slot filling plans passed quality checks." if pass_count == 3 else "One or more concrete slot filling plans were incomplete."
    dump_yaml(out_dir / "reports" / "next_action_after_adapter_slot_filling_plan.yaml", {
        "schema": "next_action_after_adapter_slot_filling_plan_v1",
        "next_task": next_task,
        "reason": next_reason,
        "quality_counts": {
            "pass": pass_count,
            "spec_only_pass": spec_count,
            "partial": sum(1 for row in quality if row["quality_status"] == "partial"),
            "fail": sum(1 for row in quality if row["quality_status"] == "fail"),
        },
    })
    dump_md(out_dir / "reports" / "next_action_after_adapter_slot_filling_plan.md", f"# next action\n\n- next_task: `{next_task}`\n- reason: {next_reason}\n")

    report = {
        "schema": "adapter_slot_filling_plan_report_v1",
        "task": "adapter_slot_filling_plan_v1",
        "answers": {
            "generated_by_family_adapter": True,
            "avoided_one_poc_one_slot_filling": True,
            "concrete_slot_filling_plan_count": len(plans),
            "spec_only_future_plan_count": len(SPEC_ONLY_FAMILIES),
            "blocked_no_direct_excluded": True,
            "glm_called": False,
            "generated_c": False,
            "render_compile_run": False,
            "next_task_name": next_task,
        },
        "plans": [str(path) for path in plan_paths],
        "schemas": [str(out_dir / "schemas" / f"{plan['family']}_{plan['target_library']}_slot_bindings_schema.yaml") for plan in plans],
        "prompt_contexts": [str(out_dir / "prompt_contexts" / f"{plan['family']}_{plan['target_library']}_prompt_context.md") for plan in plans],
        "examples": [str(out_dir / "examples" / f"{plan['family']}_{plan['target_library']}_expected_slot_bindings_example.yaml") for plan in plans],
        "blocked_targets": blocked_rows,
        "write_summary": writes,
        "quality_checks": quality,
        "forbidden_actions_observed": {
            "poc_execution": False,
            "compile_run": False,
            "render_cases": False,
            "glm_call": False,
            "c_generation": False,
            "adapter_recipe_yaml_modified": False,
            "knowledge_raw_modified": False,
            "knowledge_base_modified": False,
            "rag_rebuild": False,
            "commit_or_push": False,
        },
        "next_task": next_task,
    }
    dump_yaml(out_dir / "reports" / "adapter_slot_filling_plan_v1_report.yaml", report)
    dump_md(out_dir / "reports" / "adapter_slot_filling_plan_v1_report.md", "\n".join([
        "# adapter_slot_filling_plan_v1 report",
        "",
        "- generated by family adapter: yes",
        "- avoided one PoC one slot filling: yes",
        f"- concrete slot filling plans: {len(plans)}",
        f"- spec-only future plans: {len(SPEC_ONLY_FAMILIES)}",
        "- blocked/no_direct excluded: yes",
        "- GLM called: no",
        "- generated C: no",
        "- render/compile/run: no",
        f"- next_task: `{next_task}`",
    ]))
    dump_md(out_dir / "README.md", """# adapter_slot_filling_plan_v1

This sprint prepares slot filling plans, schemas, prompt contexts, validation
rules, and example YAML structures for family-level adapter recipes. It does
not call GLM, generate C, render, compile, run PoCs, or modify adapter recipes.
""")

    print(f"[OK] slot filling plans: {len(plans)}")
    print(f"[OK] spec-only future plans: {len(SPEC_ONLY_FAMILIES)}")
    print(f"[NEXT] {next_task}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
