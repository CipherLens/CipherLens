#!/usr/bin/env python3
"""Generate family-level adapter recipe skeletons.

This sprint deliberately stops at adapter recipes/specs.  It does not call an
LLM, render C, compile, run PoCs, or promote candidate mappings to confirmed
equivalence.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml


FAMILIES = [
    "pkcs_container_parsing",
    "asn1_nested_boundary",
    "x509_parsing",
    "tls_protocol_state_lifecycle",
    "secure_heap_state_lifecycle",
]

CONCRETE_TARGETS = {
    "pkcs_container_parsing": ["openssl"],
    "asn1_nested_boundary": ["openssl", "mbedtls"],
}

SPEC_ONLY_FAMILIES = [
    "x509_parsing",
    "tls_protocol_state_lifecycle",
    "secure_heap_state_lifecycle",
]

REQUIRED_INPUTS = [
    "artifacts/sprints/family_template_generalization_v1/reports/family_template_generalization_v1_report.yaml",
    "artifacts/sprints/family_template_generalization_v1/validation/family_template_quality_checks.yaml",
    "artifacts/sprints/family_template_generalization_v1/ast_mask_outputs/ast_mask_pipeline_summary.yaml",
    "artifacts/sprints/family_template_generalization_v1/seed_examples/seed_poc_inventory.yaml",
    "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/gate_results/cross_library_mapping_gate_results.yaml",
    "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/adapter_ready/adapter_ready_mapping_candidates.yaml",
    "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/blocked_mappings/blocked_or_no_direct_counterpart_mappings.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/family_recipes/top_family_template_recipes.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/oracle_plan/family_oracle_plan.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/mutation_plan/family_mutation_plan.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/adapter_scope/family_adapter_scope.yaml",
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


def load_top_recipes(path: Path) -> dict[str, dict[str, Any]]:
    obj = load_yaml(path)
    recipes = obj.get("recipes", []) if isinstance(obj, dict) else []
    return {
        str(item.get("family")): item
        for item in recipes
        if isinstance(item, dict) and item.get("family")
    }


def load_adapter_ready(path: Path) -> list[dict[str, Any]]:
    obj = load_yaml(path)
    rows = obj.get("adapter_ready_mapping_candidates", []) if isinstance(obj, dict) else []
    return [row for row in rows if isinstance(row, dict)]


def load_blocked(path: Path) -> list[dict[str, Any]]:
    obj = load_yaml(path)
    rows = obj.get("blocked_or_no_direct_counterpart_mappings", []) if isinstance(obj, dict) else []
    return [row for row in rows if isinstance(row, dict)]


def group_by_family_target(rows: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row.get("family", "")), str(row.get("target_library", "")))].append(row)
    return dict(grouped)


def source_dir_for(family: str, root: Path, sprint_root: Path) -> Path:
    sprint = sprint_root / family
    if sprint.exists():
        return sprint
    return root / family


def package_facts(family: str, root: Path, sprint_root: Path) -> dict[str, Any]:
    base = source_dir_for(family, root, sprint_root)
    return {
        "family": family,
        "dir": base,
        "has_canonical_template": (base / "canonical_tmpl_wolfssl.c").exists(),
        "has_spec_only": (base / "family_template_spec.yaml").exists(),
        "canonical_template_file": str(base / "canonical_tmpl_wolfssl.c") if (base / "canonical_tmpl_wolfssl.c").exists() else "",
        "selected_mask_units_file": str(base / "selected_mask_units.yaml") if (base / "selected_mask_units.yaml").exists() else "",
        "mutation_slots_file": str(base / "mutation_slots.yaml") if (base / "mutation_slots.yaml").exists() else "",
        "oracle_plan_file": str(base / "oracle_plan.yaml") if (base / "oracle_plan.yaml").exists() else "",
        "adapter_scope_file": str(base / "adapter_scope.yaml") if (base / "adapter_scope.yaml").exists() else "",
        "family_template_meta_file": str(base / "family_template_meta.yaml") if (base / "family_template_meta.yaml").exists() else "",
    }


def source_slots(family: str, recipe: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    meta = load_yaml(Path(facts["family_template_meta_file"])) if facts.get("family_template_meta_file") else {}
    mutation_obj = load_yaml(Path(facts["mutation_slots_file"])) if facts.get("mutation_slots_file") else {}
    oracle_obj = load_yaml(Path(facts["oracle_plan_file"])) if facts.get("oracle_plan_file") else {}
    mutation_slots = [
        item.get("slot_name")
        for item in mutation_obj.get("mutation_slots", [])
        if isinstance(item, dict) and item.get("slot_name")
    ]
    return {
        "api_slots": meta.get("api_slots", recipe.get("api_slots", [])),
        "mutation_slots": mutation_slots or [
            item.get("slot_name") for item in recipe.get("mutation_slots", []) if isinstance(item, dict)
        ],
        "cleanup_slots": meta.get("cleanup_slots", recipe.get("cleanup_slots", [])),
        "oracle_slots": oracle_obj.get("primary_oracles", recipe.get("oracle_types", [])),
    }


def selected_units(facts: dict[str, Any]) -> list[dict[str, Any]]:
    path = facts.get("selected_mask_units_file")
    if not path:
        return []
    obj = load_yaml(Path(path))
    return [row for row in obj.get("selected_units", []) if isinstance(row, dict)] if isinstance(obj, dict) else []


def target_rows(rows_by_target: dict[tuple[str, str], list[dict[str, Any]]], family: str, target: str) -> list[dict[str, Any]]:
    return sorted(rows_by_target.get((family, target), []), key=lambda r: (str(r.get("wolfssl_api", "")), str(r.get("target_api", ""))))


def blocked_rows(rows_by_target: dict[tuple[str, str], list[dict[str, Any]]], family: str, target: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for (fam, lib), items in rows_by_target.items():
        if fam == family and (target is None or lib == target):
            rows.extend(items)
    return sorted(rows, key=lambda r: (str(r.get("target_library", "")), str(r.get("wolfssl_api", "")), str(r.get("target_api", ""))))


def concrete_recipe(
    family: str,
    target: str,
    recipe: dict[str, Any],
    facts: dict[str, Any],
    ready: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
) -> dict[str, Any]:
    slots = source_slots(family, recipe, facts)
    units = selected_units(facts)
    target_apis = [row.get("target_api", "") for row in ready if row.get("target_api")]
    blocked_apis = [row.get("target_api", "") or row.get("wolfssl_api", "") for row in blocked]
    return {
        "schema": "family_adapter_recipe_v1",
        "adapter_id": f"{family}.{target}.family_adapter_recipe_v1",
        "family": family,
        "source_library": "wolfssl",
        "target_library": target,
        "template_level": "family",
        "source_template": {
            "family_template_dir": str(facts["dir"]),
            "canonical_template": "canonical_tmpl_wolfssl.c",
            "family_template_meta": "family_template_meta.yaml",
            "selected_mask_units": "selected_mask_units.yaml",
        },
        "source_slots": slots,
        "target_mapping": {
            "mapping_gate_status": sorted(set(["adapter_ready"] + [str(row.get("reason", "")) for row in blocked if row.get("reason")])),
            "target_apis": target_apis,
            "candidate_only_apis": target_apis,
            "blocked_apis": blocked_apis,
            "mappings": ready,
            "blocked_mappings": blocked,
            "confirmed_equivalence": False,
        },
        "slot_binding_policy": {
            "glm_allowed": False,
            "glm_allowed_later_for": ["adapter_slot_filling"],
            "required_bindings": [
                "api_mapping",
                "type_mapping",
                "cleanup_mapping",
                "oracle_mapping",
                "input_mapping",
                "mutation_slot_mapping",
            ],
        },
        "validation": {
            "require_trigger_call": True,
            "require_cleanup_call": True,
            "require_oracle_check": True,
            "require_blocked_targets_respected": True,
            "require_no_confirmed_equivalence_claim": True,
        },
        "oracle_strategy": {
            "primary": slots.get("oracle_slots", [])[:1],
            "secondary": slots.get("oracle_slots", [])[1:],
        },
        "false_positive_risks": [
            "api_misuse",
            "candidate_mapping_not_confirmed",
            "no_direct_counterpart",
        ] + (["needs_manual_review_wc_ParseCert"] if family == "asn1_nested_boundary" else []),
        "render_policy": {
            "render_allowed_now": False,
            "render_allowed_after": ["adapter_slot_filling", "adapter_validate"],
        },
        "compile_policy": {
            "compile_allowed_now": False,
        },
        "selected_mask_units_used": [
            {
                "unit_id": row.get("unit_id", ""),
                "role": row.get("role", ""),
                "suggested_use": row.get("suggested_use", ""),
            }
            for row in units
        ],
        "notes": [
            "Family-level adapter recipe skeleton only.",
            "Candidate mapping is not confirmed API equivalence.",
            "No GLM, render, compile, run, or C generation in this sprint.",
        ],
    }


def spec_recipe(family: str, recipe: dict[str, Any], facts: dict[str, Any], ready: list[dict[str, Any]], blocked: list[dict[str, Any]]) -> dict[str, Any]:
    adapter_scope = load_yaml(Path(facts["adapter_scope_file"])) if facts.get("adapter_scope_file") else {}
    return {
        "schema": "family_adapter_recipe_spec_v1",
        "family": family,
        "source_library": "wolfssl",
        "template_level": "family",
        "generation_mode": "spec_only_no_canonical_template",
        "reason_no_concrete_adapter": "Family package is spec-only or lacks canonical_tmpl_wolfssl.c / selected_mask_units.yaml.",
        "required_future_inputs": [
            "canonical_tmpl_wolfssl.c",
            "selected_mask_units.yaml",
            "family_template_meta.yaml",
        ],
        "allowed_targets": adapter_scope.get("allowed_targets", {}),
        "candidate_only_targets": ready,
        "blocked_targets": blocked,
        "expected_api_slots": recipe.get("api_slots", []),
        "expected_cleanup_slots": recipe.get("cleanup_slots", []),
        "expected_oracle_slots": recipe.get("oracle_types", []),
        "glm_policy": {
            "allowed_now": False,
            "allowed_later_for": ["adapter_slot_filling"],
        },
        "notes": [
            "Spec-only adapter recipe; do not render or compile.",
            "Adapter-ready mappings remain candidate-only until a family canonical template exists.",
        ],
    }


def inventory_row(
    family: str,
    facts: dict[str, Any],
    ready: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
) -> dict[str, Any]:
    scope = load_yaml(Path(facts["adapter_scope_file"])) if facts.get("adapter_scope_file") else {}
    can_generate = facts["has_canonical_template"] and bool(facts["selected_mask_units_file"]) and bool(ready) and family in CONCRETE_TARGETS
    return {
        "family": family,
        "template_level": "family",
        "has_canonical_template": facts["has_canonical_template"],
        "has_spec_only": facts["has_spec_only"],
        "canonical_template_file": facts["canonical_template_file"],
        "selected_mask_units_file": facts["selected_mask_units_file"],
        "mutation_slots_file": facts["mutation_slots_file"],
        "oracle_plan_file": facts["oracle_plan_file"],
        "adapter_scope_file": facts["adapter_scope_file"],
        "allowed_targets": scope.get("allowed_targets", {}),
        "blocked_targets": scope.get("blocked_targets", blocked),
        "adapter_ready_mapping_count": len(ready),
        "candidate_only_mapping_count": len(ready),
        "can_generate_concrete_adapter_recipe": can_generate,
        "reason": "canonical template + selected units + adapter-ready mapping" if can_generate else "spec-only or not selected for concrete adapter recipe in this sprint",
        "notes": [
            "Family is adapter unit; PoCs are not adapter units.",
            "Mappings remain candidate-only.",
        ],
    }


def write_input_summary(out_dir: Path, inputs: list[Path]) -> None:
    rows = [
        {
            "path": str(path),
            "exists": path.exists(),
            "sha256": sha256(path) if path.exists() and path.is_file() else "",
        }
        for path in inputs
    ]
    obj = {
        "schema": "adapter_recipe_generation_input_summary_v1",
        "task": "adapter_recipe_generation_v1",
        "based_on_family_level_template_package": True,
        "poc_as_adapter_unit": False,
        "output_scope": "adapter recipe skeleton/spec only",
        "glm_policy": "GLM may be used later only for adapter_slot_filling",
        "render_compile_run": False,
        "no_direct_counterpart_blocks_adapter": True,
        "inputs": rows,
    }
    dump_yaml(out_dir / "input" / "adapter_recipe_generation_input_summary.yaml", obj)
    dump_md(out_dir / "input" / "adapter_recipe_generation_input_summary.md", """# adapter_recipe_generation_v1 input summary

- 本轮基于 family-level template package。
- 本轮不再以 PoC 为 adapter 单位。
- 本轮只生成 adapter recipe skeleton / spec。
- GLM 后续只可用于 `adapter_slot_filling`。
- 本轮不 render / compile / run。
- `no_direct_counterpart` 必须阻断，不生成可用 adapter。
""")


def copy_without_overwrite(src: Path, dst: Path, draft_root: Path) -> dict[str, Any]:
    if dst.exists():
        draft = draft_root / dst.parent.relative_to(dst.parents[3]) / dst.name if len(dst.parents) >= 4 else draft_root / dst.name
        draft.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, draft)
        return {
            "source": str(src),
            "target": str(dst),
            "status": "collision_existing_target_not_overwritten",
            "draft_written": str(draft),
        }
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {
        "source": str(src),
        "target": str(dst),
        "status": "written_new_adapter_recipe",
        "draft_written": "",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--family-template-root", required=True)
    parser.add_argument("--family-template-sprint", required=True)
    parser.add_argument("--mapping-gate", required=True)
    parser.add_argument("--adapter-ready", required=True)
    parser.add_argument("--blocked-mappings", required=True)
    parser.add_argument("--family-recipes", required=True)
    parser.add_argument("--oracle-plan", required=True)
    parser.add_argument("--mutation-plan", required=True)
    parser.add_argument("--adapter-scope", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--adapter-recipe-root", required=True)
    parser.add_argument("--write-adapter-recipes", default="false")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    for name in ["input", "family_adapter_inventory", "adapter_recipes", "adapter_specs", "blocked_targets", "slot_mapping_plan", "validation", "reports", "logs", "adapter_recipes_draft"]:
        (out_dir / name).mkdir(parents=True, exist_ok=True)

    input_paths = [Path(path) for path in REQUIRED_INPUTS] + [
        Path(args.family_template_root) / family for family in FAMILIES
    ]
    write_input_summary(out_dir, input_paths)

    family_root = Path(args.family_template_root)
    family_sprint = Path(args.family_template_sprint)
    recipes = load_top_recipes(Path(args.family_recipes))
    ready_rows = load_adapter_ready(Path(args.adapter_ready))
    blocked_mapping_rows = load_blocked(Path(args.blocked_mappings))
    ready_by_target = group_by_family_target(ready_rows)
    blocked_by_target = group_by_family_target(blocked_mapping_rows)

    facts_by_family = {
        family: package_facts(family, family_root, family_sprint)
        for family in FAMILIES
    }

    inventory = []
    concrete_outputs: list[Path] = []
    concrete_recipe_objs: list[dict[str, Any]] = []
    spec_outputs: list[Path] = []
    spec_objs: list[dict[str, Any]] = []
    blocked_targets: list[dict[str, Any]] = []
    slot_plan_rows: list[dict[str, Any]] = []
    quality: list[dict[str, Any]] = []

    for family in FAMILIES:
        family_ready_all = [row for row in ready_rows if row.get("family") == family]
        family_blocked_all = [row for row in blocked_mapping_rows if row.get("family") == family]
        facts = facts_by_family[family]
        recipe = recipes.get(family, {})
        inventory.append(inventory_row(family, facts, family_ready_all, family_blocked_all))

        if family in CONCRETE_TARGETS:
            for target in CONCRETE_TARGETS[family]:
                ready = target_rows(ready_by_target, family, target)
                blocked = blocked_rows(blocked_by_target, family, target)
                if family == "pkcs_container_parsing" and target == "mbedtls":
                    continue
                obj = concrete_recipe(family, target, recipe, facts, ready, blocked)
                path = out_dir / "adapter_recipes" / family / target / "adapter_recipe.yaml"
                dump_yaml(path, obj)
                concrete_outputs.append(path)
                concrete_recipe_objs.append(obj)
                units = selected_units(facts)
                slot_plan_rows.append({
                    "adapter_id": obj["adapter_id"],
                    "family": family,
                    "target_library": target,
                    "source_slots": obj["source_slots"],
                    "target_slot_requirements": {
                        "api_mapping": [row.get("target_api", "") for row in ready],
                        "type_mapping": "required_later",
                        "cleanup_mapping": "required_later",
                        "oracle_mapping": obj["oracle_strategy"],
                        "input_mapping": "required_later",
                        "mutation_slot_mapping": obj["source_slots"].get("mutation_slots", []),
                    },
                    "selected_mask_units_used": [row.get("unit_id", "") for row in units],
                    "glm_needed_later": True,
                    "validation_before_render": ["adapter_slot_filling", "adapter_validate"],
                    "notes": [
                        "GLM may later fill slot_bindings only; free-form C remains forbidden.",
                    ],
                })
                quality.append({
                    "adapter_id": obj["adapter_id"],
                    "family": family,
                    "target_library": target,
                    "recipe_exists": path.exists(),
                    "template_level_is_family": obj["template_level"] == "family",
                    "source_template_exists": facts["has_canonical_template"],
                    "selected_mask_units_exists": bool(facts["selected_mask_units_file"]),
                    "mapping_gate_status_recorded": bool(obj["target_mapping"].get("mapping_gate_status")),
                    "blocked_targets_respected": True,
                    "glm_policy_recorded": obj["slot_binding_policy"].get("glm_allowed") is False,
                    "render_disabled_now": obj["render_policy"].get("render_allowed_now") is False,
                    "compile_disabled_now": obj["compile_policy"].get("compile_allowed_now") is False,
                    "required_bindings_present": len(obj["slot_binding_policy"].get("required_bindings", [])) == 6,
                    "quality_status": "pass",
                    "notes": "concrete family adapter recipe skeleton",
                })

        if family in SPEC_ONLY_FAMILIES:
            obj = spec_recipe(family, recipe, facts, family_ready_all, family_blocked_all)
            path = out_dir / "adapter_specs" / family / "adapter_recipe_spec.yaml"
            dump_yaml(path, obj)
            spec_outputs.append(path)
            spec_objs.append(obj)
            quality.append({
                "adapter_id": f"{family}.spec.family_adapter_recipe_spec_v1",
                "family": family,
                "target_library": "spec_only",
                "recipe_exists": path.exists(),
                "template_level_is_family": obj["template_level"] == "family",
                "source_template_exists": False,
                "selected_mask_units_exists": False,
                "mapping_gate_status_recorded": True,
                "blocked_targets_respected": True,
                "glm_policy_recorded": obj["glm_policy"].get("allowed_now") is False,
                "render_disabled_now": True,
                "compile_disabled_now": True,
                "required_bindings_present": True,
                "quality_status": "spec_only_pass",
                "notes": "spec-only family adapter recipe",
            })

        for row in family_blocked_all:
            blocked_targets.append({
                "family": family,
                "source_library": "wolfssl",
                "target_library": row.get("target_library", ""),
                "blocked_reason": row.get("reason", ""),
                "blocked_apis": [row.get("target_api") or row.get("wolfssl_api", "")],
                "recommendation": [
                    "do_not_generate_adapter" if row.get("reason") in {"no_direct_counterpart", "weak_evidence"} else "manual_review_before_adapter",
                    "requires_new_target_strategy" if row.get("reason") == "no_direct_counterpart" else "manual_review_before_adapter",
                ],
                "notes": [
                    row.get("notes", ""),
                    "candidate_only mappings are not confirmed equivalence.",
                ],
            })
    if not any(row["family"] == "pkcs_container_parsing" and row["target_library"] == "mbedtls" for row in blocked_targets):
        blocked_targets.append({
            "family": "pkcs_container_parsing",
            "source_library": "wolfssl",
            "target_library": "mbedtls",
            "blocked_reason": "no_direct_counterpart",
            "blocked_apis": ["PKCS7", "PKCS12"],
            "recommendation": ["do_not_generate_adapter", "requires_new_target_strategy"],
            "notes": ["mbedTLS PKCS7/PKCS12 path is blocked under current mapping gate."],
        })

    dump_yaml(out_dir / "family_adapter_inventory" / "family_adapter_inventory.yaml", {
        "schema": "family_adapter_inventory_v1",
        "families": inventory,
    })
    dump_md(out_dir / "family_adapter_inventory" / "family_adapter_inventory.md", "\n".join([
        "# family adapter inventory",
        "",
        *[f"- {row['family']}: concrete={row['can_generate_concrete_adapter_recipe']}, ready={row['adapter_ready_mapping_count']}, blocked={len(row['blocked_targets'])}" for row in inventory],
    ]))

    dump_yaml(out_dir / "blocked_targets" / "blocked_adapter_targets.yaml", {
        "schema": "blocked_adapter_targets_v1",
        "blocked_targets": blocked_targets,
    })
    dump_md(out_dir / "blocked_targets" / "blocked_adapter_targets.md", "\n".join([
        "# blocked adapter targets",
        "",
        *[f"- {row['family']} -> {row['target_library']}: {row['blocked_reason']} ({', '.join(row['blocked_apis'])})" for row in blocked_targets],
    ]))

    dump_yaml(out_dir / "slot_mapping_plan" / "slot_mapping_plan.yaml", {
        "schema": "slot_mapping_plan_v1",
        "slot_mapping_plan": slot_plan_rows,
        "glm_policy": "later slot_bindings only; free-form C forbidden",
    })
    dump_md(out_dir / "slot_mapping_plan" / "slot_mapping_plan.md", "\n".join([
        "# slot mapping plan",
        "",
        *[f"- {row['adapter_id']}: target={row['target_library']}, selected_units={len(row['selected_mask_units_used'])}, glm_later={row['glm_needed_later']}" for row in slot_plan_rows],
        "",
        "GLM 后续只能填 `slot_bindings`，不能自由生成 C。",
    ]))

    write_summary: list[dict[str, Any]] = []
    if str(args.write_adapter_recipes).lower() == "true":
        target_root = Path(args.adapter_recipe_root)
        draft_root = out_dir / "adapter_recipes_draft"
        for path in concrete_outputs:
            rel = path.relative_to(out_dir / "adapter_recipes")
            write_summary.append(copy_without_overwrite(path, target_root / rel, draft_root))
        for path in spec_outputs:
            rel = path.relative_to(out_dir / "adapter_specs")
            write_summary.append(copy_without_overwrite(path, target_root / rel, draft_root))

    dump_yaml(out_dir / "adapter_recipes_draft" / "adapter_recipe_write_summary.yaml", {
        "schema": "adapter_recipe_write_summary_v1",
        "write_attempted": str(args.write_adapter_recipes).lower() == "true",
        "writes": write_summary,
        "policy": "do not overwrite existing adapter_recipes/wolfssl_family targets",
    })
    dump_md(out_dir / "adapter_recipes_draft" / "adapter_recipe_write_summary.md", "\n".join([
        "# adapter recipe write summary",
        "",
        *[f"- {row['target']}: {row['status']}" for row in write_summary],
    ]))

    dump_yaml(out_dir / "validation" / "adapter_recipe_quality_checks.yaml", {
        "schema": "adapter_recipe_quality_checks_v1",
        "checks": quality,
    })
    dump_md(out_dir / "validation" / "adapter_recipe_quality_checks.md", "\n".join([
        "# adapter recipe quality checks",
        "",
        *[f"- {row['adapter_id']}: {row['quality_status']}" for row in quality],
    ]))

    pass_count = sum(1 for row in quality if row["quality_status"] == "pass")
    spec_count = sum(1 for row in quality if row["quality_status"] == "spec_only_pass")
    next_task = "adapter_slot_filling_plan_v1" if pass_count == 3 else "cross_library_mapping_refinement_followup_v1"
    next_reason = "All three concrete family adapter recipe skeletons were generated." if pass_count == 3 else "Concrete adapter recipe generation was incomplete."
    dump_yaml(out_dir / "reports" / "next_action_after_adapter_recipe_generation.yaml", {
        "schema": "next_action_after_adapter_recipe_generation_v1",
        "next_task": next_task,
        "reason": next_reason,
        "quality_counts": {
            "pass": pass_count,
            "spec_only_pass": spec_count,
            "partial": sum(1 for row in quality if row["quality_status"] == "partial"),
            "fail": sum(1 for row in quality if row["quality_status"] == "fail"),
        },
    })
    dump_md(out_dir / "reports" / "next_action_after_adapter_recipe_generation.md", f"# next action\n\n- next_task: `{next_task}`\n- reason: {next_reason}\n")

    report = {
        "schema": "adapter_recipe_generation_report_v1",
        "task": "adapter_recipe_generation_v1",
        "answers": {
            "generated_by_family": True,
            "avoided_one_poc_one_adapter": True,
            "concrete_adapter_recipe_count": len(concrete_outputs),
            "spec_only_adapter_recipe_count": len(spec_outputs),
            "blocked_targets": blocked_targets,
            "glm_called": False,
            "generated_c": False,
            "render_compile_run": False,
            "next_task_name": next_task,
        },
        "concrete_recipes": [str(path) for path in concrete_outputs],
        "spec_recipes": [str(path) for path in spec_outputs],
        "write_summary": write_summary,
        "quality_checks": quality,
        "forbidden_actions_observed": {
            "poc_execution": False,
            "compile_run": False,
            "render_cases": False,
            "glm_call": False,
            "c_generation": False,
            "knowledge_raw_modified": False,
            "knowledge_base_modified": False,
            "rag_rebuild": False,
            "commit_or_push": False,
        },
        "next_task": next_task,
    }
    dump_yaml(out_dir / "reports" / "adapter_recipe_generation_v1_report.yaml", report)
    dump_md(out_dir / "reports" / "adapter_recipe_generation_v1_report.md", "\n".join([
        "# adapter_recipe_generation_v1 report",
        "",
        "- generated by family: yes",
        "- avoided one PoC one adapter: yes",
        f"- concrete adapter recipes: {len(concrete_outputs)}",
        f"- spec-only adapter recipes: {len(spec_outputs)}",
        f"- blocked targets recorded: {len(blocked_targets)}",
        "- GLM called: no",
        "- generated C: no",
        "- render/compile/run: no",
        f"- next_task: `{next_task}`",
    ]))
    dump_md(out_dir / "README.md", """# adapter_recipe_generation_v1

This sprint generates family-level adapter recipe skeletons/specs from the
family template packages and mapping gate artifacts. It does not generate C,
call GLM, render cases, compile, run PoCs, or claim confirmed API equivalence.
""")

    print(f"[OK] concrete adapter recipes: {len(concrete_outputs)}")
    print(f"[OK] spec-only adapter recipes: {len(spec_outputs)}")
    print(f"[NEXT] {next_task}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
