"""Plan family-level mutation cases for validated adapters.

This module emits case specifications only. It does not render C, compile, run
PoCs, call GLM, or mutate adapter/template inputs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from mutation.mutation_case_records import (
    adapter_slug,
    build_family_case,
    dump_yaml,
    load_yaml,
    mutation_slot_lookup,
    now_iso,
    result_by_id,
    selected_unit_slots,
    write_md,
)
from mutation.mutation_policy import strategies_for_family


def build_input_summary(args: argparse.Namespace, render_ready_ids: list[str], blocked_ids: list[str]) -> dict[str, Any]:
    return {
        "schema": "mutation_planner_input_summary_v1",
        "generated_at": now_iso(),
        "why_not_direct_render": "Insert controlled family-level mutation planning before render to avoid direct historical-PoC migration.",
        "render_ready_adapters": render_ready_ids,
        "blocked_adapters": blocked_ids,
        "pkcs_openssl_enters_mutation": "pkcs_container_parsing_openssl" in render_ready_ids,
        "asn1_openssl_enters_mutation": "asn1_nested_boundary_openssl" in render_ready_ids,
        "asn1_mbedtls_blocked": "asn1_nested_boundary_mbedtls" in blocked_ids,
        "no_c_generation": True,
        "no_render_compile_run": True,
        "no_glm": True,
        "inputs": {
            "adapter_root": args.adapter_root,
            "family_template_root": args.family_template_root,
            "adapter_validate_results": args.adapter_validate_results,
            "render_readiness": args.render_readiness,
            "mapping_gate": args.mapping_gate,
            "blocked_mappings": args.blocked_mappings,
        },
    }


def build_oracle_family(family: str, target: str, oracle_types: list[str], cases: list[dict[str, Any]], adapter_id: str) -> dict[str, Any]:
    return {
        "family": family,
        "target_library": target,
        "primary_oracles": oracle_types[:1] or ["parser_reject_accept"],
        "secondary_oracles": oracle_types[1:],
        "expected_result_labels": sorted(
            {
                case["expected_oracle"]["expected_result_label"]
                for case in cases
                if case["base_adapter"] == adapter_id
            }
        ),
        "oracle_interpretation_rules": [
            {
                "rule": "parser accept/reject divergence",
                "meaning": "candidate behavioral divergence only",
                "false_positive_risk": "API-level permissiveness or input construction mismatch",
            },
            {
                "rule": "return-code divergence",
                "meaning": "semantic_divergence_candidate",
                "false_positive_risk": "different library error taxonomy",
            },
            {
                "rule": "crash signal",
                "meaning": "requires reproduction and sanitizer evidence before vulnerability claim",
                "false_positive_risk": "harness misuse or invalid API setup",
            },
            {
                "rule": "API misuse",
                "meaning": "downgrade to api_misuse_false_positive",
                "false_positive_risk": "adapter did not preserve target preconditions",
            },
        ],
        "candidate_label_policy": {
            "do_not_claim_confirmed_vulnerability": True,
            "semantic_divergence_requires_triage": True,
            "crash_requires_reproduction": True,
        },
    }


def plan_family_mutations(args: argparse.Namespace) -> dict[str, Any]:
    adapter_root = Path(args.adapter_root)
    template_root = Path(args.family_template_root)
    validate_results = load_yaml(Path(args.adapter_validate_results)) or {}
    readiness = load_yaml(Path(args.render_readiness)) or {}
    results = result_by_id(validate_results)

    render_ready_ids = [item["adapter_id"] for item in readiness.get("render_ready_adapters", []) or []]
    blocked_ids = [item["adapter_id"] for item in readiness.get("blocked_adapters", []) or []]

    inventory_items: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    oracle_families: list[dict[str, Any]] = []

    for adapter_id in render_ready_ids:
        result = results.get(adapter_id, {})
        family = result.get("family")
        target = result.get("target_library")
        strategies = strategies_for_family(str(family), int(args.max_cases_per_adapter))
        if not strategies:
            continue

        adapter_dir = adapter_root / str(family) / str(target)
        template_dir = template_root / str(family)
        mutation_slots = load_yaml(template_dir / "mutation_slots.yaml") or {}
        selected_units = load_yaml(template_dir / "selected_mask_units.yaml") or {}
        oracle_plan = load_yaml(template_dir / "oracle_plan.yaml") or {}
        slot_lookup = mutation_slot_lookup(mutation_slots)
        selected_slots = selected_unit_slots(selected_units)
        oracle_types = oracle_plan.get("oracle_types", []) or []

        inventory_items.append(
            {
                "adapter_id": adapter_id,
                "family": family,
                "target_library": target,
                "adapter_recipe": str(adapter_dir / "adapter_recipe.yaml"),
                "slot_bindings": str(adapter_dir / "slot_bindings.yaml"),
                "family_mutation_slots": sorted(slot_lookup),
                "selected_mask_units": sorted(selected_slots),
                "oracle_types": oracle_types,
                "can_mutate": True,
                "reason": "adapter validation pass and render_ready=true",
                "blocked": False,
                "notes": ["case specs only; no render in this sprint"],
            }
        )

        for idx, (strategy, slot_specs, label) in enumerate(strategies, start=1):
            cases.append(
                build_family_case(
                    idx,
                    adapter_id,
                    str(family),
                    str(target),
                    strategy,
                    slot_specs,
                    label,
                    slot_lookup,
                    oracle_types,
                )
            )

        oracle_families.append(build_oracle_family(str(family), str(target), oracle_types, cases, adapter_id))

    blocked_items: list[dict[str, Any]] = []
    for adapter_id in blocked_ids:
        result = results.get(adapter_id, {})
        item = {
            "adapter_id": adapter_id,
            "family": result.get("family"),
            "target_library": result.get("target_library"),
            "can_mutate": False,
            "blocked_reason": "blocked_expected / needs_manual_review / mapping gate not render-ready",
            "notes": ["blocked adapter excluded from mutation case matrix"],
        }
        inventory_items.append(item)
        blocked_items.append(
            {
                "adapter_id": adapter_id,
                "family": result.get("family"),
                "target_library": result.get("target_library"),
                "blocked_status": result.get("binding_status"),
                "reason": "blocked_expected / needs_manual_review / mapping gate not render-ready",
                "mutation_allowed": False,
                "render_allowed": False,
                "notes": ["must not enter render candidates"],
            }
        )

    render_candidates = [
        {
            "case_id": case["case_id"],
            "family": case["family"],
            "target_library": case["target_library"],
            "base_adapter": case["base_adapter"],
            "render_allowed": True,
            "reason": "case belongs to validated render-ready adapter",
            "required_inputs": [
                "family_template",
                "adapter_recipe",
                "slot_bindings",
                "mutation_case",
                "oracle_expectation",
            ],
        }
        for case in cases
        if case["render_allowed"]
    ]
    blocked_cases = [
        {
            "case_id": f"{adapter_slug(item['adapter_id'])}__blocked",
            "family": item["family"],
            "target_library": item["target_library"],
            "reason": item["reason"],
        }
        for item in blocked_items
    ]
    render_plan = {
        "schema": "render_candidate_plan_v1",
        "render_candidates": render_candidates,
        "blocked_cases": blocked_cases,
        "summary": {
            "total_cases": len(cases),
            "render_allowed": len(render_candidates),
            "render_blocked": len(blocked_cases),
        },
    }

    pkcs_count = sum(1 for c in cases if c["family"] == "pkcs_container_parsing")
    asn1_count = sum(1 for c in cases if c["family"] == "asn1_nested_boundary")
    blocked_excluded = all(item["adapter_id"] not in {c["base_adapter"] for c in cases} for item in blocked_items)
    all_have_oracle = all(bool(c.get("expected_oracle", {}).get("primary")) for c in cases)
    all_have_label = all(bool(c.get("expected_oracle", {}).get("expected_result_label")) for c in cases)
    all_render_from_pass = all(results.get(c["base_adapter"], {}).get("validation_status") == "pass" for c in cases)
    quality_status = (
        "pass"
        if pkcs_count > 0
        and asn1_count > 0
        and blocked_excluded
        and all_have_oracle
        and all_have_label
        and all_render_from_pass
        else "fail"
    )
    quality = {
        "schema": "mutation_planner_quality_checks_v1",
        "render_ready_adapters_seen": render_ready_ids,
        "blocked_adapters_seen": blocked_ids,
        "mutation_cases_generated": len(cases),
        "pkcs_cases_count": pkcs_count,
        "asn1_cases_count": asn1_count,
        "blocked_adapter_excluded_from_cases": blocked_excluded,
        "all_cases_have_oracle": all_have_oracle,
        "all_cases_have_result_label": all_have_label,
        "all_render_candidates_from_pass_adapters": all_render_from_pass,
        "no_c_generated": True,
        "no_render_executed": True,
        "no_compile_executed": True,
        "quality_status": quality_status,
        "notes": [],
    }

    if not cases:
        next_task = "mutation_slot_extraction_fixup_v1"
        why = "case matrix has zero cases"
    elif not all_have_oracle:
        next_task = "oracle_expectation_plan_fixup_v1"
        why = "one or more cases lack oracle expectations"
    elif any(item["adapter_id"] in {c["base_adapter"] for c in cases} for item in blocked_items):
        next_task = "mutation_planner_blocking_policy_fixup_v1"
        why = "blocked adapter entered mutation/render candidates"
    elif all_render_from_pass:
        next_task = "render_plan_v1"
        why = "mutation case matrix generated and render candidates only reference pass adapters"
    else:
        next_task = "mutation_planner_triage_v1"
        why = "mutation planner output needs triage"

    return {
        "input_summary": build_input_summary(args, render_ready_ids, blocked_ids),
        "inventory": {"schema": "mutation_inventory_v1", "adapters": inventory_items},
        "matrix": {"schema": "mutation_case_matrix_v1", "cases": cases},
        "oracle_expectation": {"schema": "oracle_expectation_plan_v1", "families": oracle_families},
        "render_plan": render_plan,
        "blocked_report": {"schema": "blocked_adapters_v1", "blocked_adapters": blocked_items},
        "quality": quality,
        "next_action": {
            "schema": "next_action_after_mutation_planner_v1",
            "next_task_name": next_task,
            "why": why,
        },
        "report": {
            "schema": "family_adapter_mutation_planner_v1_report",
            "generated_at": now_iso(),
            "only_render_ready_adapters_planned": True,
            "pkcs_cases_generated": pkcs_count,
            "asn1_cases_generated": asn1_count,
            "blocked_adapter_excluded": blocked_excluded,
            "mutation_case_total": len(cases),
            "render_candidate_total": len(render_candidates),
            "generated_c": False,
            "render": False,
            "compile_run": False,
            "glm": False,
            "next_task_name": next_task,
            "quality": quality,
        },
    }


def write_plan(out: Path, plan: dict[str, Any]) -> None:
    for sub in [
        "input",
        "mutation_inventory",
        "mutation_case_matrix",
        "oracle_expectation_plan",
        "render_candidate_plan",
        "blocked_adapters",
        "validation",
        "reports",
        "logs",
    ]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    dump_yaml(out / "input" / "mutation_planner_input_summary.yaml", plan["input_summary"])
    write_md(out / "input" / "mutation_planner_input_summary.md", "Mutation Planner Input Summary", plan["input_summary"])
    dump_yaml(out / "mutation_inventory" / "mutation_inventory.yaml", plan["inventory"])
    write_md(out / "mutation_inventory" / "mutation_inventory.md", "Mutation Inventory", plan["inventory"])
    dump_yaml(out / "mutation_case_matrix" / "mutation_case_matrix.yaml", plan["matrix"])
    write_md(out / "mutation_case_matrix" / "mutation_case_matrix.md", "Mutation Case Matrix", plan["matrix"])
    dump_yaml(out / "oracle_expectation_plan" / "oracle_expectation_plan.yaml", plan["oracle_expectation"])
    write_md(out / "oracle_expectation_plan" / "oracle_expectation_plan.md", "Oracle Expectation Plan", plan["oracle_expectation"])
    dump_yaml(out / "render_candidate_plan" / "render_candidate_plan.yaml", plan["render_plan"])
    write_md(out / "render_candidate_plan" / "render_candidate_plan.md", "Render Candidate Plan", plan["render_plan"])
    dump_yaml(out / "blocked_adapters" / "blocked_adapters.yaml", plan["blocked_report"])
    write_md(out / "blocked_adapters" / "blocked_adapters.md", "Blocked Adapters", plan["blocked_report"])
    dump_yaml(out / "validation" / "mutation_planner_quality_checks.yaml", plan["quality"])
    write_md(out / "validation" / "mutation_planner_quality_checks.md", "Mutation Planner Quality Checks", plan["quality"])
    dump_yaml(out / "reports" / "next_action_after_mutation_planner.yaml", plan["next_action"])
    write_md(out / "reports" / "next_action_after_mutation_planner.md", "Next Action After Mutation Planner", plan["next_action"])
    dump_yaml(out / "reports" / "family_adapter_mutation_planner_v1_report.yaml", plan["report"])
    write_md(out / "reports" / "family_adapter_mutation_planner_v1_report.md", "Family Adapter Mutation Planner V1 Report", plan["report"])
    write_md(out / "README.md", "family_adapter_mutation_planner_v1", plan["report"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-root", required=True)
    parser.add_argument("--family-template-root", required=True)
    parser.add_argument("--adapter-validate-results", required=True)
    parser.add_argument("--render-readiness", required=True)
    parser.add_argument("--mapping-gate", required=True)
    parser.add_argument("--blocked-mappings", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--max-cases-per-adapter", type=int, default=12)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    plan = plan_family_mutations(args)
    write_plan(out, plan)
    matrix = plan["matrix"]
    render_plan = plan["render_plan"]
    print(f"[OK] mutation planner artifacts written to {out}")
    print(f"[SUMMARY] total_cases: {len(matrix.get('cases', []))}")
    print(f"[SUMMARY] render_candidates: {len(render_plan.get('render_candidates', []))}")
    print(f"[SUMMARY] next_task_name: {plan['next_action']['next_task_name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
