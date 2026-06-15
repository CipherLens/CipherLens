#!/usr/bin/env python3
"""Audit MAC lifecycle sprint compliance with the recipe-slot A path."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml


SPRINT_ROOT = Path("artifacts/sprints/mac_lifecycle_family_v1")
MIGRATION_ROOT = Path("artifacts/migrations/openssl-issue-22842-evp-mac-get-size-uninit-lifecycle")
MAIN_CHAIN_ROOT = MIGRATION_ROOT / "main_chain_rag_llm_v0"
OUT_YAML = SPRINT_ROOT / "a_path_compliance_report.yaml"
OUT_MD = SPRINT_ROOT / "a_path_compliance_report.md"


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}
    return obj if isinstance(obj, dict) else {}


def exists(path: Path) -> bool:
    return path.exists()


def first_existing(paths: List[Path]) -> Path | None:
    for path in paths:
        if exists(path):
            return path
    return None


def step(
    name: str,
    status: str,
    path: Path | str,
    evidence: str,
    *,
    is_manual_shortcut: bool = False,
    does_it_violate_runbook: bool = False,
    required_fix: str = "",
    notes: str = "",
) -> Dict[str, Any]:
    return {
        "step": name,
        "status": status,
        "path": str(path) if path else "",
        "evidence": evidence,
        "is_manual_shortcut": bool(is_manual_shortcut),
        "does_it_violate_runbook": bool(does_it_violate_runbook),
        "required_fix": required_fix,
        "notes": notes,
    }


def adapter_llm_status(path: Path) -> str:
    return str(load_yaml(path).get("_llm_status", ""))


def adapter_has_disallowed_blocks(path: Path) -> bool:
    obj = load_yaml(path)
    disallowed = {
        "init_block",
        "input_construction_block",
        "trigger_block",
        "cleanup_block",
        "oracle_strategy",
    }
    return any(key in obj for key in disallowed)


def build_report() -> Dict[str, Any]:
    pattern = Path("knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-22842.yaml")
    source_template = SPRINT_ROOT / "source_template" / "tmpl_mac_lifecycle.c"
    template_meta = SPRINT_ROOT / "source_template" / "template_meta.yaml"
    mask_report = SPRINT_ROOT / "mask" / "mask_report.yaml"
    ast_report = first_existing(
        [
            SPRINT_ROOT / "mask" / "ast_mask_report.yaml",
            MAIN_CHAIN_ROOT
            / "cross_templates_recipe"
            / "EVP_MAC_GET_SIZE_UNINIT_LIFECYCLE"
            / "mbedtls_psa_mac_sign_setup"
            / "ast_mask_report.yaml",
            MIGRATION_ROOT
            / "cross_templates_recipe"
            / "EVP_MAC_GET_SIZE_UNINIT_LIFECYCLE"
            / "mbedtls_psa_mac_sign_setup"
            / "ast_mask_report.lite.yaml",
        ]
    )
    selected = SPRINT_ROOT / "mask" / "selected_mask_units.yaml"
    candidates = first_existing(
        [
            SPRINT_ROOT / "candidates.yaml",
            MIGRATION_ROOT / "main_chain_rag_llm_v0" / "candidates.yaml",
            MIGRATION_ROOT / "main_chain_api_cards_v0" / "candidates.yaml",
        ]
    )
    candidates_with_evidence = first_existing(
        [
            SPRINT_ROOT / "candidates_with_evidence.yaml",
            MAIN_CHAIN_ROOT / "candidates_with_evidence.yaml",
            MIGRATION_ROOT / "main_chain_api_cards_v0" / "candidates_with_evidence.yaml",
        ]
    )
    recipe = Path("adapter_recipes/openssl_mbedtls/mac_lifecycle.recipe_slot.yaml")
    adapter = SPRINT_ROOT / "recipe" / "adapter.yaml"
    validated = SPRINT_ROOT / "recipe_validated" / "adapter.yaml"
    validate_report = SPRINT_ROOT / "recipe" / "adapter_validate_report.json"
    cross_templates = SPRINT_ROOT / "cross_templates_recipe" / "cross_mapping.yaml"
    rendered_cases = SPRINT_ROOT / "rendered_cases"
    run_results = SPRINT_ROOT / "results" / "run.jsonl"
    analyze_summary = SPRINT_ROOT / "results" / "run.summary.json"
    behavior_summary = SPRINT_ROOT / "results" / "behavior_summary.json"
    generic_main_summary = MAIN_CHAIN_ROOT / "results" / "run_main_chain.summary.json"
    generic_cross_summary = MAIN_CHAIN_ROOT / "results" / "run_main_chain.migration_summary.json"

    llm_status = adapter_llm_status(adapter)
    manual_slot = llm_status == "manual_controlled_slot_binding"
    has_disallowed = adapter_has_disallowed_blocks(adapter)

    steps = [
        step(
            "real_poc_or_issue_seed",
            "present" if exists(pattern) else "missing",
            pattern,
            "OPENSSL-ISSUE-22842 pattern seed is available.",
        ),
        step(
            "root_cause_or_oracle_extraction",
            "present" if exists(pattern) else "missing",
            pattern,
            "Pattern YAML records root_cause and mac_context_size_lifecycle_oracle.",
        ),
        step(
            "poc_pattern_knowledge",
            "present" if exists(pattern) else "missing",
            pattern,
            "PoC pattern knowledge exists under knowledge_raw.",
        ),
        step(
            "normalized_source_template",
            "present" if exists(source_template) else "missing",
            source_template,
            "MAC lifecycle source template exists in sprint source_template.",
        ),
        step(
            "template_meta",
            "present" if exists(template_meta) else "missing",
            template_meta,
            "Template metadata exists.",
        ),
        step(
            "mask_report",
            "present" if exists(mask_report) else "missing",
            mask_report,
            "Mask report exists.",
        ),
        step(
            "ast_mask_report",
            "present" if ast_report else "partial",
            ast_report or SPRINT_ROOT / "mask",
            "AST report exists in main-chain or migration artifacts."
            if ast_report
            else "Sprint mask directory has selected units but no ast_mask_report.yaml.",
            required_fix="Store the A-path ast_mask_report.yaml next to the sprint mask report."
            if not ast_report
            else "",
            notes="Tree/lite AST reports are available in migration cross-template artifacts."
            if ast_report
            else "",
        ),
        step(
            "selected_mask_units",
            "present" if exists(selected) else "missing",
            selected,
            "Selected mask units are available and validator records them as trace context.",
        ),
        step(
            "rag_evidence",
            "present" if list((SPRINT_ROOT / "evidence").glob("*.json")) else "missing",
            SPRINT_ROOT / "evidence",
            "RAG evidence JSON files are present.",
        ),
        step(
            "candidates_yaml",
            "present" if candidates else "partial",
            candidates or SPRINT_ROOT,
            "candidates.yaml is present."
            if candidates
            else "No candidates.yaml found for the MAC sprint; evidence and recipe skeleton were used directly.",
            is_manual_shortcut=not bool(candidates),
            required_fix="Add candidates.yaml with scored API suitability before claiming full A-path compliance."
            if not candidates
            else "",
        ),
        step(
            "candidates_with_evidence",
            "present" if candidates_with_evidence else "partial",
            candidates_with_evidence or SPRINT_ROOT,
            "candidates_with_evidence.yaml is present in main-chain artifacts."
            if candidates_with_evidence
            else "No candidates_with_evidence.yaml found.",
            is_manual_shortcut=not bool(candidates_with_evidence),
            required_fix="Run migration.evidence_collector and keep candidates_with_evidence.yaml in the sprint root."
            if not candidates_with_evidence
            else "",
        ),
        step(
            "adapter_recipe",
            "present" if exists(recipe) else "missing",
            recipe,
            "Reusable MAC lifecycle recipe exists.",
        ),
        step(
            "llm_slot_bindings_only",
            "partial" if manual_slot else ("present" if llm_status == "ok" else "missing"),
            adapter,
            f"Adapter _llm_status={llm_status!r}; disallowed free-form blocks present={has_disallowed}.",
            is_manual_shortcut=manual_slot,
            does_it_violate_runbook=has_disallowed,
            required_fix="Regenerate through migration.adapter_filler strict recipe mode with LLM slot_bindings only."
            if manual_slot or has_disallowed
            else "",
            notes="manual_controlled_slot_binding validates controlled slots, but is not full LLM A-path compliance."
            if manual_slot
            else "",
        ),
        step(
            "adapter_yaml",
            "present" if exists(adapter) else "missing",
            adapter,
            "Structured adapter.yaml exists.",
        ),
        step(
            "adapter_validate",
            "present" if exists(validated) and exists(validate_report) else "missing",
            validate_report,
            "adapter_validate report and validated adapter exist.",
        ),
        step(
            "cross_generator_from_adapters",
            "partial" if exists(cross_templates) else "missing",
            cross_templates,
            "Cross mapping exists, but sprint README identifies mutation.apply_mac_lifecycle_matrix_to_template as controlled renderer.",
            is_manual_shortcut=True,
            required_fix="Route the family through template_maker.cross_generator_from_adapters for full runbook compliance.",
            notes="Family-specific controlled renderer shortcut; acceptable for core semantic validation.",
        ),
        step(
            "render_cases",
            "partial" if exists(rendered_cases) else "missing",
            rendered_cases,
            "Rendered cases exist under sprint rendered_cases, not standard rendered_cases_recipe.",
            is_manual_shortcut=True,
            required_fix="Use template_maker.render_cases or mirror outputs into standard rendered_cases_recipe layout.",
        ),
        step(
            "compile_run",
            "present" if exists(run_results) else "missing",
            run_results,
            "Runnable sprint produced run.jsonl.",
        ),
        step(
            "analyze_results",
            "partial" if exists(analyze_summary) or exists(behavior_summary) else "missing",
            analyze_summary if exists(analyze_summary) else behavior_summary,
            "Family analyzer produced run.summary.json and behavior_summary.json.",
            is_manual_shortcut=True,
            required_fix="Also run generic runner.analyze_results on standard run_recipe.jsonl for full A-path compliance.",
            notes="Family-specific analyzer extension.",
        ),
        step(
            "analyze_cross_results",
            "partial" if exists(generic_cross_summary) else "missing",
            generic_cross_summary if exists(generic_cross_summary) else SPRINT_ROOT / "results",
            "Generic cross analysis exists in main_chain_rag_llm_v0, but MAC sprint relies on family-specific behavior summary.",
            is_manual_shortcut=True,
            required_fix="Keep generic analyze_cross_results output beside the sprint outputs for full compliance.",
        ),
    ]

    critical_deviations = [
        "adapter _llm_status is manual_controlled_slot_binding, not strict LLM adapter_filler output",
        "candidates.yaml is missing from the MAC sprint root",
        "cross generation and rendering use family-specific controlled shortcuts",
        "MAC sprint analysis relies on family-specific analyzer outputs",
    ]
    acceptable_shortcuts = [
        "selected_mask_units are preserved as trace context",
        "manual controlled slot bindings avoid free-form C generation",
        "family-specific renderer produced deterministic 48-case MAC lifecycle matrix",
        "family-specific analyzer captures lifecycle semantic divergence categories",
    ]
    must_fix = [
        "Generate MAC adapter through migration.adapter_filler strict recipe mode with _llm_status=ok",
        "Store candidates.yaml and candidates_with_evidence.yaml in the sprint root",
        "Route MAC adapter through template_maker.cross_generator_from_adapters",
        "Render through template_maker.render_cases into rendered_cases_recipe",
        "Run generic analyze_results and analyze_cross_results over standard run_recipe outputs",
    ]

    report = {
        "audit_name": "MAC lifecycle A-path compliance audit",
        "sprint_root": str(SPRINT_ROOT),
        "steps": steps,
        "free_form_c_blocks_present": has_disallowed,
        "selected_mask_units_used": exists(selected),
        "recipe_slot_adapter_present": exists(adapter),
        "adapter_validate_ran": exists(validated) and exists(validate_report),
        "adapter_filler_used": not manual_slot and llm_status == "ok",
        "cross_generator_from_adapters_used": False,
        "template_maker_render_cases_used": False,
        "generic_analyze_results_used": exists(generic_main_summary),
        "generic_analyze_cross_results_used": exists(generic_cross_summary),
        "final_compliance_status": "partial_a_path_compliant",
        "can_continue_to_d_path": True,
        "critical_deviations": critical_deviations,
        "acceptable_shortcuts": acceptable_shortcuts,
        "must_fix_before_claiming_full_a_path": must_fix,
        "reason": (
            "MAC lifecycle validated core A-path semantics, but is not full runbook compliant yet. "
            "It preserves template, mask, selected_mask_units, recipe-slot adapter shape, "
            "adapter validation, controlled rendering, compile/run/analyze, and feedback. "
            "However, the adapter uses manual_controlled_slot_binding and several downstream "
            "steps use family-specific shortcuts rather than the standard generic A-path tools."
        ),
    }
    return report


def write_markdown(report: Dict[str, Any]) -> None:
    lines = [
        "# MAC Lifecycle A-Path Compliance Audit",
        "",
        "## Conclusion",
        "",
        f"- final_compliance_status: `{report['final_compliance_status']}`",
        f"- can_continue_to_d_path: `{str(report['can_continue_to_d_path']).lower()}`",
        "",
        "MAC lifecycle validated core A-path semantics, but is not full runbook compliant yet.",
        "",
        "## Critical Deviations",
        "",
    ]
    lines += [f"- {item}" for item in report["critical_deviations"]]
    lines += ["", "## Acceptable Shortcuts", ""]
    lines += [f"- {item}" for item in report["acceptable_shortcuts"]]
    lines += ["", "## Must Fix Before Claiming Full A-Path", ""]
    lines += [f"- {item}" for item in report["must_fix_before_claiming_full_a_path"]]
    lines += ["", "## Step Audit", ""]
    lines += [
        "| step | status | manual shortcut | violates runbook | evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report["steps"]:
        evidence = str(item.get("evidence", "")).replace("|", "\\|")
        lines.append(
            f"| `{item['step']}` | `{item['status']}` | "
            f"`{str(item['is_manual_shortcut']).lower()}` | "
            f"`{str(item['does_it_violate_runbook']).lower()}` | {evidence} |"
        )
    lines += ["", "## Reason", "", report["reason"], ""]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    report = build_report()
    OUT_YAML.parent.mkdir(parents=True, exist_ok=True)
    with OUT_YAML.open("w", encoding="utf-8") as f:
        yaml.safe_dump(report, f, sort_keys=False, allow_unicode=True)
    write_markdown(report)
    print(f"[OK] wrote {OUT_YAML}")
    print(f"[OK] wrote {OUT_MD}")
    print(f"[SUMMARY] final_compliance_status={report['final_compliance_status']}")
    print(f"[SUMMARY] can_continue_to_d_path={report['can_continue_to_d_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
