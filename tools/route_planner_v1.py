#!/usr/bin/env python3
"""Route planner v1 for scheduler-selected families.

This tool converts auto_scheduler_v1 output into route contracts and next-task
contracts. It is intentionally read-only with respect to Pattern Bank and does
not render, compile, run, call GLM, or claim vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml


TOP_FAMILY = "x509_parsing"


def load_json(path: Path, errors: list[dict[str, str]]) -> Any:
    if not path.exists():
        errors.append({"path": str(path), "error": "missing"})
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append({"path": str(path), "error": str(exc)})
        return {}


def load_yaml(path: Path, errors: list[dict[str, str]]) -> Any:
    if not path.exists():
        errors.append({"path": str(path), "error": "missing"})
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        errors.append({"path": str(path), "error": str(exc)})
        return {}


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def write_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def md_table(rows: list[dict[str, Any]], headers: list[str]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    return "\n".join(lines) + "\n"


def flatten(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(flatten(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for key, val in value.items():
            out.append(str(key))
            out.extend(flatten(val))
        return out
    return [str(value)]


def find_by_family(items: list[dict[str, Any]], family: str) -> dict[str, Any]:
    for item in items:
        if item.get("family") == family:
            return item
    return {}


def load_feedback_files(feedback_dir: Path, errors: list[dict[str, str]]) -> list[str]:
    files = []
    for path in sorted(feedback_dir.glob("*.jsonl")):
        files.append(str(path))
        try:
            # Touch-parse enough to report invalid JSONL, but do not aggregate here.
            for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                line = line.strip()
                if line:
                    json.loads(line)
        except Exception as exc:
            errors.append({"path": str(path), "line": str(idx), "error": str(exc)})
    return files


def collect_x509_pattern_info(pattern_bank: dict[str, Any], knowledge_dir: Path) -> dict[str, Any]:
    seeds: list[str] = []
    apis: set[str] = set()
    artifacts: set[str] = set()
    trigger_behaviors: set[str] = set()
    components: set[str] = set()

    for pat in pattern_bank.get("patterns", []) or []:
        if not isinstance(pat, dict) or pat.get("family") != TOP_FAMILY:
            continue
        if pat.get("pattern_id"):
            seeds.append(str(pat["pattern_id"]))
        for value in pat.get("source_api", []) or []:
            apis.add(str(value))
        for value in pat.get("target_api", []) or []:
            apis.add(str(value))
        for value in pat.get("evidence_files", []) or []:
            artifacts.add(str(value))
        for value in pat.get("notes", []) or []:
            text = str(value)
            if "Trigger behavior:" in text:
                trigger_behaviors.add(text.split("Trigger behavior:", 1)[1].strip().split(".")[0])
            if "Component:" in text:
                components.add(text.split("Component:", 1)[1].strip().split(".")[0])

    for path in sorted(knowledge_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for block in re.split(r"\n## ", text):
            if "Family: x509_parsing" not in block:
                continue
            first = block.splitlines()[0].strip("# ").strip()
            if first and first not in seeds:
                seeds.append(first)
            for match in re.finditer(r"Source API:\s*(.+)", block):
                for token in re.split(r",\s*", match.group(1).strip()):
                    if token:
                        apis.add(token)

    return {
        "known_seeds": sorted(dict.fromkeys(seeds)),
        "known_artifacts": sorted(artifacts),
        "api_groups": sorted(apis),
        "trigger_behaviors": sorted(trigger_behaviors),
        "components": sorted(components),
    }


def build_input_summary(
    auto_scheduler_dir: Path,
    schema_dir: Path,
    pattern_bank_path: Path,
    scheduler_seed_path: Path,
    feedback_dir: Path,
    knowledge_dir: Path,
    next_rec: dict[str, Any],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    required = [
        auto_scheduler_dir / "output/next_task_recommendation.json",
        auto_scheduler_dir / "output/route_decisions.json",
        auto_scheduler_dir / "scoring/family_scores.json",
        auto_scheduler_dir / "gates/gate_results.json",
        auto_scheduler_dir / "parsed/family_inventory.json",
        schema_dir / "schema/route_decision_schema.yaml",
        schema_dir / "gates/evidence_gate.yaml",
        schema_dir / "gates/a_path_glm_gate.yaml",
        pattern_bank_path,
        scheduler_seed_path,
        knowledge_dir / "unified_patterns.md",
        knowledge_dir / "openssl_issue_patterns.md",
    ]
    missing = [str(path) for path in required if not path.exists()]
    return {
        "loaded_sources": {
            "auto_scheduler": str(auto_scheduler_dir),
            "schema_dir": str(schema_dir),
            "pattern_bank": str(pattern_bank_path),
            "scheduler_seed": str(scheduler_seed_path),
            "feedback_files": load_feedback_files(feedback_dir, errors),
            "knowledge_files": [str(knowledge_dir / "unified_patterns.md"), str(knowledge_dir / "openssl_issue_patterns.md")],
        },
        "missing_sources": missing,
        "parse_errors": errors,
        "auto_scheduler_recommendation": {
            "top_1_family": next_rec.get("top_1_family"),
            "top_2_family": next_rec.get("top_2_family"),
            "top_3_family": next_rec.get("top_3_family"),
            "recommended_next_task": next_rec.get("recommended_next_task"),
            "recommended_route": next_rec.get("recommended_route"),
            "glm_allowed": next_rec.get("glm_allowed"),
            "auto_render_allowed": next_rec.get("auto_render_allowed"),
            "auto_run_allowed": next_rec.get("auto_run_allowed"),
        },
        "interpretation": {
            "why_top_1_x509": "x509_parsing has many historical seeds, medium evidence, and is not blocked by seed-missing, closed negative feedback, or external validation.",
            "why_route_c_is_tentative": "Many x509 issues involve app-visible x509/verify/crl behavior, but some seeds overlap with D-path crash audit and ASN.1 boundary families; C-path is a triage hypothesis, not a final execution route.",
            "why_no_render_run": "auto_scheduler_v1 explicitly set auto_render_allowed=false and auto_run_allowed=false; route_planner_v1 only emits contracts.",
            "why_no_glm": "A-path gate is false for x509_parsing and no recipe-slot contract exists for this route yet.",
        },
    }


def make_x509_contract(
    route: dict[str, Any],
    gate: dict[str, Any],
    score: dict[str, Any],
    inventory: dict[str, Any],
    pattern_info: dict[str, Any],
) -> dict[str, Any]:
    route_confidence = "medium"
    ambiguity = [
        "C_app_level_validation_gap is plausible because several x509 seeds are app-visible wrong-result/wrong-output cases.",
        "D_crash_sanitizer_evidence_audit remains plausible for seeds such as CSR/ASN.1 NULL dereference reports.",
        "A-path is premature until seed inventory, API grouping, and oracle comparability are explicit.",
        "B-path is possible later for verifier/state-machine style mutations, but controls are not defined yet.",
    ]
    return {
        "family": TOP_FAMILY,
        "scheduler_rank": 1,
        "recommended_route": route.get("recommended_route", "C_app_level_validation_gap"),
        "route_confidence": route_confidence,
        "evidence_strength": inventory.get("evidence_strength", "medium"),
        "known_seeds": pattern_info["known_seeds"],
        "known_artifacts": pattern_info["known_artifacts"],
        "api_groups": pattern_info["api_groups"],
        "oracle_candidates": [
            "app visible wrong-result / wrong-output",
            "safe rejection vs accepted malformed certificate/CRL/CSR",
            "verification result divergence",
            "sanitizer/null-dereference evidence for D-path seeds only",
        ],
        "gate_results": {
            "evidence_gate": gate.get("evidence_gate", {}),
            "a_path_gate": gate.get("a_path_gate", {}),
            "glm_gate": gate.get("glm_gate", {}),
        },
        "allowed_actions": {
            "auto_triage": True,
            "auto_render": False,
            "auto_run": False,
            "glm": False,
        },
        "blocked_actions": [
            "render_cases",
            "compile_run",
            "GLM slot filling",
            "free-form C generation",
            "vulnerability or CVE claim",
            "Pattern Bank write-back",
        ],
        "route_ambiguity": ambiguity,
        "relation_to_der_full_consumption": "DER full-consumption is already an app-level trailing-data validation gap; x509_parsing is broader and must avoid duplicating that exact completed C-path unless a new x509-specific app behavior is identified.",
        "relation_to_asn1_nested_boundary": "ASN.1 nested boundary is blocked on missing crash seed; x509_parsing must first classify seeds into app-visible semantics vs D-path crash audit before using ASN.1 evidence.",
        "triage_requirements": [
            "build x509 seed inventory",
            "separate semantic/app-level cases from crash/ASN.1 nested boundary cases",
            "identify OpenSSL app-level x509/verify/crl/req/decoder paths",
            "define controls and oracle candidates before any render/run",
        ],
        "next_task_name": "x509_parsing_triage_v1",
        "next_task_goal": "Create seed inventory, route disambiguation, API group map, and oracle candidates for x509_parsing without render/run.",
        "score_snapshot": score,
    }


def make_gate_decision(contract: dict[str, Any]) -> dict[str, Any]:
    evidence_gate = contract["gate_results"]["evidence_gate"]
    a_path_gate = contract["gate_results"]["a_path_gate"]
    glm_gate = contract["gate_results"]["glm_gate"]
    return {
        "evidence_gate": {
            "passed": bool(evidence_gate.get("passed")),
            "reason": "Medium scheduler evidence is enough for triage, not for render/run.",
            "strength": evidence_gate.get("strength", contract["evidence_strength"]),
        },
        "route_gate": {
            "selected_route": contract["recommended_route"],
            "reason": "Use C-path only as a triage hypothesis because x509 has app-visible wrong-result cases; D-path and A/B alternatives remain unresolved.",
            "alternatives": {
                "D_crash_sanitizer_evidence_audit": "Use only for seeds with real crash/sanitizer input and reproducibility path.",
                "A_recipe_slot_cross_library_migration": "Blocked until source/target API mapping and oracle comparability are explicit.",
                "B_controlled_family_mutation": "Possible later for verifier/state machine behavior after controls exist.",
            },
        },
        "a_path_gate": {
            "passed": bool(a_path_gate.get("passed")),
            "reason": "No validated cross-library recipe-slot mapping or comparable oracle yet.",
        },
        "glm_gate": {
            "glm_allowed": bool(glm_gate.get("glm_allowed")),
            "reason": "GLM is disallowed because A-path gate is false.",
            "allowed_role": "none",
            "forbidden_role": [
                "free_form_c_generation",
                "API_contract_guessing",
                "vulnerability_claim",
                "sanitizer_interpretation",
            ],
        },
        "execution_gate": {
            "auto_triage_allowed": True,
            "auto_render_allowed": False,
            "auto_run_allowed": False,
            "reason": "Planner can authorize only evidence collection and route disambiguation in the next sprint.",
        },
    }


def make_top3_overview(next_rec: dict[str, Any], route_decisions: list[dict[str, Any]], scores: list[dict[str, Any]]) -> dict[str, Any]:
    route_by_family = {row.get("family"): row for row in route_decisions}
    score_by_family = {row.get("family"): row for row in scores}
    families = [next_rec.get("top_1_family"), next_rec.get("top_2_family"), next_rec.get("top_3_family")]
    rows = []
    for idx, family in enumerate(families, 1):
        route = route_by_family.get(family, {})
        score = score_by_family.get(family, {})
        rows.append(
            {
                "rank": idx,
                "family": family,
                "recommended_route": route.get("recommended_route"),
                "final_score": score.get("final_score"),
                "reason": route.get("reason"),
            }
        )
    return {
        "top3": rows,
        "why_top2_not_first": "evp_pkey_context_lifecycle has weak evidence gate in scheduler output; it should wait for evidence strengthening.",
        "why_top3_der_not_directly_continue": "der_full_consumption already has strong C-path signal and should proceed via minimal reproducer/upstream inquiry, not repeat the completed discovery path.",
        "fallback_if_x509_blocked": "evp_pkey_context_lifecycle_evidence_strengthening_v1 before any render/run; if its evidence remains weak, use der_full_consumption minimal reproducer/upstream inquiry track.",
    }


def make_task_contract(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "next_task_name": "x509_parsing_triage_v1",
        "family": TOP_FAMILY,
        "task_type": "auto_triage_contract",
        "goal": "Decide whether x509_parsing should follow C, D, A, or B route using seed inventory, API grouping, and oracle abstraction.",
        "allowed_actions": {
            "collect_seed_inventory": True,
            "read_existing_artifacts": True,
            "collect_api_evidence": True,
            "define_oracle_candidates": True,
            "render_cases": False,
            "compile_run": False,
            "glm": False,
        },
        "required_steps": [
            "Collect x509_parsing historical seeds from Pattern Bank and knowledge_raw.",
            "Separate x509_parsing from der_full_consumption and asn1_nested_boundary.",
            "Map OpenSSL app-level x509/verify/crl/req/decoder/d2i APIs.",
            "Abstract oracle candidates for wrong-result, wrong-output, safe rejection, and crash-audit seeds.",
            "Choose final route among C/D/A/B or block.",
            "Do not render/run and do not use GLM in triage.",
            "Emit whether gated_auto_triage_v1 can continue.",
        ],
        "route_questions": [
            "Which seeds have real inputs?",
            "Which seeds are app-level behavior vs parser boundary vs crash audit?",
            "Which app or API paths expose observable behavior?",
            "Which controls are required before any mutation/render?",
        ],
        "handoff_to": "gated_auto_triage_v1 if seed inventory and route disambiguation are sufficient",
        "source_route_contract": contract["family"],
    }


def render_contract_md(contract: dict[str, Any]) -> str:
    return (
        "# x509_parsing Route Contract\n\n"
        + yaml.safe_dump(contract, sort_keys=False)
        + "\n## Interpretation\n\n"
        + "The contract accepts the scheduler top-1 selection for triage only. It keeps `C_app_level_validation_gap` as a tentative route, while explicitly preserving D/A/B alternatives until seed inventory and oracle abstraction are complete.\n"
    )


def render_gate_md(decision: dict[str, Any]) -> str:
    return "# x509_parsing Gate Decision\n\n" + yaml.safe_dump(decision, sort_keys=False)


def render_top3_md(overview: dict[str, Any]) -> str:
    return "# Top-3 Route Overview\n\n" + yaml.safe_dump(overview, sort_keys=False)


def render_task_md(task: dict[str, Any]) -> str:
    return "# x509_parsing_triage_v1 Task Contract\n\n" + yaml.safe_dump(task, sort_keys=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only route planner v1")
    parser.add_argument("--auto-scheduler-dir", required=True)
    parser.add_argument("--schema-dir", required=True)
    parser.add_argument("--pattern-bank", required=True)
    parser.add_argument("--scheduler-seed", required=True)
    parser.add_argument("--feedback-dir", required=True)
    parser.add_argument("--knowledge-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    auto_dir = Path(args.auto_scheduler_dir)
    schema_dir = Path(args.schema_dir)
    pattern_bank_path = Path(args.pattern_bank)
    scheduler_seed_path = Path(args.scheduler_seed)
    feedback_dir = Path(args.feedback_dir)
    knowledge_dir = Path(args.knowledge_dir)
    out_dir = Path(args.out_dir)
    errors: list[dict[str, str]] = []

    next_rec = load_json(auto_dir / "output/next_task_recommendation.json", errors)
    route_decisions = (load_json(auto_dir / "output/route_decisions.json", errors).get("route_decisions") or [])
    scores = (load_json(auto_dir / "scoring/family_scores.json", errors).get("family_scores") or [])
    gates = (load_json(auto_dir / "gates/gate_results.json", errors).get("gate_results") or [])
    inventory_rows = (load_json(auto_dir / "parsed/family_inventory.json", errors).get("families") or [])
    route_schema = load_yaml(schema_dir / "schema/route_decision_schema.yaml", errors)
    evidence_schema = load_yaml(schema_dir / "gates/evidence_gate.yaml", errors)
    glm_schema = load_yaml(schema_dir / "gates/a_path_glm_gate.yaml", errors)
    pattern_bank = load_yaml(pattern_bank_path, errors)
    scheduler_seed = load_yaml(scheduler_seed_path, errors)

    input_summary = build_input_summary(
        auto_dir,
        schema_dir,
        pattern_bank_path,
        scheduler_seed_path,
        feedback_dir,
        knowledge_dir,
        next_rec,
        errors,
    )
    input_summary["schema_loaded"] = {
        "route_decision_schema": bool(route_schema),
        "evidence_gate": bool(evidence_schema),
        "a_path_glm_gate": bool(glm_schema),
        "scheduler_seed": bool(scheduler_seed),
    }

    x509_route = find_by_family(route_decisions, TOP_FAMILY)
    x509_gate = find_by_family(gates, TOP_FAMILY)
    x509_score = find_by_family(scores, TOP_FAMILY)
    x509_inventory = find_by_family(inventory_rows, TOP_FAMILY)
    pattern_info = collect_x509_pattern_info(pattern_bank, knowledge_dir)
    contract = make_x509_contract(x509_route, x509_gate, x509_score, x509_inventory, pattern_info)
    gate_decision = make_gate_decision(contract)
    top3 = make_top3_overview(next_rec, route_decisions, scores)
    task_contract = make_task_contract(contract)

    write_yaml(out_dir / "input/route_planner_input_summary.yaml", input_summary)
    write_md(
        out_dir / "input/route_planner_input_summary.md",
        "# route_planner_v1 Input Summary\n\n" + yaml.safe_dump(input_summary, sort_keys=False),
    )
    write_json(out_dir / "route_contracts/x509_parsing_route_contract.json", contract)
    write_md(out_dir / "route_contracts/x509_parsing_route_contract.md", render_contract_md(contract))
    write_json(out_dir / "route_contracts/top3_route_overview.json", top3)
    write_md(out_dir / "route_contracts/top3_route_overview.md", render_top3_md(top3))
    write_json(out_dir / "gates/x509_parsing_gate_decision.json", gate_decision)
    write_md(out_dir / "gates/x509_parsing_gate_decision.md", render_gate_md(gate_decision))
    write_yaml(out_dir / "next_task/x509_parsing_triage_task_contract.yaml", task_contract)
    write_md(out_dir / "next_task/x509_parsing_triage_task_contract.md", render_task_md(task_contract))

    report = {
        "sprint": "route_planner_v1",
        "input_sources": input_summary["loaded_sources"],
        "auto_scheduler_recommendation_accepted": True,
        "top_1_family": TOP_FAMILY,
        "top_1_route": contract["recommended_route"],
        "route_confidence": contract["route_confidence"],
        "route_ambiguity": contract["route_ambiguity"],
        "auto_triage_allowed": True,
        "auto_render_allowed": False,
        "auto_run_allowed": False,
        "glm_allowed": False,
        "top2_fallback": "evp_pkey_context_lifecycle_evidence_strengthening_v1",
        "top3_fallback": "der_full_consumption_minimal_reproducer_or_upstream_inquiry",
        "next_task_name": "x509_parsing_triage_v1",
        "vulnerability_found": False,
        "pattern_bank_modified": False,
        "next_stage": "gated_auto_triage_v1 after x509 seed inventory and route disambiguation",
    }
    write_yaml(out_dir / "reports/route_planner_v1_report.yaml", report)
    report_md = (
        "# route_planner_v1 Report\n\n"
        f"- Top-1 family: `{TOP_FAMILY}`\n"
        f"- Route: `{contract['recommended_route']}`\n"
        f"- Route confidence: `{contract['route_confidence']}`\n"
        "- Auto triage: `true`\n"
        "- Auto render/run: `false` / `false`\n"
        "- GLM allowed: `false`\n"
        "- Pattern Bank modified: `false`\n"
        "- Vulnerability found: `false`\n\n"
        "## Route Ambiguity\n\n"
        + "\n".join(f"- {item}" for item in contract["route_ambiguity"])
        + "\n"
    )
    write_md(out_dir / "reports/route_planner_v1_report.md", report_md)
    write_md(
        out_dir / "README.md",
        "# route_planner_v1\n\n"
        "Read-only route planner sprint. It consumes `auto_scheduler_v1` output and emits x509 route/gate/task contracts. It does not modify Pattern Bank, render cases, compile/run harnesses, call GLM, or claim vulnerabilities.\n",
    )

    print("route_planner_v1 completed: family=x509_parsing next=x509_parsing_triage_v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
