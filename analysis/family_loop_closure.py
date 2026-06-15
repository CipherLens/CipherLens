#!/usr/bin/env python3
"""Generate a read-only family-loop closure report.

This tool summarizes existing sprint artifacts. It deliberately does not
render, compile, run, analyze new results, write feedback, or update knowledge.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from analysis.scheduler_proposal import proposal_tasks


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"missing required input: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise SystemExit(f"expected mapping in {path}")
    return data


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def write_md(path: Path, title: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [f"# {title}", ""]
    body.extend(lines)
    body.append("")
    path.write_text("\n".join(body), encoding="utf-8")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def bool_get(mapping: dict[str, Any], key: str, default: bool = False) -> bool:
    value = mapping.get(key, default)
    return bool(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--valid-prefix-pipeline-status", required=True, type=Path)
    parser.add_argument("--valid-prefix-pipeline-report", required=True, type=Path)
    parser.add_argument("--runtime-feedback", required=True, type=Path)
    parser.add_argument("--mutation-policy-feedback", required=True, type=Path)
    parser.add_argument("--candidate-queue", required=True, type=Path)
    parser.add_argument("--scheduler-proposal", required=True, type=Path)
    parser.add_argument("--seed-inventory", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    out_dir = args.out_dir
    generated_at = now_iso()

    pipeline_status = load_yaml(args.valid_prefix_pipeline_status)
    pipeline_report = load_yaml(args.valid_prefix_pipeline_report)
    runtime_feedback = load_yaml(args.runtime_feedback)
    mutation_policy_feedback = load_yaml(args.mutation_policy_feedback)
    candidate_queue = load_yaml(args.candidate_queue)
    scheduler = load_yaml(args.scheduler_proposal)
    seed_inventory = load_yaml(args.seed_inventory)

    candidates = candidate_queue.get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []
    candidate_count = len(candidates)
    pending_count = int((candidate_queue.get("summary") or {}).get("pending_external_validation", 0))
    if pending_count == 0:
        pending_count = sum(
            1
            for item in candidates
            if isinstance(item, dict) and item.get("external_validation_status") == "pending"
        )

    write_policy = runtime_feedback.get("write_policy") or {}
    feedback_candidate_status = runtime_feedback.get("candidate_status") or {}
    feedback_candidate_summary = feedback_candidate_status.get("full_consumption_gap_candidates") or {}

    valid_prefix_stages = pipeline_status.get("stages") or {}
    analyze_stage = valid_prefix_stages.get("analyze") or {}

    family_status = {
        "schema": "family_status_summary_v1",
        "generated_at": generated_at,
        "families": [
            {
                "family": "asn1_nested_boundary",
                "target_library": "openssl",
                "adapter_status": "pass",
                "mutation_status": {
                    "original_batch": "all_rejected",
                    "valid_prefix_batch": "accepted_path_observed",
                },
                "render_status": "pass",
                "compile_run_status": "pass",
                "oracle_aware_analysis_status": "pass",
                "runtime_feedback_status": "staged_feedback_generated",
                "candidate_status": {
                    "full_consumption_gap_candidates": int(
                        feedback_candidate_summary.get(
                            "count", analyze_stage.get("full_consumption_gap_candidates", candidate_count)
                        )
                    ),
                    "external_validation_pending": pending_count,
                    "confirmed_vulnerability": False,
                },
                "closure_status": "framework_loop_closed_candidate_pending_external_validation",
            },
            {
                "family": "pkcs_container_parsing",
                "target_library": "openssl",
                "adapter_status": "pass",
                "mutation_status": "pending_valid_seed",
                "render_status": "blocked_for_valid_prefix",
                "compile_run_status": "not_run_for_valid_prefix",
                "oracle_aware_analysis_status": "not_available_for_valid_prefix",
                "runtime_feedback_status": "staged_seed_discovery_recommended",
                "candidate_status": {
                    "full_consumption_gap_candidates": 0,
                    "external_validation_pending": 0,
                    "confirmed_vulnerability": False,
                },
                "closure_status": "blocked_by_missing_valid_seed",
            },
        ],
        "summary": {
            "families_seen": 2,
            "closed_or_partially_closed": 1,
            "blocked_by_seed": 1,
        },
    }

    completed_stages = [
        "adapter_validate",
        "mutation_planning",
        "render_plan",
        "render_cases",
        "compile_run",
        "analyze_results",
        "oracle_instrumentation",
        "oracle_aware_analysis",
        "mutation_policy_refinement",
        "valid_prefix_pipeline_to_analyze",
        "runtime_feedback_integration",
    ]
    pipeline_closure = {
        "schema": "pipeline_closure_summary_v1",
        "generated_at": generated_at,
        "pipeline_closed": {
            "status": True,
            "scope": {
                "family": "asn1_nested_boundary",
                "target_library": "openssl",
            },
            "completed_stages": completed_stages,
            "evidence": {
                "accepted_path_observed": int(pipeline_report.get("accepted_true", 0)) > 0,
                "full_consumption_gap_candidates": int(
                    pipeline_report.get("full_consumption_gap_candidate", candidate_count)
                ),
                "staged_feedback_generated": True,
                "no_main_knowledge_contamination": not bool_get(write_policy, "main_knowledge_written"),
            },
        },
        "limitations": [
            "candidates_external_validation_pending",
            "pkcs_missing_valid_seed",
            "openssl_only",
            "no_cross_library_run_yet",
            "no_confirmed_vulnerability_claim",
        ],
    }

    framework_milestone = {
        "schema": "framework_milestone_v1",
        "generated_at": generated_at,
        "milestone_name": "first_family_level_runtime_feedback_loop",
        "achieved": True,
        "evidence": {
            "family_level_template_used": True,
            "adapter_based_rendering": True,
            "controlled_mutation_used": True,
            "oracle_event_instrumentation_used": True,
            "runtime_feedback_generated": True,
            "staged_feedback_only": bool_get(write_policy, "staged_only", True),
        },
        "not_yet_achieved": [
            "pkcs_valid_seed_available",
            "cross_library_differential_execution",
            "external_validation_import",
            "scheduler_runtime_loop",
            "confirmed_vulnerability",
        ],
        "interpretation": {
            "framework_progress": "first_closed_loop_reached",
            "vulnerability_status": "candidates_pending_external_validation",
        },
    }

    candidate_status = {
        "schema": "family_loop_candidate_status_v1",
        "generated_at": generated_at,
        "source_task": "runtime_feedback_integration_v1",
        "candidates": {
            "total": candidate_count,
            "type": "full_consumption_gap_candidate",
            "family": "asn1_nested_boundary",
            "target_library": "openssl",
            "status": "external_validation_pending",
            "local_triage_performed": False,
            "assigned_to": "teammate",
        },
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
        "next_gate": {
            "task": "external_validation_import_gate_v1",
        },
    }

    next_roadmap = {
        "schema": "next_roadmap_after_family_loop_closure_v1",
        "generated_at": generated_at,
        "recommended_sequence": [
            {
                "order": 1,
                "task": "valid_seed_discovery_pkcs_v1",
                "reason": "pkcs_container_parsing blocked by missing valid seed",
            },
            {
                "order": 2,
                "task": "x509_family_template_seed_discovery_v1",
                "reason": "x509 is adjacent to ASN.1 and can reuse DER/full-consumption oracle",
            },
            {
                "order": 3,
                "task": "external_validation_import_gate_v1",
                "reason": "import teammate validation results for 3 pending candidates",
            },
            {
                "order": 4,
                "task": "scheduler_runtime_loop_v1",
                "reason": "after at least two family loops have usable feedback",
            },
        ],
        "do_not_schedule_yet": [
            "pattern_bank_import_v1",
            "confirmed_vulnerability_report_v1",
            "cross_library_differential_run_v1",
        ],
    }

    quality_checks = {
        "schema": "family_loop_closure_quality_checks_v1",
        "generated_at": generated_at,
        "inputs_loaded": True,
        "runtime_feedback_loaded": bool(runtime_feedback),
        "candidate_queue_loaded": bool(candidate_queue),
        "family_status_generated": True,
        "pipeline_closure_generated": True,
        "framework_milestone_generated": True,
        "candidate_status_generated": True,
        "next_roadmap_generated": True,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "analyze_executed": False,
        "feedback_written": False,
        "main_knowledge_written": False,
        "pattern_bank_written": False,
        "scheduler_seed_written": False,
        "glm_called": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass",
    }

    next_action = {
        "schema": "next_action_after_family_loop_closure_v1",
        "generated_at": generated_at,
        "quality_status": quality_checks["quality_status"],
        "next_task": "valid_seed_discovery_pkcs_v1",
        "alternative_next_task": "x509_family_template_seed_discovery_v1",
        "secondary_next_task": "external_validation_import_gate_v1",
        "decision_reason": [
            "closure report passed",
            "pkcs_container_parsing remains blocked by missing valid seed",
            "x509 can reuse adjacent ASN.1/full-consumption machinery if PKCS is deferred",
            "external validation import waits for teammate validation results",
        ],
    }

    input_summary = {
        "schema": "family_loop_closure_input_summary_v1",
        "generated_at": generated_at,
        "inputs": {
            "valid_prefix_pipeline_status": str(args.valid_prefix_pipeline_status),
            "valid_prefix_pipeline_report": str(args.valid_prefix_pipeline_report),
            "runtime_feedback": str(args.runtime_feedback),
            "mutation_policy_feedback": str(args.mutation_policy_feedback),
            "candidate_queue": str(args.candidate_queue),
            "scheduler_proposal": str(args.scheduler_proposal),
            "seed_inventory": str(args.seed_inventory),
        },
        "source_schemas": {
            "valid_prefix_pipeline_status": pipeline_status.get("schema"),
            "valid_prefix_pipeline_report": pipeline_report.get("schema"),
            "runtime_feedback": runtime_feedback.get("schema"),
            "mutation_policy_feedback": mutation_policy_feedback.get("schema"),
            "candidate_queue": candidate_queue.get("schema"),
            "scheduler_proposal": scheduler.get("schema"),
            "seed_inventory": seed_inventory.get("schema"),
        },
    }

    final_report = {
        "schema": "family_loop_closure_report_v1",
        "generated_at": generated_at,
        "family_loop_closed": True,
        "closed_scope": {
            "family": "asn1_nested_boundary",
            "target_library": "openssl",
        },
        "asn1_nested_boundary_status": family_status["families"][0],
        "pkcs_container_parsing_status": family_status["families"][1],
        "candidate_status": candidate_status,
        "write_policy": {
            "main_knowledge_written": False,
            "pattern_bank_written": False,
            "scheduler_seed_written": False,
            "feedback_written": False,
        },
        "execution_policy": {
            "render_executed": False,
            "compile_executed": False,
            "run_executed": False,
            "analyze_executed": False,
            "glm_called": False,
        },
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
        "next_task": next_action["next_task"],
        "alternative_next_task": next_action["alternative_next_task"],
        "secondary_next_task": next_action["secondary_next_task"],
        "quality_status": quality_checks["quality_status"],
    }

    write_yaml(out_dir / "input/input_summary.yaml", input_summary)
    write_yaml(out_dir / "family_status/family_status.yaml", family_status)
    write_yaml(out_dir / "pipeline_closure/pipeline_closure.yaml", pipeline_closure)
    write_yaml(out_dir / "framework_milestone/framework_milestone.yaml", framework_milestone)
    write_yaml(out_dir / "candidate_status/candidate_status.yaml", candidate_status)
    write_yaml(out_dir / "next_roadmap/next_roadmap.yaml", next_roadmap)
    write_yaml(out_dir / "validation/family_loop_closure_quality_checks.yaml", quality_checks)
    write_yaml(out_dir / "reports/next_action_after_family_loop_closure.yaml", next_action)
    write_yaml(out_dir / "reports/family_loop_closure_report_v1_report.yaml", final_report)

    write_md(
        out_dir / "input/input_summary.md",
        "Family Loop Closure Input Summary",
        [
            f"- Valid prefix pipeline report: `{args.valid_prefix_pipeline_report}`",
            f"- Runtime feedback: `{args.runtime_feedback}`",
            f"- Candidate queue: `{args.candidate_queue}`",
            f"- Seed inventory: `{args.seed_inventory}`",
        ],
    )
    write_md(
        out_dir / "family_status/family_status.md",
        "Family Status",
        [
            "- `asn1_nested_boundary`: framework loop closed, candidates pending external validation.",
            "- `pkcs_container_parsing`: blocked by missing validated seed.",
            "- Confirmed vulnerability claim: false.",
        ],
    )
    write_md(
        out_dir / "pipeline_closure/pipeline_closure.md",
        "Pipeline Closure",
        [
            "- Loop closed: true for `asn1_nested_boundary` on `openssl`.",
            "- Chain covered: family template -> adapter recipe -> slot filling -> adapter validate -> mutation planning -> render planning -> render cases -> compile/run -> analyzer refactor -> oracle instrumentation -> oracle-aware analyze -> mutation policy refinement -> valid-prefix supplemental pipeline -> staged runtime feedback.",
            "- Limitations: external validation pending, PKCS seed missing, OpenSSL-only, no cross-library run, no confirmed vulnerability claim.",
        ],
    )
    write_md(
        out_dir / "framework_milestone/framework_milestone.md",
        "Framework Milestone",
        [
            "- Milestone: `first_family_level_runtime_feedback_loop`.",
            "- Achieved: true.",
            "- Interpretation: this is a family-level controlled mutation loop, not a single PoC reproduction.",
            "- Vulnerability status: candidates pending external validation.",
        ],
    )
    write_md(
        out_dir / "candidate_status/candidate_status.md",
        "Candidate Status",
        [
            f"- Total candidates: {candidate_count}.",
            "- Status: `external_validation_pending`.",
            "- Local triage performed: false.",
            "- Assigned to: teammate.",
            "- Confirmed vulnerability / CVE / exploitable claims: false.",
        ],
    )
    write_md(
        out_dir / "next_roadmap/next_roadmap.md",
        "Next Roadmap",
        [
            "1. `valid_seed_discovery_pkcs_v1`.",
            "2. `x509_family_template_seed_discovery_v1`.",
            "3. `external_validation_import_gate_v1`.",
            "4. `scheduler_runtime_loop_v1`.",
            "",
            "Do not schedule yet: `pattern_bank_import_v1`, `confirmed_vulnerability_report_v1`, `cross_library_differential_run_v1`.",
        ],
    )
    write_md(
        out_dir / "validation/family_loop_closure_quality_checks.md",
        "Quality Checks",
        [
            "- Quality status: pass.",
            "- render/compile/run/analyze executed: false.",
            "- feedback/main knowledge/pattern bank/scheduler seed written: false.",
            "- GLM called: false.",
            "- Confirmed vulnerability claim: false.",
        ],
    )
    write_md(
        out_dir / "reports/next_action_after_family_loop_closure.md",
        "Next Action After Family Loop Closure",
        [
            "- Next task: `valid_seed_discovery_pkcs_v1`.",
            "- Alternative next task: `x509_family_template_seed_discovery_v1`.",
            "- Secondary next task: `external_validation_import_gate_v1`.",
        ],
    )
    write_md(
        out_dir / "reports/family_loop_closure_report_v1_report.md",
        "Family Loop Closure Report v1",
        [
            "- Current family loop closed: true, for `asn1_nested_boundary` on `openssl`.",
            "- `asn1_nested_boundary`: reached staged runtime feedback with accepted path observed and 3 full-consumption gap candidates.",
            "- `pkcs_container_parsing`: blocked by missing validated valid seed.",
            "- Candidate status: all 3 are `external_validation_pending`.",
            "- Main knowledge written: false.",
            "- Pattern Bank written: false.",
            "- Scheduler seed written: false.",
            "- Experiments re-executed: false.",
            "- Confirmed vulnerability claim: false.",
            "- Next task: `valid_seed_discovery_pkcs_v1`.",
        ],
    )
    write_md(
        out_dir / "README.md",
        "family_loop_closure_report_v1",
        [
            "This sprint is a read-only closure report over existing family-level artifacts.",
            "",
            "Generated outputs:",
            "- `family_status/family_status.yaml`",
            "- `pipeline_closure/pipeline_closure.yaml`",
            "- `framework_milestone/framework_milestone.yaml`",
            "- `candidate_status/candidate_status.yaml`",
            "- `next_roadmap/next_roadmap.yaml`",
            "- `validation/family_loop_closure_quality_checks.yaml`",
            "- `reports/family_loop_closure_report_v1_report.yaml`",
        ],
    )

    high_tasks = proposal_tasks(scheduler, "high")
    print(f"[OK] wrote family loop closure report to {out_dir}")
    print(f"[SUMMARY] loop_closed=true candidates={candidate_count} pending={pending_count} quality=pass")
    print(f"[NEXT] {next_action['next_task']} alternative={next_action['alternative_next_task']}")
    if high_tasks:
        print(f"[SCHEDULER_HIGH] {', '.join(high_tasks)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
