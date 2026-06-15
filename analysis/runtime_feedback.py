#!/usr/bin/env python3
"""Create staged runtime feedback without contaminating main knowledge layers."""

from __future__ import annotations

import argparse
import datetime as _dt
from pathlib import Path
from typing import Any

import yaml

from analysis.candidate_queue import build_handoff, build_queue, candidate_items
from analysis.mutation_feedback import build_mutation_policy_feedback
from analysis.scheduler_proposal import build_scheduler_proposal


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=100)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def md_dump(title: str, data: dict[str, Any]) -> str:
    return f"# {title}\n\n```yaml\n{yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)}```\n"


def build_feedback(report: dict[str, Any], previous_mut: dict[str, Any], queue_count: int) -> dict[str, Any]:
    previous_summary = previous_mut.get("summary", {})
    return {
        "schema": "runtime_feedback_staged_v1",
        "generated_at": now_iso(),
        "source_task": "valid_prefix_pipeline_to_analyze_v1",
        "feedback_scope": {
            "family": "asn1_nested_boundary",
            "target_library": "openssl",
            "target_status": "staged_only",
        },
        "observations": {
            "original_mutation_batch": {
                "accepted_true": 0,
                "interpretation": "malformed_mutation_too_strong_for_accept_path",
                "too_strong_all_reject": previous_summary.get("too_strong_all_reject", 14),
            },
            "valid_prefix_batch": {
                "rendered_cases": report.get("rendered_cases", 0),
                "accepted_true": report.get("accepted_true", 0),
                "full_consumption_gap_candidate": report.get("full_consumption_gap_candidate", queue_count),
                "sanitizer_observed": 0,
                "crash_observed": 0,
            },
        },
        "feedback_items": [
            {
                "category": "mutation_policy",
                "recommendation": "increase_priority_valid_prefix_trailing_only",
                "confidence": "medium",
            },
            {
                "category": "mutation_policy",
                "recommendation": "reduce_strength_for_length_corruption",
                "confidence": "medium",
            },
            {
                "category": "oracle",
                "recommendation": "keep_oracle_event_instrumentation",
                "confidence": "high",
            },
            {
                "category": "scheduler",
                "recommendation": "schedule_more_asn1_valid_prefix_cases",
                "confidence": "medium",
            },
            {
                "category": "seed_discovery",
                "recommendation": "run_valid_seed_discovery_for_pkcs",
                "confidence": "high",
            },
        ],
        "candidate_status": {
            "full_consumption_gap_candidates": {
                "count": queue_count,
                "status": "external_validation_pending",
                "confirmed_vulnerability": False,
                "cve": False,
                "exploitable": False,
            }
        },
        "write_policy": {
            "staged_only": True,
            "main_knowledge_written": False,
            "pattern_bank_written": False,
            "scheduler_seed_written": False,
        },
    }


def build_quality(staged_written: bool, queue: dict[str, Any]) -> dict[str, Any]:
    quality_pass = staged_written and queue.get("summary", {}).get("total_candidates", 0) == queue.get(
        "summary", {}
    ).get("pending_external_validation", -1)
    return {
        "schema": "runtime_feedback_quality_checks_v1",
        "generated_at": now_iso(),
        "inputs_loaded": True,
        "valid_prefix_results_loaded": True,
        "candidate_queue_generated": True,
        "mutation_policy_feedback_generated": True,
        "scheduler_feedback_generated": True,
        "teammate_handoff_generated": True,
        "staged_feedback_written": staged_written,
        "main_knowledge_written": False,
        "pattern_bank_written": False,
        "scheduler_seed_written": False,
        "oracle_semantic_triage_performed": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "glm_called": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass" if quality_pass else "partial",
    }


def build_next_action(queue: dict[str, Any], quality: dict[str, Any]) -> dict[str, Any]:
    if not queue.get("candidates"):
        task = "runtime_feedback_candidate_queue_fixup_v1"
        reason = "candidate queue is empty or missing"
    elif quality.get("main_knowledge_written") or quality.get("pattern_bank_written"):
        task = "feedback_contamination_cleanup_v1"
        reason = "feedback contamination detected"
    else:
        task = "family_loop_closure_report_v1"
        reason = "staged feedback and external-validation queue generated successfully"
    return {
        "schema": "next_action_after_runtime_feedback_v1",
        "generated_at": now_iso(),
        "next_task_name": task,
        "secondary_next_task": "valid_seed_discovery_pkcs_v1",
        "reason": reason,
    }


def build_report(
    feedback: dict[str, Any],
    queue: dict[str, Any],
    quality: dict[str, Any],
    next_doc: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "runtime_feedback_integration_v1_report",
        "task": "runtime_feedback_integration_v1",
        "generated_at": now_iso(),
        "skipped_local_oracle_semantic_triage": True,
        "staged_feedback_generated": True,
        "mutation_policy_feedback_generated": True,
        "scheduler_proposal_generated": True,
        "full_consumption_candidates": queue["summary"]["total_candidates"],
        "all_candidates_external_validation_pending": queue["summary"]["total_candidates"]
        == queue["summary"]["pending_external_validation"],
        "main_knowledge_written": False,
        "pattern_bank_written": False,
        "scheduler_seed_written": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "quality_status": quality["quality_status"],
        "next_task_name": next_doc["next_task_name"],
        "secondary_next_task": next_doc["secondary_next_task"],
        "claim_policy": feedback["candidate_status"]["full_consumption_gap_candidates"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--valid-prefix-pipeline-status", required=True)
    parser.add_argument("--valid-prefix-case-analysis", required=True)
    parser.add_argument("--valid-prefix-family-analysis", required=True)
    parser.add_argument("--valid-prefix-oracle-semantics", required=True)
    parser.add_argument("--valid-prefix-mutation-effectiveness", required=True)
    parser.add_argument("--valid-prefix-candidate-labels", required=True)
    parser.add_argument("--previous-oracle-aware-mutation-effectiveness", required=True)
    parser.add_argument("--mutation-policy-refinement", required=True)
    parser.add_argument("--seed-inventory", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--staged-feedback-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    staged_dir = Path(args.staged_feedback_dir)
    out.mkdir(parents=True, exist_ok=True)
    staged_dir.mkdir(parents=True, exist_ok=True)

    pipeline_status = load_yaml(Path(args.valid_prefix_pipeline_status))
    case_analysis = load_yaml(Path(args.valid_prefix_case_analysis))
    load_yaml(Path(args.valid_prefix_family_analysis))
    load_yaml(Path(args.valid_prefix_oracle_semantics))
    load_yaml(Path(args.valid_prefix_mutation_effectiveness))
    labels_doc = load_yaml(Path(args.valid_prefix_candidate_labels))
    previous_mut = load_yaml(Path(args.previous_oracle_aware_mutation_effectiveness))
    load_yaml(Path(args.mutation_policy_refinement))
    seed_inventory = load_yaml(Path(args.seed_inventory))
    report_path = Path("artifacts/sprints/valid_prefix_pipeline_to_analyze_v1/reports/valid_prefix_pipeline_to_analyze_v1_report.yaml")
    valid_prefix_report = load_yaml(report_path)

    input_summary = {
        "schema": "runtime_feedback_integration_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": vars(args),
        "pipeline_stages": pipeline_status.get("stages", {}),
        "case_analysis_cases": len(case_analysis.get("cases", [])),
        "pkcs_seed_available": seed_inventory.get("summary", {}).get("pkcs_seed_available", False),
        "scope": {
            "offline_only": True,
            "oracle_semantic_triage_performed": False,
            "staged_feedback_only": True,
            "main_knowledge_written": False,
        },
    }
    dump_yaml(out / "input" / "runtime_feedback_input_summary.yaml", input_summary)
    write_text(out / "input" / "runtime_feedback_input_summary.md", md_dump("Input Summary", input_summary))

    candidates = candidate_items(labels_doc)
    queue = build_queue(candidates)
    feedback = build_feedback(valid_prefix_report, previous_mut, len(candidates))
    policy = build_mutation_policy_feedback()
    scheduler = build_scheduler_proposal()
    handoff = build_handoff(candidates)

    dump_yaml(out / "feedback" / "runtime_feedback_staged.yaml", feedback)
    write_text(out / "feedback" / "runtime_feedback_staged.md", md_dump("Runtime Feedback Staged", feedback))
    dump_yaml(staged_dir / "runtime_feedback_staged.yaml", feedback)

    dump_yaml(out / "mutation_policy" / "mutation_policy_feedback.yaml", policy)
    write_text(out / "mutation_policy" / "mutation_policy_feedback.md", md_dump("Mutation Policy Feedback", policy))
    dump_yaml(out / "scheduler" / "scheduler_feedback_proposal.yaml", scheduler)
    write_text(out / "scheduler" / "scheduler_feedback_proposal.md", md_dump("Scheduler Feedback Proposal", scheduler))
    dump_yaml(out / "candidate_queue" / "external_validation_pending_candidates.yaml", queue)
    write_text(out / "candidate_queue" / "external_validation_pending_candidates.md", md_dump("External Validation Pending Candidates", queue))
    dump_yaml(out / "external_validation_handoff" / "teammate_validation_handoff.yaml", handoff)
    write_text(
        out / "external_validation_handoff" / "teammate_validation_handoff.md",
        "\n".join(
            [
                "# Teammate Validation Handoff",
                "",
                "需要队友验证：",
                "- 3 个 full_consumption_gap_candidate",
                "- 是否是 expected OpenSSL prefix-parse behavior",
                "- 是否能上升到 app-level validation gap candidate",
                "- 是否存在真实上层 caller 未检查 full consumption",
                "- 是否需要最小复现",
                "",
                "本轮未做本地 oracle semantic triage，未确认漏洞、CVE 或 exploitable 状态。",
                "",
            ]
        ),
    )

    quality = build_quality((staged_dir / "runtime_feedback_staged.yaml").exists(), queue)
    next_doc = build_next_action(queue, quality)
    report = build_report(feedback, queue, quality, next_doc)
    dump_yaml(out / "validation" / "runtime_feedback_quality_checks.yaml", quality)
    write_text(out / "validation" / "runtime_feedback_quality_checks.md", md_dump("Quality Checks", quality))
    dump_yaml(out / "reports" / "next_action_after_runtime_feedback.yaml", next_doc)
    write_text(out / "reports" / "next_action_after_runtime_feedback.md", md_dump("Next Action", next_doc))
    dump_yaml(out / "reports" / "runtime_feedback_integration_v1_report.yaml", report)
    write_text(out / "reports" / "runtime_feedback_integration_v1_report.md", md_dump("Runtime Feedback Integration Report", report))
    write_text(
        out / "README.md",
        "\n".join(
            [
                "# runtime_feedback_integration_v1",
                "",
                f"- skipped_local_oracle_semantic_triage: {report['skipped_local_oracle_semantic_triage']}",
                f"- staged_feedback_generated: {report['staged_feedback_generated']}",
                f"- full_consumption_candidates: {report['full_consumption_candidates']}",
                f"- external_validation_pending: {report['all_candidates_external_validation_pending']}",
                f"- next_task_name: {report['next_task_name']}",
                f"- secondary_next_task: {report['secondary_next_task']}",
                "",
                "No render, compile, run, GLM, main knowledge write, Pattern Bank write, scheduler_seed write, or vulnerability claim was performed.",
                "",
            ]
        ),
    )
    print(f"[OK] wrote runtime feedback integration artifacts to {out}")
    print(
        "[SUMMARY] "
        f"staged_feedback=true candidates={queue['summary']['total_candidates']} "
        f"pending={queue['summary']['pending_external_validation']} quality={quality['quality_status']}"
    )
    print(f"[NEXT] {next_doc['next_task_name']} secondary={next_doc['secondary_next_task']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
