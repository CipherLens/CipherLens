"""Record X.509 candidate as external pending and continue scheduler planning."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from analysis.analysis_records import dump_yaml, now_iso, write_text


TASK = "x509_external_pending_and_continue_scheduler_v1"


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--candidate-sprint", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def external_pending_record(candidate_sprint: Path, triage: dict[str, Any], brief_path: Path) -> dict[str, Any]:
    candidates = triage.get("candidates", []) or []
    candidate = candidates[0] if candidates else {}
    return {
        "schema": "x509_external_pending_candidate_v1",
        "generated_at": now_iso(),
        "candidate_id": candidate.get("candidate_id", ""),
        "case_id": candidate.get("case_id", ""),
        "family": "x509_parsing",
        "classification": candidate.get("classification", ""),
        "external_validation_status": "external_validation_pending",
        "reason": candidate.get("reason", ""),
        "recommended_next_action": candidate.get("recommended_next_action", ""),
        "evidence_paths": {
            "candidate_sprint": candidate_sprint.as_posix(),
            "triage": (candidate_sprint / "triage/x509_candidate_triage.yaml").as_posix(),
            "teammate_validation_brief": brief_path.as_posix(),
            "evidence_bundle": (candidate_sprint / "evidence/candidate_evidence_bundle").as_posix(),
            "app_replay_results": (candidate_sprint / "replay/x509_app_replay_results.yaml").as_posix(),
        },
        "assigned_to": "teammate",
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }


def existing_external_items(repo_root: Path) -> list[dict[str, Any]]:
    queue = load_yaml(repo_root / "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml")
    items = []
    for task in queue.get("tasks", []) or []:
        if task.get("status") == "external_pending":
            items.append(
                {
                    "task_name": task.get("task_name", ""),
                    "family": task.get("family", ""),
                    "status": "external_validation_pending",
                    "reason": task.get("reason", ""),
                    "blocked_by": task.get("blocked_by", []),
                    "owner": task.get("owner", ""),
                    "source": "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml",
                }
            )
    return items


def build_external_pending_queue(repo_root: Path, x509_record: dict[str, Any]) -> dict[str, Any]:
    items = existing_external_items(repo_root)
    items.append(
        {
            "task_name": "x509_external_validation_pending_v1",
            "family": "x509_parsing",
            "status": "external_validation_pending",
            "reason": x509_record.get("reason", ""),
            "blocked_by": ["teammate_x509_app_level_validation"],
            "owner": "teammate",
            "source": x509_record.get("evidence_paths", {}).get("triage", ""),
            "case_id": x509_record.get("case_id", ""),
            "classification": x509_record.get("classification", ""),
        }
    )
    return {
        "schema": "external_pending_queue_v1",
        "generated_at": now_iso(),
        "items": items,
        "summary": {
            "total_external_pending": len(items),
            "families": sorted({item.get("family", "") for item in items}),
        },
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }


def updated_scheduler_queue(repo_root: Path, external_queue: dict[str, Any]) -> dict[str, Any]:
    source = load_yaml(repo_root / "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml")
    pending_families = set((external_queue.get("summary") or {}).get("families", []))
    mapped_pending = pending_families | {"x509_asn1_inner_boundary"}
    tasks = []
    for task in source.get("tasks", []) or []:
        item = dict(task)
        family = str(item.get("family", ""))
        if family in mapped_pending:
            if item.get("status") == "ready":
                item["status"] = "blocked"
                item["allowed_to_run_now"] = False
                item["blocked_by"] = sorted(set(item.get("blocked_by", []) + ["external_validation_pending"]))
                item["reason"] = item.get("reason", "") + " Local continuation paused because this family has external validation pending."
        tasks.append(item)
    tasks.insert(
        0,
        {
            "task_name": "scheduler_runtime_loop_refresh_v1",
            "family": "scheduler",
            "priority": "medium",
            "status": "ready",
            "reason": "All active candidate families are paused for external validation; local scheduler maintenance can refresh queues and wait gates.",
            "required_inputs": [
                "artifacts/sprints/x509_external_pending_and_continue_scheduler_v1/queue/external_pending_queue.yaml",
                "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml",
            ],
            "blocked_by": [],
            "allowed_to_run_now": True,
            "owner": "local",
        },
    )
    return {
        "schema": "updated_scheduler_task_queue_v1",
        "generated_at": now_iso(),
        "source_queue": "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml",
        "tasks": tasks,
        "summary": {
            "total_tasks": len(tasks),
            "ready": len([task for task in tasks if task.get("status") == "ready"]),
            "blocked": len([task for task in tasks if task.get("status") == "blocked"]),
            "external_pending": len([task for task in tasks if task.get("status") == "external_pending"]),
            "skipped_families": sorted(mapped_pending),
        },
    }


def next_local_plan(updated_queue: dict[str, Any]) -> dict[str, Any]:
    ready = [
        task
        for task in updated_queue.get("tasks", []) or []
        if task.get("status") == "ready" and task.get("owner") == "local" and task.get("allowed_to_run_now") is True
    ]
    selected = ready[0] if ready else {}
    return {
        "schema": "next_local_execution_plan_v1",
        "generated_at": now_iso(),
        "next_local_task": selected.get("task_name", ""),
        "family": selected.get("family", ""),
        "stage": "scheduler_update" if selected.get("family") == "scheduler" else selected.get("task_name", ""),
        "why": selected.get("reason", ""),
        "skipped_families": (updated_queue.get("summary") or {}).get("skipped_families", []),
        "status": "ready" if selected else "no_local_task_ready",
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }


def quality_checks(triage: dict[str, Any], external_record: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "x509_external_pending_scheduler_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "x509_candidate_loaded": bool((triage.get("candidates") or [])),
        "external_pending_recorded": external_record.get("external_validation_status") == "external_validation_pending",
        "main_feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "confirmed_vulnerability_claim": False,
        "next_local_task_generated": bool(plan.get("next_local_task")),
        "quality_status": "pass"
        if bool((triage.get("candidates") or []))
        and external_record.get("external_validation_status") == "external_validation_pending"
        and bool(plan.get("next_local_task"))
        else "blocked",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    candidate_sprint = (repo_root / args.candidate_sprint).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("external_pending", "queue", "plans", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    triage_path = candidate_sprint / "triage/x509_candidate_triage.yaml"
    brief_path = candidate_sprint / "summary/teammate_validation_brief.md"
    triage = load_yaml(triage_path)
    x509_record = external_pending_record(candidate_sprint, triage, brief_path)
    external_queue = build_external_pending_queue(repo_root, x509_record)
    updated_queue = updated_scheduler_queue(repo_root, external_queue)
    plan = next_local_plan(updated_queue)
    qc = quality_checks(triage, x509_record, plan)

    dump_yaml(out_dir / "external_pending" / "x509_external_pending_candidate.yaml", x509_record)
    brief_text = brief_path.read_text(encoding="utf-8") if brief_path.exists() else ""
    write_text(
        out_dir / "external_pending" / "teammate_validation_packet.md",
        "# X.509 External Validation Packet\n\n"
        + brief_text
        + "\n\n## External Pending Record\n\n"
        + f"- case_id: `{x509_record.get('case_id')}`\n"
        + f"- classification: `{x509_record.get('classification')}`\n"
        + "- claim policy: no confirmed vulnerability / CVE / exploitable claim\n",
    )
    dump_yaml(out_dir / "queue" / "external_pending_queue.yaml", external_queue)
    dump_yaml(out_dir / "queue" / "updated_scheduler_task_queue.yaml", updated_queue)
    dump_yaml(out_dir / "plans" / "next_local_execution_plan.yaml", plan)
    dump_yaml(out_dir / "validation" / "x509_external_pending_scheduler_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

## X.509 Candidate

- case_id: {x509_record.get('case_id')}
- classification: {x509_record.get('classification')}
- external pending: {x509_record.get('external_validation_status') == 'external_validation_pending'}

## Scheduler

- skipped_families: {plan.get('skipped_families')}
- next_local_task: {plan.get('next_local_task')}
- why: {plan.get('why')}

## Policy

No render, compile, run, feedback, knowledge, pattern-bank, adapter recipe,
normalized template, git, CVE, exploitability, or confirmed vulnerability
claim was produced.

## Quality

- quality_status: {qc.get('quality_status')}
"""
    write_text(out_dir / "reports" / f"{TASK}_report.md", report)
    print(f"[OK] wrote {TASK} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"x509_pending={qc['external_pending_recorded']} next={plan.get('next_local_task')} "
        f"quality={qc['quality_status']}"
    )
    return 0 if qc["quality_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
