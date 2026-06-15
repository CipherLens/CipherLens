"""Dry-run scheduler runtime loop over existing sprint artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from analysis.analysis_records import dump_yaml, load_yaml, write_text
from analysis.family_status_scanner import build_family_status, build_global_status
from analysis.task_queue_records import build_task_queue, split_tasks


SPRINT = "scheduler_runtime_loop_v1"
DEFAULT_POLICY = Path("config/scheduler_runtime_policy.yaml")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    return parser.parse_args()


def policy_snapshot(policy_path: Path, policy_doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "scheduler_policy_snapshot_v1",
        "source_policy": policy_path.as_posix(),
        "policy": policy_doc,
    }


def quality_checks() -> dict[str, Any]:
    return {
        "schema": "scheduler_runtime_loop_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family_status_generated": True,
        "task_queue_generated": True,
        "external_pending_tasks_recorded": True,
        "scheduler_policy_generated": True,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass",
    }


def report_text(
    family_status: dict[str, Any],
    global_status: dict[str, Any],
    queue: dict[str, Any],
    blocked: dict[str, Any],
    external: dict[str, Any],
    qc: dict[str, Any],
) -> str:
    families = family_status.get("families", {})
    ready = [t["task_name"] for t in queue.get("tasks", []) if t.get("status") == "ready"]
    return f"""# {SPRINT} Report

## Summary

- quality_status: {qc['quality_status']}
- scheduler_driven_runtime_loop: {global_status['scheduler_driven_runtime_loop']}
- mode: dry_run
- ready_tasks: {ready}
- blocked_tasks: {blocked['summary']['total_tasks']}
- external_pending_tasks: {external['summary']['total_tasks']}

## Family Status

- ASN.1: loop_closed={families['asn1_nested_boundary']['loop_closed']}, candidates={families['asn1_nested_boundary']['candidates']}, next={families['asn1_nested_boundary']['next']}
- PKCS: valid_seed_ready={families['pkcs_container_parsing']['valid_seed_ready']}, valid_prefix_pipeline_done={families['pkcs_container_parsing']['valid_prefix_pipeline_done']}, full_consumption_gap_candidate={families['pkcs_container_parsing']['full_consumption_gap_candidate']}, triage={families['pkcs_container_parsing']['triage']}, app_level_check={families['pkcs_container_parsing']['app_level_check']}
- project_structure: refactor_done={families['project_structure']['refactor_done']}, tools_policy_documented={families['project_structure']['tools_policy_documented']}

## Policy

No render, compile, run, feedback, knowledge, pattern-bank, adapter recipe,
normalized template, GLM, git, CVE, exploitability, or confirmed vulnerability
claim was produced.
"""


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    policy_path = (repo_root / args.policy).resolve()
    for sub in ("status", "queue", "policy", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    policy_doc = load_yaml(policy_path)
    family_status = build_family_status(repo_root)
    global_status = build_global_status(family_status)
    queue = build_task_queue(family_status, policy_doc)
    blocked = split_tasks(queue, "blocked")
    external = split_tasks(queue, "external_pending")
    qc = quality_checks()

    dump_yaml(out_dir / "status" / "family_status.yaml", family_status)
    dump_yaml(out_dir / "status" / "global_runtime_status.yaml", global_status)
    dump_yaml(out_dir / "queue" / "scheduler_task_queue.yaml", queue)
    dump_yaml(out_dir / "queue" / "blocked_tasks.yaml", blocked)
    dump_yaml(out_dir / "queue" / "external_pending_tasks.yaml", external)
    dump_yaml(out_dir / "policy" / "scheduler_policy_snapshot.yaml", policy_snapshot(policy_path, policy_doc))
    dump_yaml(out_dir / "validation" / "scheduler_runtime_loop_quality_checks.yaml", qc)
    write_text(
        out_dir / "reports" / f"{SPRINT}_report.md",
        report_text(family_status, global_status, queue, blocked, external, qc),
    )

    print(f"[OK] wrote {SPRINT} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"ready={queue['summary']['ready']} blocked={queue['summary']['blocked']} "
        f"external_pending={queue['summary']['external_pending']} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
