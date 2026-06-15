"""Shared records for mining campaign runs."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, now_iso, write_text


CANDIDATE_STOP_LABELS = {
    "crash_candidate",
    "sanitizer_candidate",
    "full_consumption_gap_candidate",
    "semantic_divergence_candidate",
}


def rel(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def run_python_module(repo_root: Path, module: str, args: list[str]) -> dict[str, Any]:
    started = now_iso()
    argv = ["python3", "-m", module] + args
    proc = subprocess.run(argv, cwd=repo_root, text=True, capture_output=True, check=False)
    ended = now_iso()
    return {
        "argv": argv,
        "return_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "started_at": started,
        "ended_at": ended,
    }


def stage_record(
    *,
    stage_id: str,
    family: str,
    stage: str,
    input_artifacts: list[str],
    output_artifacts: list[str],
    status: str,
    started_at: str,
    ended_at: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "stage_id": stage_id,
        "family": family,
        "stage": stage,
        "input_artifacts": input_artifacts,
        "output_artifacts": output_artifacts,
        "status": status,
        "started_at": started_at,
        "ended_at": ended_at,
        "summary": summary,
    }


def write_command_logs(out_dir: Path, command_result: dict[str, Any]) -> dict[str, str]:
    logs = out_dir / "logs"
    write_text(logs / "stdout.log", command_result.get("stdout", ""))
    write_text(logs / "stderr.log", command_result.get("stderr", ""))
    dump_yaml(logs / "command.yaml", command_result)
    return {
        "stdout": (logs / "stdout.log").as_posix(),
        "stderr": (logs / "stderr.log").as_posix(),
        "command": (logs / "command.yaml").as_posix(),
    }


def candidate_summary_from_queue(queue: dict[str, Any], family: str, source_sprint: str) -> dict[str, Any]:
    by_label = {
        "crash_candidate": 0,
        "sanitizer_candidate": 0,
        "full_consumption_gap_candidate": 0,
        "semantic_divergence_candidate": 0,
        "needs_triage": 0,
    }
    candidates = []
    for item in queue.get("candidates", []) or []:
        label = str(item.get("candidate_label") or item.get("label") or "needs_triage")
        if label in by_label:
            by_label[label] += 1
        candidates.append(
            {
                "family": item.get("family") or family,
                "case_id": item.get("case_id", ""),
                "label": label,
                "source_sprint": source_sprint,
                "recommended_next_action": item.get("recommended_next_action")
                or item.get("external_validation_status", "not_required"),
            }
        )
    stop_candidates = [item for item in candidates if item["label"] in CANDIDATE_STOP_LABELS]
    return {
        "schema": "campaign_candidate_summary_v1",
        "generated_at": now_iso(),
        "candidate_found": bool(stop_candidates),
        "candidate_count": len(stop_candidates),
        "by_label": by_label,
        "candidates": candidates,
    }
