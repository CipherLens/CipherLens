"""Select the next local family while skipping external-pending families."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from analysis.analysis_records import dump_yaml, now_iso, write_text


TASK = "scheduler_family_selection_expand_v1"
RECOMMENDED_FAMILIES = [
    "pkey_parsing",
    "pkcs8_parsing",
    "cms_container_parsing",
    "x509_crl_parsing",
    "asn1_nested_boundary_variant",
]
ALWAYS_SKIP = {
    "asn1_nested_boundary",
    "pkcs_container_parsing",
    "x509_parsing",
    "x509_asn1_inner_boundary",
}


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--external-pending", required=True)
    parser.add_argument("--family-profiles", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def pending_families(external_pending: dict[str, Any]) -> set[str]:
    families = set((external_pending.get("summary") or {}).get("families", []) or [])
    for item in external_pending.get("items", []) or []:
        if item.get("status") == "external_validation_pending" and item.get("family"):
            families.add(str(item["family"]))
    return families | ALWAYS_SKIP


def artifact_status(repo_root: Path, family: str, pending: set[str], profiles: dict[str, Any]) -> dict[str, Any]:
    profile_exists = family in ((profiles.get("families") or {}).keys())
    related = sorted(
        path.as_posix()
        for path in (repo_root / "artifacts/sprints").glob(f"*{family}*")
        if path.exists()
    )
    if family in pending:
        status = "external_pending"
        reason = "family has external_validation_pending candidate or alias"
    elif not profile_exists:
        status = "missing_profile"
        reason = "family profile is not defined in config/family_profiles.yaml"
    elif related:
        status = "artifact_exists"
        reason = "profile exists and prior artifacts are present; needs scheduler-specific review"
    else:
        status = "candidate_ready_for_seed_discovery"
        reason = "profile exists and no blocking artifacts were found"
    return {
        "family": family,
        "profile_exists": profile_exists,
        "status": status,
        "reason": reason,
        "related_artifacts": related[:20],
    }


def build_ranking(status_rows: list[dict[str, Any]]) -> dict[str, Any]:
    ranked = []
    for priority, row in enumerate(status_rows, start=1):
        score = 0
        if row["status"] == "candidate_ready_for_seed_discovery":
            score = 100 - priority
        elif row["status"] == "artifact_exists":
            score = 70 - priority
        elif row["status"] == "missing_profile":
            score = 20 - priority
        ranked.append({**row, "priority_rank": priority, "selection_score": score})
    ranked.sort(key=lambda item: item["selection_score"], reverse=True)
    return {
        "schema": "family_candidate_ranking_v1",
        "generated_at": now_iso(),
        "candidates": ranked,
        "summary": {
            "candidate_count": len(ranked),
            "ready_count": len([r for r in ranked if r["status"] == "candidate_ready_for_seed_discovery"]),
            "missing_profile_count": len([r for r in ranked if r["status"] == "missing_profile"]),
        },
    }


def select_next(ranking: dict[str, Any]) -> dict[str, Any]:
    ready = [
        item
        for item in ranking.get("candidates", []) or []
        if item.get("status") in {"candidate_ready_for_seed_discovery", "artifact_exists"}
    ]
    if ready:
        selected = ready[0]
        return {
            "schema": "selected_next_family_v1",
            "generated_at": now_iso(),
            "selected": True,
            "family": selected["family"],
            "status": selected["status"],
            "reason": selected["reason"],
            "missing_family_profiles": [],
        }
    missing = [item["family"] for item in ranking.get("candidates", []) or [] if item.get("status") == "missing_profile"]
    return {
        "schema": "selected_next_family_v1",
        "generated_at": now_iso(),
        "selected": False,
        "family": "",
        "status": "missing_family_profiles",
        "reason": "No non-pending family has a profile; add a generic family profile before seed discovery.",
        "missing_family_profiles": missing,
    }


def seed_task(selected: dict[str, Any]) -> dict[str, Any]:
    family = selected.get("family", "")
    if selected.get("selected"):
        return {
            "schema": "next_seed_discovery_task_v1",
            "generated_at": now_iso(),
            "task_name": f"{family}_seed_discovery_v1",
            "family": family,
            "stage": "seed_discovery",
            "allowed_to_run_now": True,
            "blocked_by": [],
            "reason": selected.get("reason", ""),
        }
    return {
        "schema": "next_seed_discovery_task_v1",
        "generated_at": now_iso(),
        "task_name": "missing_family_profiles_v1",
        "family": "",
        "stage": "family_profile_definition",
        "allowed_to_run_now": False,
        "blocked_by": ["missing_family_profiles"],
        "missing_family_profiles": selected.get("missing_family_profiles", []),
        "reason": selected.get("reason", ""),
    }


def updated_queue(plan: dict[str, Any], skipped: list[str]) -> dict[str, Any]:
    task = {
        "task_name": plan["task_name"],
        "family": plan.get("family", "scheduler"),
        "priority": "high" if plan.get("allowed_to_run_now") else "medium",
        "status": "ready" if plan.get("allowed_to_run_now") else "blocked",
        "reason": plan.get("reason", ""),
        "required_inputs": ["config/family_profiles.yaml"],
        "blocked_by": plan.get("blocked_by", []),
        "allowed_to_run_now": bool(plan.get("allowed_to_run_now")),
        "owner": "local",
    }
    return {
        "schema": "updated_scheduler_task_queue_v1",
        "generated_at": now_iso(),
        "tasks": [task],
        "summary": {
            "total_tasks": 1,
            "ready": 1 if task["status"] == "ready" else 0,
            "blocked": 1 if task["status"] == "blocked" else 0,
            "external_pending_skipped_families": skipped,
        },
    }


def quality_checks(external_pending: dict[str, Any], profiles: dict[str, Any], ranking: dict[str, Any], selected: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "family_selection_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "external_pending_loaded": bool(external_pending),
        "external_pending_families_skipped": True,
        "family_profiles_loaded": bool(profiles),
        "candidate_ranking_generated": bool(ranking.get("candidates")),
        "next_family_selected": bool(selected.get("selected")),
        "next_seed_discovery_task_generated": bool(plan.get("task_name")),
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
        "quality_status": "pass"
        if bool(external_pending) and bool(profiles) and bool(ranking.get("candidates")) and bool(plan.get("task_name"))
        else "blocked",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    external_path = (repo_root / args.external_pending).resolve()
    profiles_path = (repo_root / args.family_profiles).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "status", "selection", "plans", "queue", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    external_pending = load_yaml(external_path)
    profiles = load_yaml(profiles_path)
    skipped = sorted(pending_families(external_pending))
    profile_families = sorted((profiles.get("families") or {}).keys())
    candidate_names = []
    for name in RECOMMENDED_FAMILIES + profile_families:
        if name not in candidate_names and name not in skipped:
            candidate_names.append(name)
    status_rows = [artifact_status(repo_root, name, set(skipped), profiles) for name in candidate_names]
    ranking = build_ranking(status_rows)
    selected = select_next(ranking)
    plan = seed_task(selected)
    queue = updated_queue(plan, skipped)
    qc = quality_checks(external_pending, profiles, ranking, selected, plan)

    dump_yaml(out_dir / "inputs/external_pending_snapshot.yaml", external_pending)
    dump_yaml(
        out_dir / "status/family_mining_status.yaml",
        {
            "schema": "family_mining_status_v1",
            "generated_at": now_iso(),
            "skipped_families": skipped,
            "profile_families": profile_families,
            "candidate_status": status_rows,
        },
    )
    dump_yaml(out_dir / "selection/family_candidate_ranking.yaml", ranking)
    dump_yaml(out_dir / "selection/selected_next_family.yaml", selected)
    dump_yaml(out_dir / "plans/next_seed_discovery_task.yaml", plan)
    dump_yaml(out_dir / "queue/updated_scheduler_task_queue.yaml", queue)
    dump_yaml(out_dir / "validation/family_selection_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

## External Pending

- skipped_families: {skipped}

## Selection

- candidate_families: {[item['family'] for item in ranking.get('candidates', [])]}
- selected_next_family: {selected.get('family') or 'none'}
- selected_status: {selected.get('status')}
- missing_family_profiles: {selected.get('missing_family_profiles', [])}

## Next Task

- task_name: {plan.get('task_name')}
- allowed_to_run_now: {plan.get('allowed_to_run_now')}
- blocked_by: {plan.get('blocked_by')}

## Policy

No render, compile, run, feedback, knowledge, pattern-bank, adapter recipe,
normalized template, GLM, git, CVE, exploitability, or confirmed vulnerability
claim was produced.

## Quality

- quality_status: {qc.get('quality_status')}
"""
    write_text(out_dir / "reports/scheduler_family_selection_expand_v1_report.md", report)
    print(f"[OK] wrote {TASK} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"selected={selected.get('family') or 'none'} status={selected.get('status')} "
        f"next={plan.get('task_name')} quality={qc['quality_status']}"
    )
    return 0 if qc["quality_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
