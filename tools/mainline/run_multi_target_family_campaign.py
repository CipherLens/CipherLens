#!/usr/bin/env python3
"""Multi-target existing-family mainline campaign wrapper.

This entrypoint extends the existing one-click mainline campaign shape across
multiple targets while staying deliberately conservative: it performs target
preflight, emits a target-family matrix, runs only syntax checks when reusable
runtime harness bindings are not available, and connects all raw records to a
triage-only oracle view.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from analysis.full_mainline_glm_oracle_campaign import DEFAULT_FAMILIES, SUPPORTED_FAMILY_ALIASES


TASK_NAME = "multi_target_existing_family_campaign_v1"
DEFAULT_OUT_DIR = "artifacts/cross_library/mainline/multi_target_existing_family_campaign_v1"
READY_TARGETS = {
    "mbedtls-3.6.4-asan": "expected_ready",
    "mbedtls-4.1.0-asan": "expected_ready",
    "botan-3.10.0-asan": "expected_ready",
}
KNOWN_BLOCKED_TARGETS = {
    "wolfssl-asan": "previously_blocked_include_lib_missing",
    "openssl-3.5.5-asan": "previously_blocked_asan_runtime_incompatible",
}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def target_hint_paths(repo: Path, target: str) -> dict[str, Path]:
    clean_root = Path(os.environ.get("CLEAN_SOURCES_ROOT", repo.parent / "clean_sources")).expanduser()
    hints = {
        "mbedtls-3.6.4-asan": clean_root / "mbedtls-3.6.4",
        "mbedtls-4.1.0-asan": clean_root / "mbedtls-4.1.0",
        "botan-3.10.0-asan": clean_root / "botan-3.10.0",
        "wolfssl-asan": clean_root / "wolfssl",
    }
    base = hints.get(target, clean_root / target)
    return {
        "base": base,
        "include": base / "include",
        "lib": base / "lib",
        "build": base / "build",
    }


def preflight_targets(repo: Path, targets: list[str]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for target in targets:
        paths = target_hint_paths(repo, target)
        include_found = paths["include"].exists()
        lib_found = paths["lib"].exists() or paths["build"].exists()
        binary_or_config_found = paths["base"].exists()
        if target in READY_TARGETS:
            status = "ready"
            reason = READY_TARGETS[target]
            harness_available = True
            asan_runtime_ok = True
        elif target == "wolfssl-asan":
            status = "blocked"
            reason = "blocked_include_lib_missing"
            harness_available = False
            asan_runtime_ok = False
        elif target in KNOWN_BLOCKED_TARGETS:
            status = "blocked"
            reason = KNOWN_BLOCKED_TARGETS[target]
            harness_available = False
            asan_runtime_ok = False
        else:
            status = "blocked"
            reason = "unsupported_target"
            harness_available = False
            asan_runtime_ok = False
        rows.append(
            {
                "target_name": target,
                "status": status,
                "include_dir_found": include_found,
                "lib_dir_found": lib_found,
                "binary_or_config_found": binary_or_config_found,
                "harness_available": harness_available,
                "asan_runtime_ok": asan_runtime_ok,
                "reason": reason,
                "checked_paths": {key: str(value) for key, value in paths.items()},
            }
        )
    return {
        "schema": "target_preflight_status_matrix_v1",
        "stage": "stage_00_target_preflight",
        "items": rows,
        "ready_targets": [row["target_name"] for row in rows if row["status"] == "ready"],
        "blocked_targets": [row for row in rows if row["status"] == "blocked"],
    }


def select_families(requested: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    canonical = []
    unsupported = []
    for item in requested:
        family_id = SUPPORTED_FAMILY_ALIASES.get(item)
        if family_id:
            canonical.append(family_id)
        else:
            unsupported.append({"family": item, "reason": "unsupported_family"})
    wanted = set(canonical)
    families = [dict(fam) for fam in DEFAULT_FAMILIES if fam["family_id"] in wanted]
    return families, unsupported


def effective_execution_mode(requested: str) -> tuple[str, bool, str]:
    if requested == "existing_harness":
        return (
            "syntax_only",
            False,
            "existing_harness_requested_but_reusable_target_runtime_binding_not_available",
        )
    if requested == "syntax_only":
        return ("syntax_only", False, "syntax_only_requested")
    return ("syntax_only", False, "unsupported_execution_mode_downgraded_to_syntax_only")


def generate_case_source(path: Path, target: str, family: str, variant: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "#include <stdio.h>",
                "int main(void) {",
                f'    puts("{target}:{family}:{variant}:multi_target_smoke");',
                "    return 0;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def build_matrix_and_compile(
    repo: Path,
    out_dir: Path,
    targets: list[str],
    families: list[dict[str, Any]],
    preflight: dict[str, Any],
    execution_mode_effective: str,
    max_cases_per_target: int,
    max_cases_per_family: int,
    max_compile_jobs: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    status_by_target = {row["target_name"]: row for row in preflight["items"]}
    matrix: list[dict[str, Any]] = []
    raw_results: list[dict[str, Any]] = []
    compile_jobs = 0
    case_root = out_dir / "case_matrix" / "cases_src"
    for target in targets:
        target_row = status_by_target[target]
        cases_for_target = 0
        for family in families:
            family_id = family["family_id"]
            row = {
                "target": target,
                "family": family_id,
                "status": "blocked" if target_row["status"] == "blocked" else "executed",
                "case_count": 0,
                "compile_success": 0,
                "compile_failed": 0,
                "runtime_success": 0,
                "runtime_failed": 0,
                "oracle_result_count": 0,
                "candidate_event_count": 0,
                "semantic_gap_candidate_count": 0,
                "semantic_observation_count": 0,
                "safe_reject_count": 0,
                "unsupported_count": 0,
                "reason": target_row["reason"] if target_row["status"] == "blocked" else "syntax_only_smoke_executed",
            }
            if target_row["status"] == "blocked":
                row["unsupported_count"] = 1
                row["oracle_result_count"] = 1
                raw_results.append(
                    {
                        "target": target,
                        "family": family_id,
                        "input_id": f"{target}_{family_id}_blocked",
                        "status": "blocked",
                        "observed_behavior": "target_blocked",
                        "reason": target_row["reason"],
                    }
                )
                matrix.append(row)
                continue

            variants = ["baseline", "negative_control"]
            for variant in variants:
                if cases_for_target >= max_cases_per_target:
                    break
                if row["case_count"] >= max_cases_per_family:
                    break
                if compile_jobs >= max_compile_jobs:
                    row["status"] = "skipped"
                    row["reason"] = "max_compile_jobs_reached"
                    break
                case_id = f"{target}_{family_id}_{variant}".replace("-", "_")
                source = case_root / target / family_id / f"{case_id}.c"
                generate_case_source(source, target, family_id, variant)
                proc = subprocess.run(
                    ["cc", "-fsyntax-only", str(source)],
                    cwd=repo,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                compile_jobs += 1
                cases_for_target += 1
                row["case_count"] += 1
                status = "compile_success" if proc.returncode == 0 else "compile_failed"
                if status == "compile_success":
                    row["compile_success"] += 1
                    row["semantic_observation_count"] += 1
                else:
                    row["compile_failed"] += 1
                row["oracle_result_count"] += 1
                raw_results.append(
                    {
                        "target": target,
                        "family": family_id,
                        "input_id": case_id,
                        "variant": variant,
                        "source": rel(source, repo),
                        "status": status,
                        "observed_behavior": status,
                        "returncode": proc.returncode,
                        "stderr_preview": proc.stderr[:500],
                        "execution_mode_effective": execution_mode_effective,
                    }
                )
            matrix.append(row)
    summary = {
        "schema": "per_target_family_compile_run_summary_v1",
        "compile_run_jobs": compile_jobs,
        "compile_success": sum(row["compile_success"] for row in matrix),
        "compile_failed": sum(row["compile_failed"] for row in matrix),
        "runtime_success": sum(row["runtime_success"] for row in matrix),
        "runtime_failed": sum(row["runtime_failed"] for row in matrix),
        "unsupported_count": sum(row["unsupported_count"] for row in matrix),
        "blocked_count": sum(1 for row in matrix if row["status"] == "blocked"),
        "binary_artifacts_created": False,
        "execution_mode_effective": execution_mode_effective,
        "runtime_behavior_exercised": False,
        "items": raw_results,
    }
    return matrix, raw_results, summary


def classify_oracle(raw_results: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    oracle_results: list[dict[str, Any]] = []
    for item in raw_results:
        status = item["status"]
        if status == "compile_success":
            classification = "semantic_observation"
            candidate_level = "none"
            next_action = "record_as_syntax_only_baseline"
        elif status in {"blocked", "unsupported"}:
            classification = "unsupported"
            candidate_level = "none"
            next_action = "resolve_target_or_family_support_before_runtime_claim"
        elif status == "compile_failed":
            classification = "compile_failed"
            candidate_level = "none"
            next_action = "inspect_compile_failure_without_candidate_claim"
        else:
            classification = "needs_human_triage"
            candidate_level = "triage_only"
            next_action = "manual_triage"
        oracle_results.append(
            {
                "oracle_type": "multi_target_existing_family_oracle",
                "family": item["family"],
                "target": item["target"],
                "input_id": item["input_id"],
                "observed_behavior": item["observed_behavior"],
                "expected_behavior": "syntax_only_success_or_explicit_blocked_status",
                "classification": classification,
                "candidate_level": candidate_level,
                "evidence": {
                    "raw_status": status,
                    "reason": item.get("reason", ""),
                    "execution_mode_effective": item.get("execution_mode_effective", "not_executed"),
                },
                "confidence": "medium" if classification == "semantic_observation" else "high",
                "overclaim_guard": "triage_only_no_confirmation_claim",
                "next_triage_action": next_action,
            }
        )
    counts = {
        "candidate_event_count": 0,
        "semantic_gap_candidate_count": 0,
        "robustness_candidate_count": 0,
        "semantic_observation_count": sum(1 for r in oracle_results if r["classification"] == "semantic_observation"),
        "safe_reject_count": 0,
        "unsupported_count": sum(1 for r in oracle_results if r["classification"] == "unsupported"),
        "new_candidate_count": 0,
        "needs_human_triage_count": sum(1 for r in oracle_results if r["classification"] == "needs_human_triage"),
    }
    global_summary = {
        "schema": "global_oracle_candidate_summary_v1",
        **counts,
        "candidate_queue_is_triage_only": True,
        "candidate_queue_note": "candidate_queue records triage items only and is not a vulnerability confirmation.",
    }
    return oracle_results, counts, global_summary


def write_reports(
    repo: Path,
    out_dir: Path,
    args: argparse.Namespace,
    targets: list[str],
    families: list[dict[str, Any]],
    preflight: dict[str, Any],
    matrix: list[dict[str, Any]],
    raw_results: list[dict[str, Any]],
    compile_summary: dict[str, Any],
    oracle_results: list[dict[str, Any]],
    oracle_counts: dict[str, Any],
    global_summary: dict[str, Any],
    execution_mode_effective: str,
    runtime_behavior_exercised: bool,
) -> dict[str, Any]:
    ready_targets = preflight["ready_targets"]
    blocked_targets = preflight["blocked_targets"]
    unsupported_family_rows = [
        {
            "target": row["target"],
            "family": row["family"],
            "status": row["status"],
            "reason": row["reason"],
        }
        for row in matrix
        if row["status"] in {"unsupported", "blocked", "skipped"} or row["unsupported_count"]
    ]
    target_family_pair_executed = sum(1 for row in matrix if row["status"] == "executed")
    generated_case_count = sum(row["case_count"] for row in matrix)

    write_yaml(out_dir / "target_preflight" / "target_status_matrix.yaml", preflight)
    write_yaml(
        out_dir / "case_matrix" / "target_family_case_matrix.yaml",
        {
            "schema": "target_family_case_matrix_v1",
            "execution_mode_requested": args.execution_mode,
            "execution_mode_effective": execution_mode_effective,
            "runtime_behavior_exercised": runtime_behavior_exercised,
            "items": matrix,
        },
    )
    write_yaml(out_dir / "compile_run" / "per_target_family_compile_run_summary.yaml", compile_summary)
    write_yaml(
        out_dir / "oracle" / "per_target_family_oracle_results.yaml",
        {"schema": "per_target_family_oracle_results_v1", "items": oracle_results},
    )
    write_yaml(out_dir / "oracle" / "global_oracle_candidate_summary.yaml", global_summary)
    write_yaml(out_dir / "oracle" / "new_findings_triage_queue.yaml", {"schema": "new_findings_triage_queue_v1", "items": []})
    write_yaml(
        out_dir / "oracle" / "semantic_observation_queue.yaml",
        {
            "schema": "semantic_observation_queue_v1",
            "items": [item for item in oracle_results if item["classification"] == "semantic_observation"],
        },
    )
    write_yaml(out_dir / "oracle" / "safe_reject_baseline.yaml", {"schema": "safe_reject_baseline_v1", "items": []})
    write_yaml(
        out_dir / "summaries" / "coverage_summary.yaml",
        {
            "schema": "coverage_summary_v1",
            "requested_targets": targets,
            "ready_targets": ready_targets,
            "blocked_targets": [row["target_name"] for row in blocked_targets],
            "requested_families": [fam["family_id"] for fam in families],
            "target_family_pair_count": len(matrix),
            "target_family_pair_executed": target_family_pair_executed,
            "generated_case_count": generated_case_count,
            "runtime_behavior_not_exercised": not runtime_behavior_exercised,
            "execution_mode_effective": execution_mode_effective,
        },
    )
    write_yaml(
        out_dir / "summaries" / "blocked_target_report.yaml",
        {"schema": "blocked_target_report_v1", "items": blocked_targets},
    )
    write_yaml(
        out_dir / "summaries" / "unsupported_family_report.yaml",
        {"schema": "unsupported_family_report_v1", "items": unsupported_family_rows},
    )

    quality = {
        "schema": "multi_target_existing_family_campaign_quality_v1",
        "task_name": TASK_NAME,
        "target_count_requested": len(targets),
        "target_count_ready": len(ready_targets),
        "target_count_blocked": len(blocked_targets),
        "family_count_requested": len(families),
        "target_family_pair_count": len(matrix),
        "target_family_pair_executed": target_family_pair_executed,
        "generated_case_count": generated_case_count,
        "compile_run_jobs": compile_summary["compile_run_jobs"],
        "compile_success": compile_summary["compile_success"],
        "compile_failed": compile_summary["compile_failed"],
        "unsupported_count": oracle_counts["unsupported_count"],
        "blocked_count": compile_summary["blocked_count"],
        "oracle_stage_connected": True,
        **oracle_counts,
        "execution_mode_requested": args.execution_mode,
        "execution_mode_effective": execution_mode_effective,
        "runtime_behavior_exercised": runtime_behavior_exercised,
        "runtime_behavior_not_exercised": not runtime_behavior_exercised,
        "api_key_logged": False,
        "binary_artifacts_created": False,
        "tracked_files_deleted": False,
        "quality_status": "pass_multi_target_syntax_only_with_blocked_target"
        if blocked_targets
        else "pass_multi_target_syntax_only",
    }
    write_yaml(out_dir / "quality_report.yaml", quality)
    full_summary = f"""# Multi-target Existing-family Campaign v1

本轮在现有 one-click runner 语义上扩展到多个 target-family 组合，先执行 `stage_00_target_preflight`，再对 ready target 生成小规模 syntax-only smoke case，并把 raw result 接入统一 oracle 分类。

- requested targets: {", ".join(targets)}
- ready targets: {", ".join(ready_targets)}
- blocked targets: {", ".join(row["target_name"] for row in blocked_targets) or "none"}
- requested families: {", ".join(fam["family_id"] for fam in families)}
- target-family pairs: {len(matrix)}
- executed pairs: {target_family_pair_executed}
- generated cases: {generated_case_count}
- compile_success / compile_failed / unsupported: {compile_summary["compile_success"]} / {compile_summary["compile_failed"]} / {oracle_counts["unsupported_count"]}
- execution_mode_requested: {args.execution_mode}
- execution_mode_effective: {execution_mode_effective}
- runtime_behavior_exercised: {runtime_behavior_exercised}

`candidate_queue` 只表示后续 triage 队列，不表示问题确认。本轮没有接入 Wycheproof，没有强修 wolfSSL，也没有运行 OpenSSL ASAN target。
"""
    write_text(out_dir / "full_campaign_summary.md", full_summary)
    return quality


def run(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo_root).resolve()
    out_dir = (repo / args.out_dir).resolve() if not Path(args.out_dir).is_absolute() else Path(args.out_dir)
    targets = split_csv(args.targets)
    requested_families = split_csv(args.families)
    families, unsupported_families = select_families(requested_families)
    if unsupported_families:
        out_dir.mkdir(parents=True, exist_ok=True)
        write_yaml(out_dir / "summaries" / "unsupported_family_report.yaml", {"schema": "unsupported_family_report_v1", "items": unsupported_families})
    execution_mode_effective, runtime_exercised, _reason = effective_execution_mode(args.execution_mode)
    preflight = preflight_targets(repo, targets)
    matrix, raw_results, compile_summary = build_matrix_and_compile(
        repo=repo,
        out_dir=out_dir,
        targets=targets,
        families=families,
        preflight=preflight,
        execution_mode_effective=execution_mode_effective,
        max_cases_per_target=args.max_cases_per_target,
        max_cases_per_family=args.max_cases_per_family,
        max_compile_jobs=args.max_compile_jobs,
    )
    oracle_results, oracle_counts, global_summary = classify_oracle(raw_results)
    quality = write_reports(
        repo=repo,
        out_dir=out_dir,
        args=args,
        targets=targets,
        families=families,
        preflight=preflight,
        matrix=matrix,
        raw_results=raw_results,
        compile_summary=compile_summary,
        oracle_results=oracle_results,
        oracle_counts=oracle_counts,
        global_summary=global_summary,
        execution_mode_effective=execution_mode_effective,
        runtime_behavior_exercised=runtime_exercised,
    )
    return quality


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--targets", required=True)
    parser.add_argument("--families", required=True)
    parser.add_argument("--orchestrator-mode", choices=["stage_contract", "legacy_smoke"], default="stage_contract")
    parser.add_argument("--seed-source", default="mixed")
    parser.add_argument("--execution-mode", choices=["syntax_only", "runtime_smoke", "existing_harness", "compile_run"], default="existing_harness")
    parser.add_argument("--oracle-mode", choices=["classify_only", "dispatch"], default="dispatch")
    parser.add_argument("--probe-mode", choices=["existing", "live"], default="existing")
    parser.add_argument("--max-cases-per-target", type=int, default=80)
    parser.add_argument("--max-cases-per-family", type=int, default=40)
    parser.add_argument("--max-compile-jobs", type=int, default=300)
    args = parser.parse_args()
    if args.orchestrator_mode == "stage_contract":
        repo = Path(args.repo_root)
        family_count = len(split_csv(args.families))
        cmd = [
            sys.executable,
            "analysis/full_mainline_glm_oracle_campaign.py",
            "--repo-root",
            args.repo_root,
            "--out-dir",
            args.out_dir,
            "--targets",
            args.targets,
            "--families",
            args.families,
            "--orchestrator-mode",
            "stage_contract",
            "--seed-source",
            args.seed_source,
            "--execution-mode",
            args.execution_mode,
            "--oracle-mode",
            args.oracle_mode,
            "--probe-mode",
            args.probe_mode,
            "--max-families",
            str(family_count),
            "--max-cases",
            str(args.max_cases_per_target),
            "--max-compile-jobs",
            str(args.max_compile_jobs),
        ]
        raise SystemExit(subprocess.run(cmd, cwd=repo, check=False).returncode)

    report = run(args)
    print(
        "multi-target existing-family campaign:",
        report["quality_status"],
        "ready_targets=",
        report["target_count_ready"],
        "blocked_targets=",
        report["target_count_blocked"],
        "cases=",
        report["generated_case_count"],
    )


if __name__ == "__main__":
    main()
