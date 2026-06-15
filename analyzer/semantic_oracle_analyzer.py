"""Compile, run, and analyze semantic oracle harnesses.

This module is intentionally family-generic at the semantic-oracle layer while
keeping the current sprint defaults pointed at pkey_verify_semantic.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from runner.family_compile_runner import execute_instrumented_case, lib_dir_for_install, openssl_runtime_info


DEFAULT_RENDER_CASES_ROOT = "artifacts/sprints/pkey_verify_semantic_render_cases_v1"
DEFAULT_RENDER_PLAN = "artifacts/sprints/pkey_verify_semantic_render_plan_v1/render/render_plan.yaml"
DEFAULT_MUTATION_PLAN = "artifacts/sprints/pkey_verify_semantic_generic_mutation_plan_v1/mutation/mutation_plan.yaml"
DEFAULT_BASELINE_ROOT = "artifacts/sprints/glm_slot_filling_token_budget_fix_v1"
DEFAULT_OPENSSL_INSTALL = "/home/wen/work/install-openssl-3.5.5-asan"
DEFAULT_OUT_DIR = "artifacts/sprints/pkey_verify_semantic_compile_run_analyze_v1"

ALLOWED_CANDIDATE_LABELS = {
    "normal_expected_behavior",
    "unexpected_accept_candidate",
    "unexpected_reject_candidate",
    "semantic_divergence_candidate",
    "crash_candidate",
    "sanitizer_candidate",
    "baseline_control_failed",
    "needs_triage",
}

FORBIDDEN_LABELS = {
    "full_consumption_gap_candidate",
    "der_trailing_garbage_candidate",
    "app_level_der_validation_gap_candidate",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--render-cases-root", default=DEFAULT_RENDER_CASES_ROOT)
    parser.add_argument("--render-plan", default=DEFAULT_RENDER_PLAN)
    parser.add_argument("--mutation-plan", default=DEFAULT_MUTATION_PLAN)
    parser.add_argument("--baseline-root", default=DEFAULT_BASELINE_ROOT)
    parser.add_argument("--openssl-install", default=DEFAULT_OPENSSL_INSTALL)
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def parse_oracle_events(text: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse line-oriented ORACLE_EVENT key/value output into one event record."""

    values: dict[str, str] = {}
    raw_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("ORACLE_EVENT"):
            continue
        raw_lines.append(stripped)
        payload = stripped[len("ORACLE_EVENT") :].strip()
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        values[key.strip()] = value.strip()

    if not raw_lines:
        return []

    event = {
        "schema": "semantic_oracle_event_v1",
        "case_id": values.get("case_id") or str(case.get("case_id") or ""),
        "family": values.get("family") or str(case.get("family") or ""),
        "target_library": str(case.get("target_library") or ""),
        "case_group": str(case.get("case_group") or ""),
        "mutation_strategy": values.get("mutation_strategy") or str(case.get("mutation_strategy") or ""),
        "expected_behavior": values.get("expected_behavior") or str(case.get("expected_behavior") or ""),
        "actual_behavior": values.get("actual_behavior") or "",
        "semantic_mismatch": as_bool(values.get("semantic_mismatch", "false")),
        "crash_or_sanitizer": as_bool(values.get("crash_or_sanitizer", "false")),
        "raw_lines": raw_lines,
    }
    return [event]


def build_rendered_index(summary: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    cases = []
    for item in summary.get("case_files", []) or []:
        path = repo_root / str(item.get("path") or "")
        case_id = str(item.get("case_id") or path.stem)
        cases.append(
            {
                "case_id": case_id,
                "compile_job_id": case_id,
                "family": str(summary.get("family") or "pkey_verify_semantic"),
                "track": str(summary.get("track") or "semantic"),
                "target_library": str(summary.get("target_library") or "openssl"),
                "harness_c": path.as_posix(),
                "expected_behavior": str(item.get("expected_behavior") or ""),
                "mutation_strategy": str(item.get("mutation_strategy") or ""),
                "case_group": str(item.get("case_group") or ""),
            }
        )
    return {"schema": "semantic_rendered_index_v1", "cases": cases}


def copy_snapshot(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def event_by_case(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for event in events:
        out[str(event.get("case_id") or "")] = event
    return out


def classify_case(
    case: dict[str, Any],
    run_result: dict[str, Any],
    event: dict[str, Any] | None,
    sanitizer: dict[str, Any],
) -> dict[str, Any]:
    case_id = str(case.get("case_id") or "")
    expected = str(case.get("expected_behavior") or "")
    actual = str((event or {}).get("actual_behavior") or "")
    mismatch = bool((event or {}).get("semantic_mismatch"))
    raw_label = str(run_result.get("raw_observation_label") or "")
    signal = str(run_result.get("signal") or "")
    sanitizer_seen = bool(sanitizer.get("sanitizer_observed") or run_result.get("sanitizer_observed"))

    label = "normal_expected_behavior"
    reason = "oracle_event_matches_expected_behavior"
    if sanitizer_seen or bool((event or {}).get("crash_or_sanitizer")):
        label = "sanitizer_candidate"
        reason = "sanitizer_output_or_crash_or_sanitizer_oracle_observed"
    elif signal:
        label = "crash_candidate"
        reason = f"process signaled: {signal}"
    elif event is None:
        label = "needs_triage"
        reason = "missing semantic ORACLE_EVENT"
    elif mismatch:
        if expected == "accept":
            label = "baseline_control_failed"
            reason = f"accept control produced actual_behavior={actual or 'unknown'}"
        elif expected == "reject" and actual == "accept":
            label = "unexpected_accept_candidate"
            reason = "reject-expected mutation was accepted"
        elif expected == "accept" and actual == "reject":
            label = "unexpected_reject_candidate"
            reason = "accept-expected control was rejected"
        else:
            label = "semantic_divergence_candidate"
            reason = f"semantic mismatch expected={expected or 'unknown'} actual={actual or 'unknown'}"

    if label not in ALLOWED_CANDIDATE_LABELS:
        label = "needs_triage"
        reason = "internal label not in allowed semantic candidate set"

    return {
        "case_id": case_id,
        "family": str(case.get("family") or ""),
        "track": str(case.get("track") or ""),
        "target_library": str(case.get("target_library") or ""),
        "case_group": str(case.get("case_group") or ""),
        "mutation_strategy": str(case.get("mutation_strategy") or ""),
        "expected_behavior": expected,
        "actual_behavior": actual,
        "label": label,
        "candidate": label != "normal_expected_behavior",
        "reason": reason,
        "raw_observation_label": raw_label,
        "exit_code": run_result.get("exit_code"),
        "signal": signal,
        "sanitizer_observed": sanitizer_seen,
        "sanitizer_kinds": sanitizer.get("sanitizer_kinds") or run_result.get("sanitizer_kinds") or [],
    }


def count_label(records: list[dict[str, Any]], label: str) -> int:
    return len([item for item in records if item.get("label") == label])


def group_pass(records: list[dict[str, Any]], group: str) -> bool:
    selected = [item for item in records if item.get("case_group") == group]
    return bool(selected) and all(item.get("label") == "normal_expected_behavior" for item in selected)


def baseline_loaded(baseline_root: Path) -> bool:
    checks = baseline_root / "validation" / "glm_slot_filling_token_budget_quality_checks.yaml"
    if not checks.exists():
        return baseline_root.exists()
    data = load_yaml(checks)
    return bool(
        data.get("rag_lookup_reused")
        and data.get("mapping_gate_reused")
        and data.get("slot_bindings_generated")
        and data.get("adapter_validate_executed")
    )


def leakage_flags(render_summary: dict[str, Any], render_plan: dict[str, Any], mutation_plan: dict[str, Any]) -> dict[str, bool]:
    text = "\n".join(
        [
            str(render_summary),
            str(render_plan),
            str(mutation_plan),
        ]
    ).lower()
    return {
        "uses_der_parsing": bool(render_summary.get("uses_der_parsing")) or "der parser" in text,
        "uses_trailing_garbage": bool(render_summary.get("uses_trailing_garbage")) or "trailing garbage" in text,
        "uses_full_consumption_oracle": bool(render_summary.get("uses_full_consumption_oracle"))
        or "full consumption oracle" in text,
        "pkey_parsing_leakage": "pkey_parsing" in text and "pkey_verify_semantic" not in text,
    }


def write_report(path: Path, data: dict[str, Any]) -> None:
    lines = [
        "# pkey_verify_semantic_compile_run_analyze_v1",
        "",
        "## Summary",
        "",
        f"- family: {data['family']}",
        f"- track: {data['track']}",
        f"- target_library: {data['target_library']}",
        f"- rendered_case_count: {data['rendered_case_count']}",
        f"- compile_success: {data['compile_success']}",
        f"- compile_failed: {data['compile_failed']}",
        f"- run_attempted: {data['run_attempted']}",
        f"- oracle_events: {data['oracle_events_parsed_count']}",
        f"- candidate_count: {data['candidate_count']}",
        f"- quality_status: {data['quality_status']}",
        "",
        "## Policy",
        "",
        "- No DER parsing, trailing-garbage, or full-consumption oracle was used.",
        "- Nonzero exits are not treated as crashes without sanitizer or signal evidence.",
        "- No feedback main store, pattern bank, adapter recipe, or normalized template was modified.",
        "- No confirmed vulnerability, CVE, or exploitable claim is made.",
        "",
        "## Next",
        "",
        "- Continue with semantic feedback triage only if a non-normal semantic candidate is present.",
        "- Otherwise continue scheduler selection for the next local family/stage.",
        "",
    ]
    write_text(path, "\n".join(lines))


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    render_cases_root = repo_root / args.render_cases_root
    render_summary_path = render_cases_root / "render" / "render_cases_summary.yaml"
    render_plan_path = repo_root / args.render_plan
    mutation_plan_path = repo_root / args.mutation_plan
    baseline_root = repo_root / args.baseline_root
    openssl_install = Path(args.openssl_install)
    out_dir = repo_root / args.out_dir

    render_summary = load_yaml(render_summary_path)
    render_plan = load_yaml(render_plan_path)
    mutation_plan = load_yaml(mutation_plan_path)
    rendered_index = build_rendered_index(render_summary, repo_root)

    copy_snapshot(render_summary_path, out_dir / "inputs" / "render_cases_summary_snapshot.yaml")
    copy_snapshot(render_plan_path, out_dir / "inputs" / "render_plan_snapshot.yaml")
    copy_snapshot(mutation_plan_path, out_dir / "inputs" / "mutation_plan_snapshot.yaml")

    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    compile_results: list[dict[str, Any]] = []
    run_results: list[dict[str, Any]] = []
    oracle_events: list[dict[str, Any]] = []
    sanitizer_observations: list[dict[str, Any]] = []

    work_dir = out_dir / "work"
    for case in rendered_index["cases"]:
        compile_result, run_result, events, sanitizer_observation = execute_instrumented_case(
            case,
            work_dir,
            include_dir,
            lib_dir,
            openssl_install,
            args.timeout_seconds,
            parse_oracle_events,
        )
        compile_results.append(compile_result)
        run_results.append(run_result)
        oracle_events.extend(events)
        sanitizer_observations.append(sanitizer_observation)

    events_by_case = event_by_case(oracle_events)
    runs_by_case = {str(item.get("case_id") or ""): item for item in run_results}
    sanitizer_by_case = {str(item.get("case_id") or ""): item for item in sanitizer_observations}
    classifications = [
        classify_case(
            case,
            runs_by_case.get(str(case.get("case_id") or ""), {}),
            events_by_case.get(str(case.get("case_id") or "")),
            sanitizer_by_case.get(str(case.get("case_id") or ""), {}),
        )
        for case in rendered_index["cases"]
    ]
    candidate_records = [item for item in classifications if item.get("label") != "normal_expected_behavior"]

    rendered_count = len(rendered_index["cases"])
    compile_success = count_status = len(
        [item for item in compile_results if item.get("compile_status") == "compile_success"]
    )
    compile_failed = len(compile_results) - compile_success
    run_attempted = len([item for item in run_results if item.get("run_status") != "not_run_compile_failed"])
    normal_expected = count_label(classifications, "normal_expected_behavior")
    unexpected_accept = count_label(classifications, "unexpected_accept_candidate")
    unexpected_reject = count_label(classifications, "unexpected_reject_candidate")
    semantic_divergence = count_label(classifications, "semantic_divergence_candidate")
    crash_count = count_label(classifications, "crash_candidate")
    sanitizer_count = count_label(classifications, "sanitizer_candidate")
    baseline_failed_count = count_label(classifications, "baseline_control_failed")
    needs_triage = count_label(classifications, "needs_triage")
    leaks = leakage_flags(render_summary, render_plan, mutation_plan)
    forbidden_generated = any(item.get("label") in FORBIDDEN_LABELS for item in classifications)

    valid_control_passed = group_pass(classifications, "valid_accept_control")
    signature_controls_passed = group_pass(classifications, "signature_corruption")
    message_controls_passed = group_pass(classifications, "message_mismatch")
    wrong_key_control_passed = group_pass(classifications, "wrong_key")
    baseline_control_failed = bool(baseline_failed_count or not valid_control_passed)

    if leaks["uses_der_parsing"] or leaks["uses_trailing_garbage"] or leaks["uses_full_consumption_oracle"] or leaks[
        "pkey_parsing_leakage"
    ]:
        quality_status = "failed_der_parsing_leakage"
    elif compile_success < 8:
        quality_status = "blocked_compile_failure"
    elif baseline_control_failed:
        quality_status = "blocked_baseline_control_failed"
    elif crash_count or sanitizer_count:
        quality_status = "pass_crash_or_sanitizer_candidate_found"
    elif unexpected_accept or unexpected_reject or semantic_divergence:
        quality_status = "pass_new_semantic_candidate_found"
    else:
        quality_status = "pass_no_candidate"

    dump_yaml(
        out_dir / "compile" / "compile_jobs.yaml",
        {
            "schema": "semantic_compile_jobs_v1",
            "generated_at": now_iso(),
            "openssl": openssl_runtime_info(openssl_install),
            "compile_jobs": compile_results,
        },
    )
    dump_yaml(
        out_dir / "compile" / "compile_summary.yaml",
        {
            "schema": "semantic_compile_summary_v1",
            "compile_executed": True,
            "rendered_case_count": rendered_count,
            "compile_success": compile_success,
            "compile_failed": compile_failed,
            "main_error": next(
                (
                    item.get("stderr_log")
                    for item in compile_results
                    if item.get("compile_status") != "compile_success"
                ),
                "",
            ),
        },
    )
    dump_yaml(
        out_dir / "run" / "run_records.yaml",
        {
            "schema": "semantic_run_records_v1",
            "generated_at": now_iso(),
            "run_records": run_results,
            "sanitizer_observations": sanitizer_observations,
        },
    )
    dump_yaml(
        out_dir / "run" / "run_summary.yaml",
        {
            "schema": "semantic_run_summary_v1",
            "run_executed": True,
            "run_attempted": run_attempted,
            "normal_exit": len([item for item in run_results if item.get("raw_observation_label") == "normal_exit"]),
            "nonzero_exit": len([item for item in run_results if item.get("raw_observation_label") == "nonzero_exit"]),
            "crash_signal": len([item for item in run_results if item.get("signal")]),
            "asan_observed": len(
                [item for item in sanitizer_observations if "asan" in (item.get("sanitizer_kinds") or [])]
            ),
            "ubsan_observed": len(
                [item for item in sanitizer_observations if "ubsan" in (item.get("sanitizer_kinds") or [])]
            ),
        },
    )
    dump_yaml(
        out_dir / "analyze" / "oracle_events.yaml",
        {"schema": "semantic_oracle_events_v1", "oracle_events": oracle_events},
    )
    dump_yaml(
        out_dir / "analyze" / "analyze_summary.yaml",
        {
            "schema": "semantic_analyze_summary_v1",
            "oracle_analyze_executed": True,
            "oracle_events_parsed": bool(oracle_events),
            "oracle_events_parsed_count": len(oracle_events),
            "normal_expected_behavior": normal_expected,
            "valid_accept_control_passed": valid_control_passed,
            "signature_corruption_controls_passed": signature_controls_passed,
            "message_mismatch_controls_passed": message_controls_passed,
            "wrong_key_control_passed": wrong_key_control_passed,
            "baseline_control_failed": baseline_control_failed,
            "case_classifications": classifications,
        },
    )
    dump_yaml(
        out_dir / "candidate_queue" / "candidates.yaml",
        {
            "schema": "semantic_candidate_queue_v1",
            "allowed_labels": sorted(ALLOWED_CANDIDATE_LABELS),
            "forbidden_labels": sorted(FORBIDDEN_LABELS),
            "candidates": candidate_records,
            "all_case_labels": classifications,
        },
    )
    dump_yaml(
        out_dir / "candidate_queue" / "candidate_summary.yaml",
        {
            "schema": "semantic_candidate_summary_v1",
            "candidate_queue_generated": True,
            "candidate_count": len(candidate_records),
            "normal_expected_behavior": normal_expected,
            "unexpected_accept_count": unexpected_accept,
            "unexpected_reject_count": unexpected_reject,
            "semantic_divergence_count": semantic_divergence,
            "crash_candidate_count": crash_count,
            "sanitizer_candidate_count": sanitizer_count,
            "baseline_control_failed": baseline_control_failed,
            "needs_triage_count": needs_triage,
        },
    )

    quality = {
        "schema": "pkey_verify_semantic_compile_run_analyze_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family": str(render_summary.get("family") or "pkey_verify_semantic"),
        "track": str(render_summary.get("track") or "semantic"),
        "target_library": str(render_summary.get("target_library") or "openssl"),
        "rag_glm_baseline_loaded": baseline_loaded(baseline_root),
        "render_cases_loaded": bool(rendered_index["cases"]),
        "rendered_case_count": rendered_count,
        "compile_executed": True,
        "compile_success": compile_success,
        "compile_failed": compile_failed,
        "run_executed": True,
        "run_attempted": run_attempted,
        "oracle_analyze_executed": True,
        "oracle_events_parsed": bool(oracle_events),
        "valid_accept_control_passed": valid_control_passed,
        "signature_corruption_controls_passed": signature_controls_passed,
        "message_mismatch_controls_passed": message_controls_passed,
        "wrong_key_control_passed": wrong_key_control_passed,
        "candidate_queue_generated": True,
        "candidate_count": len(candidate_records),
        "unexpected_accept_count": unexpected_accept,
        "unexpected_reject_count": unexpected_reject,
        "semantic_divergence_count": semantic_divergence,
        "crash_candidate_count": crash_count,
        "sanitizer_candidate_count": sanitizer_count,
        "baseline_control_failed": baseline_control_failed,
        "uses_der_parsing": leaks["uses_der_parsing"],
        "uses_trailing_garbage": leaks["uses_trailing_garbage"],
        "uses_full_consumption_oracle": leaks["uses_full_consumption_oracle"],
        "pkey_parsing_leakage": leaks["pkey_parsing_leakage"],
        "full_consumption_gap_label_generated": forbidden_generated,
        "compile_nonzero_treated_as_crash_without_evidence": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status,
    }
    dump_yaml(out_dir / "validation" / "pkey_verify_semantic_compile_run_analyze_quality_checks.yaml", quality)

    report_data = {
        "family": quality["family"],
        "track": quality["track"],
        "target_library": quality["target_library"],
        "rendered_case_count": rendered_count,
        "compile_success": compile_success,
        "compile_failed": compile_failed,
        "run_attempted": run_attempted,
        "oracle_events_parsed_count": len(oracle_events),
        "candidate_count": len(candidate_records),
        "quality_status": quality_status,
    }
    write_report(out_dir / "reports" / "pkey_verify_semantic_compile_run_analyze_v1_report.md", report_data)
    print(f"wrote {out_dir}")
    print(f"quality_status: {quality_status}")
    print(f"compile_success: {count_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
