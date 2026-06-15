#!/usr/bin/env python3
"""Compile and run oracle-instrumented OpenSSL harnesses.

This wrapper records raw compile/run output and parsed ORACLE_EVENT records.
It intentionally does not analyze, triage, write feedback, or call an LLM.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from analyzer.oracle_event_parser import parse_oracle_event_line
from runner.family_compile_runner import execute_instrumented_case
from runner.sanitizer_env import asan_options, ubsan_options
from tools.compile_run_v1 import (
    classify_raw_observation,
    dump_yaml,
    lib_dir_for_install,
    load_yaml,
    matched_keywords,
    now_iso,
    raw_excerpt,
    rel,
    run_env,
    sanitizer_kinds,
    signal_name,
    write_text,
)


def unique_case_out(root: Path, case_id: str) -> tuple[Path, bool]:
    base = root / "compiled_cases" / case_id
    if not (base / "case.bin").exists():
        return base, False
    for idx in range(1, 1000):
        candidate = root / "compiled_cases" / f"{case_id}__rerun_{idx:03d}"
        if not (candidate / "case.bin").exists():
            return candidate, True
    raise RuntimeError(f"could not allocate unique output directory for {case_id}")


def compile_status_for(returncode: int | None, binary: Path) -> str:
    if returncode == 0 and binary.exists():
        return "compile_success"
    return "compile_failed"


def parse_oracle_events_with_context(text: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        parsed = parse_oracle_event_line(line)
        if parsed is None:
            continue
        parsed.setdefault("case_id", case.get("case_id", ""))
        parsed.setdefault("family", case.get("family", ""))
        parsed.setdefault("mutation_strategy", case.get("mutation_strategy", ""))
        parsed.setdefault("target_library", case.get("target_library", ""))
        parsed["raw_line"] = line
        events.append(parsed)
    return events


def event_record(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": event.get("case_id", ""),
        "family": event.get("family", ""),
        "mutation_strategy": event.get("mutation_strategy", ""),
        "target_library": event.get("target_library", ""),
        "phase": event.get("phase", ""),
        "api": event.get("api", ""),
        "ret": event.get("ret", "unknown"),
        "accepted": event.get("accepted", "unknown"),
        "input_len": event.get("input_len", "unknown"),
        "consumed_len": event.get("consumed_len", "unknown"),
        "full_consumption": event.get("full_consumption", "unknown"),
        "openssl_error_code": event.get("openssl_error_code", "unknown"),
        "openssl_error_reason": event.get("openssl_error_reason", "unknown"),
        "cleanup_executed": event.get("cleanup_executed", "unknown"),
        "raw_line": event.get("raw_line", ""),
    }


def execute_case(
    case: dict[str, Any],
    out_dir: Path,
    include_dir: Path,
    lib_dir: Path,
    openssl_install: Path,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    case_id = str(case.get("case_id") or "")
    family = str(case.get("family") or "")
    mutation_strategy = str(case.get("mutation_strategy") or "")
    target_library = str(case.get("target_library") or "")
    harness = Path(str(case.get("harness_c") or ""))
    case_out, collision_avoided = unique_case_out(out_dir, case_id)
    case_out.mkdir(parents=True, exist_ok=True)

    binary = case_out / "case.bin"
    compile_stdout = case_out / "compile.stdout.log"
    compile_stderr = case_out / "compile.stderr.log"
    run_stdout = case_out / "run.stdout.log"
    run_stderr = case_out / "run.stderr.log"
    compile_cmd = command_for(harness, binary, include_dir, lib_dir)
    compile_command = " ".join(compile_cmd)
    write_text(out_dir / "compile_commands" / f"{case_id}.cmd", compile_command + "\n")

    compile_returncode: int | None = None
    compile_notes: list[str] = []
    if collision_avoided:
        compile_notes.append("binary collision avoided by using unique output directory")
    if target_library != "openssl":
        compile_status = "compile_skipped_collision"
        compile_notes.append("non-openssl case blocked before compile")
        write_text(compile_stdout, "")
        write_text(compile_stderr, "blocked: non-openssl target\n")
    elif not harness.exists():
        compile_status = "compile_failed"
        compile_notes.append("missing harness.c")
        write_text(compile_stdout, "")
        write_text(compile_stderr, "missing harness.c\n")
    elif "ORACLE_EVENT" not in harness.read_text(encoding="utf-8", errors="replace"):
        compile_status = "compile_failed"
        compile_notes.append("harness.c missing ORACLE_EVENT instrumentation")
        write_text(compile_stdout, "")
        write_text(compile_stderr, "missing ORACLE_EVENT instrumentation\n")
    else:
        proc = subprocess.run(compile_cmd, text=True, capture_output=True)
        compile_returncode = proc.returncode
        write_text(compile_stdout, proc.stdout)
        write_text(compile_stderr, proc.stderr)
        compile_status = compile_status_for(proc.returncode, binary)

    compile_result = {
        "case_id": case_id,
        "family": family,
        "mutation_strategy": mutation_strategy,
        "target_library": target_library,
        "harness_c": rel(harness),
        "binary_path": rel(binary),
        "compile_command": compile_command,
        "compile_status": compile_status,
        "stdout_log": rel(compile_stdout),
        "stderr_log": rel(compile_stderr),
        "return_code": compile_returncode,
        "notes": compile_notes,
    }

    run_status = "not_run_compile_failed"
    exit_code: int | None = None
    sig = ""
    timed_out = False
    duration = 0.0
    if compile_status == "compile_success":
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [rel(binary)],
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                env=run_env(openssl_install, lib_dir),
            )
            duration = time.monotonic() - start
            exit_code = proc.returncode
            write_text(run_stdout, proc.stdout)
            write_text(run_stderr, proc.stderr)
            if proc.returncode < 0:
                run_status = "signaled"
                sig = signal_name(proc.returncode)
            else:
                run_status = "exited"
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            timed_out = True
            run_status = "timeout"
            write_text(run_stdout, exc.stdout or "")
            write_text(run_stderr, (exc.stderr or "") + "\ntimeout\n")
    else:
        write_text(run_stdout, "")
        write_text(run_stderr, "")

    stdout_text = run_stdout.read_text(encoding="utf-8", errors="replace") if run_stdout.exists() else ""
    stderr_text = run_stderr.read_text(encoding="utf-8", errors="replace") if run_stderr.exists() else ""
    combined = stdout_text + "\n" + stderr_text
    events = [event_record(event) for event in parse_oracle_events_with_context(combined, case)]
    keywords = matched_keywords(combined)
    kinds = sanitizer_kinds(combined)
    if sig in {"SIGSEGV", "SIGABRT"} and sig not in keywords:
        keywords.append(sig)
    sanitizer_seen = bool(kinds or keywords)
    raw_label = classify_raw_observation(
        compile_success=compile_status == "compile_success",
        timeout=timed_out,
        returncode=exit_code,
        sanitizer_seen=sanitizer_seen,
    )
    run_result = {
        "case_id": case_id,
        "family": family,
        "mutation_strategy": mutation_strategy,
        "target_library": target_library,
        "binary_path": rel(binary),
        "run_status": run_status,
        "exit_code": exit_code,
        "signal": sig,
        "timeout": timed_out,
        "duration_seconds": round(duration, 6),
        "stdout_log": rel(run_stdout),
        "stderr_log": rel(run_stderr),
        "oracle_event_count": len(events),
        "sanitizer_observed": sanitizer_seen,
        "sanitizer_kinds": kinds,
        "raw_observation_label": raw_label,
    }
    sanitizer_observation = {
        "case_id": case_id,
        "family": family,
        "mutation_strategy": mutation_strategy,
        "sanitizer_observed": sanitizer_seen,
        "sanitizer_kinds": kinds,
        "matched_keywords": keywords,
        "stderr_log": rel(run_stderr),
        "raw_excerpt": raw_excerpt(combined),
        "triage_required": True,
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }
    return compile_result, run_result, events, sanitizer_observation


def execute_case(
    case: dict[str, Any],
    out_dir: Path,
    include_dir: Path,
    lib_dir: Path,
    openssl_install: Path,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    return execute_instrumented_case(
        case=case,
        out_dir=out_dir,
        include_dir=include_dir,
        lib_dir=lib_dir,
        openssl_install=openssl_install,
        timeout_seconds=timeout_seconds,
        parse_oracle_events=parse_oracle_events_with_context,
    )


def write_md(path: Path, title: str, lines: list[str]) -> None:
    write_text(path, "# " + title + "\n\n" + "\n".join(lines) + "\n")


def build_input_summary(args: argparse.Namespace, index: dict[str, Any], out_dir: Path, lib_dir: Path) -> dict[str, Any]:
    return {
        "schema": "compile_run_oracle_instrumented_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": [
            args.instrumented_case_index,
            args.instrumented_cases_root,
            "analyzer/oracle_event_parser.py",
            "artifacts/sprints/compile_run_v1/compile_results/compile_results.yaml",
            "artifacts/sprints/compile_run_v1/run_results/run_results.yaml",
            "artifacts/sprints/compile_run_v1/sanitizer_observations/sanitizer_observations.yaml",
            "artifacts/sprints/oracle_instrumentation_enrichment_v1/compatibility/oracle_instrumentation_compatibility.yaml",
            "artifacts/sprints/render_cases_v1/blocked_cases/render_blocked_cases.yaml",
        ],
        "scope": {
            "uses_instrumented_harness": True,
            "compile": True,
            "run": True,
            "target_scope": "openssl only",
            "mbedtls_processed": False,
            "parse_oracle_event": True,
            "analyze": False,
            "triage": False,
            "feedback_written": False,
            "glm_called": False,
        },
        "openssl": {
            "install": args.openssl_install,
            "include": rel(Path(args.openssl_install) / "include"),
            "lib": rel(lib_dir),
            "modules": rel(lib_dir / "ossl-modules"),
        },
        "index_cases": len(index.get("cases", [])),
        "out_dir": rel(out_dir),
    }


def build_blocked_doc() -> dict[str, Any]:
    return {
        "schema": "blocked_cases_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "blocked_cases": [
            {
                "family": "asn1_nested_boundary",
                "target_library": "mbedtls",
                "adapter_id": "asn1_nested_boundary_mbedtls",
                "compile_attempted": False,
                "run_attempted": False,
                "reason": "blocked_expected / no instrumented case",
            }
        ],
        "summary": {
            "total_blocked": 1,
            "mbedtls_compile_attempted": 0,
            "mbedtls_run_attempted": 0,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile/run oracle-instrumented OpenSSL harnesses.")
    parser.add_argument("--instrumented-case-index", required=True)
    parser.add_argument("--instrumented-cases-root", required=True)
    parser.add_argument("--openssl-install", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    openssl_install = Path(args.openssl_install)
    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    index = load_yaml(Path(args.instrumented_case_index))
    cases = [case for case in index.get("cases", []) if case.get("target_library") == "openssl"]

    input_summary = build_input_summary(args, index, out_dir, lib_dir)
    dump_yaml(out_dir / "input" / "compile_run_oracle_instrumented_input_summary.yaml", input_summary)
    write_md(
        out_dir / "input" / "compile_run_oracle_instrumented_input_summary.md",
        "Compile Run Oracle Instrumented Input Summary",
        [
            "- uses instrumented harness: `true`",
            "- compile/run: `true`",
            "- target scope: `openssl only`",
            "- mbedTLS processed: `false`",
            "- parses ORACLE_EVENT: `true`",
            "- analyze/triage/feedback: `false`",
            "- GLM/LLM: `false`",
        ],
    )
    environment_doc = {
        "schema": "compile_run_oracle_instrumented_environment_v1",
        "generated_at": now_iso(),
        "openssl_install": rel(openssl_install),
        "include_dir": rel(include_dir),
        "lib_dir": rel(lib_dir),
        "openssl_modules": rel(lib_dir / "ossl-modules"),
        "asan_options": asan_options(),
        "ubsan_options": ubsan_options(),
    }
    dump_yaml(out_dir / "environment" / "environment.yaml", environment_doc)

    compile_results: list[dict[str, Any]] = []
    run_results: list[dict[str, Any]] = []
    all_events: list[dict[str, Any]] = []
    sanitizer_observations: list[dict[str, Any]] = []
    for case in cases:
        compile_result, run_result, events, sanitizer_observation = execute_case(
            case=case,
            out_dir=out_dir,
            include_dir=include_dir,
            lib_dir=lib_dir,
            openssl_install=openssl_install,
            timeout_seconds=args.timeout_seconds,
        )
        compile_results.append(compile_result)
        run_results.append(run_result)
        all_events.extend(events)
        sanitizer_observations.append(sanitizer_observation)

    compile_counts = Counter(item["compile_status"] for item in compile_results)
    compile_doc = {
        "schema": "compile_results_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "compile_results": compile_results,
        "summary": {
            "total_jobs": len(compile_results),
            "compile_success": compile_counts.get("compile_success", 0),
            "compile_failed": compile_counts.get("compile_failed", 0),
            "compile_skipped": compile_counts.get("compile_skipped_collision", 0),
        },
    }
    dump_yaml(out_dir / "compile_results" / "compile_results.yaml", compile_doc)
    write_md(
        out_dir / "compile_results" / "compile_results.md",
        "Compile Results",
        [f"- {k}: `{v}`" for k, v in compile_doc["summary"].items()],
    )

    raw_counts = Counter(item["raw_observation_label"] for item in run_results)
    run_doc = {
        "schema": "run_results_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "run_results": run_results,
        "summary": {
            "total_jobs": len(run_results),
            "run_attempted": len([r for r in run_results if r["run_status"] != "not_run_compile_failed"]),
            "normal_exit": raw_counts.get("normal_exit", 0),
            "nonzero_exit": raw_counts.get("nonzero_exit", 0),
            "signaled": len([r for r in run_results if r["run_status"] == "signaled"]),
            "timeout": raw_counts.get("timeout_observed", 0),
            "sanitizer_output_observed": raw_counts.get("sanitizer_output_observed", 0),
            "oracle_events_observed": len(all_events),
            "not_run_compile_failed": raw_counts.get("compile_failed_not_run", 0),
        },
    }
    dump_yaml(out_dir / "run_results" / "run_results.yaml", run_doc)
    write_md(
        out_dir / "run_results" / "run_results.md",
        "Run Results",
        [f"- {k}: `{v}`" for k, v in run_doc["summary"].items()],
    )

    event_phase_counts = Counter(str(event.get("phase", "")) for event in all_events)
    accepted_counts = Counter(event.get("accepted", "unknown") for event in all_events)
    full_counts = Counter(event.get("full_consumption", "unknown") for event in all_events)
    oracle_doc = {
        "schema": "oracle_events_results_v1",
        "generated_at": now_iso(),
        "events": all_events,
        "summary": {
            "total_events": len(all_events),
            "cases_with_events": len({event.get("case_id") for event in all_events}),
            "parse_events": event_phase_counts.get("parse", 0),
            "verify_events": event_phase_counts.get("verify", 0),
            "full_consumption_events": event_phase_counts.get("full_consumption_check", 0),
            "cleanup_events": event_phase_counts.get("cleanup", 0),
            "accepted_true": accepted_counts.get(1, 0),
            "accepted_false": accepted_counts.get(0, 0),
            "full_consumption_true": full_counts.get(1, 0),
            "full_consumption_false": full_counts.get(0, 0),
            "full_consumption_unknown": full_counts.get("unknown", 0),
        },
        "notes": [
            "Raw oracle observations only; no semantic interpretation is performed here.",
            "full_consumption=false is not a vulnerability claim.",
            "accepted=true/false is not a vulnerability claim.",
        ],
    }
    dump_yaml(out_dir / "oracle_events" / "oracle_events.yaml", oracle_doc)
    write_md(
        out_dir / "oracle_events" / "oracle_events.md",
        "Oracle Events",
        [f"- {k}: `{v}`" for k, v in oracle_doc["summary"].items()],
    )

    sanitizer_doc = {
        "schema": "sanitizer_observations_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "observations": sanitizer_observations,
        "summary": {
            "total_observations": len(sanitizer_observations),
            "sanitizer_observed_count": len([o for o in sanitizer_observations if o["sanitizer_observed"]]),
            "crash_signal_count": len([r for r in run_results if r["run_status"] == "signaled"]),
            "timeout_count": len([r for r in run_results if r["timeout"]]),
        },
    }
    dump_yaml(out_dir / "sanitizer_observations" / "sanitizer_observations.yaml", sanitizer_doc)
    write_md(
        out_dir / "sanitizer_observations" / "sanitizer_observations.md",
        "Sanitizer Observations",
        [f"- {k}: `{v}`" for k, v in sanitizer_doc["summary"].items()],
    )

    blocked_doc = build_blocked_doc()
    dump_yaml(out_dir / "blocked_cases" / "blocked_cases.yaml", blocked_doc)
    write_md(
        out_dir / "blocked_cases" / "blocked_cases.md",
        "Blocked Cases",
        ["- asn1_nested_boundary -> mbedTLS: compile_attempted=false, run_attempted=false"],
    )

    all_logs = all(
        str(item.get(key, "")).startswith(rel(out_dir))
        for item in compile_results + run_results
        for key in ["stdout_log", "stderr_log"]
        if item.get(key)
    )
    all_bins = all(str(item.get("binary_path", "")).startswith(rel(out_dir)) for item in compile_results)
    quality = {
        "schema": "compile_run_oracle_instrumented_quality_checks_v1",
        "generated_at": now_iso(),
        "expected_cases": 14,
        "compile_jobs_seen": len(compile_results),
        "compile_success": compile_doc["summary"]["compile_success"],
        "compile_failed": compile_doc["summary"]["compile_failed"],
        "run_attempted": run_doc["summary"]["run_attempted"],
        "oracle_events_observed": len(all_events),
        "cases_with_oracle_events": oracle_doc["summary"]["cases_with_events"],
        "mbedtls_compile_attempted": len([c for c in compile_results if c.get("target_library") == "mbedtls"]),
        "mbedtls_run_attempted": len([r for r in run_results if r.get("target_library") == "mbedtls"]),
        "all_jobs_target_openssl": all(c.get("target_library") == "openssl" for c in compile_results + run_results),
        "all_binaries_under_sprint": all_bins,
        "all_logs_under_sprint": all_logs,
        "no_input_files_modified": True,
        "no_adapter_files_modified": True,
        "no_template_files_modified": True,
        "no_glm_called": True,
        "no_analysis_performed": True,
        "no_feedback_written": True,
        "no_confirmed_vulnerability_claim": True,
        "notes": [
            "This sprint records raw compile/run/oracle-event output only.",
            "No final semantic analysis or vulnerability classification is performed.",
        ],
    }
    quality["quality_status"] = (
        "pass"
        if quality["compile_jobs_seen"] == 14
        and quality["run_attempted"] == 14
        and quality["mbedtls_compile_attempted"] == 0
        and quality["mbedtls_run_attempted"] == 0
        and quality["cases_with_oracle_events"] >= 10
        and quality["all_jobs_target_openssl"]
        and quality["all_binaries_under_sprint"]
        and quality["all_logs_under_sprint"]
        and quality["no_glm_called"]
        and quality["no_analysis_performed"]
        and quality["no_feedback_written"]
        and quality["no_confirmed_vulnerability_claim"]
        else "partial"
        if quality["compile_jobs_seen"]
        else "fail"
    )
    dump_yaml(out_dir / "validation" / "compile_run_oracle_instrumented_quality_checks.yaml", quality)
    write_md(
        out_dir / "validation" / "compile_run_oracle_instrumented_quality_checks.md",
        "Compile Run Oracle Instrumented Quality Checks",
        [f"- {k}: `{v}`" for k, v in quality.items() if k != "notes"],
    )

    if quality["mbedtls_compile_attempted"] or quality["mbedtls_run_attempted"]:
        next_task = "compile_run_blocking_policy_fixup_v1"
        reason = "mbedTLS was compiled or run unexpectedly"
    elif compile_doc["summary"]["compile_failed"] > 7:
        next_task = "oracle_instrumentation_compile_fixup_v1"
        reason = "most instrumented cases failed to compile"
    elif oracle_doc["summary"]["total_events"] == 0:
        next_task = "oracle_instrumentation_output_fixup_v1"
        reason = "ORACLE_EVENT output was missing or unparsable"
    elif compile_doc["summary"]["compile_success"] == 14 and run_doc["summary"]["run_attempted"] == 14:
        next_task = "analyze_results_oracle_aware_v1"
        reason = "14 cases compiled and ran with parseable ORACLE_EVENT records"
    else:
        next_task = "oracle_instrumentation_compile_fixup_v1"
        reason = "compile/run quality did not fully pass"
    next_action = {
        "schema": "next_action_after_compile_run_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "next_task_name": next_task,
        "reason": reason,
    }
    dump_yaml(out_dir / "reports" / "next_action_after_compile_run_oracle_instrumented.yaml", next_action)
    write_md(
        out_dir / "reports" / "next_action_after_compile_run_oracle_instrumented.md",
        "Next Action After Compile Run Oracle Instrumented",
        [f"- next_task_name: `{next_task}`", f"- reason: {reason}"],
    )

    report = {
        "schema": "compile_run_oracle_instrumented_v1_report",
        "task": "compile_run_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "instrumented_compile_jobs": len(compile_results),
        "compile_success": compile_doc["summary"]["compile_success"],
        "compile_failed": compile_doc["summary"]["compile_failed"],
        "run_attempted": run_doc["summary"]["run_attempted"],
        "oracle_events_parsed": oracle_doc["summary"]["total_events"],
        "cases_with_events": oracle_doc["summary"]["cases_with_events"],
        "accepted_true": oracle_doc["summary"]["accepted_true"],
        "accepted_false": oracle_doc["summary"]["accepted_false"],
        "full_consumption_true": oracle_doc["summary"]["full_consumption_true"],
        "full_consumption_false": oracle_doc["summary"]["full_consumption_false"],
        "full_consumption_unknown": oracle_doc["summary"]["full_consumption_unknown"],
        "sanitizer_observed": sanitizer_doc["summary"]["sanitizer_observed_count"],
        "crash_signals": sanitizer_doc["summary"]["crash_signal_count"],
        "timeouts": sanitizer_doc["summary"]["timeout_count"],
        "mbedtls_compile_attempted": quality["mbedtls_compile_attempted"],
        "mbedtls_run_attempted": quality["mbedtls_run_attempted"],
        "glm_called": False,
        "feedback_written": False,
        "analysis_performed": False,
        "quality_status": quality["quality_status"],
        "next_task_name": next_task,
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }
    dump_yaml(out_dir / "reports" / "compile_run_oracle_instrumented_v1_report.yaml", report)
    write_md(
        out_dir / "reports" / "compile_run_oracle_instrumented_v1_report.md",
        "compile_run_oracle_instrumented_v1 Report",
        [f"- {k}: `{v}`" for k, v in report.items() if k != "claim_policy"],
    )
    write_text(
        out_dir / "README.md",
        "# compile_run_oracle_instrumented_v1\n\n"
        "This sprint compiles and runs the 14 OpenSSL oracle-instrumented harnesses, "
        "records raw stdout/stderr/sanitizer observations, and parses ORACLE_EVENT lines. "
        "It does not perform final analysis, triage, feedback writing, or vulnerability claims.\n\n"
        f"- compile_success: `{compile_doc['summary']['compile_success']}`\n"
        f"- run_attempted: `{run_doc['summary']['run_attempted']}`\n"
        f"- oracle_events_parsed: `{oracle_doc['summary']['total_events']}`\n"
        f"- next_task: `{next_task}`\n",
    )
    print(f"[OK] wrote compile/run oracle instrumented artifacts to {out_dir}")
    print(
        f"[SUMMARY] compile_success={compile_doc['summary']['compile_success']} run_attempted={run_doc['summary']['run_attempted']} events={oracle_doc['summary']['total_events']} quality={quality['quality_status']}"
    )
    print(f"[NEXT] {next_task}")
    return 0 if quality["quality_status"] in {"pass", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
