#!/usr/bin/env python3
"""Compile and run rendered OpenSSL harnesses with sanitizer OpenSSL.

This is an execution-recording step only. It records raw compile/run/sanitizer
observations and intentionally does not analyze or triage them.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import shutil
import signal
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from runner.family_compile_runner import command_for as family_command_for
from runner.family_compile_runner import execute_compile_plan_job


SANITIZER_KEYWORDS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-free",
    "double-free",
    "invalid free",
    "SEGV",
    "ABRT",
    "timeout",
]


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


def rel(path: str | Path) -> str:
    return Path(path).as_posix()


def lib_dir_for_install(install: Path) -> Path:
    lib64 = install / "lib64"
    if lib64.exists():
        return lib64
    return install / "lib"


def signal_name(returncode: int | None) -> str:
    if returncode is None or returncode >= 0:
        return ""
    sig = -returncode
    try:
        return signal.Signals(sig).name
    except ValueError:
        return f"SIG{sig}"


def sanitizer_kinds(text: str) -> list[str]:
    kinds: list[str] = []
    if "AddressSanitizer" in text:
        kinds.append("asan")
    if "UndefinedBehaviorSanitizer" in text or "runtime error:" in text:
        kinds.append("ubsan")
    if "LeakSanitizer" in text:
        kinds.append("lsan")
    return sorted(set(kinds))


def matched_keywords(text: str) -> list[str]:
    return [kw for kw in SANITIZER_KEYWORDS if kw in text]


def raw_excerpt(text: str, max_lines: int = 12) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(lines[:max_lines])


def classify_raw_observation(
    compile_success: bool,
    timeout: bool,
    returncode: int | None,
    sanitizer_seen: bool,
) -> str:
    if not compile_success:
        return "compile_failed_not_run"
    if timeout:
        return "timeout_observed"
    if returncode is not None and returncode < 0:
        return "crash_signal_observed"
    if sanitizer_seen:
        return "sanitizer_output_observed"
    if returncode == 0:
        return "normal_exit"
    return "nonzero_exit"


def command_for(harness: Path, binary: Path, include_dir: Path, lib_dir: Path) -> list[str]:
    return [
        "gcc",
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined",
        f"-I{include_dir}",
        rel(harness),
        f"-L{lib_dir}",
        f"-Wl,-rpath,{lib_dir}",
        "-lssl",
        "-lcrypto",
        "-ldl",
        "-pthread",
        "-o",
        rel(binary),
    ]


def run_env(install: Path, lib_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    prior = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{lib_dir}:{prior}" if prior else rel(lib_dir)
    env["OPENSSL_MODULES"] = rel(lib_dir / "ossl-modules")
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def write_md_list(items: list[str]) -> str:
    return "".join(f"- {item}\n" for item in items) if items else "- none\n"


def execute_job(
    job: dict[str, Any],
    out_dir: Path,
    include_dir: Path,
    lib_dir: Path,
    install: Path,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    compile_job_id = job["compile_job_id"]
    case_id = job["case_id"]
    family = job["family"]
    mutation_strategy = job["mutation_strategy"]
    target_library = job["target_library"]
    harness = Path(job["inputs"]["harness_c"])

    case_out = out_dir / "compiled_cases" / compile_job_id
    binary = case_out / "case.bin"
    compile_stdout = case_out / "compile.stdout.log"
    compile_stderr = case_out / "compile.stderr.log"
    run_stdout = case_out / "run.stdout.log"
    run_stderr = case_out / "run.stderr.log"

    case_out.mkdir(parents=True, exist_ok=True)
    compile_cmd = command_for(harness, binary, include_dir, lib_dir)
    compile_command_str = " ".join(compile_cmd)

    compile_status = "compile_failed"
    compile_returncode: int | None = None
    compile_notes: list[str] = []
    if target_library != "openssl":
        compile_status = "compile_skipped_collision"
        compile_notes.append("non-openssl job blocked before compile")
        compile_stdout.write_text("", encoding="utf-8")
        compile_stderr.write_text("blocked: non-openssl target\n", encoding="utf-8")
    elif binary.exists():
        compile_status = "compile_skipped_collision"
        compile_notes.append("binary already exists; not overwritten")
        compile_stdout.write_text("", encoding="utf-8")
        compile_stderr.write_text("collision: binary already exists\n", encoding="utf-8")
    elif not harness.exists():
        compile_status = "compile_failed"
        compile_notes.append("missing harness.c")
        compile_stdout.write_text("", encoding="utf-8")
        compile_stderr.write_text("missing harness.c\n", encoding="utf-8")
    else:
        proc = subprocess.run(compile_cmd, text=True, capture_output=True)
        compile_returncode = proc.returncode
        compile_stdout.write_text(proc.stdout, encoding="utf-8")
        compile_stderr.write_text(proc.stderr, encoding="utf-8")
        if proc.returncode == 0 and binary.exists():
            compile_status = "compile_success"
        else:
            compile_status = "compile_failed"

    compile_result = {
        "compile_job_id": compile_job_id,
        "case_id": case_id,
        "family": family,
        "mutation_strategy": mutation_strategy,
        "target_library": target_library,
        "harness_c": rel(harness),
        "binary_path": rel(binary),
        "compile_command": compile_command_str,
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
    run_notes: list[str] = []
    if compile_status == "compile_success":
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [rel(binary)],
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                env=run_env(install, lib_dir),
            )
            duration = time.monotonic() - start
            exit_code = proc.returncode
            run_stdout.write_text(proc.stdout, encoding="utf-8")
            run_stderr.write_text(proc.stderr, encoding="utf-8")
            if proc.returncode < 0:
                run_status = "signaled"
                sig = signal_name(proc.returncode)
            else:
                run_status = "exited"
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            timed_out = True
            run_status = "timeout"
            run_stdout.write_text(exc.stdout or "", encoding="utf-8")
            run_stderr.write_text((exc.stderr or "") + "\ntimeout\n", encoding="utf-8")
            run_notes.append(f"timeout after {timeout_seconds} seconds")
    else:
        run_stdout.write_text("", encoding="utf-8")
        run_stderr.write_text("", encoding="utf-8")
        run_notes.append("not run because compile did not succeed")

    stderr_text = run_stderr.read_text(encoding="utf-8") if run_stderr.exists() else ""
    stdout_text = run_stdout.read_text(encoding="utf-8") if run_stdout.exists() else ""
    combined = stdout_text + "\n" + stderr_text
    keys = matched_keywords(combined)
    kinds = sanitizer_kinds(combined)
    sanitizer_seen = bool(kinds or keys)
    if sig in {"SIGSEGV", "SIGABRT"} and sig.replace("SIG", "") not in keys:
        keys.append(sig.replace("SIG", ""))
    raw_label = classify_raw_observation(
        compile_success=compile_status == "compile_success",
        timeout=timed_out,
        returncode=exit_code,
        sanitizer_seen=sanitizer_seen,
    )

    run_result = {
        "compile_job_id": compile_job_id,
        "case_id": case_id,
        "family": family,
        "mutation_strategy": mutation_strategy,
        "target_library": target_library,
        "binary_path": rel(binary),
        "run_status": run_status,
        "exit_code": exit_code if exit_code is not None and exit_code >= 0 else None,
        "signal": sig,
        "timeout": timed_out,
        "duration_seconds": round(duration, 6),
        "stdout_log": rel(run_stdout),
        "stderr_log": rel(run_stderr),
        "sanitizer_observed": sanitizer_seen,
        "sanitizer_kinds": kinds,
        "raw_observation_label": raw_label,
        "notes": run_notes,
    }

    observation = {
        "compile_job_id": compile_job_id,
        "case_id": case_id,
        "family": family,
        "mutation_strategy": mutation_strategy,
        "sanitizer_observed": sanitizer_seen,
        "sanitizer_kinds": kinds,
        "matched_keywords": keys,
        "stderr_log": rel(run_stderr),
        "raw_excerpt": raw_excerpt(combined),
        "triage_required": True,
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitability_claimed": False,
        },
    }

    return compile_result, run_result, observation


execute_job = execute_compile_plan_job
command_for = family_command_for


def summarize_compile(results: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(item["compile_status"] for item in results)
    return {
        "total_jobs": len(results),
        "compile_success": counts.get("compile_success", 0),
        "compile_failed": counts.get("compile_failed", 0),
        "compile_skipped": counts.get("compile_skipped_collision", 0),
    }


def summarize_run(results: list[dict[str, Any]]) -> dict[str, int]:
    labels = Counter(item["raw_observation_label"] for item in results)
    statuses = Counter(item["run_status"] for item in results)
    return {
        "total_jobs": len(results),
        "run_attempted": len([r for r in results if r["run_status"] != "not_run_compile_failed"]),
        "normal_exit": labels.get("normal_exit", 0),
        "nonzero_exit": labels.get("nonzero_exit", 0),
        "signaled": statuses.get("signaled", 0),
        "timeout": statuses.get("timeout", 0),
        "sanitizer_output_observed": labels.get("sanitizer_output_observed", 0),
        "not_run_compile_failed": statuses.get("not_run_compile_failed", 0),
    }


def write_markdown(out_dir: Path, docs: dict[str, Any]) -> None:
    input_summary = docs["input_summary"]
    write_text(
        out_dir / "input" / "compile_run_input_summary.md",
        "# compile_run_v1 Input Summary\n\n"
        "- consumes: `compile_plan_v1`\n"
        "- real compile: `true`\n"
        "- real run: `true`\n"
        "- OpenSSL: ASan/UBSan install\n"
        "- analyze/triage: `false`\n"
        "- GLM: `false`\n"
        "- modifies harness/template/adapter: `false`\n\n"
        "## Inputs\n\n"
        + write_md_list(input_summary["inputs"]),
    )

    env = docs["environment"]
    write_text(
        out_dir / "environment" / "compile_run_environment.md",
        "# Compile/Run Environment\n\n"
        f"- install root: `{env['openssl_install']}`\n"
        f"- include dir: `{env['include_dir']}`\n"
        f"- lib dir: `{env['lib_dir']}`\n"
        f"- openssl binary: `{env['openssl_binary']}`\n"
        f"- OPENSSL_MODULES: `{env['openssl_modules']}`\n"
        f"- gcc: `{env['gcc']}`\n",
    )

    compile_results = docs["compile_results"]
    write_text(
        out_dir / "compile_results" / "compile_results.md",
        "# Compile Results\n\n"
        f"- total_jobs: `{compile_results['summary']['total_jobs']}`\n"
        f"- compile_success: `{compile_results['summary']['compile_success']}`\n"
        f"- compile_failed: `{compile_results['summary']['compile_failed']}`\n"
        f"- compile_skipped: `{compile_results['summary']['compile_skipped']}`\n",
    )

    run_results = docs["run_results"]
    write_text(
        out_dir / "run_results" / "run_results.md",
        "# Run Results\n\n"
        f"- run_attempted: `{run_results['summary']['run_attempted']}`\n"
        f"- normal_exit: `{run_results['summary']['normal_exit']}`\n"
        f"- nonzero_exit: `{run_results['summary']['nonzero_exit']}`\n"
        f"- signaled: `{run_results['summary']['signaled']}`\n"
        f"- timeout: `{run_results['summary']['timeout']}`\n"
        f"- sanitizer_output_observed: `{run_results['summary']['sanitizer_output_observed']}`\n",
    )

    sanitizer = docs["sanitizer"]
    write_text(
        out_dir / "sanitizer_observations" / "sanitizer_observations.md",
        "# Sanitizer Observations\n\n"
        f"- total_observations: `{sanitizer['summary']['total_observations']}`\n"
        f"- sanitizer_observed_count: `{sanitizer['summary']['sanitizer_observed_count']}`\n"
        f"- crash_signal_count: `{sanitizer['summary']['crash_signal_count']}`\n"
        f"- timeout_count: `{sanitizer['summary']['timeout_count']}`\n\n"
        "Raw observations only; no validated issue, CVE, or exploitability claim is made.\n",
    )

    blocked = docs["blocked"]
    write_text(
        out_dir / "blocked_cases" / "compile_run_blocked_cases.md",
        "# Compile/Run Blocked Cases\n\n"
        + write_md_list(
            [
                f"{item['family']} -> {item['target_library']}: compile_attempted={item['compile_attempted']} run_attempted={item['run_attempted']}"
                for item in blocked["blocked_cases"]
            ]
        ),
    )

    quality = docs["quality"]
    write_text(
        out_dir / "validation" / "compile_run_quality_checks.md",
        "# Compile/Run Quality Checks\n\n"
        f"- quality_status: `{quality['quality_status']}`\n"
        f"- compile_jobs_seen: `{quality['compile_jobs_seen']}`\n"
        f"- mbedtls_compile_attempted: `{quality['mbedtls_compile_attempted']}`\n"
        f"- mbedtls_run_attempted: `{quality['mbedtls_run_attempted']}`\n"
        f"- all_binaries_under_sprint: `{quality['all_binaries_under_sprint']}`\n"
        f"- all_logs_under_sprint: `{quality['all_logs_under_sprint']}`\n"
        f"- no_analysis_performed: `{quality['no_analysis_performed']}`\n",
    )

    next_action = docs["next_action"]
    write_text(
        out_dir / "reports" / "next_action_after_compile_run.md",
        "# Next Action After Compile Run\n\n"
        f"- next_task: `{next_action['next_task']}`\n"
        f"- reason: {next_action['reason']}\n",
    )

    report = docs["report"]
    write_text(
        out_dir / "reports" / "compile_run_v1_report.md",
        "# compile_run_v1 Report\n\n"
        f"- status: `{report['status']}`\n"
        f"- compile_jobs: `{report['summary']['compile_jobs']}`\n"
        f"- compile_success: `{report['summary']['compile_success']}`\n"
        f"- compile_failed: `{report['summary']['compile_failed']}`\n"
        f"- run_attempted: `{report['summary']['run_attempted']}`\n"
        f"- sanitizer_output_observed: `{report['summary']['sanitizer_output_observed']}`\n"
        f"- mbedtls_attempted: `{report['summary']['mbedtls_attempted']}`\n"
        f"- next_task: `{report['next_task']}`\n\n"
        "## Answers\n\n"
        + write_md_list(report["answers"]),
    )

    write_text(
        out_dir / "README.md",
        "# compile_run_v1\n\n"
        "This sprint compiles and runs the 14 rendered OpenSSL harnesses against the ASan/UBSan OpenSSL install.\n"
        "It records raw execution observations only and does not analyze or triage results.\n",
    )


def write_md_list(items: list[str]) -> str:
    return "".join(f"- {item}\n" for item in items) if items else "- none\n"


def all_under(path_values: list[str], root: Path) -> bool:
    root_abs = root.resolve()
    for value in path_values:
        if not value:
            continue
        try:
            Path(value).resolve().relative_to(root_abs)
        except ValueError:
            return False
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile and run compile_plan_v1 jobs.")
    parser.add_argument("--compile-plan", required=True)
    parser.add_argument("--compile-manifest", required=True)
    parser.add_argument("--rendered-case-index", required=True)
    parser.add_argument("--openssl-install", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    compile_plan_path = Path(args.compile_plan)
    compile_manifest_path = Path(args.compile_manifest)
    rendered_case_index_path = Path(args.rendered_case_index)
    openssl_install = Path(args.openssl_install)
    out_dir = Path(args.out_dir)
    timeout_seconds = args.timeout_seconds

    out_dir.mkdir(parents=True, exist_ok=True)
    plan = load_yaml(compile_plan_path)
    manifest = load_yaml(compile_manifest_path)
    rendered_index = load_yaml(rendered_case_index_path)
    jobs = [j for j in plan.get("compile_jobs", []) if j.get("target_library") == "openssl"]

    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    env_doc = {
        "schema": "compile_run_environment_v1",
        "generated_at": now_iso(),
        "openssl_install": rel(openssl_install),
        "include_dir": rel(include_dir),
        "include_dir_exists": include_dir.exists(),
        "lib_dir": rel(lib_dir),
        "lib_dir_exists": lib_dir.exists(),
        "openssl_binary": rel(openssl_install / "bin" / "openssl"),
        "openssl_binary_exists": (openssl_install / "bin" / "openssl").exists(),
        "openssl_modules": rel(lib_dir / "ossl-modules"),
        "openssl_modules_exists": (lib_dir / "ossl-modules").exists(),
        "gcc": shutil.which("gcc") or "",
        "timeout_seconds": timeout_seconds,
        "asan_options": "detect_leaks=0:abort_on_error=1:symbolize=1",
        "ubsan_options": "halt_on_error=1:print_stacktrace=1",
    }

    input_summary = {
        "schema": "compile_run_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": [
            rel(compile_plan_path),
            rel(compile_manifest_path),
            rel(rendered_case_index_path),
            rel(openssl_install),
        ],
        "scope": {
            "consumes_compile_plan_v1": True,
            "real_compile": True,
            "real_run": True,
            "uses_asan_ubsan_openssl": True,
            "analyze": False,
            "triage": False,
            "glm_called": False,
            "modifies_harness_template_adapter": False,
            "manifest_cases": len(manifest.get("cases", [])),
            "rendered_index_cases": len(rendered_index.get("cases", [])),
        },
    }

    compile_commands = []
    compile_results = []
    run_results = []
    observations = []
    for job in jobs:
        compile_job_id = job["compile_job_id"]
        binary = out_dir / "compiled_cases" / compile_job_id / "case.bin"
        command = command_for(Path(job["inputs"]["harness_c"]), binary, include_dir, lib_dir)
        compile_commands.append(
            {
                "compile_job_id": compile_job_id,
                "case_id": job["case_id"],
                "family": job["family"],
                "mutation_strategy": job["mutation_strategy"],
                "target_library": "openssl",
                "command": " ".join(command),
                "binary_path": rel(binary),
            }
        )
        c_result, r_result, observation = execute_job(
            job=job,
            out_dir=out_dir,
            include_dir=include_dir,
            lib_dir=lib_dir,
            install=openssl_install,
            timeout_seconds=timeout_seconds,
        )
        compile_results.append(c_result)
        run_results.append(r_result)
        observations.append(observation)

    compile_summary = summarize_compile(compile_results)
    run_summary = summarize_run(run_results)

    compile_results_doc = {
        "schema": "compile_results_v1",
        "generated_at": now_iso(),
        "compile_results": compile_results,
        "summary": compile_summary,
    }
    run_results_doc = {
        "schema": "run_results_v1",
        "generated_at": now_iso(),
        "run_results": run_results,
        "summary": run_summary,
    }
    sanitizer_doc = {
        "schema": "sanitizer_observations_v1",
        "generated_at": now_iso(),
        "observations": observations,
        "summary": {
            "total_observations": len(observations),
            "sanitizer_observed_count": len([o for o in observations if o["sanitizer_observed"]]),
            "crash_signal_count": len([r for r in run_results if r["signal"]]),
            "timeout_count": len([r for r in run_results if r["timeout"]]),
        },
    }
    blocked_doc = {
        "schema": "compile_run_blocked_cases_v1",
        "generated_at": now_iso(),
        "blocked_cases": [
            {
                "adapter_id": "asn1_nested_boundary_mbedtls",
                "family": "asn1_nested_boundary",
                "target_library": "mbedtls",
                "compile_attempted": False,
                "run_attempted": False,
                "reason": "blocked_expected / no rendered case / no compile job",
            }
        ],
    }

    output_paths = []
    for item in compile_results:
        output_paths.extend([item["binary_path"], item["stdout_log"], item["stderr_log"]])
    for item in run_results:
        output_paths.extend([item["stdout_log"], item["stderr_log"]])
    mbedtls_compile_attempted = len([r for r in compile_results if r["target_library"] == "mbedtls"])
    mbedtls_run_attempted = len([r for r in run_results if r["target_library"] == "mbedtls"])
    quality_conditions = [
        len(compile_results) == 14,
        mbedtls_compile_attempted == 0,
        mbedtls_run_attempted == 0,
        all(r["target_library"] == "openssl" for r in compile_results + run_results),
        all_under(output_paths, out_dir),
    ]
    quality_status = "pass" if all(quality_conditions) else ("partial" if compile_results else "fail")
    quality_doc = {
        "schema": "compile_run_quality_checks_v1",
        "expected_compile_jobs": 14,
        "compile_jobs_seen": len(compile_results),
        "compile_success": compile_summary["compile_success"],
        "compile_failed": compile_summary["compile_failed"],
        "run_attempted": run_summary["run_attempted"],
        "not_run_compile_failed": run_summary["not_run_compile_failed"],
        "mbedtls_compile_attempted": mbedtls_compile_attempted,
        "mbedtls_run_attempted": mbedtls_run_attempted,
        "all_jobs_target_openssl": all(r["target_library"] == "openssl" for r in compile_results + run_results),
        "all_binaries_under_sprint": all_under([r["binary_path"] for r in compile_results], out_dir),
        "all_logs_under_sprint": all_under(
            [r["stdout_log"] for r in compile_results + run_results]
            + [r["stderr_log"] for r in compile_results + run_results],
            out_dir,
        ),
        "no_input_files_modified": True,
        "no_adapter_files_modified": True,
        "no_template_files_modified": True,
        "no_glm_called": True,
        "no_analysis_performed": True,
        "quality_status": quality_status,
        "notes": [
            "Raw compile/run execution only.",
            "No vulnerability conclusion, CVE claim, exploitability claim, analysis, or triage is made.",
        ],
    }

    if mbedtls_compile_attempted or mbedtls_run_attempted:
        next_task = "compile_run_blocking_policy_fixup_v1"
        reason = "mbedTLS compile or run was attempted"
    elif compile_summary["compile_failed"] >= 8:
        next_task = "render_cases_compile_fixup_v1"
        reason = "most cases failed to compile"
    elif compile_summary["compile_success"] == 0:
        next_task = "compile_environment_fixup_v1"
        reason = "no cases compiled successfully; likely environment/link issue"
    elif run_summary["run_attempted"] > 0:
        next_task = "analyze_results_v1"
        reason = "at least one case ran and raw result files are complete"
    else:
        next_task = "render_cases_compile_fixup_v1"
        reason = "no run results available"

    next_action = {
        "schema": "next_action_after_compile_run_v1",
        "generated_at": now_iso(),
        "next_task": next_task,
        "reason": reason,
    }
    report = {
        "schema": "compile_run_v1_report",
        "generated_at": now_iso(),
        "status": quality_status,
        "summary": {
            "compile_jobs": len(compile_results),
            "compile_success": compile_summary["compile_success"],
            "compile_failed": compile_summary["compile_failed"],
            "compile_skipped": compile_summary["compile_skipped"],
            "run_attempted": run_summary["run_attempted"],
            "normal_exit": run_summary["normal_exit"],
            "nonzero_exit": run_summary["nonzero_exit"],
            "signaled": run_summary["signaled"],
            "timeout": run_summary["timeout"],
            "sanitizer_output_observed": run_summary["sanitizer_output_observed"],
            "mbedtls_attempted": bool(mbedtls_compile_attempted or mbedtls_run_attempted),
            "glm_called": False,
            "analysis_performed": False,
            "triage_performed": False,
        },
        "answers": [
            f"Compile jobs: {len(compile_results)}.",
            f"Compile success: {compile_summary['compile_success']}.",
            f"Compile failed: {compile_summary['compile_failed']}.",
            f"Run attempted: {run_summary['run_attempted']}.",
            f"normal/nonzero/signaled/timeout: {run_summary['normal_exit']}/{run_summary['nonzero_exit']}/{run_summary['signaled']}/{run_summary['timeout']}.",
            f"Sanitizer output observed: {run_summary['sanitizer_output_observed']}.",
            f"mbedTLS compile/run attempted: {bool(mbedtls_compile_attempted or mbedtls_run_attempted)}.",
            "GLM was not called.",
            "Analyze/triage was not performed.",
            f"Next task: {next_task}.",
        ],
        "next_task": next_task,
    }

    compile_commands_doc = {
        "schema": "compile_commands_v1",
        "generated_at": now_iso(),
        "compile_commands": compile_commands,
        "summary": {"total_commands": len(compile_commands)},
    }
    docs = {
        "input_summary": input_summary,
        "environment": env_doc,
        "compile_results": compile_results_doc,
        "run_results": run_results_doc,
        "sanitizer": sanitizer_doc,
        "blocked": blocked_doc,
        "quality": quality_doc,
        "next_action": next_action,
        "report": report,
    }

    dump_yaml(out_dir / "input" / "compile_run_input_summary.yaml", input_summary)
    dump_yaml(out_dir / "environment" / "compile_run_environment.yaml", env_doc)
    dump_yaml(out_dir / "compile_commands" / "compile_commands.yaml", compile_commands_doc)
    dump_yaml(out_dir / "compile_results" / "compile_results.yaml", compile_results_doc)
    dump_yaml(out_dir / "run_results" / "run_results.yaml", run_results_doc)
    dump_yaml(out_dir / "sanitizer_observations" / "sanitizer_observations.yaml", sanitizer_doc)
    dump_yaml(out_dir / "blocked_cases" / "compile_run_blocked_cases.yaml", blocked_doc)
    dump_yaml(out_dir / "validation" / "compile_run_quality_checks.yaml", quality_doc)
    dump_yaml(out_dir / "reports" / "next_action_after_compile_run.yaml", next_action)
    dump_yaml(out_dir / "reports" / "compile_run_v1_report.yaml", report)
    write_markdown(out_dir, docs)

    print(f"[OK] wrote compile/run artifacts to {out_dir}")
    print(
        "[SUMMARY] compile_success={compile_success} compile_failed={compile_failed} run_attempted={run_attempted} sanitizer={sanitizer}".format(
            compile_success=compile_summary["compile_success"],
            compile_failed=compile_summary["compile_failed"],
            run_attempted=run_summary["run_attempted"],
            sanitizer=run_summary["sanitizer_output_observed"],
        )
    )
    print(f"[NEXT] {next_task}")
    return 0 if quality_status in {"pass", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
