"""Reusable family-level compile/run execution helpers.

The functions here are intentionally small and schema-preserving so sprint
wrappers can keep their CLI/report layout while sharing execution mechanics.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from runner.run_records import (
    classify_raw_observation,
    compile_result_record,
    run_result_record,
    sanitizer_observation_record,
)
from runner.sanitizer_env import (
    lib_dir_for_install,
    matched_keywords,
    rel,
    run_env,
    sanitizer_kinds,
    signal_name,
)


OracleParser = Callable[[str, dict[str, Any]], list[dict[str, Any]]]


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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


def execute_compile_plan_job(
    job: dict[str, Any],
    out_dir: Path,
    include_dir: Path,
    lib_dir: Path,
    install: Path,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    compile_job_id = str(job["compile_job_id"])
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
    if job.get("target_library") != "openssl":
        compile_status = "compile_skipped_collision"
        compile_notes.append("non-openssl job blocked before compile")
        write_text(compile_stdout, "")
        write_text(compile_stderr, "blocked: non-openssl target\n")
    elif binary.exists():
        compile_status = "compile_skipped_collision"
        compile_notes.append("binary already exists; not overwritten")
        write_text(compile_stdout, "")
        write_text(compile_stderr, "collision: binary already exists\n")
    elif not harness.exists():
        compile_status = "compile_failed"
        compile_notes.append("missing harness.c")
        write_text(compile_stdout, "")
        write_text(compile_stderr, "missing harness.c\n")
    else:
        proc = subprocess.run(compile_cmd, text=True, capture_output=True)
        compile_returncode = proc.returncode
        write_text(compile_stdout, proc.stdout)
        write_text(compile_stderr, proc.stderr)
        compile_status = compile_status_for(proc.returncode, binary)

    compile_result = compile_result_record(
        case=job,
        harness=harness,
        binary=binary,
        compile_command=compile_command_str,
        compile_status=compile_status,
        compile_stdout=compile_stdout,
        compile_stderr=compile_stderr,
        return_code=compile_returncode,
        notes=compile_notes,
        include_compile_job_id=True,
    )

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
            run_notes.append(f"timeout after {timeout_seconds} seconds")
    else:
        write_text(run_stdout, "")
        write_text(run_stderr, "")
        run_notes.append("not run because compile did not succeed")

    stdout_text = run_stdout.read_text(encoding="utf-8", errors="replace") if run_stdout.exists() else ""
    stderr_text = run_stderr.read_text(encoding="utf-8", errors="replace") if run_stderr.exists() else ""
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

    run_result = run_result_record(
        case=job,
        binary=binary,
        run_status=run_status,
        exit_code=exit_code if exit_code is not None and exit_code >= 0 else None,
        signal=sig,
        timeout=timed_out,
        duration_seconds=duration,
        run_stdout=run_stdout,
        run_stderr=run_stderr,
        sanitizer_observed=sanitizer_seen,
        sanitizer_kinds=kinds,
        raw_observation_label=raw_label,
        notes=run_notes,
        include_compile_job_id=True,
    )
    observation = sanitizer_observation_record(
        case=job,
        sanitizer_observed=sanitizer_seen,
        sanitizer_kinds=kinds,
        matched_keywords=keys,
        stderr_log=run_stderr,
        combined_output=combined,
        include_compile_job_id=True,
    )
    return compile_result, run_result, observation


def execute_instrumented_case(
    case: dict[str, Any],
    out_dir: Path,
    include_dir: Path,
    lib_dir: Path,
    openssl_install: Path,
    timeout_seconds: int,
    parse_oracle_events: OracleParser,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    case_id = str(case.get("case_id") or "")
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
    if case.get("target_library") != "openssl":
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

    case_for_record = dict(case)
    case_for_record.setdefault("compile_job_id", case_id)
    compile_result = compile_result_record(
        case=case_for_record,
        harness=harness,
        binary=binary,
        compile_command=compile_command,
        compile_status=compile_status,
        compile_stdout=compile_stdout,
        compile_stderr=compile_stderr,
        return_code=compile_returncode,
        notes=compile_notes,
        include_compile_job_id=False,
    )

    run_status = "not_run_compile_failed"
    exit_code: int | None = None
    sig = ""
    timed_out = False
    duration = 0.0
    if compile_status == "compile_success":
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [binary.resolve().as_posix()],
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                env=run_env(openssl_install, lib_dir),
                cwd=harness.parent,
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
    events = parse_oracle_events(combined, case)
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
    run_result = run_result_record(
        case=case_for_record,
        binary=binary,
        run_status=run_status,
        exit_code=exit_code,
        signal=sig,
        timeout=timed_out,
        duration_seconds=duration,
        run_stdout=run_stdout,
        run_stderr=run_stderr,
        sanitizer_observed=sanitizer_seen,
        sanitizer_kinds=kinds,
        raw_observation_label=raw_label,
        oracle_event_count=len(events),
        include_compile_job_id=False,
    )
    sanitizer_observation = sanitizer_observation_record(
        case=case_for_record,
        sanitizer_observed=sanitizer_seen,
        sanitizer_kinds=kinds,
        matched_keywords=keywords,
        stderr_log=run_stderr,
        combined_output=combined,
        include_compile_job_id=False,
    )
    return compile_result, run_result, events, sanitizer_observation


def openssl_runtime_info(openssl_install: Path) -> dict[str, Any]:
    lib_dir = lib_dir_for_install(openssl_install)
    env = run_env(openssl_install, lib_dir)
    openssl_bin = openssl_install / "bin" / "openssl"
    fallback_reason = ""
    asan_available = False
    version = ""
    path = openssl_bin
    if openssl_bin.exists():
        proc = subprocess.run(
            [openssl_bin.as_posix(), "version"],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if proc.returncode == 0:
            asan_available = True
            version = proc.stdout.strip()
        else:
            fallback_reason = (proc.stderr or proc.stdout or "ASAN OpenSSL probe failed").strip()
            path = Path("/usr/bin/openssl")
            proc = subprocess.run([path.as_posix(), "version"], text=True, capture_output=True, check=False)
            version = proc.stdout.strip() if proc.returncode == 0 else ""
    else:
        fallback_reason = f"{openssl_bin} not found"
        path = Path("/usr/bin/openssl")
        proc = subprocess.run([path.as_posix(), "version"], text=True, capture_output=True, check=False)
        version = proc.stdout.strip() if proc.returncode == 0 else ""
    return {
        "openssl_install": openssl_install.as_posix(),
        "openssl_path": path.as_posix(),
        "openssl_version": version,
        "asan_openssl_available": asan_available,
        "fallback_reason": fallback_reason,
        "ld_library_path": env.get("LD_LIBRARY_PATH", ""),
        "openssl_modules": env.get("OPENSSL_MODULES", ""),
        "asan_options": env.get("ASAN_OPTIONS", ""),
        "ubsan_options": env.get("UBSAN_OPTIONS", ""),
    }


def execute_rendered_case_index(
    *,
    repo_root: Path,
    rendered_index: dict[str, Any],
    out_dir: Path,
    openssl_install: Path,
    timeout_seconds: int,
    parse_oracle_events: OracleParser,
) -> dict[str, Any]:
    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    compile_results = []
    run_results = []
    sanitizer_observations = []
    oracle_events = []
    for case in rendered_index.get("cases", []) or []:
        normalized = dict(case)
        normalized["harness_c"] = (repo_root / str(case.get("harness_c", ""))).as_posix()
        compile_result, run_result, events, sanitizer_observation = execute_instrumented_case(
            normalized,
            out_dir,
            include_dir,
            lib_dir,
            openssl_install,
            timeout_seconds,
            parse_oracle_events,
        )
        compile_results.append(compile_result)
        run_results.append(run_result)
        sanitizer_observations.append(sanitizer_observation)
        oracle_events.extend(events)
    compile_success = len([item for item in compile_results if item.get("compile_status") == "compile_success"])
    run_attempted = len([item for item in run_results if item.get("run_status") != "not_run_compile_failed"])
    normal_exit = len(
        [
            item
            for item in run_results
            if item.get("run_status") == "exited" and int(item.get("exit_code") or 0) == 0
        ]
    )
    nonzero_exit = len(
        [
            item
            for item in run_results
            if item.get("run_status") == "exited" and int(item.get("exit_code") or 0) != 0
        ]
    )
    return {
        "schema": "pkey_compile_run_results_v1",
        "openssl": openssl_runtime_info(openssl_install),
        "compile_results": compile_results,
        "run_results": run_results,
        "sanitizer_observations": sanitizer_observations,
        "oracle_events": oracle_events,
        "summary": {
            "rendered_cases": len(rendered_index.get("cases", []) or []),
            "compile_success": compile_success,
            "compile_failed": len(compile_results) - compile_success,
            "run_attempted": run_attempted,
            "normal_exit": normal_exit,
            "nonzero_exit": nonzero_exit,
            "crash_signals": len([item for item in run_results if item.get("signal")]),
            "timeout": len([item for item in run_results if item.get("timeout")]),
            "asan_observed": len(
                [item for item in sanitizer_observations if "asan" in (item.get("sanitizer_kinds") or [])]
            ),
            "ubsan_observed": len(
                [item for item in sanitizer_observations if "ubsan" in (item.get("sanitizer_kinds") or [])]
            ),
            "oracle_events": len(oracle_events),
        },
    }
