#!/usr/bin/env python3
"""Generate compile_plan_v1 from rendered OpenSSL cases.

This tool only plans compile jobs. It does not invoke gcc/clang, run binaries,
analyze results, call an LLM, or modify rendered harnesses.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


SPRINT_NAME = "compile_plan_v1"
ALLOWED_TARGET_LIBRARY = "openssl"
BLOCKED_ADAPTER_ID = "asn1_nested_boundary_mbedtls"


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


def rel(path: Path | str) -> str:
    return Path(path).as_posix()


def run_probe(args: list[str]) -> str:
    try:
        proc = subprocess.run(args, check=False, text=True, capture_output=True)
    except FileNotFoundError:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def path_list(paths: list[Path]) -> list[str]:
    return [rel(p) for p in paths if p.exists()]


def environment_inventory(openssl_root: Path) -> dict[str, Any]:
    install_root = openssl_root / "_install"
    include_candidates = [
        install_root / "include",
        openssl_root / "include",
        openssl_root / "apps" / "include",
    ]
    lib_candidates = [
        install_root / "lib64",
        install_root / "lib",
        openssl_root,
    ]
    return {
        "schema": "compile_environment_inventory_v1",
        "generated_at": now_iso(),
        "compilers": {
            "gcc": {"path": shutil.which("gcc") or "", "available": shutil.which("gcc") is not None},
            "clang": {"path": shutil.which("clang") or "", "available": shutil.which("clang") is not None},
        },
        "openssl": {
            "source_root": rel(openssl_root),
            "source_root_exists": openssl_root.exists(),
            "install_root": rel(install_root),
            "install_root_exists": install_root.exists(),
            "include_candidates": path_list(include_candidates),
            "lib_candidates": path_list(lib_candidates),
            "library_artifacts": path_list(
                [
                    install_root / "lib64" / "libcrypto.a",
                    install_root / "lib64" / "libssl.a",
                    install_root / "lib" / "libcrypto.a",
                    install_root / "lib" / "libssl.a",
                    openssl_root / "libcrypto.a",
                    openssl_root / "libssl.a",
                    openssl_root / "libcrypto.so",
                    openssl_root / "libssl.so",
                ]
            ),
        },
        "pkg_config": {
            "openssl_cflags": run_probe(["pkg-config", "--cflags", "openssl"]),
            "openssl_libs": run_probe(["pkg-config", "--libs", "openssl"]),
        },
        "notes": [
            "Environment inventory only; no compiler was invoked.",
            "OpenSSL paths are compile candidates for the next compile_run_v1 stage.",
        ],
    }


def compile_tool_inventory(out_dir: Path) -> dict[str, Any]:
    rg_file = out_dir / "compile_tool_inventory" / "compile_related_rg.txt"
    tooling_file = out_dir / "compile_tool_inventory" / "tooling_files.txt"
    rg_text = rg_file.read_text(encoding="utf-8") if rg_file.exists() else ""
    tooling_text = tooling_file.read_text(encoding="utf-8") if tooling_file.exists() else ""
    likely = []
    for candidate in ["runner/compile_run.py", "runner/analyze_results.py", "template_maker/render_cases.py"]:
        if Path(candidate).exists():
            likely.append(candidate)
    return {
        "schema": "compile_tool_inventory_v1",
        "generated_at": now_iso(),
        "existing_compile_run_tool_found": Path("runner/compile_run.py").exists(),
        "likely_compile_script": "runner/compile_run.py" if Path("runner/compile_run.py").exists() else "",
        "likely_next_wrapper": "tools/harness/compile_run_v1.py or runner.compile_run with compile_plan_v1 manifest",
        "candidate_tooling_files": likely,
        "raw_inventory_files": {
            "compile_related_rg": rel(rg_file),
            "tooling_files": rel(tooling_file),
        },
        "rg_match_count": len([line for line in rg_text.splitlines() if line.strip()]),
        "compile_executed": False,
        "run_executed": False,
        "notes": [
            "Inventory only; compile/run tooling was not invoked.",
            "compile_run_v1 should either wrap runner.compile_run or consume compile_plan_v1 directly.",
        ],
        "tooling_file_count": len([line for line in tooling_text.splitlines() if line.strip()]),
    }


def first_existing(paths: list[str]) -> str:
    for p in paths:
        if p and Path(p).exists():
            return p
    return ""


def command_template(
    harness_c: str,
    binary_path: str,
    include_dirs: list[str],
    library_dirs: list[str],
    libraries: list[str],
    extra_cflags: list[str],
    extra_ldflags: list[str],
) -> str:
    inc = " ".join(f"-I{p}" for p in include_dirs)
    lib_dirs = " ".join(f"-L{p}" for p in library_dirs)
    libs = " ".join(f"-l{lib}" for lib in libraries)
    cflags = " ".join(extra_cflags)
    ldflags = " ".join(extra_ldflags)
    return f"${{CC:-gcc}} {cflags} {inc} {harness_c} -o {binary_path} {lib_dirs} {libs} {ldflags}".strip()


def build_compile_jobs(
    case_index: dict[str, Any],
    out_dir: Path,
    env: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    include_dirs = env["openssl"]["include_candidates"] or []
    library_dirs = env["openssl"]["lib_candidates"] or []
    jobs: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for case in case_index.get("cases", []):
        if case.get("target_library") != ALLOWED_TARGET_LIBRARY:
            blocked.append(
                {
                    "adapter_id": case.get("base_adapter", ""),
                    "family": case.get("family"),
                    "target_library": case.get("target_library"),
                    "blocked_reason": "target_library_not_openssl",
                    "compile_allowed": False,
                    "run_allowed": False,
                    "source": "rendered_case_index",
                }
            )
            continue
        if case.get("render_status") != "rendered":
            blocked.append(
                {
                    "adapter_id": case.get("base_adapter", ""),
                    "family": case.get("family"),
                    "target_library": case.get("target_library"),
                    "blocked_reason": "case_not_rendered",
                    "compile_allowed": False,
                    "run_allowed": False,
                    "source": "rendered_case_index",
                }
            )
            continue

        render_job_id = case["render_job_id"]
        compile_job_id = f"compile__{render_job_id.removeprefix('render__')}"
        build_dir = out_dir / "planned_build" / compile_job_id
        binary_path = build_dir / "case.bin"
        compile_stdout = build_dir / "compile.stdout.log"
        compile_stderr = build_dir / "compile.stderr.log"
        compile_metadata = build_dir / "compile_metadata.yaml"
        build_meta = load_yaml(Path(case["build_metadata"]))
        oracle_meta = load_yaml(Path(case["oracle_metadata"]))
        libraries = build_meta.get("expected_libraries") or ["crypto", "ssl"]
        extra_cflags = ["-Wall", "-Wextra", "-O0", "-g"]
        extra_ldflags: list[str] = []
        job = {
            "compile_job_id": compile_job_id,
            "render_job_id": render_job_id,
            "case_id": case["case_id"],
            "family": case["family"],
            "target_library": "openssl",
            "mutation_strategy": case["mutation_strategy"],
            "inputs": {
                "case_dir": case["case_dir"],
                "harness_c": case["harness_c"],
                "build_metadata": case["build_metadata"],
                "oracle_metadata": case["oracle_metadata"],
                "case_metadata": case["case_metadata"],
                "render_trace": case["render_trace"],
            },
            "planned_outputs": {
                "build_dir": rel(build_dir),
                "binary_path": rel(binary_path),
                "compile_stdout": rel(compile_stdout),
                "compile_stderr": rel(compile_stderr),
                "compile_metadata": rel(compile_metadata),
            },
            "compile_command_plan": {
                "compiler_preference": "gcc",
                "include_dirs": include_dirs,
                "library_dirs": library_dirs,
                "libraries": libraries,
                "extra_cflags": extra_cflags,
                "extra_ldflags": extra_ldflags,
                "command_template": command_template(
                    harness_c=case["harness_c"],
                    binary_path=rel(binary_path),
                    include_dirs=include_dirs,
                    library_dirs=library_dirs,
                    libraries=libraries,
                    extra_cflags=extra_cflags,
                    extra_ldflags=extra_ldflags,
                ),
            },
            "compile_policy": {
                "compile_allowed_next_stage": True,
                "compile_now": False,
                "run_now": False,
            },
            "safety_policy": {
                "target_library_must_be_openssl": True,
                "no_mbedtls": True,
                "no_run_now": True,
                "no_confirmed_vulnerability_claim": True,
            },
            "expected_result_label": oracle_meta.get("expected_result_label", ""),
            "risk_notes": [
                "Compile command is planned only.",
                "Candidate mapping only; no vulnerability claim.",
            ],
        }
        jobs.append(job)
    return jobs, blocked


def md_list(items: list[str]) -> str:
    return "".join(f"- {item}\n" for item in items) if items else "- none\n"


def write_markdown(out_dir: Path, docs: dict[str, Any]) -> None:
    input_summary = docs["input_summary"]
    write_text(
        out_dir / "input" / "compile_plan_input_summary.md",
        "# compile_plan_v1 Input Summary\n\n"
        "- consumes: `render_cases_v1`\n"
        "- output: compile plan only\n"
        "- compile: `false`\n"
        "- run: `false`\n"
        "- target scope: `OpenSSL only`\n"
        "- mbedTLS compile jobs: `false`\n"
        "- GLM called: `false`\n\n"
        "## Inputs\n\n"
        + md_list(input_summary["inputs"]),
    )

    inv = docs["tool_inventory"]
    write_text(
        out_dir / "compile_tool_inventory" / "compile_tool_inventory.md",
        "# Compile Tool Inventory\n\n"
        f"- existing compile/run tool found: `{inv['existing_compile_run_tool_found']}`\n"
        f"- likely compile script: `{inv['likely_compile_script']}`\n"
        f"- next wrapper suggestion: `{inv['likely_next_wrapper']}`\n"
        f"- compile executed: `{inv['compile_executed']}`\n"
        f"- run executed: `{inv['run_executed']}`\n",
    )

    env = docs["environment"]
    write_text(
        out_dir / "environment_inventory" / "compile_environment_inventory.md",
        "# Compile Environment Inventory\n\n"
        f"- gcc: `{env['compilers']['gcc']['path']}` available={env['compilers']['gcc']['available']}\n"
        f"- clang: `{env['compilers']['clang']['path']}` available={env['compilers']['clang']['available']}\n"
        f"- OpenSSL source root: `{env['openssl']['source_root']}` exists={env['openssl']['source_root_exists']}\n"
        f"- OpenSSL install root: `{env['openssl']['install_root']}` exists={env['openssl']['install_root_exists']}\n"
        f"- pkg-config cflags: `{env['pkg_config']['openssl_cflags']}`\n"
        f"- pkg-config libs: `{env['pkg_config']['openssl_libs']}`\n\n"
        "## Include Candidates\n\n"
        + md_list(env["openssl"]["include_candidates"])
        + "\n## Library Candidates\n\n"
        + md_list(env["openssl"]["lib_candidates"]),
    )

    plan = docs["compile_plan"]
    rows = ["| compile_job_id | family | mutation_strategy | target |", "|---|---|---|---|"]
    for job in plan["compile_jobs"]:
        rows.append(
            f"| {job['compile_job_id']} | {job['family']} | {job['mutation_strategy']} | {job['target_library']} |"
        )
    write_text(
        out_dir / "compile_plan" / "compile_plan.md",
        "# Compile Plan\n\n"
        f"- total_compile_jobs: `{plan['summary']['total_compile_jobs']}`\n"
        f"- target_libraries: `{plan['summary']['target_libraries']}`\n"
        "- compile_now: `false`\n\n"
        + "\n".join(rows)
        + "\n",
    )

    manifest = docs["manifest"]
    write_text(
        out_dir / "compile_manifest" / "compile_manifest.md",
        "# Compile Manifest\n\n"
        f"- total_cases: `{manifest['summary']['total_cases']}`\n"
        f"- pkcs_cases: `{manifest['summary']['pkcs_cases']}`\n"
        f"- asn1_cases: `{manifest['summary']['asn1_cases']}`\n"
        "- compile_status: `planned_only`\n",
    )

    preflight = docs["preflight"]
    write_text(
        out_dir / "preflight" / "compile_preflight_plan.md",
        "# Compile Preflight Plan\n\n"
        f"- total_checks: `{preflight['summary']['total_checks']}`\n"
        "- expected_status: `preflight_pending`\n"
        "- required_files: harness, build/oracle/case metadata, render trace\n"
        "- required_environment: compiler, OpenSSL include, OpenSSL library\n",
    )

    blocked = docs["blocked"]
    write_text(
        out_dir / "blocked_cases" / "blocked_compile_cases.md",
        "# Blocked Compile Cases\n\n"
        + md_list(
            [
                f"{item['family']} -> {item['target_library']}: compile_allowed={item['compile_allowed']} reason={item['blocked_reason']}"
                for item in blocked["blocked"]
            ]
        ),
    )

    quality = docs["quality"]
    write_text(
        out_dir / "validation" / "compile_plan_quality_checks.md",
        "# Compile Plan Quality Checks\n\n"
        f"- quality_status: `{quality['quality_status']}`\n"
        f"- total_compile_jobs: `{quality['total_compile_jobs']}`\n"
        f"- pkcs_jobs: `{quality['pkcs_jobs']}`\n"
        f"- asn1_jobs: `{quality['asn1_jobs']}`\n"
        f"- mbedtls_jobs: `{quality['mbedtls_jobs']}`\n"
        f"- no_binary_created: `{quality['no_binary_created']}`\n"
        f"- no_compile_executed: `{quality['no_compile_executed']}`\n"
        f"- no_run_executed: `{quality['no_run_executed']}`\n",
    )

    next_action = docs["next_action"]
    write_text(
        out_dir / "reports" / "next_action_after_compile_plan.md",
        "# Next Action After Compile Plan\n\n"
        f"- next_task: `{next_action['next_task']}`\n"
        f"- reason: {next_action['reason']}\n",
    )

    report = docs["report"]
    write_text(
        out_dir / "reports" / "compile_plan_v1_report.md",
        "# compile_plan_v1 Report\n\n"
        f"- status: `{report['status']}`\n"
        f"- compile_jobs: `{report['summary']['compile_jobs']}`\n"
        f"- pkcs_jobs: `{report['summary']['pkcs_jobs']}`\n"
        f"- asn1_jobs: `{report['summary']['asn1_jobs']}`\n"
        f"- mbedtls_jobs: `{report['summary']['mbedtls_jobs']}`\n"
        f"- compile_executed: `false`\n"
        f"- run_executed: `false`\n"
        f"- openssl_environment_usable: `{report['summary']['openssl_environment_usable']}`\n"
        f"- next_task: `{report['next_task']}`\n\n"
        "## Answers\n\n"
        + md_list(report["answers"]),
    )

    write_text(
        out_dir / "README.md",
        "# compile_plan_v1\n\n"
        "This sprint creates compile jobs for rendered OpenSSL cases. It does not compile or run anything.\n\n"
        "## Outputs\n\n"
        + md_list(
            [
                "compile_plan/compile_plan.yaml",
                "compile_manifest/compile_manifest.yaml",
                "preflight/compile_preflight_plan.yaml",
                "validation/compile_plan_quality_checks.yaml",
                "reports/compile_plan_v1_report.yaml",
            ]
        ),
    )


def build_manifest(jobs: list[dict[str, Any]]) -> dict[str, Any]:
    cases = []
    for job in jobs:
        oracle_meta = load_yaml(Path(job["inputs"]["oracle_metadata"]))
        cases.append(
            {
                "compile_job_id": job["compile_job_id"],
                "case_id": job["case_id"],
                "family": job["family"],
                "target_library": job["target_library"],
                "mutation_strategy": job["mutation_strategy"],
                "harness_c": job["inputs"]["harness_c"],
                "planned_binary": job["planned_outputs"]["binary_path"],
                "compile_status": "planned_only",
                "dependencies": {
                    "build_metadata": job["inputs"]["build_metadata"],
                    "oracle_metadata": job["inputs"]["oracle_metadata"],
                    "case_metadata": job["inputs"]["case_metadata"],
                    "render_trace": job["inputs"]["render_trace"],
                },
                "expected_oracle": {
                    "primary": oracle_meta.get("primary_oracle"),
                    "secondary": oracle_meta.get("secondary_oracles", []),
                    "expected_result_label": oracle_meta.get("expected_result_label"),
                },
            }
        )
    return {
        "schema": "compile_manifest_v1",
        "generated_at": now_iso(),
        "cases": cases,
        "summary": {
            "total_cases": len(cases),
            "pkcs_cases": len([c for c in cases if c["family"] == "pkcs_container_parsing"]),
            "asn1_cases": len([c for c in cases if c["family"] == "asn1_nested_boundary"]),
        },
    }


def build_preflight(jobs: list[dict[str, Any]], env: dict[str, Any]) -> dict[str, Any]:
    compiler_available = env["compilers"]["gcc"]["available"] or env["compilers"]["clang"]["available"]
    include_available = bool(env["openssl"]["include_candidates"])
    library_available = bool(env["openssl"]["library_artifacts"] or env["openssl"]["lib_candidates"])
    checks = []
    for job in jobs:
        required_files = [
            job["inputs"]["harness_c"],
            job["inputs"]["build_metadata"],
            job["inputs"]["oracle_metadata"],
            job["inputs"]["case_metadata"],
            job["inputs"]["render_trace"],
        ]
        checks.append(
            {
                "compile_job_id": job["compile_job_id"],
                "case_id": job["case_id"],
                "required_files": required_files,
                "required_files_exist": all(Path(p).exists() for p in required_files),
                "required_environment": {
                    "compiler_available": compiler_available,
                    "openssl_include_available": include_available,
                    "openssl_library_available": library_available,
                },
                "required_policy": {
                    "target_library": "openssl",
                    "no_mbedtls": True,
                    "compile_now": False,
                    "run_now": False,
                },
                "expected_status": "preflight_pending",
            }
        )
    return {
        "schema": "compile_preflight_plan_v1",
        "generated_at": now_iso(),
        "checks": checks,
        "summary": {"total_checks": len(checks)},
    }


def quality(jobs: list[dict[str, Any]], preflight: dict[str, Any]) -> dict[str, Any]:
    planned_binaries = [Path(job["planned_outputs"]["binary_path"]) for job in jobs]
    q = {
        "schema": "compile_plan_quality_checks_v1",
        "total_compile_jobs": len(jobs),
        "expected_compile_jobs": 14,
        "pkcs_jobs": len([j for j in jobs if j["family"] == "pkcs_container_parsing"]),
        "asn1_jobs": len([j for j in jobs if j["family"] == "asn1_nested_boundary"]),
        "mbedtls_jobs": len([j for j in jobs if j["target_library"] == "mbedtls"]),
        "only_rendered_cases_included": True,
        "all_jobs_have_harness_c": all(Path(j["inputs"]["harness_c"]).exists() for j in jobs),
        "all_jobs_have_build_metadata": all(Path(j["inputs"]["build_metadata"]).exists() for j in jobs),
        "all_jobs_have_oracle_metadata": all(Path(j["inputs"]["oracle_metadata"]).exists() for j in jobs),
        "all_jobs_have_case_metadata": all(Path(j["inputs"]["case_metadata"]).exists() for j in jobs),
        "all_jobs_have_binary_path": all(bool(j["planned_outputs"]["binary_path"]) for j in jobs),
        "all_jobs_compile_now_false": all(j["compile_policy"]["compile_now"] is False for j in jobs),
        "all_jobs_run_now_false": all(j["compile_policy"]["run_now"] is False for j in jobs),
        "no_binary_created": not any(p.exists() for p in planned_binaries),
        "no_compile_executed": True,
        "no_run_executed": True,
        "no_glm_called": True,
        "notes": [
            "Compile plan only; no binary should exist yet.",
            "Preflight remains pending for compile_run_v1.",
        ],
    }
    pass_conditions = [
        q["total_compile_jobs"] == 14,
        q["pkcs_jobs"] == 7,
        q["asn1_jobs"] == 7,
        q["mbedtls_jobs"] == 0,
        q["all_jobs_have_harness_c"],
        q["all_jobs_have_build_metadata"],
        q["all_jobs_have_oracle_metadata"],
        q["all_jobs_have_case_metadata"],
        q["all_jobs_have_binary_path"],
        q["all_jobs_compile_now_false"],
        q["all_jobs_run_now_false"],
        q["no_binary_created"],
        q["no_compile_executed"],
        q["no_run_executed"],
        q["no_glm_called"],
    ]
    q["quality_status"] = "pass" if all(pass_conditions) else ("partial" if jobs else "fail")
    return q


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate compile_plan_v1 artifacts.")
    parser.add_argument("--rendered-case-index", required=True)
    parser.add_argument("--render-cases-root", required=True)
    parser.add_argument("--render-quality", required=True)
    parser.add_argument("--adapter-validate-results", required=True)
    parser.add_argument("--openssl-root", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rendered_case_index_path = Path(args.rendered_case_index)
    render_cases_root = Path(args.render_cases_root)
    render_quality_path = Path(args.render_quality)
    adapter_validate_path = Path(args.adapter_validate_results)
    openssl_root = Path(args.openssl_root)

    case_index = load_yaml(rendered_case_index_path)
    render_quality = load_yaml(render_quality_path)
    adapter_validate = load_yaml(adapter_validate_path)
    env = environment_inventory(openssl_root)
    tool_inv = compile_tool_inventory(out_dir)
    jobs, blocked_from_cases = build_compile_jobs(case_index, out_dir, env)

    blocked = {
        "schema": "blocked_compile_cases_v1",
        "generated_at": now_iso(),
        "blocked": blocked_from_cases
        + [
            {
                "adapter_id": BLOCKED_ADAPTER_ID,
                "family": "asn1_nested_boundary",
                "target_library": "mbedtls",
                "blocked_reason": "blocked_expected; not rendered; not allowed in compile_plan_v1",
                "compile_allowed": False,
                "run_allowed": False,
                "source": "render_cases_v1/blocked_cases/render_blocked_cases.yaml",
            }
        ],
        "notes": [
            "Blocked mbedTLS adapter remains outside compile jobs.",
            "No mbedTLS binary path is planned.",
        ],
    }

    compile_plan = {
        "schema": "compile_plan_v1",
        "generated_at": now_iso(),
        "compile_jobs": jobs,
        "summary": {
            "total_compile_jobs": len(jobs),
            "families": sorted(set(job["family"] for job in jobs)),
            "target_libraries": sorted(set(job["target_library"] for job in jobs)),
        },
    }
    manifest = build_manifest(jobs)
    preflight = build_preflight(jobs, env)
    q = quality(jobs, preflight)

    env_usable = (
        (env["compilers"]["gcc"]["available"] or env["compilers"]["clang"]["available"])
        and bool(env["openssl"]["include_candidates"])
        and bool(env["openssl"]["library_artifacts"] or env["openssl"]["lib_candidates"])
    )
    if q["mbedtls_jobs"] > 0:
        next_task = "compile_plan_blocking_policy_fixup_v1"
        reason = "mbedTLS compile job was planned"
    elif not (
        q["all_jobs_have_harness_c"]
        and q["all_jobs_have_build_metadata"]
        and q["all_jobs_have_oracle_metadata"]
        and q["all_jobs_have_case_metadata"]
    ):
        next_task = "compile_plan_dependency_fixup_v1"
        reason = "one or more compile jobs lacks harness or metadata"
    elif not env_usable:
        next_task = "compile_environment_setup_v1"
        reason = "OpenSSL compile environment is missing compiler/include/library candidates"
    else:
        next_task = "compile_run_v1"
        reason = "compile plan has 14 rendered OpenSSL jobs and environment candidates are present"

    next_action = {
        "schema": "next_action_after_compile_plan_v1",
        "generated_at": now_iso(),
        "next_task": next_task,
        "reason": reason,
    }

    input_summary = {
        "schema": "compile_plan_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": [
            rel(rendered_case_index_path),
            rel(render_cases_root),
            rel(render_quality_path),
            rel(adapter_validate_path),
            rel(openssl_root),
            "artifacts/sprints/render_plan_v1/render_plan/render_plan.yaml",
            "artifacts/sprints/render_plan_v1/case_manifest/case_manifest.yaml",
            "artifacts/sprints/render_plan_v1/preflight/render_preflight_plan.yaml",
        ],
        "scope": {
            "consumes_render_cases_v1": True,
            "compile_plan_only": True,
            "compile_executed": False,
            "run_executed": False,
            "target_scope": "OpenSSL only",
            "blocked_mbedtls_cases_excluded": True,
            "glm_called": False,
        },
        "render_quality_status": render_quality.get("quality_status"),
        "adapter_validation_summary": adapter_validate.get("summary", {}),
    }

    report = {
        "schema": "compile_plan_v1_report",
        "generated_at": now_iso(),
        "status": q["quality_status"],
        "summary": {
            "compile_plan_generated": True,
            "compile_jobs": len(jobs),
            "pkcs_jobs": q["pkcs_jobs"],
            "asn1_jobs": q["asn1_jobs"],
            "mbedtls_jobs": q["mbedtls_jobs"],
            "compile_executed": False,
            "run_executed": False,
            "openssl_environment_usable": env_usable,
        },
        "answers": [
            "Compile plan generated.",
            f"Compile jobs: {len(jobs)}.",
            f"PKCS jobs: {q['pkcs_jobs']}.",
            f"ASN.1 jobs: {q['asn1_jobs']}.",
            f"mbedTLS jobs: {q['mbedtls_jobs']}.",
            "Compile was not executed.",
            "Run was not executed.",
            f"OpenSSL environment usable: {env_usable}.",
            f"Next task: {next_task}.",
        ],
        "next_task": next_task,
    }

    docs = {
        "input_summary": input_summary,
        "tool_inventory": tool_inv,
        "environment": env,
        "compile_plan": compile_plan,
        "manifest": manifest,
        "preflight": preflight,
        "blocked": blocked,
        "quality": q,
        "next_action": next_action,
        "report": report,
    }

    dump_yaml(out_dir / "input" / "compile_plan_input_summary.yaml", input_summary)
    dump_yaml(out_dir / "compile_tool_inventory" / "compile_tool_inventory.yaml", tool_inv)
    dump_yaml(out_dir / "environment_inventory" / "compile_environment_inventory.yaml", env)
    dump_yaml(out_dir / "compile_plan" / "compile_plan.yaml", compile_plan)
    dump_yaml(out_dir / "compile_manifest" / "compile_manifest.yaml", manifest)
    dump_yaml(out_dir / "preflight" / "compile_preflight_plan.yaml", preflight)
    dump_yaml(out_dir / "blocked_cases" / "blocked_compile_cases.yaml", blocked)
    dump_yaml(out_dir / "validation" / "compile_plan_quality_checks.yaml", q)
    dump_yaml(out_dir / "reports" / "next_action_after_compile_plan.yaml", next_action)
    dump_yaml(out_dir / "reports" / "compile_plan_v1_report.yaml", report)
    write_markdown(out_dir, docs)

    print(f"[OK] wrote compile plan artifacts to {out_dir}")
    print(f"[SUMMARY] compile_jobs={len(jobs)} quality={q['quality_status']} env_usable={env_usable}")
    print(f"[NEXT] {next_task}")
    return 0 if q["quality_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
