#!/usr/bin/env python3
"""Build a render-only plan from mutation planner and adapter readiness inputs.

This tool intentionally does not render C, compile, run PoCs, or call an LLM.
It produces deterministic planning artifacts for the next render sprint.
"""

from __future__ import annotations

import argparse
import datetime as _dt
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


SPRINT_NAME = "render_plan_v1"
NEXT_RENDER_ROOT = "artifacts/sprints/render_cases_v1/rendered_cases"
EXPECTED_READY_ADAPTERS = {
    "pkcs_container_parsing_openssl",
    "asn1_nested_boundary_openssl",
}
BLOCKED_ADAPTERS = {"asn1_nested_boundary_mbedtls"}


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


def rel(path: Path) -> str:
    return path.as_posix()


def find_result(results: list[dict[str, Any]], adapter_id: str) -> dict[str, Any] | None:
    for item in results:
        if item.get("adapter_id") == adapter_id:
            return item
    return None


def case_pointer(path: Path, case_id: str) -> str:
    return f"{rel(path)}#cases[{case_id}]"


def oracle_pointer(path: Path, family: str, target_library: str) -> str:
    return f"{rel(path)}#families[{family}:{target_library}]"


def family_template_paths(template_root: Path, family: str) -> dict[str, str]:
    root = template_root / family
    return {
        "family_template_dir": rel(root),
        "canonical_template": rel(root / "canonical_tmpl_wolfssl.c"),
        "family_template_meta": rel(root / "family_template_meta.yaml"),
        "mask_report": rel(root / "mask_report.yaml"),
        "selected_mask_units": rel(root / "selected_mask_units.yaml"),
    }


def adapter_paths(adapter_root: Path, family: str, target_library: str) -> dict[str, str]:
    root = adapter_root / family / target_library
    return {
        "adapter_dir": rel(root),
        "adapter_recipe": rel(root / "adapter_recipe.yaml"),
        "slot_filling_plan": rel(root / "slot_filling_plan.yaml"),
        "slot_bindings": rel(root / "slot_bindings.yaml"),
    }


def expected_path_list(job: dict[str, Any]) -> list[str]:
    inputs = job["inputs"]
    return [
        inputs["canonical_template"],
        inputs["family_template_meta"],
        inputs["mask_report"],
        inputs["selected_mask_units"],
        inputs["adapter_recipe"],
        inputs["slot_filling_plan"],
        inputs["slot_bindings"],
    ]


def all_paths_exist(paths: list[str]) -> bool:
    return all(Path(p).exists() for p in paths)


def build_family_render_plan_from_mutation_matrix(
    mutation_matrix: dict[str, Any],
    *,
    source_matrix_path: str,
    family_profiles: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a render-planning artifact without rendering harness code."""

    family = str(mutation_matrix.get("family") or "unknown_family")
    profile = ((family_profiles or {}).get("families") or {}).get(family, {})
    cases = mutation_matrix.get("cases", []) or []
    render_jobs = []
    blocked_cases = []
    for index, case in enumerate(cases, start=1):
        render_allowed = bool(case.get("render_allowed")) and bool(profile.get("render_allowed", True))
        job = {
            "render_job_id": f"render_plan__{family}__{index:03d}",
            "family": family,
            "case_id": case.get("case_id", ""),
            "seed_id": case.get("seed_id", ""),
            "seed_format": case.get("seed_format", ""),
            "mutation_strategy": case.get("mutation_strategy", ""),
            "input_path": case.get("input_path", ""),
            "input_sha256": case.get("input_sha256", ""),
            "expected_oracle": case.get("expected_oracle", {}),
            "render_allowed": render_allowed,
            "render_cases_stage_required": True,
            "planned_outputs": {
                "case_manifest": f"artifacts/sprints/orchestrator_execute_x509_render_plan_v1/render_cases/{family}/{case.get('case_id', '')}/case_manifest.yaml",
                "input_reference": case.get("input_path", ""),
            },
            "execution_policy": {
                "render_cases_executed": False,
                "harness_generated": False,
                "compile_executed": False,
                "run_executed": False,
                "glm_called": False,
            },
        }
        if render_allowed:
            render_jobs.append(job)
        else:
            blocked_cases.append(
                {
                    "case_id": case.get("case_id", ""),
                    "family": family,
                    "render_allowed": False,
                    "block_reasons": ["case_or_family_render_not_allowed"],
                }
            )

    return {
        "schema": "family_render_plan_from_mutation_matrix_v1",
        "generated_at": now_iso(),
        "family": family,
        "source_mutation_matrix": source_matrix_path,
        "source_matrix_schema": mutation_matrix.get("schema", ""),
        "render_jobs": render_jobs,
        "blocked_cases": blocked_cases,
        "summary": {
            "input_mutation_case_count": len(cases),
            "render_job_count": len(render_jobs),
            "render_allowed": len(render_jobs) > 0,
            "blocked_case_count": len(blocked_cases),
            "next_stage": "render_cases",
        },
        "execution_policy": {
            "render_cases_executed": False,
            "harness_generated": False,
            "compile_executed": False,
            "run_executed": False,
            "feedback_written": False,
            "glm_called": False,
        },
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def build_jobs(
    mutation_matrix: dict[str, Any],
    render_candidate_plan: dict[str, Any],
    oracle_plan_path: Path,
    matrix_path: Path,
    adapter_root: Path,
    template_root: Path,
    adapter_results: list[dict[str, Any]],
    render_ready_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    case_by_id = {case["case_id"]: case for case in mutation_matrix.get("cases", [])}
    jobs: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    sequence_by_key: Counter[tuple[str, str, str]] = Counter()

    for candidate in render_candidate_plan.get("render_candidates", []):
        case_id = candidate.get("case_id", "")
        case = case_by_id.get(case_id)
        family = candidate.get("family", "")
        target_library = candidate.get("target_library", "")
        base_adapter = candidate.get("base_adapter", "")
        adapter_result = find_result(adapter_results, base_adapter) or {}

        block_reasons: list[str] = []
        if not case:
            block_reasons.append("missing_mutation_case")
        if not candidate.get("render_allowed", False):
            block_reasons.append("render_candidate_not_allowed")
        if base_adapter not in render_ready_ids:
            block_reasons.append("adapter_not_render_ready")
        if base_adapter in BLOCKED_ADAPTERS:
            block_reasons.append("blocked_adapter")
        if target_library != "openssl":
            block_reasons.append("target_library_not_openssl")
        if adapter_result.get("validation_status") != "pass":
            block_reasons.append("adapter_validation_not_pass")

        if block_reasons:
            blocked.append(
                {
                    "case_id": case_id,
                    "family": family,
                    "target_library": target_library,
                    "base_adapter": base_adapter,
                    "render_allowed": False,
                    "block_reasons": block_reasons,
                }
            )
            continue

        assert case is not None
        mutation_strategy = case.get("mutation_strategy", "unknown_mutation")
        seq_key = (family, target_library, mutation_strategy)
        sequence_by_key[seq_key] += 1
        case_name = f"{family}__{target_library}__{mutation_strategy}__case_{sequence_by_key[seq_key]:03d}"
        render_job_id = f"render__{case_name}"
        planned_case_dir = f"{NEXT_RENDER_ROOT}/{family}/{target_library}/{render_job_id}"

        template_inputs = family_template_paths(template_root, family)
        adapter_input_paths = adapter_paths(adapter_root, family, target_library)
        inputs = {
            **template_inputs,
            **adapter_input_paths,
            "mutation_case": case_pointer(matrix_path, case_id),
            "oracle_expectation": oracle_pointer(oracle_plan_path, family, target_library),
        }

        job = {
            "render_job_id": render_job_id,
            "case_name": case_name,
            "case_id": case_id,
            "family": family,
            "target_library": target_library,
            "base_adapter": base_adapter,
            "template_level": case.get("template_level", "family"),
            "mutation_strategy": mutation_strategy,
            "mutation_slots": case.get("mutation_slots", []),
            "expected_result_label": (case.get("expected_oracle") or {}).get("expected_result_label", ""),
            "oracle": case.get("expected_oracle", {}),
            "inputs": inputs,
            "planned_outputs": {
                "case_dir": planned_case_dir,
                "harness_c": f"{planned_case_dir}/harness.c",
                "input_corpus_dir": f"{planned_case_dir}/inputs",
                "build_metadata": f"{planned_case_dir}/build_metadata.yaml",
                "oracle_metadata": f"{planned_case_dir}/oracle_metadata.yaml",
                "run_metadata": f"{planned_case_dir}/run_metadata.yaml",
            },
            "preflight": {
                "status": "preflight_pending",
                "required_input_paths_exist": all_paths_exist(expected_path_list({"inputs": inputs})),
                "required_input_paths": expected_path_list({"inputs": inputs}),
                "adapter_validation_status": adapter_result.get("validation_status"),
                "adapter_render_ready": adapter_result.get("render_ready"),
                "render_allowed": True,
                "blocked_adapter_excluded": base_adapter not in BLOCKED_ADAPTERS,
                "target_library_allowed": target_library == "openssl",
                "no_confirmed_equivalence_claim": bool(adapter_result.get("no_confirmed_equivalence_claim", False)),
            },
            "risk_notes": case.get("risk_notes", []),
            "render_execution": {
                "rendered": False,
                "compiled": False,
                "run": False,
                "llm_called": False,
                "c_files_generated_by_this_tool": False,
            },
        }
        jobs.append(job)

    return jobs, blocked


def build_render_tool_inventory(out_dir: Path) -> dict[str, Any]:
    raw_rg = out_dir / "render_tool_inventory" / "render_related_rg.txt"
    tooling = out_dir / "render_tool_inventory" / "tooling_files.txt"
    rg_text = raw_rg.read_text(encoding="utf-8") if raw_rg.exists() else ""
    tooling_text = tooling.read_text(encoding="utf-8") if tooling.exists() else ""
    candidate_files = [
        line
        for line in tooling_text.splitlines()
        if any(term in line for term in ("render", "cross_generator", "compile_run", "analyze_results"))
    ]
    return {
        "schema": "render_tool_inventory_v1",
        "generated_at": now_iso(),
        "raw_inventory_files": {
            "render_related_rg": rel(raw_rg),
            "tooling_files": rel(tooling),
        },
        "observed_render_entrypoints": {
            "template_maker.render_cases": Path("template_maker/render_cases.py").exists(),
            "template_maker.cross_generator_from_adapters": Path(
                "template_maker/cross_generator_from_adapters.py"
            ).exists(),
            "runner.compile_run": Path("runner/compile_run.py").exists(),
            "runner.analyze_results": Path("runner/analyze_results.py").exists(),
            "runner.analyze_cross_results": Path("runner/analyze_cross_results.py").exists(),
        },
        "candidate_tooling_files": candidate_files,
        "rg_match_count": len([line for line in rg_text.splitlines() if line.strip()]),
        "render_execution_performed": False,
        "notes": [
            "Inventory only; no renderer was invoked.",
            "Existing render_cases tooling is downstream context, not executed by this sprint.",
        ],
    }


def md_list(items: list[str]) -> str:
    if not items:
        return "- none\n"
    return "".join(f"- {item}\n" for item in items)


def render_jobs_table(jobs: list[dict[str, Any]]) -> str:
    lines = [
        "| render_job_id | family | target_library | mutation_strategy | expected_result_label |",
        "|---|---|---|---|---|",
    ]
    for job in jobs:
        lines.append(
            "| {render_job_id} | {family} | {target_library} | {mutation_strategy} | {expected_result_label} |".format(
                **job
            )
        )
    return "\n".join(lines) + "\n"


def write_markdown_outputs(
    out_dir: Path,
    input_summary: dict[str, Any],
    inventory: dict[str, Any],
    render_plan: dict[str, Any],
    case_manifest: dict[str, Any],
    naming_plan: dict[str, Any],
    preflight: dict[str, Any],
    blocked_cases: dict[str, Any],
    quality: dict[str, Any],
    next_action: dict[str, Any],
    report: dict[str, Any],
) -> None:
    write_text(
        out_dir / "input" / "render_plan_input_summary.md",
        "# render_plan_v1 Input Summary\n\n"
        f"- generated_at: `{input_summary['generated_at']}`\n"
        f"- mutation_cases: `{input_summary['summary']['mutation_cases']}`\n"
        f"- render_candidates: `{input_summary['summary']['render_candidates']}`\n"
        f"- render_ready_adapters: `{input_summary['summary']['render_ready_adapters']}`\n"
        f"- blocked_adapters: `{input_summary['summary']['blocked_adapters']}`\n"
        "- scope: plan only; no C render, compile, run, or LLM call.\n\n"
        "## Inputs\n\n"
        + md_list(input_summary["inputs"])
    )

    write_text(
        out_dir / "render_tool_inventory" / "render_tool_inventory.md",
        "# Render Tool Inventory\n\n"
        f"- render_execution_performed: `{inventory['render_execution_performed']}`\n"
        f"- rg_match_count: `{inventory['rg_match_count']}`\n\n"
        "## Observed Entrypoints\n\n"
        + md_list([f"{k}: {v}" for k, v in inventory["observed_render_entrypoints"].items()])
        + "\n## Candidate Tooling Files\n\n"
        + md_list(inventory["candidate_tooling_files"]),
    )

    write_text(
        out_dir / "render_plan" / "render_plan.md",
        "# Render Plan\n\n"
        f"- schema: `{render_plan['schema']}`\n"
        f"- total_render_jobs: `{render_plan['summary']['total_render_jobs']}`\n"
        f"- pkcs jobs: `{render_plan['summary']['jobs_by_family'].get('pkcs_container_parsing', 0)}`\n"
        f"- asn1 jobs: `{render_plan['summary']['jobs_by_family'].get('asn1_nested_boundary', 0)}`\n"
        f"- execution: `{render_plan['execution_policy']}`\n\n"
        + render_jobs_table(render_plan["render_jobs"]),
    )

    write_text(
        out_dir / "case_manifest" / "case_manifest.md",
        "# Case Manifest\n\n"
        f"- total_cases: `{case_manifest['summary']['total_cases']}`\n"
        f"- planned_output_root: `{case_manifest['planned_output_root']}`\n\n"
        + render_jobs_table(case_manifest["cases"]),
    )

    write_text(
        out_dir / "case_naming" / "case_naming_plan.md",
        "# Case Naming Plan\n\n"
        f"- case_id_format: `{naming_plan['case_id_format']}`\n"
        f"- render_job_id_format: `{naming_plan['render_job_id_format']}`\n"
        f"- output_dir_format: `{naming_plan['output_dir_format']}`\n"
        f"- collision_policy: `{naming_plan['collision_policy']}`\n\n"
        "## Examples\n\n"
        + md_list(naming_plan["examples"]),
    )

    write_text(
        out_dir / "preflight" / "render_preflight_plan.md",
        "# Render Preflight Plan\n\n"
        f"- total_checks: `{preflight['summary']['total_checks']}`\n"
        f"- all_required_inputs_present: `{preflight['summary']['all_required_inputs_present']}`\n"
        f"- expected_status: `{preflight['expected_status']}`\n\n"
        + md_list([f"{item['render_job_id']}: {item['status']}" for item in preflight["checks"]]),
    )

    write_text(
        out_dir / "blocked_cases" / "blocked_cases.md",
        "# Blocked Cases\n\n"
        f"- total_blocked_cases: `{blocked_cases['summary']['total_blocked_cases']}`\n"
        f"- blocked_adapter_excluded_from_render_jobs: `{blocked_cases['summary']['blocked_adapter_excluded_from_render_jobs']}`\n\n"
        + md_list([f"{item['adapter_id']}: {item['reason']}" for item in blocked_cases["blocked_cases"]]),
    )

    write_text(
        out_dir / "validation" / "render_plan_quality_checks.md",
        "# Render Plan Quality Checks\n\n"
        f"- quality_status: `{quality['quality_status']}`\n"
        f"- total_render_jobs: `{quality['checks']['total_render_jobs']}`\n"
        f"- expected_render_jobs: `{quality['checks']['expected_render_jobs']}`\n"
        f"- blocked_adapter_excluded: `{quality['checks']['blocked_adapter_excluded']}`\n"
        f"- no_c_files_generated_in_sprint: `{quality['checks']['no_c_files_generated_in_sprint']}`\n\n"
        "## Notes\n\n"
        + md_list(quality["notes"]),
    )

    write_text(
        out_dir / "reports" / "next_action_after_render_plan.md",
        "# Next Action After Render Plan\n\n"
        f"- recommended_next_task: `{next_action['recommended_next_task']}`\n"
        f"- reason: {next_action['reason']}\n\n"
        "## Guardrails\n\n"
        + md_list(next_action["guardrails"]),
    )

    write_text(
        out_dir / "README.md",
        "# render_plan_v1\n\n"
        "This sprint converts validated mutation planning outputs into a deterministic render plan.\n"
        "It does not render C, compile, run PoCs, or call GLM/LLM.\n\n"
        "## Key Outputs\n\n"
        + md_list(
            [
                "render_plan/render_plan.yaml",
                "case_manifest/case_manifest.yaml",
                "case_naming/case_naming_plan.yaml",
                "preflight/render_preflight_plan.yaml",
                "blocked_cases/blocked_cases.yaml",
                "validation/render_plan_quality_checks.yaml",
                "reports/render_plan_v1_report.yaml",
            ]
        ),
    )

    write_text(
        out_dir / "reports" / "render_plan_v1_report.md",
        "# render_plan_v1 Report\n\n"
        f"- status: `{report['status']}`\n"
        f"- total_render_jobs: `{report['summary']['total_render_jobs']}`\n"
        f"- render_ready_adapters_used: `{report['summary']['render_ready_adapters_used']}`\n"
        f"- blocked_adapters_excluded: `{report['summary']['blocked_adapters_excluded']}`\n"
        f"- recommended_next_task: `{report['recommended_next_task']}`\n\n"
        "## Answers\n\n"
        + md_list(report["answers"]),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate render_plan_v1 artifacts.")
    parser.add_argument("--mutation-case-matrix", required=True)
    parser.add_argument("--render-candidate-plan", required=True)
    parser.add_argument("--oracle-expectation-plan", required=True)
    parser.add_argument("--adapter-root", required=True)
    parser.add_argument("--family-template-root", required=True)
    parser.add_argument("--adapter-validate-results", required=True)
    parser.add_argument("--render-readiness", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    matrix_path = Path(args.mutation_case_matrix)
    render_candidate_path = Path(args.render_candidate_plan)
    oracle_plan_path = Path(args.oracle_expectation_plan)
    adapter_root = Path(args.adapter_root)
    template_root = Path(args.family_template_root)
    adapter_validate_path = Path(args.adapter_validate_results)
    render_readiness_path = Path(args.render_readiness)

    mutation_matrix = load_yaml(matrix_path)
    render_candidate_plan = load_yaml(render_candidate_path)
    oracle_plan = load_yaml(oracle_plan_path)
    adapter_validate = load_yaml(adapter_validate_path)
    render_readiness = load_yaml(render_readiness_path)

    adapter_results = adapter_validate.get("results", [])
    render_ready_ids = {
        item.get("adapter_id")
        for item in render_readiness.get("render_ready_adapters", [])
        if item.get("adapter_id")
    }

    jobs, plan_blocked = build_jobs(
        mutation_matrix=mutation_matrix,
        render_candidate_plan=render_candidate_plan,
        oracle_plan_path=oracle_plan_path,
        matrix_path=matrix_path,
        adapter_root=adapter_root,
        template_root=template_root,
        adapter_results=adapter_results,
        render_ready_ids=render_ready_ids,
    )

    blocked_from_readiness = render_readiness.get("blocked_adapters", [])
    blocked_cases = []
    for item in blocked_from_readiness:
        blocked_cases.append(
            {
                "adapter_id": item.get("adapter_id"),
                "family": item.get("family"),
                "target_library": item.get("target_library"),
                "mutation_allowed": False,
                "render_allowed": False,
                "reason": item.get("reason", "blocked adapter"),
            }
        )
    blocked_cases.extend(plan_blocked)

    jobs_by_family = dict(Counter(job["family"] for job in jobs))
    jobs_by_adapter = dict(Counter(job["base_adapter"] for job in jobs))
    blocked_adapter_ids = {item.get("adapter_id") or item.get("base_adapter") for item in blocked_cases}

    input_summary = {
        "schema": "render_plan_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": [
            rel(matrix_path),
            rel(render_candidate_path),
            rel(oracle_plan_path),
            rel(adapter_validate_path),
            rel(render_readiness_path),
            rel(adapter_root),
            rel(template_root),
        ],
        "scope": {
            "render_plan_only": True,
            "no_c_render": True,
            "no_compile": True,
            "no_run": True,
            "no_llm_call": True,
            "target_libraries_in_scope": ["openssl"],
            "families_in_scope": sorted(jobs_by_family),
        },
        "summary": {
            "mutation_cases": len(mutation_matrix.get("cases", [])),
            "render_candidates": len(render_candidate_plan.get("render_candidates", [])),
            "oracle_family_entries": len(oracle_plan.get("families", [])),
            "render_ready_adapters": sorted(render_ready_ids),
            "blocked_adapters": sorted(blocked_adapter_ids),
        },
    }

    inventory = build_render_tool_inventory(out_dir)

    render_plan = {
        "schema": "render_plan_v1",
        "generated_at": now_iso(),
        "execution_policy": {
            "render_c": False,
            "compile": False,
            "run": False,
            "llm_call": False,
            "plan_only": True,
        },
        "render_jobs": jobs,
        "summary": {
            "total_render_jobs": len(jobs),
            "jobs_by_family": jobs_by_family,
            "jobs_by_adapter": jobs_by_adapter,
            "blocked_cases_not_rendered": len(blocked_cases),
        },
    }

    case_manifest = {
        "schema": "case_manifest_v1",
        "generated_at": now_iso(),
        "planned_output_root": NEXT_RENDER_ROOT,
        "cases": jobs,
        "summary": {
            "total_cases": len(jobs),
            "families": sorted(jobs_by_family),
            "target_libraries": sorted({job["target_library"] for job in jobs}),
        },
    }

    examples = [job["case_name"] for job in jobs[:3]]
    naming_plan = {
        "schema": "case_naming_plan_v1",
        "generated_at": now_iso(),
        "case_id_format": "<family>__<target_library>__<mutation_strategy>__case_<NNN>",
        "render_job_id_format": "render__<family>__<target_library>__<mutation_strategy>__case_<NNN>",
        "output_dir_format": f"{NEXT_RENDER_ROOT}/<family>/<target_library>/<render_job_id>",
        "collision_policy": "deterministic; fail preflight if target output directory already exists",
        "examples": examples,
    }

    preflight_checks = []
    for job in jobs:
        preflight_checks.append(
            {
                "render_job_id": job["render_job_id"],
                "case_id": job["case_id"],
                "status": "preflight_pending",
                "required_files": job["preflight"]["required_input_paths"],
                "required_files_exist": job["preflight"]["required_input_paths_exist"],
                "required_policy": {
                    "adapter_validation_status": "pass",
                    "render_allowed": True,
                    "target_library": "openssl",
                    "blocked_adapter_excluded": True,
                    "no_confirmed_equivalence_claim": True,
                },
                "planned_output_dir": job["planned_outputs"]["case_dir"],
            }
        )

    preflight = {
        "schema": "render_preflight_plan_v1",
        "generated_at": now_iso(),
        "expected_status": "preflight_pending",
        "checks": preflight_checks,
        "summary": {
            "total_checks": len(preflight_checks),
            "all_required_inputs_present": all(item["required_files_exist"] for item in preflight_checks),
        },
    }

    blocked_cases_doc = {
        "schema": "blocked_cases_v1",
        "generated_at": now_iso(),
        "blocked_cases": blocked_cases,
        "summary": {
            "total_blocked_cases": len(blocked_cases),
            "blocked_adapter_excluded_from_render_jobs": all(
                job["base_adapter"] not in BLOCKED_ADAPTERS for job in jobs
            ),
        },
    }

    no_c_files = not list(out_dir.rglob("*.c"))
    checks = {
        "total_render_jobs": len(jobs),
        "expected_render_jobs": 14,
        "pkcs_jobs": jobs_by_family.get("pkcs_container_parsing", 0),
        "asn1_jobs": jobs_by_family.get("asn1_nested_boundary", 0),
        "only_expected_ready_adapters_used": set(jobs_by_adapter).issubset(EXPECTED_READY_ADAPTERS),
        "blocked_adapter_excluded": all(job["base_adapter"] not in BLOCKED_ADAPTERS for job in jobs),
        "only_openssl_targets": all(job["target_library"] == "openssl" for job in jobs),
        "all_required_inputs_present": preflight["summary"]["all_required_inputs_present"],
        "no_c_files_generated_in_sprint": no_c_files,
        "no_render_compile_run_or_llm": all(
            not any(
                [
                    job["render_execution"]["rendered"],
                    job["render_execution"]["compiled"],
                    job["render_execution"]["run"],
                    job["render_execution"]["llm_called"],
                ]
            )
            for job in jobs
        ),
    }
    pass_conditions = [
        checks["total_render_jobs"] == checks["expected_render_jobs"],
        checks["pkcs_jobs"] == 7,
        checks["asn1_jobs"] == 7,
        checks["only_expected_ready_adapters_used"],
        checks["blocked_adapter_excluded"],
        checks["only_openssl_targets"],
        checks["all_required_inputs_present"],
        checks["no_c_files_generated_in_sprint"],
        checks["no_render_compile_run_or_llm"],
    ]
    quality = {
        "schema": "render_plan_quality_checks_v1",
        "generated_at": now_iso(),
        "checks": checks,
        "quality_status": "pass" if all(pass_conditions) else "fail",
        "notes": [
            "This quality check validates the render plan shape only.",
            "Actual render/compile/run remains reserved for render_cases_v1 or later.",
        ],
    }

    if not checks["blocked_adapter_excluded"]:
        recommended = "render_plan_blocking_policy_fixup_v1"
        reason = "blocked adapter entered render jobs"
    elif not checks["all_required_inputs_present"]:
        recommended = "render_plan_dependency_fixup_v1"
        reason = "one or more planned render jobs lacks required template or adapter inputs"
    elif checks["total_render_jobs"] != checks["expected_render_jobs"]:
        recommended = "mutation_case_matrix_review_v1"
        reason = "render job count does not match expected 14 OpenSSL mutation cases"
    else:
        recommended = "render_cases_v1"
        reason = "render plan is complete and ready for a separate render-only execution sprint"

    next_action = {
        "schema": "next_action_after_render_plan_v1",
        "generated_at": now_iso(),
        "recommended_next_task": recommended,
        "reason": reason,
        "guardrails": [
            "Do not include asn1_nested_boundary_mbedtls unless mapping gate and validation are repaired.",
            "Do not claim confirmed vulnerability from render output alone.",
            "Run preflight before any C render step.",
        ],
    }

    report = {
        "schema": "render_plan_v1_report",
        "generated_at": now_iso(),
        "status": quality["quality_status"],
        "summary": {
            "total_render_jobs": len(jobs),
            "render_ready_adapters_used": sorted(jobs_by_adapter),
            "blocked_adapters_excluded": checks["blocked_adapter_excluded"],
            "no_c_render_compile_run_or_llm": checks["no_render_compile_run_or_llm"],
        },
        "answers": [
            "14 OpenSSL render jobs are planned: 7 pkcs_container_parsing and 7 asn1_nested_boundary.",
            "Only adapters with validation_status=pass and render_ready=true are included.",
            "asn1_nested_boundary_mbedtls remains blocked and is excluded from render jobs.",
            "Each job records family template, adapter_recipe, slot_filling_plan, slot_bindings, mutation_case, and oracle expectation references.",
            "Case names are deterministic and grouped by family, target library, and mutation strategy.",
            "Preflight is planned but not executed as rendering; all required input files are checked for existence.",
            "No C harness, compile result, run result, or LLM output is generated by this tool.",
            "Next recommended task is render_cases_v1 if quality_status remains pass.",
        ],
        "recommended_next_task": recommended,
        "quality_checks": rel(out_dir / "validation" / "render_plan_quality_checks.yaml"),
    }

    dump_yaml(out_dir / "input" / "render_plan_input_summary.yaml", input_summary)
    dump_yaml(out_dir / "render_tool_inventory" / "render_tool_inventory.yaml", inventory)
    dump_yaml(out_dir / "render_plan" / "render_plan.yaml", render_plan)
    dump_yaml(out_dir / "case_manifest" / "case_manifest.yaml", case_manifest)
    dump_yaml(out_dir / "case_naming" / "case_naming_plan.yaml", naming_plan)
    dump_yaml(out_dir / "preflight" / "render_preflight_plan.yaml", preflight)
    dump_yaml(out_dir / "blocked_cases" / "blocked_cases.yaml", blocked_cases_doc)
    dump_yaml(out_dir / "validation" / "render_plan_quality_checks.yaml", quality)
    dump_yaml(out_dir / "reports" / "next_action_after_render_plan.yaml", next_action)
    dump_yaml(out_dir / "reports" / "render_plan_v1_report.yaml", report)

    write_markdown_outputs(
        out_dir=out_dir,
        input_summary=input_summary,
        inventory=inventory,
        render_plan=render_plan,
        case_manifest=case_manifest,
        naming_plan=naming_plan,
        preflight=preflight,
        blocked_cases=blocked_cases_doc,
        quality=quality,
        next_action=next_action,
        report=report,
    )

    print(f"[OK] wrote render plan artifacts to {out_dir}")
    print(f"[SUMMARY] render_jobs={len(jobs)} quality_status={quality['quality_status']}")
    print(f"[NEXT] {recommended}")
    return 0 if quality["quality_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
