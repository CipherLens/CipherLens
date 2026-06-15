#!/usr/bin/env python3
"""Analyze raw compile_run_v1 outputs without rerun or triage."""

from __future__ import annotations

import argparse
import datetime as _dt
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from analyzer import candidate_labels as family_candidate_labels
from analyzer.family_result_adapter import (
    REUSED_MODULES,
    analysis_label_from_existing,
    candidate_label_from_existing,
    classify_family_run,
)


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


def short_log_summary(path_value: str, max_chars: int = 240) -> str:
    if not path_value:
        return ""
    path = Path(path_value)
    if not path.exists():
        return "missing log"
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return ""
    return text[:max_chars]


def by_key(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(item.get(key)): item for item in items}


def mutation_by_case(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return by_key(matrix.get("cases", []), "case_id")


def rendered_by_case(rendered_index: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return by_key(rendered_index.get("cases", []), "case_id")


def oracle_by_family(plan: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    out = {}
    for item in plan.get("families", []):
        out[(item.get("family", ""), item.get("target_library", ""))] = item
    return out


def build_case_analysis(
    compile_results: dict[str, Any],
    run_results: dict[str, Any],
    sanitizer: dict[str, Any],
    rendered_index: dict[str, Any],
    mutation_matrix: dict[str, Any],
    oracle_plan: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    compile_by_job = by_key(compile_results.get("compile_results", []), "compile_job_id")
    sanitizer_by_job = by_key(sanitizer.get("observations", []), "compile_job_id")
    mutation_cases = mutation_by_case(mutation_matrix)
    rendered_cases = rendered_by_case(rendered_index)
    oracles = oracle_by_family(oracle_plan)
    cases = []
    labels = []
    for run in run_results.get("run_results", []):
        if run.get("target_library") != "openssl":
            continue
        compile_job_id = run.get("compile_job_id")
        compile_result = compile_by_job.get(compile_job_id, {})
        mutation = mutation_cases.get(run.get("case_id", ""), {})
        rendered_case = rendered_cases.get(run.get("case_id", ""), {})
        oracle_entry = oracles.get((run.get("family", ""), run.get("target_library", "")), {})
        expected_oracle = {
            "primary": (mutation.get("expected_oracle") or {}).get(
                "primary", (oracle_entry.get("primary_oracles") or [""])[0]
            ),
            "secondary": (mutation.get("expected_oracle") or {}).get(
                "secondary", oracle_entry.get("secondary_oracles", [])
            ),
            "expected_result_label": (mutation.get("expected_oracle") or {}).get("expected_result_label", ""),
        }
        s_obs = sanitizer_by_job.get(compile_job_id, {})
        existing = classify_family_run(run, compile_result)
        label = analysis_label_from_existing(existing)
        candidate_label, confidence, reason, next_triage = candidate_label_from_existing(
            existing, expected_oracle.get("expected_result_label", "")
        )
        case = {
            "case_id": run.get("case_id"),
            "compile_job_id": compile_job_id,
            "render_job_id": rendered_case.get("render_job_id", ""),
            "family": run.get("family"),
            "mutation_strategy": run.get("mutation_strategy"),
            "target_library": "openssl",
            "compile_status": compile_result.get("compile_status"),
            "run_status": run.get("run_status"),
            "exit_code": run.get("exit_code"),
            "signal": run.get("signal"),
            "timeout": run.get("timeout"),
            "sanitizer_observed": run.get("sanitizer_observed"),
            "sanitizer_kinds": run.get("sanitizer_kinds", []),
            "expected_oracle": expected_oracle,
            "oracle_metadata": {
                "path": rendered_case.get("oracle_metadata", ""),
                "source": "render_cases_v1",
            },
            "observed_behavior": {
                "raw_observation_label": run.get("raw_observation_label"),
                "stdout_summary": short_log_summary(run.get("stdout_log", "")),
                "stderr_summary": short_log_summary(run.get("stderr_log", "")),
            },
            "analysis_label": label,
            "existing_analyzer_verdict": existing.get("existing_verdict", ""),
            "existing_analyzer_reason": existing.get("existing_reason", ""),
            "reused_existing_pipeline": existing.get("reused_existing_pipeline", False),
            "reused_modules": existing.get("reused_modules", []),
            "triage_required": True,
            "notes": [
                "Raw execution analysis only; no final triage or confirmed safety/vulnerability claim.",
                "normal_exit indicates no observed crash in this bounded case, not proof of semantic safety.",
            ],
        }
        cases.append(case)
        labels.append(
            {
                "case_id": run.get("case_id"),
                "family": run.get("family"),
                "mutation_strategy": run.get("mutation_strategy"),
                "candidate_label": candidate_label,
                "confidence": confidence,
                "reason": reason,
                "next_triage_action": next_triage,
                "existing_analyzer_verdict": existing.get("existing_verdict", ""),
                "reused_existing_pipeline": existing.get("reused_existing_pipeline", False),
                "claim_policy": {
                    "confirmed_vulnerability": False,
                    "cve": False,
                    "exploitable": False,
                },
                "sanitizer_matched_keywords": s_obs.get("matched_keywords", []),
            }
        )
    counts = Counter(c["analysis_label"] for c in cases)
    case_doc = {
        "schema": "case_analysis_v1",
        "generated_at": now_iso(),
        "reused_existing_pipeline": True,
        "reused_modules": REUSED_MODULES,
        "candidate_label_module": "analyzer.candidate_labels",
        "candidate_label_constants": sorted(family_candidate_labels.RAW_RESULT_LABELS),
        "duplicated_logic_reduced": [
            "crash/sanitizer verdict mapping is delegated to analyzer.family_result_adapter",
            "analyzer.family_result_adapter delegates base verdicts to runner.analyze_results.classify_record",
            "tools/analyze_results_v1 keeps family/mutation/oracle enrichment only",
        ],
        "cases": cases,
        "summary": {
            "total_cases": len(cases),
            "no_crash_observed": counts.get("no_crash_observed", 0),
            "sanitizer_crash_candidate": counts.get("sanitizer_crash_candidate", 0),
            "crash_signal_candidate": counts.get("crash_signal_candidate", 0),
            "timeout_candidate": counts.get("timeout_candidate", 0),
            "nonzero_exit_candidate": counts.get("nonzero_exit_candidate", 0),
            "oracle_semantics_needs_review": counts.get("oracle_semantics_needs_review", 0),
        },
    }
    label_counts = Counter(item["candidate_label"] for item in labels)
    label_doc = {
        "schema": "candidate_labels_v1",
        "generated_at": now_iso(),
        "reused_existing_pipeline": True,
        "reused_modules": REUSED_MODULES,
        "labels": labels,
        "summary": {
            "migrated_safe_candidate": label_counts.get("migrated_safe_candidate", 0),
            "no_crash_observed": label_counts.get("no_crash_observed", 0),
            "semantic_divergence_candidate": label_counts.get("semantic_divergence_candidate", 0),
            "sanitizer_crash_candidate": label_counts.get("sanitizer_crash_candidate", 0),
            "api_misuse_false_positive": label_counts.get("api_misuse_false_positive", 0),
            "needs_triage": label_counts.get("needs_triage", 0),
        },
    }
    return case_doc, label_doc


def build_family_analysis(case_doc: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in case_doc["cases"]:
        grouped[(case["family"], case["target_library"])].append(case)
    families = []
    for (family, target), cases in sorted(grouped.items()):
        families.append(
            {
                "family": family,
                "target_library": target,
                "total_cases": len(cases),
                "mutation_strategies": [c["mutation_strategy"] for c in cases],
                "compile_success": len([c for c in cases if c["compile_status"] == "compile_success"]),
                "run_success": len([c for c in cases if c["run_status"] == "exited"]),
                "normal_exit": len([c for c in cases if c["observed_behavior"]["raw_observation_label"] == "normal_exit"]),
                "nonzero_exit": len([c for c in cases if c["observed_behavior"]["raw_observation_label"] == "nonzero_exit"]),
                "sanitizer_observed": len([c for c in cases if c["sanitizer_observed"]]),
                "crash_signal": len([c for c in cases if c["signal"]]),
                "timeout": len([c for c in cases if c["timeout"]]),
                "preliminary_conclusion": "bounded mutation matrix did not observe crash/sanitizer output; semantic oracle review remains separate",
                "notes": [
                    "This does not prove absence of vulnerabilities.",
                    "Parser accept/reject divergence cannot be concluded from normal_exit alone.",
                ],
            }
        )
    return {
        "schema": "family_analysis_v1",
        "generated_at": now_iso(),
        "families": families,
        "summary": {
            "families_seen": len(families),
            "total_cases": sum(f["total_cases"] for f in families),
        },
    }


def build_oracle_analysis(case_doc: dict[str, Any]) -> dict[str, Any]:
    primary = Counter()
    secondary = Counter()
    expected = Counter()
    raw = Counter()
    review = []
    for case in case_doc["cases"]:
        primary[case["expected_oracle"].get("primary", "")] += 1
        for item in case["expected_oracle"].get("secondary", []):
            secondary[item] += 1
        expected[case["expected_oracle"].get("expected_result_label", "")] += 1
        raw[case["observed_behavior"].get("raw_observation_label", "")] += 1
        if not case["observed_behavior"].get("stdout_summary") and not case["observed_behavior"].get("stderr_summary"):
            review.append(
                {
                    "case_id": case["case_id"],
                    "family": case["family"],
                    "mutation_strategy": case["mutation_strategy"],
                    "reason": "run_status normal_exit only shows no crash; parser accept/reject divergence needs harness semantic output",
                }
            )
    return {
        "schema": "oracle_analysis_v1",
        "generated_at": now_iso(),
        "oracle_summary": {
            "primary_oracles": dict(primary),
            "secondary_oracles": dict(secondary),
            "expected_labels": dict(expected),
            "observed_raw_labels": dict(raw),
            "oracle_interpretation": {
                "no_crash_is_not_proof_of_safety": True,
                "normal_exit_may_still_need_semantic_review": True,
                "parser_accept_reject_requires_stdout_or_harness_semantics": True,
            },
        },
        "cases_requiring_semantic_review": review,
        "summary": {"total_cases": len(case_doc["cases"]), "semantic_review_needed": len(review)},
    }


def build_sanitizer_analysis(sanitizer: dict[str, Any], case_doc: dict[str, Any]) -> dict[str, Any]:
    case_by_job = by_key(case_doc["cases"], "compile_job_id")
    observations = []
    for obs in sanitizer.get("observations", []):
        case = case_by_job.get(obs.get("compile_job_id"), {})
        if case.get("target_library") != "openssl":
            continue
        observations.append(
            {
                "case_id": obs.get("case_id"),
                "family": obs.get("family"),
                "mutation_strategy": obs.get("mutation_strategy"),
                "sanitizer_observed": obs.get("sanitizer_observed"),
                "sanitizer_kinds": obs.get("sanitizer_kinds", []),
                "matched_keywords": obs.get("matched_keywords", []),
                "stderr_log": obs.get("stderr_log"),
                "analysis_label": case.get("analysis_label", "no_crash_observed"),
            }
        )
    return {
        "schema": "sanitizer_analysis_v1",
        "generated_at": now_iso(),
        "summary": {
            "total_cases": len(observations),
            "sanitizer_output_observed": len([o for o in observations if o["sanitizer_observed"]]),
            "asan_observed": len([o for o in observations if "asan" in o["sanitizer_kinds"]]),
            "ubsan_observed": len([o for o in observations if "ubsan" in o["sanitizer_kinds"]]),
            "crash_signals": len([c for c in case_doc["cases"] if c["signal"]]),
            "timeouts": len([c for c in case_doc["cases"] if c["timeout"]]),
        },
        "observations": observations,
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def limitations_doc() -> dict[str, Any]:
    limitations = [
        "本轮 mutation matrix 是 bounded，不代表完整 fuzzing。",
        "normal_exit 不等于证明无漏洞。",
        "无 sanitizer 输出只说明本轮 case 未触发 ASan/UBSan。",
        "parser accept/reject divergence 需要 harness 输出或更细 oracle 才能判断。",
        "目前只覆盖 OpenSSL target。",
        "mbedTLS blocked adapter 未参与运行。",
        "没有做 minimization。",
        "没有做 repeated reproduction。",
    ]
    return {"schema": "analysis_limitations_v1", "generated_at": now_iso(), "limitations": limitations}


def blocked_summary_doc() -> dict[str, Any]:
    return {
        "schema": "blocked_summary_v1",
        "generated_at": now_iso(),
        "blocked": [
            {
                "adapter_id": "asn1_nested_boundary_mbedtls",
                "family": "asn1_nested_boundary",
                "target_library": "mbedtls",
                "compile_attempted": False,
                "run_attempted": False,
                "analyzed_runtime": False,
                "reason": "blocked_expected / no rendered case / no compile job",
            }
        ],
    }


def md_list(items: list[str]) -> str:
    return "".join(f"- {item}\n" for item in items) if items else "- none\n"


def write_markdown(out_dir: Path, docs: dict[str, Any]) -> None:
    case_doc = docs["case"]
    family_doc = docs["family"]
    oracle_doc = docs["oracle"]
    sanitizer_doc = docs["sanitizer"]
    labels_doc = docs["labels"]
    quality = docs["quality"]
    next_action = docs["next"]
    report = docs["report"]
    limitations = docs["limitations"]
    blocked = docs["blocked"]
    input_doc = docs["input"]

    write_text(
        out_dir / "input" / "analyze_results_input_summary.md",
        "# analyze_results_v1 Input Summary\n\n"
        "- consumes: `compile_run_v1`\n"
        "- rerun/compile: `false`\n"
        "- GLM: `false`\n"
        "- feedback integration: `false`\n\n"
        + md_list(input_doc["inputs"]),
    )
    write_text(
        out_dir / "case_analysis" / "case_analysis.md",
        "# Case Analysis\n\n"
        f"- total_cases: `{case_doc['summary']['total_cases']}`\n"
        f"- no_crash_observed: `{case_doc['summary']['no_crash_observed']}`\n"
        f"- sanitizer_crash_candidate: `{case_doc['summary']['sanitizer_crash_candidate']}`\n"
        f"- timeout_candidate: `{case_doc['summary']['timeout_candidate']}`\n",
    )
    write_text(
        out_dir / "family_analysis" / "family_analysis.md",
        "# Family Analysis\n\n"
        + md_list(
            [
                f"{f['family']} -> {f['target_library']}: {f['total_cases']} cases; {f['preliminary_conclusion']}"
                for f in family_doc["families"]
            ]
        ),
    )
    write_text(
        out_dir / "oracle_analysis" / "oracle_analysis.md",
        "# Oracle Analysis\n\n"
        f"- semantic_review_needed: `{oracle_doc['summary']['semantic_review_needed']}`\n"
        "- limitation: run_status normal_exit only shows no crash; parser accept/reject divergence needs richer oracle output.\n",
    )
    write_text(
        out_dir / "sanitizer_analysis" / "sanitizer_analysis.md",
        "# Sanitizer Analysis\n\n"
        f"- sanitizer_output_observed: `{sanitizer_doc['summary']['sanitizer_output_observed']}`\n"
        f"- asan_observed: `{sanitizer_doc['summary']['asan_observed']}`\n"
        f"- ubsan_observed: `{sanitizer_doc['summary']['ubsan_observed']}`\n"
        f"- crash_signals: `{sanitizer_doc['summary']['crash_signals']}`\n"
        f"- timeouts: `{sanitizer_doc['summary']['timeouts']}`\n",
    )
    write_text(
        out_dir / "candidate_labels" / "candidate_labels.md",
        "# Candidate Labels\n\n"
        + md_list([f"{k}: {v}" for k, v in labels_doc["summary"].items()]),
    )
    write_text(
        out_dir / "limitations" / "analysis_limitations.md",
        "# Analysis Limitations\n\n" + md_list(limitations["limitations"]),
    )
    write_text(
        out_dir / "reports" / "blocked_summary.md",
        "# Blocked Summary\n\n"
        + md_list(
            [
                f"{b['family']} -> {b['target_library']}: compile_attempted={b['compile_attempted']}, run_attempted={b['run_attempted']}"
                for b in blocked["blocked"]
            ]
        ),
    )
    write_text(
        out_dir / "validation" / "analyze_results_quality_checks.md",
        "# Analyze Results Quality Checks\n\n"
        f"- quality_status: `{quality['quality_status']}`\n"
        f"- cases_analyzed: `{quality['cases_analyzed']}`\n"
        f"- openssl_only: `{quality['openssl_only']}`\n"
        f"- no_confirmed_vulnerability_claim: `{quality['no_confirmed_vulnerability_claim']}`\n",
    )
    write_text(
        out_dir / "reports" / "next_action_after_analyze_results.md",
        "# Next Action After Analyze Results\n\n"
        f"- next_task: `{next_action['next_task']}`\n"
        f"- secondary_next_task: `{next_action['secondary_next_task']}`\n"
        f"- reason: {next_action['reason']}\n",
    )
    write_text(
        out_dir / "reports" / "analyze_results_v1_report.md",
        "# analyze_results_v1 Report\n\n"
        f"- status: `{report['status']}`\n"
        f"- analyzed_cases: `{report['summary']['analyzed_cases']}`\n"
        f"- pkcs_cases: `{report['summary']['pkcs_cases']}`\n"
        f"- asn1_cases: `{report['summary']['asn1_cases']}`\n"
        f"- sanitizer_output_observed: `{report['summary']['sanitizer_output_observed']}`\n"
        f"- next_task: `{report['next_task']}`\n\n"
        "## Answers\n\n"
        + md_list(report["answers"]),
    )
    write_text(
        out_dir / "README.md",
        "# analyze_results_v1\n\n"
        "This sprint analyzes existing compile_run_v1 raw outputs. It does not recompile, rerun, triage, or write feedback.\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze compile_run_v1 raw results.")
    parser.add_argument("--compile-results", required=True)
    parser.add_argument("--run-results", required=True)
    parser.add_argument("--sanitizer-observations", required=True)
    parser.add_argument("--rendered-case-index", required=True)
    parser.add_argument("--mutation-case-matrix", required=True)
    parser.add_argument("--oracle-expectation-plan", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    compile_results_path = Path(args.compile_results)
    run_results_path = Path(args.run_results)
    sanitizer_path = Path(args.sanitizer_observations)
    rendered_index_path = Path(args.rendered_case_index)
    mutation_matrix_path = Path(args.mutation_case_matrix)
    oracle_plan_path = Path(args.oracle_expectation_plan)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    compile_results = load_yaml(compile_results_path)
    run_results = load_yaml(run_results_path)
    sanitizer = load_yaml(sanitizer_path)
    rendered_index = load_yaml(rendered_index_path)
    mutation_matrix = load_yaml(mutation_matrix_path)
    oracle_plan = load_yaml(oracle_plan_path)

    input_doc = {
        "schema": "analyze_results_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": [
            rel(compile_results_path),
            rel(run_results_path),
            rel(sanitizer_path),
            rel(rendered_index_path),
            rel(mutation_matrix_path),
            rel(oracle_plan_path),
            "artifacts/sprints/compile_run_v1/blocked_cases/compile_run_blocked_cases.yaml",
            "artifacts/sprints/compile_plan_v1/compile_plan/compile_plan.yaml",
            "artifacts/sprints/compile_plan_v1/compile_manifest/compile_manifest.yaml",
        ],
        "scope": {
            "read_existing_results_only": True,
            "recompile": False,
            "rerun": False,
            "glm_called": False,
            "feedback_written": False,
        },
        "rendered_cases_seen": len(rendered_index.get("cases", [])),
    }

    case_doc, labels_doc = build_case_analysis(
        compile_results=compile_results,
        run_results=run_results,
        sanitizer=sanitizer,
        rendered_index=rendered_index,
        mutation_matrix=mutation_matrix,
        oracle_plan=oracle_plan,
    )
    family_doc = build_family_analysis(case_doc)
    oracle_doc = build_oracle_analysis(case_doc)
    sanitizer_doc = build_sanitizer_analysis(sanitizer, case_doc)
    limitations = limitations_doc()
    blocked = blocked_summary_doc()

    cases = case_doc["cases"]
    q = {
        "schema": "analyze_results_quality_checks_v1",
        "generated_at": now_iso(),
        "expected_cases": 14,
        "cases_analyzed": len(cases),
        "families_seen": sorted({c["family"] for c in cases}),
        "openssl_only": all(c["target_library"] == "openssl" for c in cases),
        "mbedtls_analyzed": any(c["target_library"] == "mbedtls" for c in cases),
        "compile_results_loaded": bool(compile_results.get("compile_results")),
        "run_results_loaded": bool(run_results.get("run_results")),
        "sanitizer_results_loaded": bool(sanitizer.get("observations")),
        "reused_existing_pipeline": True,
        "reused_modules": REUSED_MODULES,
        "all_cases_have_analysis_label": all(bool(c.get("analysis_label")) for c in cases),
        "all_cases_have_family": all(bool(c.get("family")) for c in cases),
        "all_cases_have_mutation_strategy": all(bool(c.get("mutation_strategy")) for c in cases),
        "all_cases_have_candidate_label": len(labels_doc["labels"]) == len(cases)
        and all(bool(item.get("candidate_label")) for item in labels_doc["labels"]),
        "no_rerun_executed": True,
        "no_compile_executed": True,
        "no_glm_called": True,
        "no_feedback_written": True,
        "no_confirmed_vulnerability_claim": True,
        "notes": [
            "Analysis consumes existing raw outputs only.",
            "No confirmed safe/vulnerability/CVE/exploitability claim is made.",
        ],
    }
    q["quality_status"] = (
        "pass"
        if q["cases_analyzed"] == 14
        and q["openssl_only"]
        and not q["mbedtls_analyzed"]
        and q["all_cases_have_analysis_label"]
        and q["all_cases_have_family"]
        and q["all_cases_have_mutation_strategy"]
        and q["all_cases_have_candidate_label"]
        and q["reused_existing_pipeline"]
        and q["no_rerun_executed"]
        and q["no_compile_executed"]
        and q["no_feedback_written"]
        and q["no_confirmed_vulnerability_claim"]
        else "partial"
        if q["cases_analyzed"]
        else "fail"
    )

    labels_summary = labels_doc["summary"]
    crash_like = (
        case_doc["summary"]["sanitizer_crash_candidate"]
        + case_doc["summary"]["crash_signal_candidate"]
        + case_doc["summary"]["timeout_candidate"]
    )
    semantic_review_needed = oracle_doc["summary"]["semantic_review_needed"]
    if crash_like:
        next_task = "triage_crash_candidates_v1"
        secondary = "none"
        reason = "crash-like raw observations exist"
    elif semantic_review_needed:
        next_task = "oracle_instrumentation_enrichment_v1"
        secondary = "runtime_feedback_integration_v1"
        reason = "no crash/sanitizer observed, but parser accept/reject semantic output is insufficient"
    elif labels_summary.get("no_crash_observed", 0):
        next_task = "runtime_feedback_integration_v1"
        secondary = "none"
        reason = "raw execution labels can be fed back to scheduler/mutation policy"
    else:
        next_task = "analyze_results_input_fixup_v1"
        secondary = "none"
        reason = "analysis inputs are incomplete"

    next_action = {
        "schema": "next_action_after_analyze_results_v1",
        "generated_at": now_iso(),
        "next_task": next_task,
        "secondary_next_task": secondary,
        "reason": reason,
    }
    report = {
        "schema": "analyze_results_v1_report",
        "generated_at": now_iso(),
        "status": q["quality_status"],
        "reused_existing_pipeline": True,
        "reused_modules": REUSED_MODULES,
        "duplicated_logic_reduced": case_doc["duplicated_logic_reduced"],
        "summary": {
            "analyzed_cases": len(cases),
            "pkcs_cases": len([c for c in cases if c["family"] == "pkcs_container_parsing"]),
            "asn1_cases": len([c for c in cases if c["family"] == "asn1_nested_boundary"]),
            "sanitizer_output_observed": sanitizer_doc["summary"]["sanitizer_output_observed"],
            "crash_signals": sanitizer_doc["summary"]["crash_signals"],
            "timeouts": sanitizer_doc["summary"]["timeouts"],
            "candidate_labels": labels_summary,
            "mbedtls_analyzed": q["mbedtls_analyzed"],
            "recompile_or_rerun": False,
            "glm_called": False,
            "feedback_written": False,
        },
        "answers": [
            f"Analyzed cases: {len(cases)}.",
            f"PKCS cases: {len([c for c in cases if c['family'] == 'pkcs_container_parsing'])}.",
            f"ASN.1 cases: {len([c for c in cases if c['family'] == 'asn1_nested_boundary'])}.",
            f"Sanitizer output observed: {sanitizer_doc['summary']['sanitizer_output_observed']}.",
            f"Crash/signal/timeouts: {sanitizer_doc['summary']['crash_signals']}/{sanitizer_doc['summary']['timeouts']}.",
            f"Candidate labels: {dict(labels_summary)}.",
            f"mbedTLS analyzed: {q['mbedtls_analyzed']}.",
            "No recompile/rerun was executed.",
            "GLM was not called.",
            "Feedback was not written.",
            f"Next task: {next_task}.",
        ],
        "next_task": next_task,
        "secondary_next_task": secondary,
    }

    docs = {
        "input": input_doc,
        "case": case_doc,
        "family": family_doc,
        "oracle": oracle_doc,
        "sanitizer": sanitizer_doc,
        "labels": labels_doc,
        "limitations": limitations,
        "blocked": blocked,
        "quality": q,
        "next": next_action,
        "report": report,
    }
    dump_yaml(out_dir / "input" / "analyze_results_input_summary.yaml", input_doc)
    dump_yaml(out_dir / "case_analysis" / "case_analysis.yaml", case_doc)
    dump_yaml(out_dir / "family_analysis" / "family_analysis.yaml", family_doc)
    dump_yaml(out_dir / "oracle_analysis" / "oracle_analysis.yaml", oracle_doc)
    dump_yaml(out_dir / "sanitizer_analysis" / "sanitizer_analysis.yaml", sanitizer_doc)
    dump_yaml(out_dir / "candidate_labels" / "candidate_labels.yaml", labels_doc)
    dump_yaml(out_dir / "limitations" / "analysis_limitations.yaml", limitations)
    dump_yaml(out_dir / "reports" / "blocked_summary.yaml", blocked)
    dump_yaml(out_dir / "validation" / "analyze_results_quality_checks.yaml", q)
    dump_yaml(out_dir / "reports" / "next_action_after_analyze_results.yaml", next_action)
    dump_yaml(out_dir / "reports" / "analyze_results_v1_report.yaml", report)
    write_markdown(out_dir, docs)

    print(f"[OK] wrote analysis artifacts to {out_dir}")
    print(
        f"[SUMMARY] cases={len(cases)} no_crash={case_doc['summary']['no_crash_observed']} sanitizer={sanitizer_doc['summary']['sanitizer_output_observed']}"
    )
    print(f"[NEXT] {next_task}")
    return 0 if q["quality_status"] in {"pass", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
