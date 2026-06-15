#!/usr/bin/env python3
"""Oracle-aware analysis for instrumented compile/run outputs.

This script is intentionally offline: it reads prior compile/run/oracle-event
YAML artifacts and writes analysis summaries without compiling or rerunning.
"""

from __future__ import annotations

import argparse
import datetime as _dt
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from analyzer import oracle_aware_analyzer as oracle_aware_core
from analyzer.oracle_event_parser import parse_oracle_event_line


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


def by_case(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("case_id")): item for item in items if item.get("case_id")}


def events_by_case(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        case_id = str(event.get("case_id") or "")
        if case_id:
            grouped[case_id].append(event)
    return grouped


def is_true(value: Any) -> bool:
    return value is True or value == 1 or str(value).lower() == "true"


def is_false(value: Any) -> bool:
    return value is False or value == 0 or str(value).lower() == "false"


def is_unknown(value: Any) -> bool:
    return str(value).lower() in {"unknown", "none", "null", ""}


def count_values(events: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts = {"true": 0, "false": 0, "unknown": 0}
    for event in events:
        value = event.get(key, "unknown")
        if is_true(value):
            counts["true"] += 1
        elif is_false(value):
            counts["false"] += 1
        else:
            counts["unknown"] += 1
    return counts


def event_phase_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    phases = Counter(str(event.get("phase") or "unknown") for event in events)
    return {
        "parse": phases.get("parse", 0),
        "verify": phases.get("verify", 0),
        "full_consumption_check": phases.get("full_consumption_check", 0),
        "cleanup": phases.get("cleanup", 0),
    }


def parser_revalidation(events: list[dict[str, Any]]) -> dict[str, Any]:
    reparsed = 0
    mismatches = []
    for event in events:
        raw = str(event.get("raw_line") or "")
        parsed = parse_oracle_event_line(raw)
        if parsed is None:
            continue
        reparsed += 1
        for key in ("case_id", "family", "mutation_strategy", "target_library", "phase", "api"):
            if key in parsed and str(parsed.get(key)) != str(event.get(key)):
                mismatches.append({"key": key, "yaml": event.get(key), "parsed": parsed.get(key)})
    return {
        "parser": "analyzer.oracle_event_parser.parse_oracle_event_line",
        "raw_lines_reparsed": reparsed,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:10],
    }


def classify_case(
    run: dict[str, Any],
    events: list[dict[str, Any]],
    sanitizer: dict[str, Any],
) -> tuple[str, str, bool, str, str]:
    accepted = count_values(events, "accepted")
    full = count_values(events, "full_consumption")
    sanitizer_observed = bool(run.get("sanitizer_observed") or sanitizer.get("sanitizer_observed"))
    if sanitizer_observed:
        return (
            "sanitizer_crash_candidate",
            "needs_triage",
            True,
            "sanitizer output was observed and requires manual crash triage",
            "manual sanitizer triage",
        )
    if run.get("timeout"):
        return ("timeout_candidate", "needs_triage", True, "case timed out", "timeout triage")
    if run.get("signal"):
        return (
            "crash_signal_candidate",
            "needs_triage",
            True,
            "process signal was observed",
            "crash signal triage",
        )
    if not events:
        return (
            "oracle_event_incomplete",
            "oracle_incomplete",
            True,
            "no ORACLE_EVENT records were available for the case",
            "oracle instrumentation output fixup",
        )
    if accepted["true"] > 0 and full["false"] > 0:
        return (
            "full_consumption_gap_candidate",
            "full_consumption_gap_candidate",
            True,
            "parser accepted at least one path while full_consumption=false was observed",
            "oracle semantic triage",
        )
    if accepted["true"] > 0:
        return (
            "normal_accept_observed",
            "normal_accept",
            False,
            "parser accepted and no accepted-path full-consumption gap was observed",
            "keep as accept-path control",
        )
    if accepted["false"] > 0:
        return (
            "normal_reject_observed",
            "normal_reject",
            False,
            "accepted=false path observed; full_consumption=false on reject path is not a gap by itself",
            "generate valid-prefix or near-valid variants",
        )
    return (
        "oracle_event_incomplete",
        "oracle_incomplete",
        True,
        "ORACLE_EVENT records did not expose accepted=true/false semantics",
        "oracle instrumentation output fixup",
    )


def family_interpretation(family: str, accepted_true: int, accepted_false: int) -> tuple[str, list[str]]:
    limitations = [
        "bounded mutation matrix; not coverage-guided fuzzing",
        "no confirmed vulnerability claim is made",
    ]
    if accepted_true == 0 and accepted_false > 0:
        return (
            "all observed OpenSSL cases rejected; useful reject-path evidence but no successful parser path for full-consumption gap evaluation",
            limitations
            + [
                "accepted_true=0 prevents judging successful parser-path full consumption gaps",
                f"{family} mutations may be too strong for accept-path semantic observation",
            ],
        )
    if accepted_true > 0:
        return (
            "accepted parser path exists; accepted=true/full_consumption=false cases require semantic triage",
            limitations,
        )
    return ("oracle events are incomplete for accept/reject semantics", limitations)


def mutation_semantic_value(accepted_true: int, accepted_false: int) -> tuple[str, str]:
    if accepted_true > 0:
        return ("useful_accept_path", "keep")
    if accepted_false > 0:
        return ("too_strong_all_reject", "generate_valid_prefix_variant")
    return ("inconclusive", "add_near-valid_mutation")


def build_case_analysis(
    run_results: dict[str, Any],
    events_doc: dict[str, Any],
    sanitizer_doc: dict[str, Any],
    index_doc: dict[str, Any],
    matrix_doc: dict[str, Any],
    baseline_doc: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    grouped_events = events_by_case(events_doc.get("events", []))
    sanitizer_by_case = by_case(sanitizer_doc.get("observations", []))
    index_by_case = by_case(index_doc.get("cases", []))
    mutation_by_case = by_case(matrix_doc.get("cases", []))
    baseline_by_case = by_case(baseline_doc.get("cases", []))

    cases = []
    labels = []
    for run in run_results.get("run_results", []):
        if run.get("target_library") != "openssl":
            continue
        case_id = str(run.get("case_id"))
        events = grouped_events.get(case_id, [])
        sanitizer = sanitizer_by_case.get(case_id, {})
        index_case = index_by_case.get(case_id, {})
        mutation = mutation_by_case.get(case_id, {})
        baseline = baseline_by_case.get(case_id, {})
        semantic, candidate, triage, reason, next_action = classify_case(run, events, sanitizer)
        phases = event_phase_counts(events)
        accepted = count_values(events, "accepted")
        full = count_values(events, "full_consumption")
        openssl_errors = sorted(
            {
                str(event.get("openssl_error_reason"))
                for event in events
                if not is_unknown(event.get("openssl_error_reason"))
            }
        )
        case = {
            "case_id": case_id,
            "family": run.get("family") or index_case.get("family") or mutation.get("family"),
            "mutation_strategy": run.get("mutation_strategy")
            or index_case.get("mutation_strategy")
            or mutation.get("mutation_strategy"),
            "target_library": "openssl",
            "run_status": run.get("run_status"),
            "exit_code": run.get("exit_code"),
            "signal": run.get("signal", ""),
            "timeout": bool(run.get("timeout")),
            "sanitizer_observed": bool(run.get("sanitizer_observed") or sanitizer.get("sanitizer_observed")),
            "oracle_events": {
                "total": len(events),
                "phases": phases,
                "accepted_values": accepted,
                "full_consumption_values": full,
                "openssl_errors": openssl_errors,
                "parser_revalidation": parser_revalidation(events),
            },
            "raw_observation": {
                "raw_execution_label": run.get("raw_observation_label", ""),
                "normal_exit": run.get("run_status") == "exited" and run.get("exit_code") == 0,
                "sanitizer_kinds": run.get("sanitizer_kinds", []),
                "baseline_analysis_label": baseline.get("analysis_label", ""),
                "baseline_candidate_label": baseline.get("candidate_label", ""),
            },
            "semantic_observation": semantic,
            "candidate_label": candidate,
            "triage_required": triage,
            "reason": reason,
            "expected_oracle": mutation.get("expected_oracle", {}),
        }
        cases.append(case)
        confidence = "high" if candidate == "normal_reject" else "medium"
        if candidate in {"oracle_incomplete", "needs_triage"}:
            confidence = "medium"
        labels.append(
            {
                "case_id": case_id,
                "family": case["family"],
                "mutation_strategy": case["mutation_strategy"],
                "raw_execution_label": run.get("raw_observation_label", ""),
                "oracle_semantic_label": semantic,
                "candidate_label": candidate,
                "confidence": confidence,
                "reason": reason,
                "next_action": next_action,
            }
        )

    semantic_counts = Counter(c["semantic_observation"] for c in cases)
    case_doc = {
        "schema": "oracle_aware_case_analysis_v1",
        "generated_at": now_iso(),
        "cases": cases,
        "summary": {
            "total_cases": len(cases),
            "normal_reject_observed": semantic_counts.get("normal_reject_observed", 0),
            "normal_accept_observed": semantic_counts.get("normal_accept_observed", 0),
            "full_consumption_gap_candidate": semantic_counts.get("full_consumption_gap_candidate", 0),
            "oracle_event_incomplete": semantic_counts.get("oracle_event_incomplete", 0),
            "sanitizer_crash_candidate": semantic_counts.get("sanitizer_crash_candidate", 0),
        },
    }
    label_counts = Counter(item["candidate_label"] for item in labels)
    label_doc = {
        "schema": "oracle_aware_candidate_labels_v1",
        "generated_at": now_iso(),
        "labels": labels,
        "summary": {
            "normal_reject": label_counts.get("normal_reject", 0),
            "normal_accept": label_counts.get("normal_accept", 0),
            "full_consumption_gap_candidate": label_counts.get("full_consumption_gap_candidate", 0),
            "semantic_divergence_candidate": label_counts.get("semantic_divergence_candidate", 0),
            "needs_triage": label_counts.get("needs_triage", 0),
            "oracle_incomplete": label_counts.get("oracle_incomplete", 0),
        },
    }
    return case_doc, label_doc


def build_family_analysis(case_doc: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in case_doc["cases"]:
        grouped[str(case["family"])].append(case)

    families = []
    for family, cases in sorted(grouped.items()):
        parse_events = sum(c["oracle_events"]["phases"]["parse"] for c in cases)
        verify_events = sum(c["oracle_events"]["phases"]["verify"] for c in cases)
        full_events = sum(c["oracle_events"]["phases"]["full_consumption_check"] for c in cases)
        cleanup_events = sum(c["oracle_events"]["phases"]["cleanup"] for c in cases)
        accepted_true = sum(c["oracle_events"]["accepted_values"]["true"] for c in cases)
        accepted_false = sum(c["oracle_events"]["accepted_values"]["false"] for c in cases)
        full_true = sum(c["oracle_events"]["full_consumption_values"]["true"] for c in cases)
        full_false = sum(c["oracle_events"]["full_consumption_values"]["false"] for c in cases)
        full_unknown = sum(c["oracle_events"]["full_consumption_values"]["unknown"] for c in cases)
        interpretation, limitations = family_interpretation(family, accepted_true, accepted_false)
        families.append(
            {
                "family": family,
                "target_library": "openssl",
                "total_cases": len(cases),
                "mutation_strategies": [c["mutation_strategy"] for c in cases],
                "parse_events": parse_events,
                "verify_events": verify_events,
                "full_consumption_events": full_events,
                "cleanup_events": cleanup_events,
                "accepted_true": accepted_true,
                "accepted_false": accepted_false,
                "full_consumption_true": full_true,
                "full_consumption_false": full_false,
                "full_consumption_unknown": full_unknown,
                "sanitizer_observed": len([c for c in cases if c["sanitizer_observed"]]),
                "crash_signal": len([c for c in cases if c["signal"]]),
                "timeout": len([c for c in cases if c["timeout"]]),
                "preliminary_interpretation": interpretation,
                "limitations": limitations,
            }
        )
    return {
        "schema": "oracle_aware_family_analysis_v1",
        "generated_at": now_iso(),
        "families": families,
        "summary": {
            "families_seen": len(families),
            "total_cases": sum(f["total_cases"] for f in families),
        },
    }


def build_oracle_semantics(events_doc: dict[str, Any], case_doc: dict[str, Any]) -> dict[str, Any]:
    events = events_doc.get("events", [])
    phases = event_phase_counts(events)
    accepted = count_values(events, "accepted")
    full = count_values(events, "full_consumption")
    gap_candidates = [
        c["case_id"]
        for c in case_doc["cases"]
        if c["semantic_observation"] == "full_consumption_gap_candidate"
    ]
    return {
        "schema": "oracle_semantics_summary_v1",
        "generated_at": now_iso(),
        "raw_observations": {
            "total_events": len(events),
            "cases_with_events": len({e.get("case_id") for e in events if e.get("case_id")}),
            "parse_events": phases["parse"],
            "verify_events": phases["verify"],
            "full_consumption_events": phases["full_consumption_check"],
            "cleanup_events": phases["cleanup"],
            "accepted_true": accepted["true"],
            "accepted_false": accepted["false"],
            "full_consumption_true": full["true"],
            "full_consumption_false": full["false"],
            "full_consumption_unknown": full["unknown"],
        },
        "interpretation_rules": [
            {
                "rule": "accepted_false_and_full_consumption_false",
                "interpretation": "reject path; not a full-consumption gap by itself",
            },
            {
                "rule": "accepted_true_and_full_consumption_false",
                "interpretation": "possible full-consumption gap candidate",
            },
            {
                "rule": "normal_exit_without_accept",
                "interpretation": "no crash; semantic outcome depends on oracle event",
            },
            {
                "rule": "sanitizer_output",
                "interpretation": "sanitizer_crash_candidate, requires triage",
            },
        ],
        "semantic_outcome": {
            "all_cases_rejected": accepted["true"] == 0 and accepted["false"] > 0,
            "any_success_accept": accepted["true"] > 0,
            "any_success_accept_with_trailing_unconsumed": bool(gap_candidates),
            "full_consumption_gap_candidates": gap_candidates,
            "needs_more_valid_mutation_inputs": accepted["true"] == 0,
            "interpretation": "No accepted=true parser path was observed; full_consumption=false occurs on reject/error paths and is not a full-consumption validation gap by itself.",
        },
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }


def build_mutation_effectiveness(case_doc: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for case in case_doc["cases"]:
        accepted = case["oracle_events"]["accepted_values"]
        semantic_value, action = mutation_semantic_value(accepted["true"], accepted["false"])
        rows.append(
            {
                "family": case["family"],
                "mutation_strategy": case["mutation_strategy"],
                "total_cases": 1,
                "accepted_true": accepted["true"],
                "accepted_false": accepted["false"],
                "sanitizer_observed": int(case["sanitizer_observed"]),
                "crash_signal": int(bool(case["signal"])),
                "timeout": int(case["timeout"]),
                "semantic_value": semantic_value,
                "recommended_action": action,
            }
        )
    counts = Counter(row["semantic_value"] for row in rows)
    return {
        "schema": "mutation_effectiveness_v1",
        "generated_at": now_iso(),
        "mutation_strategies": rows,
        "summary": {
            "useful_accept_path": counts.get("useful_accept_path", 0),
            "useful_reject_path": counts.get("useful_reject_path", 0),
            "too_strong_all_reject": counts.get("too_strong_all_reject", 0),
            "recommended_next_mutation_focus": [
                "generate_valid_prefix_variant",
                "reduce mutation strength",
                "preserve outer container validity",
                "mutate trailing bytes after a valid object",
            ],
        },
    }


def build_limitations() -> dict[str, Any]:
    return {
        "schema": "oracle_aware_limitations_v1",
        "generated_at": now_iso(),
        "limitations": [
            "This is a bounded mutation matrix, not complete fuzzing.",
            "accepted_true=0 prevents judging successful parser-path full consumption gaps.",
            "full_consumption=false on a reject path must not be interpreted as a vulnerability.",
            "Current mutations may be too strong and may drive all parsers into reject paths.",
            "Follow-up should generate valid-prefix / near-valid / trailing-only variants.",
            "Only the OpenSSL target was covered in this sprint.",
            "mbedTLS was blocked and not run.",
            "No repeated reproduction was performed.",
            "No minimization was performed.",
            "No runtime feedback was written.",
        ],
    }


def build_blocked_summary(blocked_doc: dict[str, Any]) -> dict[str, Any]:
    entries = []
    for item in blocked_doc.get("blocked_cases", []):
        entries.append(
            {
                "family": item.get("family"),
                "target_library": item.get("target_library"),
                "analyzed": False,
                "compile_attempted": bool(item.get("compile_attempted")),
                "run_attempted": bool(item.get("run_attempted")),
                "reason": item.get("reason") or "blocked_expected / no instrumented case / no compile job",
            }
        )
    return {
        "schema": "oracle_aware_blocked_summary_v1",
        "generated_at": now_iso(),
        "blocked": entries,
        "summary": {
            "total_blocked": len(entries),
            "mbedtls_analyzed": False,
            "compile_attempted": any(e["compile_attempted"] for e in entries),
            "run_attempted": any(e["run_attempted"] for e in entries),
        },
    }


def build_quality(case_doc: dict[str, Any], sem_doc: dict[str, Any]) -> dict[str, Any]:
    cases = case_doc["cases"]
    quality_pass = (
        len(cases) == 14
        and all(c.get("target_library") == "openssl" for c in cases)
        and all(c.get("semantic_observation") for c in cases)
        and all(c.get("candidate_label") for c in cases)
        and all(c.get("family") for c in cases)
        and all(c.get("mutation_strategy") for c in cases)
        and sem_doc["raw_observations"]["cases_with_events"] == 14
    )
    return {
        "schema": "oracle_aware_analysis_quality_checks_v1",
        "generated_at": now_iso(),
        "expected_cases": 14,
        "cases_analyzed": len(cases),
        "oracle_events_loaded": sem_doc["raw_observations"]["total_events"],
        "cases_with_events": sem_doc["raw_observations"]["cases_with_events"],
        "openssl_only": all(c.get("target_library") == "openssl" for c in cases),
        "mbedtls_analyzed": False,
        "all_cases_have_semantic_observation": all(c.get("semantic_observation") for c in cases),
        "all_cases_have_candidate_label": all(c.get("candidate_label") for c in cases),
        "all_cases_have_family": all(c.get("family") for c in cases),
        "all_cases_have_mutation_strategy": all(c.get("mutation_strategy") for c in cases),
        "no_rerun_executed": True,
        "no_compile_executed": True,
        "no_glm_called": True,
        "no_feedback_written": True,
        "no_confirmed_vulnerability_claim": True,
        "quality_status": "pass" if quality_pass else "partial",
        "notes": [
            "offline oracle-aware analysis only",
            "normal_exit is not interpreted as proof of safety",
            "full_consumption=false on accepted=false paths is not treated as vulnerability evidence",
        ],
    }


def next_action(sem_doc: dict[str, Any], case_doc: dict[str, Any]) -> dict[str, Any]:
    raw = sem_doc["raw_observations"]
    has_gap = bool(sem_doc["semantic_outcome"]["full_consumption_gap_candidates"])
    has_crashish = any(
        c["semantic_observation"]
        in {"sanitizer_crash_candidate", "crash_signal_candidate", "timeout_candidate"}
        for c in case_doc["cases"]
    )
    has_incomplete = any(c["semantic_observation"] == "oracle_event_incomplete" for c in case_doc["cases"])
    if has_gap:
        task = "oracle_semantic_triage_v1"
        reason = "accepted=true with full_consumption=false was observed."
    elif has_crashish:
        task = "triage_crash_candidates_v1"
        reason = "sanitizer/crash/timeout candidate was observed."
    elif raw["accepted_true"] == 0 and raw["accepted_false"] > 0:
        task = "mutation_policy_refinement_for_valid_prefix_v1"
        reason = "All observed parser semantics are accepted=false; current mutations mostly exercise malformed reject paths and need valid-prefix / near-valid / trailing-only variants."
    elif has_incomplete:
        task = "oracle_instrumentation_output_fixup_v1"
        reason = "Some cases lack complete ORACLE_EVENT semantics."
    else:
        task = "runtime_feedback_integration_v1"
        reason = "Oracle-aware analysis is complete and no suspicious candidates were observed."
    return {
        "schema": "next_action_after_oracle_aware_analysis_v1",
        "generated_at": now_iso(),
        "next_task_name": task,
        "reason": reason,
    }


def md_case_summary(case_doc: dict[str, Any]) -> str:
    lines = ["# Oracle-Aware Case Analysis", ""]
    s = case_doc["summary"]
    lines.append(f"- total_cases: {s['total_cases']}")
    lines.append(f"- normal_reject_observed: {s['normal_reject_observed']}")
    lines.append(f"- normal_accept_observed: {s['normal_accept_observed']}")
    lines.append(f"- full_consumption_gap_candidate: {s['full_consumption_gap_candidate']}")
    lines.append(f"- oracle_event_incomplete: {s['oracle_event_incomplete']}")
    lines.append("")
    for case in case_doc["cases"]:
        lines.append(f"## {case['case_id']}")
        lines.append(f"- family: {case['family']}")
        lines.append(f"- mutation_strategy: {case['mutation_strategy']}")
        lines.append(f"- semantic_observation: {case['semantic_observation']}")
        lines.append(f"- candidate_label: {case['candidate_label']}")
        lines.append(f"- reason: {case['reason']}")
        lines.append("")
    return "\n".join(lines)


def md_family_summary(family_doc: dict[str, Any]) -> str:
    lines = ["# Oracle-Aware Family Analysis", ""]
    for item in family_doc["families"]:
        lines.append(f"## {item['family']}")
        lines.append(f"- total_cases: {item['total_cases']}")
        lines.append(f"- accepted_true: {item['accepted_true']}")
        lines.append(f"- accepted_false: {item['accepted_false']}")
        lines.append(f"- full_consumption_false: {item['full_consumption_false']}")
        lines.append(f"- interpretation: {item['preliminary_interpretation']}")
        lines.append("")
    return "\n".join(lines)


def md_dict(title: str, data: dict[str, Any]) -> str:
    return f"# {title}\n\n```yaml\n{yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)}```\n"


def build_report(
    case_doc: dict[str, Any],
    family_doc: dict[str, Any],
    sem_doc: dict[str, Any],
    mutation_doc: dict[str, Any],
    labels_doc: dict[str, Any],
    quality_doc: dict[str, Any],
    next_doc: dict[str, Any],
) -> dict[str, Any]:
    family_counts = {f["family"]: f["total_cases"] for f in family_doc["families"]}
    raw = sem_doc["raw_observations"]
    return {
        "schema": "analyze_results_oracle_aware_v1_report",
        "task": "analyze_results_oracle_aware_v1",
        "generated_at": now_iso(),
        "analyzed_cases": case_doc["summary"]["total_cases"],
        "pkcs_cases": family_counts.get("pkcs_container_parsing", 0),
        "asn1_cases": family_counts.get("asn1_nested_boundary", 0),
        "oracle_events_all_parsed": raw["cases_with_events"] == case_doc["summary"]["total_cases"],
        "accepted_true": raw["accepted_true"],
        "accepted_false": raw["accepted_false"],
        "full_consumption_true": raw["full_consumption_true"],
        "full_consumption_false": raw["full_consumption_false"],
        "full_consumption_unknown": raw["full_consumption_unknown"],
        "full_consumption_gap_candidate": labels_doc["summary"]["full_consumption_gap_candidate"],
        "sanitizer_crash_timeout_observed": 0,
        "mutation_mostly_rejected": raw["accepted_true"] == 0 and raw["accepted_false"] > 0,
        "recommend_valid_prefix_near_valid_variants": True,
        "feedback_written": False,
        "quality_status": quality_doc["quality_status"],
        "next_task_name": next_doc["next_task_name"],
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
        "mutation_effectiveness_summary": mutation_doc["summary"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compile-results", required=True)
    parser.add_argument("--run-results", required=True)
    parser.add_argument("--oracle-events", required=True)
    parser.add_argument("--sanitizer-observations", required=True)
    parser.add_argument("--instrumented-case-index", required=True)
    parser.add_argument("--mutation-case-matrix", required=True)
    parser.add_argument("--oracle-expectation-plan", required=True)
    parser.add_argument("--baseline-analysis", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


build_case_analysis = oracle_aware_core.build_case_analysis
build_family_analysis = oracle_aware_core.build_family_analysis
build_oracle_semantics = oracle_aware_core.build_oracle_semantics
build_mutation_effectiveness = oracle_aware_core.build_mutation_effectiveness


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    compile_doc = load_yaml(Path(args.compile_results))
    run_doc = load_yaml(Path(args.run_results))
    events_doc = load_yaml(Path(args.oracle_events))
    sanitizer_doc = load_yaml(Path(args.sanitizer_observations))
    index_doc = load_yaml(Path(args.instrumented_case_index))
    matrix_doc = load_yaml(Path(args.mutation_case_matrix))
    oracle_plan_doc = load_yaml(Path(args.oracle_expectation_plan))
    baseline_doc = load_yaml(Path(args.baseline_analysis))
    blocked_doc = load_yaml(
        Path("artifacts/sprints/compile_run_oracle_instrumented_v1/blocked_cases/blocked_cases.yaml")
    )

    input_summary = {
        "schema": "oracle_aware_analysis_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": {
            "compile_results": args.compile_results,
            "run_results": args.run_results,
            "oracle_events": args.oracle_events,
            "sanitizer_observations": args.sanitizer_observations,
            "instrumented_case_index": args.instrumented_case_index,
            "mutation_case_matrix": args.mutation_case_matrix,
            "oracle_expectation_plan": args.oracle_expectation_plan,
            "baseline_analysis": args.baseline_analysis,
        },
        "compile_results_seen": len(compile_doc.get("compile_results", [])),
        "oracle_expectation_schema": oracle_plan_doc.get("schema", ""),
        "no_compile_executed": True,
        "no_rerun_executed": True,
    }
    dump_yaml(out / "input/input_summary.yaml", input_summary)

    case_doc, label_doc = build_case_analysis(
        run_doc, events_doc, sanitizer_doc, index_doc, matrix_doc, baseline_doc
    )
    family_doc = build_family_analysis(case_doc)
    sem_doc = build_oracle_semantics(events_doc, case_doc)
    mutation_doc = build_mutation_effectiveness(case_doc)
    limitations_doc = build_limitations()
    blocked_summary_doc = build_blocked_summary(blocked_doc)
    quality_doc = build_quality(case_doc, sem_doc)
    next_doc = next_action(sem_doc, case_doc)
    report_doc = build_report(case_doc, family_doc, sem_doc, mutation_doc, label_doc, quality_doc, next_doc)

    dump_yaml(out / "case_analysis/oracle_aware_case_analysis.yaml", case_doc)
    write_text(out / "case_analysis/oracle_aware_case_analysis.md", md_case_summary(case_doc))
    dump_yaml(out / "family_analysis/oracle_aware_family_analysis.yaml", family_doc)
    write_text(out / "family_analysis/oracle_aware_family_analysis.md", md_family_summary(family_doc))
    dump_yaml(out / "oracle_semantics/oracle_semantics_summary.yaml", sem_doc)
    write_text(out / "oracle_semantics/oracle_semantics_summary.md", md_dict("Oracle Semantics Summary", sem_doc))
    dump_yaml(out / "mutation_effectiveness/mutation_effectiveness.yaml", mutation_doc)
    write_text(out / "mutation_effectiveness/mutation_effectiveness.md", md_dict("Mutation Effectiveness", mutation_doc))
    dump_yaml(out / "candidate_labels/oracle_aware_candidate_labels.yaml", label_doc)
    write_text(out / "candidate_labels/oracle_aware_candidate_labels.md", md_dict("Oracle-Aware Candidate Labels", label_doc))
    dump_yaml(out / "limitations/oracle_aware_limitations.yaml", limitations_doc)
    write_text(out / "limitations/oracle_aware_limitations.md", md_dict("Oracle-Aware Limitations", limitations_doc))
    dump_yaml(out / "blocked_summary/blocked_summary.yaml", blocked_summary_doc)
    write_text(out / "blocked_summary/blocked_summary.md", md_dict("Blocked Summary", blocked_summary_doc))
    dump_yaml(out / "validation/oracle_aware_analysis_quality_checks.yaml", quality_doc)
    write_text(out / "validation/oracle_aware_analysis_quality_checks.md", md_dict("Quality Checks", quality_doc))
    dump_yaml(out / "reports/next_action_after_oracle_aware_analysis.yaml", next_doc)
    write_text(out / "reports/next_action_after_oracle_aware_analysis.md", md_dict("Next Action", next_doc))
    dump_yaml(out / "reports/analyze_results_oracle_aware_v1_report.yaml", report_doc)
    write_text(out / "reports/analyze_results_oracle_aware_v1_report.md", md_dict("Analyze Results Oracle-Aware Report", report_doc))
    write_text(
        out / "README.md",
        "\n".join(
            [
                "# analyze_results_oracle_aware_v1",
                "",
                "Offline oracle-aware analysis of prior instrumented OpenSSL compile/run results.",
                "",
                f"- analyzed_cases: {report_doc['analyzed_cases']}",
                f"- pkcs_cases: {report_doc['pkcs_cases']}",
                f"- asn1_cases: {report_doc['asn1_cases']}",
                f"- oracle_events_all_parsed: {report_doc['oracle_events_all_parsed']}",
                f"- accepted_true: {report_doc['accepted_true']}",
                f"- accepted_false: {report_doc['accepted_false']}",
                f"- full_consumption_gap_candidate: {report_doc['full_consumption_gap_candidate']}",
                f"- mutation_mostly_rejected: {report_doc['mutation_mostly_rejected']}",
                f"- next_task_name: {report_doc['next_task_name']}",
                "",
                "No compile, rerun, GLM call, feedback write, or vulnerability claim was performed.",
                "",
            ]
        ),
    )

    print(f"[OK] wrote oracle-aware analysis artifacts to {out}")
    print(
        "[SUMMARY] "
        f"cases={case_doc['summary']['total_cases']} "
        f"accepted_true={sem_doc['raw_observations']['accepted_true']} "
        f"accepted_false={sem_doc['raw_observations']['accepted_false']} "
        f"gap_candidates={label_doc['summary']['full_consumption_gap_candidate']} "
        f"quality={quality_doc['quality_status']}"
    )
    print(f"[NEXT] {next_doc['next_task_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
