"""Reusable oracle-aware analysis builders for family-level runs."""

from __future__ import annotations

import datetime as _dt
from collections import Counter, defaultdict
from typing import Any

from analyzer.oracle_event_parser import parse_oracle_event_line
from analyzer.semantic_labels import (
    classify_oracle_case,
    count_values,
    event_phase_counts,
    family_interpretation,
    is_unknown,
    mutation_semantic_value,
)


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def by_case(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("case_id")): item for item in items if item.get("case_id")}


def events_by_case(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        case_id = str(event.get("case_id") or "")
        if case_id:
            grouped[case_id].append(event)
    return grouped


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
        semantic, candidate, triage, reason, next_action = classify_oracle_case(run, events, sanitizer)
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
    label_counts = Counter(item["candidate_label"] for item in labels)
    return (
        {
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
        },
        {
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
        },
    )


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
        "summary": {"families_seen": len(families), "total_cases": sum(f["total_cases"] for f in families)},
    }


def build_oracle_semantics(events_doc: dict[str, Any], case_doc: dict[str, Any]) -> dict[str, Any]:
    events = events_doc.get("events", [])
    phases = event_phase_counts(events)
    accepted = count_values(events, "accepted")
    full = count_values(events, "full_consumption")
    gap_candidates = [
        c["case_id"] for c in case_doc["cases"] if c["semantic_observation"] == "full_consumption_gap_candidate"
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
        "semantic_outcome": {
            "all_cases_rejected": accepted["true"] == 0 and accepted["false"] > 0,
            "any_success_accept": accepted["true"] > 0,
            "any_success_accept_with_trailing_unconsumed": bool(gap_candidates),
            "full_consumption_gap_candidates": gap_candidates,
            "needs_more_valid_mutation_inputs": accepted["true"] == 0,
            "interpretation": "No accepted=true parser path was observed; full_consumption=false occurs on reject/error paths and is not a full-consumption validation gap by itself.",
        },
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
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
