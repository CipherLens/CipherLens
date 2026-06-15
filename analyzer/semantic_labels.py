"""Semantic labels for oracle-aware family analysis."""

from __future__ import annotations

from collections import Counter
from typing import Any


NORMAL_REJECT_OBSERVED = "normal_reject_observed"
NORMAL_ACCEPT_OBSERVED = "normal_accept_observed"
FULL_CONSUMPTION_GAP_CANDIDATE = "full_consumption_gap_candidate"
REJECTED_BEFORE_CONSUMPTION_SEMANTICS = "rejected_before_consumption_semantics"
ORACLE_EVENT_INCOMPLETE = "oracle_event_incomplete"


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


def classify_oracle_case(
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
            ORACLE_EVENT_INCOMPLETE,
            "oracle_incomplete",
            True,
            "no ORACLE_EVENT records were available for the case",
            "oracle instrumentation output fixup",
        )
    if accepted["true"] > 0 and full["false"] > 0:
        return (
            FULL_CONSUMPTION_GAP_CANDIDATE,
            "full_consumption_gap_candidate",
            True,
            "parser accepted at least one path while full_consumption=false was observed",
            "oracle semantic triage",
        )
    if accepted["true"] > 0:
        return (
            NORMAL_ACCEPT_OBSERVED,
            "normal_accept",
            False,
            "parser accepted and no accepted-path full-consumption gap was observed",
            "keep as accept-path control",
        )
    if accepted["false"] > 0:
        return (
            NORMAL_REJECT_OBSERVED,
            "normal_reject",
            False,
            "accepted=false path observed; full_consumption=false on reject path is not a gap by itself",
            "generate valid-prefix or near-valid variants",
        )
    return (
        ORACLE_EVENT_INCOMPLETE,
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
