from __future__ import annotations

import re
from pathlib import Path
from typing import Any


CASE_RE = re.compile(r"^case=(?P<name>\S+)\s+(?P<body>.+)$")
SUMMARY_RE = re.compile(r"^summary=(?P<name>\S+)\s+(?P<body>.*)$")
KEY_VALUE_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\S+)")


def _coerce(value: str) -> Any:
    if value in {"0", "1"}:
        return value == "1"
    try:
        return int(value)
    except ValueError:
        return value


def parse_structured_output(text: str) -> dict[str, Any]:
    cases: dict[str, dict[str, Any]] = {}
    summaries: dict[str, dict[str, Any]] = {}
    markers: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        case_match = CASE_RE.match(line)
        if case_match:
            fields = {
                item.group("key"): _coerce(item.group("value"))
                for item in KEY_VALUE_RE.finditer(case_match.group("body"))
            }
            cases[case_match.group("name")] = fields
            continue

        summary_match = SUMMARY_RE.match(line)
        if summary_match:
            fields = {
                item.group("key"): _coerce(item.group("value"))
                for item in KEY_VALUE_RE.finditer(summary_match.group("body"))
            }
            summaries[summary_match.group("name")] = fields
            continue

        if line.startswith("[") or "=" in line:
            markers.append(line)

    return {
        "cases": cases,
        "summaries": summaries,
        "markers": markers,
    }


def load_command_output(
    command_results: list[dict[str, Any]],
    command_name: str,
) -> str:
    parts: list[str] = []
    for result in command_results:
        if result.get("name") != command_name:
            continue
        for key in ("stdout_log", "stderr_log"):
            path = Path(str(result.get(key, "")))
            if path.is_file():
                parts.append(path.read_text(
                    encoding="utf-8", errors="replace"
                ))
    return "\n".join(parts)


def _case_satisfies(
    case: dict[str, Any],
    required: dict[str, Any],
) -> bool:
    return all(case.get(key) == value for key, value in required.items())


def evaluate_phase(
    parsed: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    cases = parsed.get("cases", {})
    baseline_name = str(spec.get("baseline_case", "canonical"))
    baseline_required = dict(spec.get("baseline_required") or {})
    mutation_names = list(spec.get("mutation_cases") or [])
    mutation_required = dict(spec.get("mutation_required") or {})
    expected_mutation_count = int(
        spec.get("expected_mutation_count", len(mutation_names))
    )

    baseline = dict(cases.get(baseline_name) or {})
    mutation_rows = {
        name: dict(cases.get(name) or {})
        for name in mutation_names
    }
    mutation_passes = {
        name: _case_satisfies(row, mutation_required)
        for name, row in mutation_rows.items()
    }

    return {
        "baseline_case": baseline_name,
        "baseline": baseline,
        "baseline_passed": _case_satisfies(
            baseline, baseline_required
        ),
        "mutation_cases": mutation_rows,
        "mutation_case_passes": mutation_passes,
        "mutation_pass_count": sum(mutation_passes.values()),
        "expected_mutation_count": expected_mutation_count,
        "mutations_passed": (
            len(mutation_passes) == expected_mutation_count
            and all(mutation_passes.values())
        ),
        "summaries": parsed.get("summaries", {}),
        "markers": parsed.get("markers", []),
    }


def parse_dynamic_evidence(
    command_results: list[dict[str, Any]],
    config: dict[str, Any],
) -> dict[str, Any]:
    baseline_command = str(
        config.get("baseline_command", "run_caller_harness")
    )
    fix_command = str(
        config.get("fix_control_command", "run_fix_control_harness")
    )

    baseline_text = load_command_output(
        command_results, baseline_command
    )
    fix_text = load_command_output(
        command_results, fix_command
    )

    baseline_parsed = parse_structured_output(baseline_text)
    fix_parsed = parse_structured_output(fix_text)

    baseline_eval = evaluate_phase(
        baseline_parsed,
        dict(config.get("baseline_phase") or {}),
    )
    fix_eval = evaluate_phase(
        fix_parsed,
        dict(config.get("fix_control_phase") or {}),
    )

    combined = baseline_text + "\n" + fix_text
    asan_patterns = list(config.get("asan_patterns") or [
        "AddressSanitizer", "heap-buffer-overflow",
        "use-after-free", "stack-buffer-overflow",
    ])
    ubsan_patterns = list(config.get("ubsan_patterns") or [
        "UndefinedBehaviorSanitizer", "runtime error:",
    ])

    return {
        "baseline_phase": baseline_eval,
        "fix_control_phase": fix_eval,
        "baseline_passed": baseline_eval["baseline_passed"],
        "mutation_candidate_confirmed": (
            baseline_eval["mutations_passed"]
        ),
        "fix_control_passed": (
            fix_eval["baseline_passed"]
            and fix_eval["mutations_passed"]
        ),
        "asan_error": any(
            pattern in combined for pattern in asan_patterns
        ),
        "ubsan_error": any(
            pattern in combined for pattern in ubsan_patterns
        ),
    }
