import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import yaml


CRASH_PATTERNS = [
    "[CRASH] secure_heap_state_lifecycle",
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "SEGV",
    "segmentation fault",
    "Invalid read",
]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_yaml_if_exists(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def find_manifest(record: Dict[str, Any]) -> Dict[str, Any]:
    source = Path(record.get("source", ""))
    if not source:
        return {}
    return load_yaml_if_exists(source.parent / "case_manifest.yaml")


def text_for(record: Dict[str, Any]) -> str:
    compile_part = record.get("compile", {}) or {}
    run_part = record.get("run", {}) or {}
    return "\n".join([
        str(compile_part.get("stdout", "")),
        str(compile_part.get("stderr", "")),
        str(run_part.get("stdout", "")),
        str(run_part.get("stderr", "")),
    ])


def contains_any(text: str, patterns: List[str]) -> bool:
    lower = text.lower()
    return any(p.lower() in lower for p in patterns)


def signal_from_returncode(code: Any) -> int | None:
    try:
        code = int(code)
    except Exception:
        return None
    if code >= 128:
        return code - 128
    if code < 0:
        return -code
    return None


def classify(record: Dict[str, Any]) -> Dict[str, Any]:
    manifest = find_manifest(record)
    text = text_for(record)
    run = record.get("run", {}) or {}
    status = record.get("status", "")
    returncode = run.get("returncode")
    signal = signal_from_returncode(returncode)

    dims = manifest.get("mutation_dimensions", {}) if isinstance(manifest.get("mutation_dimensions"), dict) else {}
    state = str(dims.get("secure_heap_state", ""))
    seq = str(dims.get("call_sequence", ""))
    expected = str(manifest.get("expected_control", ""))

    crash = bool(signal in {6, 7, 11}) or contains_any(text, CRASH_PATTERNS)
    asan = "AddressSanitizer" in text
    ubsan = "UndefinedBehaviorSanitizer" in text or "runtime error:" in text
    invalid_read = "Invalid read" in text

    verdict = "api_misuse_needs_triage"
    reason = "Default triage: no crash evidence and no recognized safe marker."

    if status == "compile_error":
        verdict = "harness_error"
        reason = "Compilation failed."
    elif status == "run_timeout":
        verdict = "harness_error"
        reason = "Harness timed out."
    elif crash:
        if state == "initialized":
            verdict = "harness_error"
            reason = "Initialized control crashed; environment or harness is unreliable."
        else:
            verdict = "crash_candidate"
            reason = "Explicit crash evidence observed: signal/sanitizer/Valgrind-like marker."
    elif "[HARNESS_ERROR]" in text:
        verdict = "harness_error"
        reason = "Harness setup reported an error."
    elif "[OK] secure_heap_state_lifecycle: initialized control" in text:
        verdict = "normal_defined_behavior"
        reason = "Initialized control returned a defined value without crash."
    elif "[OK] secure_heap_state_lifecycle: initialized_check_then_used" in text:
        verdict = "normal_defined_behavior"
        reason = "Initialized check plus used returned a defined value without crash."
    elif "[OK] secure_heap_state_lifecycle: initialized check prevented" in text:
        verdict = "safe_precondition_failure"
        reason = "Precondition check prevented post-done used call."
    elif "[OK] secure_heap_state_lifecycle:" in text:
        if state in {"pre_init", "initialized_then_done"}:
            verdict = "safe_precondition_failure"
            reason = "Potential precondition path returned without crash."
        else:
            verdict = "normal_defined_behavior"
            reason = "Case returned defined behavior without crash."
    elif status == "run_nonzero":
        verdict = "api_misuse_needs_triage"
        reason = "Nonzero exit without explicit crash evidence."

    return {
        "case_id": manifest.get("case_id") or Path(record.get("relative_source", "")).stem,
        "source": record.get("source", ""),
        "library": record.get("library", ""),
        "raw_status": status,
        "exit_code": returncode,
        "signal": signal,
        "mutation_dimensions": dims,
        "expected_control": expected,
        "signals": {
            "exit_code": returncode,
            "signal": signal,
            "valgrind_invalid_read": invalid_read,
            "asan": asan,
            "ubsan": ubsan,
        },
        "verdict": verdict,
        "reason": reason,
    }


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze secure heap state lifecycle sprint results.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--case-output", required=True)
    parser.add_argument("--behavior-output", required=True)
    parser.add_argument("--novel-output", required=True)
    parser.add_argument("--feedback-output", default="")
    args = parser.parse_args()

    records = load_jsonl(Path(args.input))
    verdicts = [classify(record) for record in records]
    counts = Counter(v["verdict"] for v in verdicts)
    raw_counts = Counter(v["raw_status"] for v in verdicts)

    summary = {
        "input": args.input,
        "total_cases": len(verdicts),
        "verdict_counts": dict(counts),
        "raw_status_counts": dict(raw_counts),
        "crash_candidate_cases": [v["case_id"] for v in verdicts if v["verdict"] == "crash_candidate"],
        "cases": verdicts,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_jsonl(Path(args.case_output), verdicts)

    behavior = {
        "family": "secure_heap_state_lifecycle",
        "seed_issue": "OPENSSL-ISSUE-28669",
        "verdict_counts": dict(counts),
        "raw_status_counts": dict(raw_counts),
        "pre_init_crash_reproduced": any(
            v["verdict"] == "crash_candidate"
            and v.get("mutation_dimensions", {}).get("secure_heap_state") == "pre_init"
            for v in verdicts
        ),
        "initialized_control_ok": any(
            v["verdict"] == "normal_defined_behavior"
            and v.get("mutation_dimensions", {}).get("secure_heap_state") == "initialized"
            for v in verdicts
        ),
        "strict_interpretation": (
            "crash_candidate is not a confirmed vulnerability; API precondition "
            "and version behavior still need confirmation."
        ),
    }
    Path(args.behavior_output).write_text(json.dumps(behavior, indent=2, ensure_ascii=False), encoding="utf-8")

    novel = [v for v in verdicts if v["verdict"] in {"crash_candidate", "api_misuse_needs_triage"}]
    write_jsonl(Path(args.novel_output), novel)

    if args.feedback_output:
        feedback = []
        for v in verdicts:
            feedback.append({
                "family": "secure_heap_state_lifecycle",
                "seed_issue": "OPENSSL-ISSUE-28669",
                "case_id": v["case_id"],
                "mutation_dimensions": v.get("mutation_dimensions", {}),
                "signals": v.get("signals", {}),
                "verdict": v["verdict"],
            })
        write_jsonl(Path(args.feedback_output), feedback)

    print(f"[INFO] total cases: {len(verdicts)}")
    print(f"[INFO] verdict counts: {dict(counts)}")
    print(f"[INFO] output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
