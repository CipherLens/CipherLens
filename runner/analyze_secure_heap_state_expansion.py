import argparse
import json
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


SEED_API = "CRYPTO_secure_used"
SEED_STATES = {"pre_init_query", "done_then_query"}


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


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


def contains_crash_signal(text: str, signal: int | None) -> bool:
    lower = text.lower()
    return bool(signal in {6, 7, 11}) or any(pattern.lower() in lower for pattern in CRASH_PATTERNS)


def classify_crash(api: str, state: str, is_seed: bool, novelty_scope: str) -> str:
    if is_seed or (api == SEED_API and state in SEED_STATES):
        return "non_novel_seed_reproduction"
    if api != SEED_API:
        return "new_api_candidate"
    if state not in SEED_STATES:
        return "new_state_combination_candidate"
    if novelty_scope == "current_version_robustness_candidate":
        return "current_version_robustness_candidate"
    return "current_version_robustness_candidate"


def classify(record: Dict[str, Any]) -> Dict[str, Any]:
    manifest = find_manifest(record)
    text = text_for(record)
    run = record.get("run", {}) or {}
    status = record.get("status", "")
    exit_code = run.get("returncode")
    signal = signal_from_returncode(exit_code)

    api = str(manifest.get("api_under_test", ""))
    role = str(manifest.get("api_role", ""))
    state = str(manifest.get("state_sequence", ""))
    is_seed = bool(manifest.get("is_seed_case", False))
    novelty_scope = str(manifest.get("novelty_scope", ""))

    crash = contains_crash_signal(text, signal)
    asan = "AddressSanitizer" in text
    ubsan = "UndefinedBehaviorSanitizer" in text or "runtime error:" in text
    valgrind_invalid_read = "Invalid read" in text

    verdict = "api_precondition_or_usage_triage"
    novelty_label = novelty_scope or "api_precondition_misuse"
    reason = "Default triage: no explicit crash evidence and no recognized safe marker."

    if status == "compile_error":
        verdict = "harness_error"
        novelty_label = "harness_error"
        reason = "Compilation failed."
    elif status == "run_timeout":
        verdict = "harness_error"
        novelty_label = "harness_error"
        reason = "Harness timed out."
    elif "[HARNESS_ERROR]" in text:
        verdict = "harness_error"
        novelty_label = "harness_error"
        reason = "Harness setup reported an error."
    elif crash:
        verdict = "crash_candidate"
        novelty_label = classify_crash(api, state, is_seed, novelty_scope)
        reason = "Explicit crash evidence observed: signal, sanitizer, or crash marker."
        if state in {"initialized_query", "initialized_alloc_free_control"}:
            verdict = "harness_error"
            novelty_label = "harness_error"
            reason = "Initialized control crashed; harness or environment is unreliable."
    elif status == "run_nonzero":
        verdict = "api_precondition_or_usage_triage"
        novelty_label = "api_precondition_misuse"
        reason = "Nonzero exit without explicit crash evidence."
    elif "[OK] secure_heap_state_lifecycle:" in text:
        verdict = "normal_defined_behavior"
        novelty_label = "normal_defined_behavior"
        reason = "Case returned without crash and printed an OK marker."

    return {
        "case_id": manifest.get("case_id") or Path(record.get("relative_source", "")).stem,
        "source": record.get("source", ""),
        "library": record.get("library", ""),
        "raw_status": status,
        "exit_code": exit_code,
        "signal": signal,
        "api_under_test": api,
        "api_role": role,
        "state_sequence": state,
        "is_seed_case": is_seed,
        "expected_control": manifest.get("expected_control", ""),
        "novelty_scope": novelty_scope,
        "novelty_label": novelty_label,
        "version_classification": "current_version_robustness_candidate"
        if novelty_label in {"new_api_candidate", "new_state_combination_candidate", "current_version_robustness_candidate"}
        else "not_reproduced",
        "crash_signal": {
            "has_crash_signal": crash,
            "exit_code": exit_code,
            "signal": signal,
            "asan": asan,
            "ubsan": ubsan,
            "valgrind_invalid_read": valgrind_invalid_read,
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
    parser = argparse.ArgumentParser(description="Analyze secure heap state lifecycle expansion results.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--case-output", required=True)
    parser.add_argument("--behavior-output", required=True)
    parser.add_argument("--novel-output", required=True)
    parser.add_argument("--seed-output", required=True)
    parser.add_argument("--feedback-output", required=True)
    args = parser.parse_args()

    records = load_jsonl(Path(args.input))
    verdicts = [classify(record) for record in records]
    verdict_counts = Counter(v["verdict"] for v in verdicts)
    raw_counts = Counter(v["raw_status"] for v in verdicts)
    novelty_counts = Counter(v["novelty_label"] for v in verdicts)

    novel_labels = {
        "new_api_candidate",
        "new_state_combination_candidate",
        "current_version_robustness_candidate",
        "potential_regression_candidate",
    }
    novel = [v for v in verdicts if v["novelty_label"] in novel_labels]
    seed = [v for v in verdicts if v["novelty_label"] == "non_novel_seed_reproduction"]

    summary = {
        "input": args.input,
        "family": "secure_heap_state_lifecycle",
        "seed_issue": "OPENSSL-ISSUE-28669",
        "execution_mode": "same_family_state_expansion",
        "total_cases": len(verdicts),
        "raw_status_counts": dict(raw_counts),
        "verdict_counts": dict(verdict_counts),
        "novelty_counts": dict(novelty_counts),
        "crash_candidate_cases": [v["case_id"] for v in verdicts if v["verdict"] == "crash_candidate"],
        "harness_error_cases": [v["case_id"] for v in verdicts if v["verdict"] == "harness_error"],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_jsonl(Path(args.case_output), verdicts)
    write_jsonl(Path(args.novel_output), novel)
    write_jsonl(Path(args.seed_output), seed)

    behavior = {
        "family": "secure_heap_state_lifecycle",
        "seed_issue": "OPENSSL-ISSUE-28669",
        "total_cases": len(verdicts),
        "api_group": sorted({v["api_under_test"] for v in verdicts if v["api_under_test"]}),
        "state_sequences": sorted({v["state_sequence"] for v in verdicts if v["state_sequence"]}),
        "verdict_counts": dict(verdict_counts),
        "raw_status_counts": dict(raw_counts),
        "novelty_counts": dict(novelty_counts),
        "strict_interpretation": (
            "Crash candidates are robustness candidates only. They are not confirmed "
            "vulnerabilities or CVEs without API contract and version confirmation."
        ),
    }
    Path(args.behavior_output).write_text(json.dumps(behavior, indent=2, ensure_ascii=False), encoding="utf-8")

    feedback = []
    for v in verdicts:
        feedback.append({
            "family": "secure_heap_state_lifecycle",
            "seed_issue": "OPENSSL-ISSUE-28669",
            "case_id": v["case_id"],
            "api_under_test": v["api_under_test"],
            "api_role": v["api_role"],
            "state_sequence": v["state_sequence"],
            "is_seed_case": v["is_seed_case"],
            "novelty_label": v["novelty_label"],
            "crash_signal": v["crash_signal"],
            "verdict": v["verdict"],
        })
    write_jsonl(Path(args.feedback_output), feedback)

    print(f"[INFO] total cases: {len(verdicts)}")
    print(f"[INFO] raw status counts: {dict(raw_counts)}")
    print(f"[INFO] verdict counts: {dict(verdict_counts)}")
    print(f"[INFO] novelty counts: {dict(novelty_counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
