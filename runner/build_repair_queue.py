"""Build a constrained repair queue from runner results."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


REPAIRABLE = {"compile_error", "link_error", "template_render_error", "harness_error"}
NON_REPAIRABLE = {
    "sanitizer_crash",
    "semantic_candidate",
    "unexpected_success_candidate",
    "behavior_divergence_candidate",
    "safe_negative",
    "projection_limitation",
    "real_app_level_validation_gap_candidate",
    "runtime_error",
}
ALLOWED_SCOPE = [
    "include",
    "function_signature",
    "type_mismatch",
    "slot_binding",
    "buffer_length_constant",
    "api_parameter_order",
]
FORBIDDEN_CHANGES = [
    "remove_oracle",
    "disable_sanitizer",
    "skip_trigger_call",
    "change_expected_verdict",
    "delete_failure_path",
    "change_mutation_semantics",
]
RAG_NEEDED = ["api_signature", "parameter_semantics", "return_value_semantics"]
CRASH_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "SEGV",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
)


def _read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _excerpt(*parts: str, limit: int = 1600) -> str:
    text = "\n".join(part for part in parts if part)
    return text[:limit]


def _classify_failure(obj: Dict[str, Any]) -> str:
    status = str(obj.get("status") or obj.get("raw_status") or "")
    verdict = str(obj.get("verdict") or "")
    compile_obj = obj.get("compile") or {}
    run_obj = obj.get("run") or {}
    compile_stderr = str(compile_obj.get("stderr") or "")
    run_stderr = str(run_obj.get("stderr") or obj.get("stderr") or "")
    combined = f"{compile_stderr}\n{run_stderr}"

    if any(marker in combined for marker in CRASH_MARKERS) or run_obj.get("returncode") == 139:
        return "sanitizer_crash"
    if "render" in status:
        return "template_render_error"
    if "compile_error" in status or compile_obj.get("returncode") not in (None, 0):
        if "undefined reference" in compile_stderr or "ld:" in compile_stderr:
            return "link_error"
        return "compile_error"
    if "harness_error" in status or verdict == "harness_error":
        return "harness_error"
    if verdict in {"bug_candidate", "migrated_bug_candidate"}:
        return "semantic_candidate"
    if verdict in {"safe_reject_behavior", "migrated_safe"}:
        return "safe_negative"
    if "projection_limitation" in verdict:
        return "projection_limitation"
    return "runtime_error" if status == "run_nonzero" else "safe_negative"


def _task_for(obj: Dict[str, Any], failure_type: str, source_root: Optional[Path]) -> Dict[str, Any]:
    source = str(obj.get("source") or obj.get("relative_source") or "")
    case_path = source
    if source_root and source and not Path(source).is_absolute():
        candidate = source_root / source
        if candidate.exists():
            case_path = str(candidate)
    compile_obj = obj.get("compile") or {}
    run_obj = obj.get("run") or {}
    return {
        "case_id": str(obj.get("relative_source") or obj.get("source") or ""),
        "case_path": case_path,
        "failure_type": failure_type,
        "error_excerpt": _excerpt(
            str(compile_obj.get("stderr") or ""),
            str(run_obj.get("stderr") or ""),
            str(run_obj.get("stdout") or ""),
        ),
        "repair_attempt": 0,
        "max_attempts": 3,
        "allowed_repair_scope": ALLOWED_SCOPE,
        "forbidden_changes": FORBIDDEN_CHANGES,
        "rag_needed": RAG_NEEDED,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build constrained repair queue from runner results.")
    parser.add_argument("--run-jsonl", type=Path, required=True)
    parser.add_argument("--summary-json", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    tasks = []
    counts: Counter[str] = Counter()
    for obj in _read_jsonl(args.run_jsonl):
        failure_type = _classify_failure(obj)
        counts[failure_type] += 1
        if failure_type in REPAIRABLE:
            tasks.append(_task_for(obj, failure_type, args.source_root))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for task in tasks:
            f.write(json.dumps(task, sort_keys=True) + "\n")

    summary = {
        "run_jsonl": str(args.run_jsonl),
        "summary_json": str(args.summary_json) if args.summary_json else "",
        "total_repair_tasks": len(tasks),
        "failure_type_counts": dict(sorted(counts.items())),
        "repairable_types": sorted(REPAIRABLE),
        "non_repairable_types": sorted(NON_REPAIRABLE),
        "out": str(args.out),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
