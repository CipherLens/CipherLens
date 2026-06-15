import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


MUTATION_DIMENSIONS = [
    "verify_api",
    "key_type",
    "signature_mutation",
    "digest_mutation",
    "key_mutation",
    "padding_mutation",
    "lifecycle_sequence",
    "mac_algorithm",
    "digest_or_cipher",
]

CRASH_MARKERS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "SEGV",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
]


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def source_case_id(source: str) -> str:
    parts = Path(source).parts
    for part in reversed(parts):
        if part.endswith(".c"):
            continue
        if part:
            return part
    return Path(source).stem


def manifest_for_source(case_manifest_root: Path, source: str) -> Optional[Path]:
    case_id = source_case_id(source)
    candidates = [
        case_manifest_root / case_id / "render_matrix_case_manifest.yaml",
        case_manifest_root / case_id / "template_meta.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def mutation_values(manifest: Dict[str, Any]) -> Dict[str, str]:
    values = {}
    source_entry = manifest.get("source_matrix_entry", {})
    if isinstance(source_entry, dict) and isinstance(source_entry.get("values"), dict):
        values.update({str(k): str(v) for k, v in source_entry.get("values", {}).items()})
    for dim in MUTATION_DIMENSIONS:
        if dim in manifest:
            values[dim] = str(manifest.get(dim))
    return values


def classify_feedback(verdict: str, raw_status: str, run_obj: Dict[str, Any]) -> str:
    text = "\n".join([
        str((run_obj.get("run") or {}).get("stdout", "")),
        str((run_obj.get("run") or {}).get("stderr", "")),
        str((run_obj.get("compile") or {}).get("stderr", "")),
    ])
    if any(marker in text for marker in CRASH_MARKERS) or run_obj.get("exit_code") == 139:
        return "crash_candidate"
    if raw_status in {"compile_error", "link_error", "template_render_error"}:
        return "harness_error"
    if verdict in {"safe_reject_behavior", "migrated_safe"}:
        return "safe_negative"
    if verdict in {"normal_expected_behavior", "normal_behavior"}:
        return "normal_expected_behavior"
    if verdict in {"unexpected_success_candidate", "bug_candidate", "migrated_bug_candidate"}:
        return "unexpected_success_candidate"
    if verdict in {"projection_limitation", "semantic_projection_limitation"}:
        return "projection_limitation"
    if "triage" in verdict:
        return "triage"
    return verdict or raw_status or "unknown"


def novelty_score(category: str) -> float:
    if category == "crash_candidate":
        return 5.0
    if category == "unexpected_success_candidate":
        return 4.0
    if category == "triage":
        return 2.0
    if category == "harness_error":
        return 0.5
    if category == "normal_expected_behavior":
        return 0.0
    if category == "safe_negative":
        return -0.2
    if category == "projection_limitation":
        return -1.0
    return 0.0


def read_behavior_summary(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def collect_feedback(
    run_jsonl: Path,
    verdicts_jsonl: Path,
    behavior_summary: Path,
    case_manifest_root: Path,
    family: str,
) -> List[Dict[str, Any]]:
    runs = {row.get("source"): row for row in read_jsonl(run_jsonl)}
    verdicts = read_jsonl(verdicts_jsonl)
    summary = read_behavior_summary(behavior_summary)
    rows: List[Dict[str, Any]] = []

    for verdict_obj in verdicts:
        source = str(verdict_obj.get("source") or "")
        run_obj = runs.get(source, {})
        raw_status = str(verdict_obj.get("raw_status") or run_obj.get("status") or "")
        verdict = str(verdict_obj.get("verdict") or "")
        manifest_path = manifest_for_source(case_manifest_root, source)
        manifest = load_yaml(manifest_path) if manifest_path else {}
        values = mutation_values(manifest)
        category = classify_feedback(verdict, raw_status, run_obj)
        target_api = str(
            values.get("verify_api")
            or verdict_obj.get("target_api")
            or (verdict_obj.get("template") or {}).get("target_api")
            or ""
        )
        rows.append({
            "family": family,
            "case_id": str(manifest.get("case_id") or source_case_id(source)),
            "source": source,
            "target_library": str(verdict_obj.get("target_library") or verdict_obj.get("library") or ""),
            "target_api": target_api,
            "raw_status": raw_status,
            "verdict": verdict,
            "feedback_category": category,
            "novelty_score": novelty_score(category),
            "repairable": category == "harness_error",
            "mutation_values": values,
            "expected_verdict_class": str(manifest.get("expected_verdict_class") or ""),
            "high_value": bool((manifest.get("source_matrix_entry") or {}).get("high_value", False)),
            "manifest": str(manifest_path or ""),
            "reason": str(verdict_obj.get("reason") or ""),
            "behavior_summary": {
                "path": str(behavior_summary),
                "verdict_counts": summary.get("verdict_counts", {}),
            },
        })
    return rows


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect mutation feedback from run and verdict artifacts.")
    parser.add_argument("--run-jsonl", required=True, type=Path)
    parser.add_argument("--verdicts-jsonl", required=True, type=Path)
    parser.add_argument("--behavior-summary", required=True, type=Path)
    parser.add_argument("--case-manifest-root", required=True, type=Path)
    parser.add_argument("--family", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    rows = collect_feedback(
        run_jsonl=args.run_jsonl,
        verdicts_jsonl=args.verdicts_jsonl,
        behavior_summary=args.behavior_summary,
        case_manifest_root=args.case_manifest_root,
        family=args.family,
    )
    write_jsonl(args.out, rows)
    verdict_counts = Counter(row["feedback_category"] for row in rows)
    print(f"[OK] mutation feedback written to {args.out}")
    print(f"[INFO] feedback_rows: {len(rows)}")
    print(f"[INFO] feedback_categories: {dict(verdict_counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
