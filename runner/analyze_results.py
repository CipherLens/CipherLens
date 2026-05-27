import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import yaml


ASAN_PATTERNS = [
    "AddressSanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-free",
    "SEGV",
    "segmentation fault",
]

UBSAN_PATTERNS = [
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "undefined behavior",
]

BUG_PATTERNS = [
    "[BUG]",
    "Canary corrupted",
    "out-of-bounds write detected",
    "wrote beyond",
]

SAFE_PATTERNS = [
    "[OK] Canary intact",
    "fixed behavior",
    "rejected safely",
]

HARNESS_ERROR_PATTERNS = [
    "read A failed",
    "read B failed",
    "prepare_output_with_canary failed",
    "mbedtls_mpi_lset failed",
    "input construction failed",
    "BN_new failed",
]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def read_text_field(record: Dict[str, Any]) -> str:
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


def parse_ret_expected(text: str) -> Dict[str, Any]:
    ret = None
    expected = None

    m = re.search(r"\bret\s*=\s*(-?\d+)", text)
    if m:
        ret = int(m.group(1))

    m = re.search(r"\bexpected\s*=\s*(-?\d+)", text)
    if m:
        expected = int(m.group(1))

    return {
        "ret": ret,
        "expected": expected,
        "ret_matches_expected": ret is not None and expected is not None and ret == expected,
    }


def load_manifest_for_record(record: Dict[str, Any]) -> Dict[str, Any]:
    source = record.get("source", "")
    if not source:
        return {}

    src_path = Path(source)
    if not src_path.exists():
        return {}

    # Supported forms:
    #   default_mbedtls.c     -> default_manifest.yaml
    #   case_0000_mbedtls.c   -> case_0000_manifest.yaml
    stem = src_path.stem

    if stem.startswith("case_"):
        parts = stem.split("_")
        if len(parts) >= 2:
            prefix = "_".join(parts[:2])
        else:
            prefix = parts[0]
    else:
        prefix = stem.split("_", 1)[0]

    manifest = src_path.parent / f"{prefix}_manifest.yaml"

    if not manifest.exists():
        return {}

    try:
        with manifest.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def classify_record(record: Dict[str, Any]) -> Dict[str, Any]:
    status = record.get("status", "")
    text = read_text_field(record)
    run_part = record.get("run", {}) or {}
    compile_part = record.get("compile", {}) or {}

    ret_info = parse_ret_expected(text)

    result = {
        "source": record.get("source", ""),
        "relative_source": record.get("relative_source", ""),
        "library": record.get("library", ""),
        "raw_status": status,
        "verdict": "",
        "reason": "",
        "exit_code": run_part.get("returncode"),
        "compile_returncode": compile_part.get("returncode"),
        "run_timeout": run_part.get("timeout", False),
        "compile_timeout": compile_part.get("timeout", False),
        "ret": ret_info["ret"],
        "expected": ret_info["expected"],
        "ret_matches_expected": ret_info["ret_matches_expected"],
    }

    manifest = load_manifest_for_record(record)
    if manifest:
        result["template_id"] = manifest.get("template_id", "")
        result["case_name"] = manifest.get("case_name", "")
        result["mutation_mapping"] = manifest.get("mapping", {})

    if status == "compile_error":
        result["verdict"] = "build_or_template_error"
        result["reason"] = "Compilation failed. This usually indicates an invalid template, missing API, wrong library version, or missing compile flags."
        return result

    if status == "run_timeout":
        result["verdict"] = "timeout"
        result["reason"] = "The harness timed out during execution."
        return result

    if contains_any(text, ASAN_PATTERNS):
        result["verdict"] = "sanitizer_crash"
        result["reason"] = "ASAN-like crash pattern found in output."
        return result

    if contains_any(text, UBSAN_PATTERNS):
        result["verdict"] = "ubsan_crash"
        result["reason"] = "UBSAN-like runtime error pattern found in output."
        return result

    if contains_any(text, BUG_PATTERNS):
        result["verdict"] = "bug_candidate"
        result["reason"] = "Harness reported explicit BUG/canary corruption pattern."
        return result

    if contains_any(text, HARNESS_ERROR_PATTERNS):
        result["verdict"] = "harness_input_error"
        result["reason"] = "The generated case failed during input construction or harness setup."
        return result

    if ret_info["ret_matches_expected"]:
        result["verdict"] = "fixed_behavior"
        result["reason"] = "Return code matches expected fixed behavior and no bug/crash pattern was observed."
        return result

    if contains_any(text, SAFE_PATTERNS):
        result["verdict"] = "safe_behavior"
        result["reason"] = "Safe output pattern was observed and no bug/crash pattern was found."
        return result

    if status == "run_ok":
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = "Program exited normally, but no strong safe/fixed oracle pattern was found."
        return result

    if status == "run_nonzero":
        result["verdict"] = "nonzero_needs_triage"
        result["reason"] = "Program exited with nonzero code but no sanitizer or explicit BUG pattern was found."
        return result

    result["verdict"] = "unknown"
    result["reason"] = f"Unhandled raw status: {status}"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze runner jsonl results and produce verdict summary.")
    parser.add_argument(
        "--input",
        default="runner/results/run_default.jsonl",
        help="Input runner jsonl path.",
    )
    parser.add_argument(
        "--output",
        default="runner/results/run_default.summary.json",
        help="Output summary json path.",
    )
    parser.add_argument(
        "--case-output",
        default="",
        help="Optional per-case verdict jsonl path.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[ERROR] input result not found: {input_path}")
        return 1

    records = load_jsonl(input_path)
    cases = [classify_record(r) for r in records]

    verdict_counter = Counter(c["verdict"] for c in cases)
    raw_status_counter = Counter(c["raw_status"] for c in cases)

    summary = {
        "input": str(input_path),
        "total_cases": len(cases),
        "verdict_counts": dict(verdict_counter),
        "raw_status_counts": dict(raw_status_counter),
        "cases": cases,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    if args.case_output:
        case_out = Path(args.case_output)
        case_out.parent.mkdir(parents=True, exist_ok=True)
        with case_out.open("w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"[OK] summary written to {output_path}")
    print(f"[INFO] total cases: {len(cases)}")
    print(f"[INFO] verdict counts: {dict(verdict_counter)}")
    print(f"[INFO] raw status counts: {dict(raw_status_counter)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
