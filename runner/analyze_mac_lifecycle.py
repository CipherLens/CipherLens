from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}
    return obj if isinstance(obj, dict) else {}


def parse_results(stdout: str) -> dict[str, int]:
    parsed: dict[str, int] = {}
    for line in stdout.splitlines():
        if not line.startswith("RESULT "):
            continue
        parts = line.split()
        if len(parts) != 4 or "=" not in parts[3]:
            continue
        key, value = parts[3].split("=", 1)
        try:
            parsed[key] = int(value)
        except ValueError:
            pass
    return parsed


def case_id_from_record(record: dict[str, Any]) -> str:
    rel = str(record.get("relative_source") or "")
    if "/" in rel:
        return rel.split("/", 1)[0]
    return Path(str(record.get("source") or "")).parent.name


def library_key(record: dict[str, Any]) -> str:
    lib = str(record.get("library") or "")
    if lib == "mbedtls":
        return "mbedtls_psa"
    return lib


def classify(case: dict[str, Any], openssl: dict[str, Any], psa: dict[str, Any]) -> str:
    dims = case.get("mutation_dimensions", {})
    sequence = dims.get("lifecycle_sequence")
    key_length = dims.get("key_length")
    if openssl.get("status") != "run_ok" or psa.get("status") != "run_ok":
        return "harness_error"

    o = openssl.get("signals", {})
    p = psa.get("signals", {})
    if key_length != "valid":
        return "needs_manual_triage"

    o_init = o.get("init_ok") == 1
    o_final1 = o.get("final1_ok") == 1
    p_import = p.get("import_status") == 0
    p_setup = p.get("setup_status") == 0
    p_final1 = p.get("final1_status") == 0

    if sequence == "normal_init_update_final":
        if o_init and o_final1 and p_import and p_setup and p_final1:
            return "normal_success"
        return "harness_error"

    if sequence == "repeated_final":
        openssl_repeated_ok = o.get("final2_ok") == 1
        psa_repeated_bad = p.get("final2_status") not in {0, None}
        if openssl_repeated_ok and psa_repeated_bad:
            return "behavior_divergence_candidate"
        if not openssl_repeated_ok and psa_repeated_bad:
            return "strict_bad_state"
        if openssl_repeated_ok and not psa_repeated_bad:
            return "permissive_legacy_behavior"
        return "needs_manual_triage"

    if sequence == "update_after_final":
        openssl_update_ok = o.get("update_after_final_ok") == 1
        psa_update_bad = p.get("update_after_final_status") not in {0, None}
        if openssl_update_ok and psa_update_bad:
            return "behavior_divergence_candidate"
        if not openssl_update_ok and psa_update_bad:
            return "strict_bad_state"
        if openssl_update_ok and not psa_update_bad:
            return "permissive_legacy_behavior"
        return "needs_manual_triage"

    if sequence == "abort_then_update":
        psa_abort_ok = p.get("abort_status") == 0
        psa_update_bad = p.get("update_after_abort_status") not in {0, None}
        if psa_abort_ok and psa_update_bad:
            return "strict_bad_state"
        return "needs_manual_triage"

    return "needs_manual_triage"


def analyze(result_path: Path, matrix_path: Path, out_dir: Path, feedback_path: Path) -> None:
    rows = read_jsonl(result_path)
    matrix = load_yaml(matrix_path)
    cases = {str(c["case_id"]): c for c in matrix.get("cases", []) or []}

    grouped: dict[str, dict[str, Any]] = defaultdict(dict)
    for row in rows:
        cid = case_id_from_record(row)
        lib = library_key(row)
        signals = parse_results((row.get("run") or {}).get("stdout") or "")
        grouped[cid][lib] = {
            "status": row.get("status"),
            "compile": row.get("compile", {}),
            "run": row.get("run", {}),
            "signals": signals,
            "source": row.get("source"),
        }

    verdict_rows = []
    feedback_rows = []
    novel_rows = []
    counts: Counter[str] = Counter()
    for cid, case in sorted(cases.items()):
        openssl = grouped.get(cid, {}).get("openssl", {"status": "missing", "signals": {}})
        psa = grouped.get(cid, {}).get("mbedtls_psa", {"status": "missing", "signals": {}})
        verdict = classify(case, openssl, psa)
        counts[verdict] += 1
        dims = case.get("mutation_dimensions", {})
        row = {
            "family": "mac_lifecycle",
            "case_id": cid,
            "mutation_dimensions": dims,
            "signals": {
                "openssl_status": openssl.get("status"),
                "psa_status": psa.get("status"),
                "openssl_output_mac": (openssl.get("signals", {}).get("out1_len") or 0) > 0,
                "psa_error_code": psa.get("signals", {}).get("final2_status")
                or psa.get("signals", {}).get("update_after_final_status")
                or psa.get("signals", {}).get("update_after_abort_status"),
                "openssl": openssl.get("signals", {}),
                "mbedtls_psa": psa.get("signals", {}),
            },
            "verdict": verdict,
        }
        verdict_rows.append(row)
        feedback_rows.append(row)
        if verdict in {"behavior_divergence_candidate", "permissive_legacy_behavior", "harness_error"}:
            novel_rows.append(row)

    summary = {
        "family": "mac_lifecycle",
        "total_cases": len(cases),
        "result_rows": len(rows),
        "verdict_counts": dict(counts),
        "note": "behavior_divergence_candidate is not a confirmed vulnerability or CVE.",
    }
    by_sequence: dict[str, Counter[str]] = defaultdict(Counter)
    by_key_length: dict[str, Counter[str]] = defaultdict(Counter)
    for row in verdict_rows:
        dims = row["mutation_dimensions"]
        by_sequence[str(dims.get("lifecycle_sequence"))][row["verdict"]] += 1
        by_key_length[str(dims.get("key_length"))][row["verdict"]] += 1
    behavior = {
        **summary,
        "by_lifecycle_sequence": {k: dict(v) for k, v in by_sequence.items()},
        "by_key_length": {k: dict(v) for k, v in by_key_length.items()},
    }

    write_json(out_dir / "run.summary.json", summary)
    write_json(out_dir / "behavior_summary.json", behavior)
    write_jsonl(out_dir / "run.verdicts.jsonl", verdict_rows)
    write_jsonl(out_dir / "novel_cases.jsonl", novel_rows)
    write_jsonl(feedback_path, feedback_rows)
    print(json.dumps(summary, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze MAC lifecycle controlled sprint results.")
    parser.add_argument("--result", type=Path, default=DEFAULT_RESULT if False else None)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--feedback", type=Path, required=True)
    args = parser.parse_args()
    if args.result is None:
        raise SystemExit("--result is required")
    analyze(args.result, args.matrix, args.out_dir, args.feedback)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
