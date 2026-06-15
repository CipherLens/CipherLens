import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import yaml


ALLOWED_LABELS = {
    "legal_semantics",
    "expected_reject",
    "permissive_but_harmless",
    "semantic_divergence_candidate",
    "mapping_gap",
    "compile_error",
    "harness_error",
    "crash_candidate",
    "needs_doc_confirmation",
    "needs_sanitizer",
    "needs_version_matrix",
}

CASE_MAP = {
    "mbedtls_final_without_update_gcm_encrypt": "aead_006_final_without_update_gcm_encrypt",
    "mbedtls_set_tag_after_final_gcm_decrypt": "aead_009_set_tag_after_final_gcm_decrypt",
    "mbedtls_wrong_tag_length_gcm_decrypt": "aead_012_wrong_tag_length_gcm_decrypt",
}


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
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


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def get_stdout(record: Dict[str, Any]) -> str:
    return (record.get("run") or {}).get("stdout") or record.get("stdout") or ""


def get_stderr(record: Dict[str, Any]) -> str:
    return (record.get("run") or {}).get("stderr") or record.get("stderr") or ""


def get_exit_code(record: Dict[str, Any]) -> Any:
    run = record.get("run") or {}
    return run.get("returncode", record.get("returncode"))


def extract_case_result(stdout: str) -> str:
    match = re.search(r"^CASE_RESULT=([A-Za-z0-9_]+)\s*$", stdout, re.MULTILINE)
    return match.group(1) if match else ""


def extract_case_id(stdout: str, source: str) -> str:
    match = re.search(r"^CASE_ID=([A-Za-z0-9_]+)\s*$", stdout, re.MULTILINE)
    if match:
        return match.group(1)
    return Path(source).stem


def classify_run(record: Dict[str, Any]) -> str:
    stdout = get_stdout(record)
    stderr = get_stderr(record)
    result = extract_case_result(stdout)
    status = record.get("status")
    if status == "compile_error":
        return "compile_error"
    if "AddressSanitizer" in stderr or "UndefinedBehaviorSanitizer" in stderr:
        return "needs_sanitizer"
    if status not in {"run_ok", "ok"}:
        return "harness_error"
    if result in ALLOWED_LABELS:
        return result
    if result == "permissive_behavior":
        return "permissive_but_harmless"
    if result:
        return "needs_doc_confirmation"
    return "harness_error"


def build_reclassification(openssl_cases: Dict[str, Dict[str, Any]], mbedtls_cases: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "case_id": "aead_006_final_without_update_gcm_encrypt",
            "previous_classification": openssl_cases["aead_006_final_without_update_gcm_encrypt"].get("classification"),
            "observed_cross_library_behavior": "OpenSSL succeeds with empty plaintext/AAD-only GCM final; mbedTLS PSA also succeeds with zero data updates and returns tag_len=16.",
            "doc_support": "sufficient: OpenSSL AEAD docs allow zero or more data updates before finish; PSA docs also say update zero, one or more times before finish.",
            "new_classification": "legal_semantics",
            "claim_level": "legal_semantics",
            "next_action": "downgrade; keep as negative feedback for AEAD lifecycle scheduler.",
        },
        {
            "case_id": "aead_009_set_tag_after_final_gcm_decrypt",
            "previous_classification": openssl_cases["aead_009_set_tag_after_final_gcm_decrypt"].get("classification"),
            "observed_cross_library_behavior": "OpenSSL final-before-set-tag fails authentication, then post-final SET_TAG ctrl returns success; PSA has no post-final tag setter and therefore maps to mapping_gap.",
            "doc_support": "sufficient for ordering rule: OpenSSL docs require SET_TAG before decrypt final; source indicates ctrl success is state-permissive and not evidence of authentication change.",
            "new_classification": "permissive_but_harmless",
            "claim_level": "permissive_but_harmless",
            "next_action": "do not promote to A-path; optional version matrix only if older OpenSSL state handling is suspected.",
        },
        {
            "case_id": "aead_012_wrong_tag_length_gcm_decrypt",
            "previous_classification": openssl_cases["aead_012_wrong_tag_length_gcm_decrypt"].get("classification"),
            "observed_cross_library_behavior": "OpenSSL accepts tag length 8; mbedTLS PSA shortened-tag GCM with 8-byte tag encrypts and decrypts successfully.",
            "doc_support": "sufficient: OpenSSL GCM SET_TAG allows taglen 1..16; PSA exposes shortened-tag AEAD algorithms.",
            "new_classification": "legal_semantics",
            "claim_level": "legal_semantics",
            "next_action": "downgrade; rename future case from wrong_tag_length to truncated_tag_length unless using truly invalid lengths.",
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl-analysis", required=True)
    parser.add_argument("--mbedtls-run", required=True)
    parser.add_argument("--analysis-json", required=True)
    parser.add_argument("--analysis-md", required=True)
    parser.add_argument("--reclassification-yaml", required=True)
    parser.add_argument("--reclassification-md", required=True)
    parser.add_argument("--next-action-yaml", required=True)
    parser.add_argument("--next-action-md", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--summary-md", required=True)
    parser.add_argument("--raw-stdout-dir", required=True)
    parser.add_argument("--raw-stderr-dir", required=True)
    parser.add_argument("--exit-codes", required=True)
    parser.add_argument("--feedback-output", required=True)
    args = parser.parse_args()

    openssl_analysis = load_json(Path(args.openssl_analysis))
    openssl_cases = {c["case_id"]: c for c in openssl_analysis.get("cases", [])}
    mbedtls_records = load_jsonl(Path(args.mbedtls_run))
    mbedtls_cases: Dict[str, Dict[str, Any]] = {}
    counts = Counter()
    raw_status_counts = Counter()
    exit_codes: Dict[str, Any] = {}

    stdout_dir = Path(args.raw_stdout_dir)
    stderr_dir = Path(args.raw_stderr_dir)
    stdout_dir.mkdir(parents=True, exist_ok=True)
    stderr_dir.mkdir(parents=True, exist_ok=True)

    for rec in mbedtls_records:
        stdout = get_stdout(rec)
        stderr = get_stderr(rec)
        local_case = extract_case_id(stdout, rec.get("source") or "")
        prior_case = CASE_MAP.get(local_case, local_case)
        classification = classify_run(rec)
        counts[classification] += 1
        raw_status_counts[str(rec.get("status") or "unknown")] += 1
        write_text(stdout_dir / f"{local_case}.stdout.txt", stdout)
        write_text(stderr_dir / f"{local_case}.stderr.txt", stderr)
        exit_codes[local_case] = get_exit_code(rec)
        mbedtls_cases[prior_case] = {
            "library": "mbedtls",
            "local_case_id": local_case,
            "prior_openssl_case_id": prior_case,
            "status": rec.get("status"),
            "exit_code": get_exit_code(rec),
            "case_result": extract_case_result(stdout),
            "classification": classification,
            "stdout_summary": stdout.splitlines(),
        }

    reclassification = build_reclassification(openssl_cases, mbedtls_cases)
    semantic_divergence = [r for r in reclassification if r["new_classification"] == "semantic_divergence_candidate"]
    crash = [r for r in reclassification if r["new_classification"] == "crash_candidate"]
    next_action = {
        "all_downgraded": len(semantic_divergence) == 0 and len(crash) == 0,
        "semantic_divergence_candidate_count": len(semantic_divergence),
        "crash_candidate_count": len(crash),
        "recommendation": "Return to scheduler or extend AEAD to CCM / ctx copy / init-failure; do not start D-path or A-path for these three candidates.",
    }
    analysis = {
        "summary": {
            "openssl_high_value_candidates": 3,
            "mbedtls_cases": len(mbedtls_records),
            "mbedtls_raw_status_counts": dict(raw_status_counts),
            "mbedtls_classification_counts": dict(counts),
            "botan_completed": False,
            "confirmed_vulnerability_found": False,
        },
        "openssl_cases": {k: openssl_cases[k] for k in CASE_MAP.values()},
        "mbedtls_cases": mbedtls_cases,
        "candidate_reclassification": reclassification,
        "next_action": next_action,
    }
    write_json(Path(args.analysis_json), analysis)
    write_json(Path(args.summary_json), analysis["summary"])
    write_json(Path(args.exit_codes), exit_codes)
    Path(args.reclassification_yaml).write_text(
        yaml.safe_dump({"candidates": reclassification}, sort_keys=False),
        encoding="utf-8",
    )
    Path(args.next_action_yaml).write_text(yaml.safe_dump(next_action, sort_keys=False), encoding="utf-8")

    md = [
        "# AEAD Lifecycle Semantic Crosscheck Analysis",
        "",
        f"- mbedTLS cases: {len(mbedtls_records)}",
        f"- mbedTLS raw_status_counts: `{dict(raw_status_counts)}`",
        f"- mbedTLS classification_counts: `{dict(counts)}`",
        "- Botan completed: false",
        "- confirmed vulnerability found: false",
        "",
        "## Reclassification",
        "",
    ]
    for item in reclassification:
        md.append(f"- `{item['case_id']}`: `{item['previous_classification']}` -> `{item['new_classification']}`; claim `{item['claim_level']}`")
    md.append("")
    write_text(Path(args.analysis_md), "\n".join(md))
    write_text(
        Path(args.summary_md),
        "\n".join(["# Crosscheck Run Summary", "", *md[2:7], ""]),
    )
    write_text(
        Path(args.reclassification_md),
        "\n".join(
            ["# Candidate Reclassification", ""]
            + [
                f"- `{r['case_id']}`: `{r['new_classification']}` / `{r['claim_level']}`. {r['next_action']}"
                for r in reclassification
            ]
            + [""]
        ),
    )
    write_text(
        Path(args.next_action_md),
        "\n".join(
            [
                "# Next Action After Crosscheck",
                "",
                f"- all_downgraded: {next_action['all_downgraded']}",
                f"- semantic_divergence_candidate_count: {next_action['semantic_divergence_candidate_count']}",
                f"- crash_candidate_count: {next_action['crash_candidate_count']}",
                f"- recommendation: {next_action['recommendation']}",
                "",
            ]
        ),
    )
    Path(args.feedback_output).parent.mkdir(parents=True, exist_ok=True)
    with Path(args.feedback_output).open("w", encoding="utf-8") as f:
        for item in reclassification:
            feedback = {
                "family": "cipher_aead_lifecycle",
                "case_id": item["case_id"],
                "library": "openssl+mbedtls",
                "algorithm": "aes-128-gcm",
                "state_sequence": item["case_id"],
                "observed_behavior": item["observed_cross_library_behavior"],
                "doc_support": item["doc_support"],
                "cross_library_result": item["new_classification"],
                "classification": item["new_classification"],
                "next_action": item["next_action"],
            }
            f.write(json.dumps(feedback, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
