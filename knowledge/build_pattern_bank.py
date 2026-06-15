import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]

CORE10_ROOT = PROJECT_ROOT / "data" / "pocs" / "core10"
OPENSSL_ARTIFACT_ROOT = PROJECT_ROOT / "datasets" / "openssl" / "poc_artifacts"
OPENSSL_SUMMARY = PROJECT_ROOT / "datasets" / "openssl" / "artifact_summary.csv"
PATTERN_BANK_ROOT = PROJECT_ROOT / "artifacts" / "pattern_bank"
POC_PATTERNS_ROOT = PROJECT_ROOT / "knowledge_raw" / "poc_patterns"

UNKNOWN = "unknown"
PENDING_CLASSIFICATION = "pending_classification"
PENDING_INFERENCE = "pending_inference"


CORE10_OVERRIDES: Dict[str, Dict[str, Any]] = {
    "MBEDTLS-POC-0001": {
        "family": "memory_length_boundary",
        "subfamily": "mpi_write_string_buffer_boundary",
        "oracle_type": "crash_or_sanitizer",
        "target_api": ["BN_bn2binpad", "BN_signed_bn2bin"],
        "migration_status": "pending_migration",
        "current_verdict": "unknown",
        "priority_score": 0.55,
        "priority_reasons": ["caller_buffer_boundary", "clear_memory_oracle"],
    },
    "MBEDTLS-POC-0002": {
        "family": "bn_mpi_arithmetic",
        "subfamily": "mpi_sub_abs_limb_boundary",
        "oracle_type": "projection_limitation",
        "target_api": ["BN_usub"],
        "migration_status": "projection_limitation",
        "current_verdict": "expected_library_behavior",
        "priority_score": 0.25,
        "priority_reasons": [
            "projection_limitation_observed",
            "likely_expected_library_behavior",
        ],
    },
    "MBEDTLS-POC-0003": {
        "family": "pkey_verify_semantic",
        "subfamily": "pk_verify_ext_null_deref",
        "oracle_type": "crash_or_sanitizer",
        "target_api": ["EVP_DigestVerify"],
        "migration_status": "pending_migration",
        "current_verdict": "unknown",
        "priority_score": 0.5,
        "priority_reasons": ["pkey_verify_dispatch", "crash_oracle"],
    },
    "MBEDTLS-POC-0004": {
        "family": "cipher_aead_lifecycle",
        "subfamily": "invalid_padding_output_length",
        "oracle_type": "behavior_divergence",
        "target_api": ["EVP_DecryptFinal_ex", "EVP_CipherFinal_ex"],
        "migration_status": "pending_migration",
        "current_verdict": "pending_inference",
        "priority_score": 0.65,
        "priority_reasons": ["clear_output_state_oracle", "return_code_outlen_semantic"],
    },
    "MBEDTLS-POC-0005": {
        "family": "api_state_machine",
        "subfamily": "zero_length_stale_state",
        "oracle_type": "safe_reject_baseline",
        "target_api": ["ASN1_STRING_set"],
        "migration_status": "migrated_safe",
        "current_verdict": "migrated_safe",
        "priority_score": 0.42,
        "priority_reasons": ["object_state_lifecycle", "safe_negative_baseline"],
        "notes": [
            "Local metadata and artifacts describe mbedtls_asn1_store_named_data stale state, not a MAC lifecycle issue.",
            "Historical request mentioned MAC for this PoC, but no local MAC evidence was found during this run.",
        ],
    },
    "MBEDTLS-POC-0011": {
        "family": "memory_length_boundary",
        "subfamily": "pem_empty_buffer_underflow",
        "oracle_type": "crash_or_sanitizer",
        "migration_status": "pending_migration",
        "current_verdict": "unknown",
        "priority_score": 0.5,
        "priority_reasons": ["pem_boundary", "underflow_oracle"],
    },
    "MBEDTLS-POC-0017": {
        "family": "asn1_nested_boundary",
        "subfamily": "x509_inner_boundary",
        "oracle_type": "safe_reject_baseline",
        "target_api": ["d2i_X509"],
        "migration_status": "migrated_safe",
        "current_verdict": "migrated_safe",
        "priority_score": 0.35,
        "priority_reasons": ["safe_safe_result", "useful_negative_case"],
    },
    "MBEDTLS-POC-0020": {
        "family": "der_full_consumption",
        "subfamily": "trailing_garbage",
        "oracle_type": "full_consumption_semantic",
        "target_api": ["d2i_RSAPrivateKey", "d2i_PrivateKey", "d2i_RSA_PUBKEY"],
        "migration_status": "migrated_candidate",
        "current_verdict": "behavior_divergence_candidate",
        "priority_score": 0.85,
        "priority_reasons": [
            "semantic_candidate_observed",
            "clear_oracle",
            "reusable_der_family",
        ],
    },
    "MBEDTLS-POC-0027": {
        "family": "x509_parsing",
        "subfamily": "tls_verify_result_semantic",
        "oracle_type": "behavior_divergence",
        "migration_status": "pending_migration",
        "current_verdict": "pending_inference",
        "priority_score": 0.45,
        "priority_reasons": ["semantic_correctness", "x509_tls_verdict"],
    },
    "MBEDTLS-POC-0028": {
        "family": "cipher_aead_lifecycle",
        "subfamily": "invalid_aead_tag_length_setup",
        "oracle_type": "unexpected_success",
        "migration_status": "pending_migration",
        "current_verdict": "pending_inference",
        "priority_score": 0.6,
        "priority_reasons": ["invalid_parameter_acceptance", "psa_aead_setup"],
    },
}


def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def read_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def safe_text(value: Any) -> str:
    if value is None:
        return UNKNOWN
    if isinstance(value, str):
        return value.strip() or UNKNOWN
    return str(value)


def listify(value: Any) -> List[str]:
    if value is None:
        return [UNKNOWN]
    if isinstance(value, list):
        values = [safe_text(x) for x in value if safe_text(x) != UNKNOWN]
        return values or [UNKNOWN]
    text = safe_text(value)
    return [text] if text != UNKNOWN else [UNKNOWN]


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def collect_artifact_files() -> List[Path]:
    roots = [
        PROJECT_ROOT / "artifacts" / "migrations",
        PROJECT_ROOT / "artifacts" / "triage",
        PROJECT_ROOT / "artifacts" / "sprints",
        PROJECT_ROOT / "artifacts" / "feedback",
    ]
    files: List[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file():
                files.append(path)
    return sorted(files)


def collect_evidence_files(
    all_files: Iterable[Path],
    terms: Iterable[str],
    limit: int = 24,
) -> List[str]:
    lowered_terms = [t.lower() for t in terms if t]
    matches: List[str] = []
    for path in all_files:
        s = rel(path).lower()
        if any(term in s for term in lowered_terms):
            matches.append(rel(path))
        if len(matches) >= limit:
            break
    return matches


def has_path_fragment(files: List[str], fragments: Iterable[str]) -> bool:
    lowered = [f.lower() for f in files]
    return any(any(fragment.lower() in path for fragment in fragments) for path in lowered)


def load_openssl_summary_rows() -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    if not OPENSSL_SUMMARY.exists():
        return rows
    with OPENSSL_SUMMARY.open("r", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            issue = safe_text(row.get("issue_number"))
            if issue != UNKNOWN:
                rows[issue] = row
    return rows


def infer_family(component: str, apis: List[str], title: str = "") -> Tuple[str, str]:
    text = " ".join([component, title] + apis).lower()
    if "evp/mac" in text or "evp_mac" in text or "cmac" in text or "hmac" in text:
        return "mac_lifecycle", "mac_context_state"
    if "pkey" in text or "digestsign" in text or "digestverify" in text or "cms" in text:
        return "pkey_verify_semantic", "pkey_sign_verify_or_encoding"
    if "x509" in text and "asn1" in text:
        return "x509_parsing", "x509_asn1_semantic"
    if "asn1" in text or "pkcs12" in text or "der" in text or "wpacket" in text:
        return "asn1_nested_boundary", "asn1_or_der_boundary"
    if "bn" in text or "bignum" in text or "rsa_get0" in text:
        return "bn_mpi_arithmetic", "bignum_state_or_boundary"
    if "evp/aes" in text or "cipher" in text or "gcm" in text or "drbg" in text:
        return "cipher_aead_lifecycle", "cipher_context_state"
    if "bio" in text or "secure_heap" in text or "crypto/mem" in text or "conf/openssl" in text:
        return "api_state_machine", "library_state_or_lifecycle"
    if "crl" in text or "verify" in text:
        return "x509_parsing", "x509_verify_semantic"
    return PENDING_CLASSIFICATION, PENDING_CLASSIFICATION


def infer_oracle(trigger: str) -> str:
    t = trigger.lower()
    if any(x in t for x in ["segv", "crash", "null_dereference", "assertion"]):
        return "crash_or_sanitizer"
    if any(x in t for x in ["wrong_result", "wrong_output", "verify_error", "corrupted_state"]):
        return "behavior_divergence"
    if "regression" in t:
        return "behavior_divergence"
    if not t or t == UNKNOWN.lower() or t == "unknown":
        return PENDING_INFERENCE
    return "unknown"


def summarize_results(evidence_files: List[str]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "total_cases": 0,
        "verdict_counts": {},
        "raw_status_counts": {},
        "migration_verdict_counts": {},
    }
    verdict_counts: Counter[str] = Counter()
    raw_counts: Counter[str] = Counter()
    migration_counts: Counter[str] = Counter()
    total = 0
    for name in evidence_files:
        path = PROJECT_ROOT / name
        if not path.name.endswith(".json"):
            continue
        data = read_json(path)
        if not isinstance(data, dict) or not data:
            continue
        total += int(data.get("total_cases") or 0)
        verdict_counts.update(data.get("verdict_counts") or {})
        raw_counts.update(data.get("raw_status_counts") or {})
        migration_counts.update(data.get("migration_verdict_counts") or {})
    summary["total_cases"] = total
    summary["verdict_counts"] = dict(verdict_counts)
    summary["raw_status_counts"] = dict(raw_counts)
    summary["migration_verdict_counts"] = dict(migration_counts)
    return summary


def build_core10_pattern(path: Path, all_artifact_files: List[Path]) -> Dict[str, Any]:
    metadata = read_json(path / "metadata.json")
    pattern_id = safe_text(metadata.get("poc_id") or path.name)
    classification = metadata.get("classification") or {}
    experiment = metadata.get("experiment_fields") or {}
    annotation = metadata.get("annotation") or {}
    override = CORE10_OVERRIDES.get(pattern_id, {})

    source_api = listify(classification.get("affected_api") or experiment.get("target_function"))
    root_cause = safe_text(annotation.get("root_cause") or experiment.get("buggy_behavior"))
    poc_num = pattern_id.split("-")[-1].lower()
    issue_terms = [
        pattern_id.lower(),
        f"mbedtls-poc-{poc_num}",
    ]
    evidence_files = collect_evidence_files(all_artifact_files, issue_terms)
    result_summary = summarize_results(evidence_files)

    current_verdict = safe_text(override.get("current_verdict"))
    migration_status = safe_text(override.get("migration_status"))
    if current_verdict == UNKNOWN:
        if result_summary["migration_verdict_counts"].get("migrated_bug_candidate"):
            current_verdict = "behavior_divergence_candidate"
            migration_status = "migrated_candidate"
        elif result_summary["migration_verdict_counts"].get("migrated_safe"):
            current_verdict = "migrated_safe"
            migration_status = "migrated_safe"
        elif result_summary["verdict_counts"].get("safe_reject_behavior"):
            current_verdict = "safe_reject_behavior"
            migration_status = migration_status if migration_status != UNKNOWN else "pending_migration"

    notes = [
        f"Dataset status: {safe_text(metadata.get('dataset_status'))}.",
        f"Failure signal: {safe_text(experiment.get('failure_signal'))}.",
    ]
    notes.extend(override.get("notes", []))
    if not evidence_files:
        notes.append("No local migration artifact was found during this run.")

    return {
        "pattern_id": pattern_id,
        "source_path": rel(path),
        "source_type": "core10_poc",
        "source_library": "mbedtls",
        "target_library": "openssl",
        "family": safe_text(override.get("family") or PENDING_CLASSIFICATION),
        "subfamily": safe_text(override.get("subfamily") or PENDING_CLASSIFICATION),
        "oracle_type": safe_text(override.get("oracle_type") or PENDING_INFERENCE),
        "root_cause": root_cause,
        "source_api": source_api,
        "target_api": listify(override.get("target_api") or UNKNOWN),
        "migration_status": migration_status if migration_status != UNKNOWN else PENDING_CLASSIFICATION,
        "current_verdict": current_verdict,
        "confidence": "medium" if evidence_files else "low",
        "has_controlled_template": has_path_fragment(
            evidence_files, ["rendered_cases", "cross_templates", "normalized_templates"]
        ),
        "has_render_matrix": has_path_fragment(evidence_files, ["render_matrix"]),
        "has_feedback": False,
        "has_rag_evidence": has_path_fragment(evidence_files, ["candidates_with_evidence"]),
        "priority_score": float(override.get("priority_score", 0.0)),
        "priority_reasons": listify(override.get("priority_reasons") or ["needs_classification"]),
        "evidence_files": evidence_files or [rel(path / "metadata.json")],
        "result_summary": result_summary,
        "notes": notes,
    }


def build_openssl_pattern(
    path: Path,
    summary_rows: Dict[str, Dict[str, Any]],
    all_artifact_files: List[Path],
) -> Dict[str, Any]:
    metadata = read_json(path / "metadata.json")
    issue = safe_text(metadata.get("issue_number") or path.name.replace("issue_", ""))
    row = summary_rows.get(issue, {})
    pattern_id = f"OPENSSL-ISSUE-{issue}"
    title = safe_text(metadata.get("title") or row.get("title"))
    component = safe_text(metadata.get("component") or row.get("component"))
    apis = listify(metadata.get("critical_api_or_function") or row.get("generated_c_api_path"))
    family, subfamily = infer_family(component, apis, title)
    oracle_type = infer_oracle(safe_text(metadata.get("trigger_behavior") or row.get("trigger_behavior")))

    evidence_files = collect_evidence_files(
        all_artifact_files,
        [f"issue-{issue}", f"issue_{issue}", f"openssl-issue-{issue}"],
    )
    result_summary = summarize_results(evidence_files)
    migration_status = "pending_migration"
    current_verdict = "unknown"
    if result_summary["migration_verdict_counts"].get("migrated_bug_candidate"):
        migration_status = "migrated_candidate"
        current_verdict = "behavior_divergence_candidate"
    elif result_summary["migration_verdict_counts"].get("migrated_safe"):
        migration_status = "migrated_safe"
        current_verdict = "migrated_safe"
    elif oracle_type == "crash_or_sanitizer" and safe_text(row.get("local_test_result")).startswith("segmentation"):
        migration_status = "pending_migration"
        current_verdict = "crash_or_sanitizer"
    elif family == PENDING_CLASSIFICATION:
        migration_status = PENDING_CLASSIFICATION

    priority_score, priority_reasons = score_pattern(
        family=family,
        oracle_type=oracle_type,
        migration_status=migration_status,
        current_verdict=current_verdict,
        has_controlled_template=bool(evidence_files),
        has_rag_evidence="C_rag" in safe_text(metadata.get("artifact_class") or row.get("artifact_class")),
        has_feedback=False,
    )

    notes = [
        f"Title: {title}.",
        f"Component: {component}.",
        f"Trigger behavior: {safe_text(metadata.get('trigger_behavior') or row.get('trigger_behavior'))}.",
    ]
    if row:
        notes.append(f"Artifact summary local_test_result: {safe_text(row.get('local_test_result'))}.")
        if safe_text(row.get("strict_reproduction")) == "False":
            notes.append("Local harness validation exists, but strict historical reproduction is not confirmed.")
    if not evidence_files:
        notes.append("Need to inspect README / metadata / crash / repro files.")

    return {
        "pattern_id": pattern_id,
        "source_path": rel(path),
        "source_type": "openssl_issue_artifact",
        "source_library": "openssl",
        "target_library": "unknown",
        "family": family,
        "subfamily": subfamily,
        "oracle_type": oracle_type,
        "root_cause": safe_text(metadata.get("root_cause")),
        "source_api": apis,
        "target_api": [UNKNOWN],
        "migration_status": migration_status,
        "current_verdict": current_verdict,
        "confidence": "medium" if family != PENDING_CLASSIFICATION else "low",
        "has_controlled_template": has_path_fragment(
            evidence_files, ["rendered_cases", "cross_templates", "poc.c"]
        ),
        "has_render_matrix": has_path_fragment(evidence_files, ["render_matrix"]),
        "has_feedback": False,
        "has_rag_evidence": "C_rag" in safe_text(metadata.get("artifact_class") or row.get("artifact_class")),
        "priority_score": priority_score,
        "priority_reasons": priority_reasons,
        "evidence_files": evidence_files or [rel(path / "metadata.json")],
        "result_summary": result_summary,
        "notes": notes,
    }


def load_pkey_feedback_summary() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    v0 = read_json(PROJECT_ROOT / "artifacts" / "sprints" / "pkey_verify_family_v0" / "results" / "run.summary.json")
    v1 = read_json(PROJECT_ROOT / "artifacts" / "sprints" / "pkey_verify_family_v1" / "results" / "run.summary.json")
    comparison = read_json(
        PROJECT_ROOT
        / "artifacts"
        / "sprints"
        / "pkey_verify_family_v1"
        / "results"
        / "v0_vs_v1_comparison.json"
    )
    verdict_counts: Counter[str] = Counter()
    total_cases = 0
    for summary in [v0, v1]:
        total_cases += int(summary.get("total_cases") or 0)
        verdict_counts.update(summary.get("verdict_counts") or {})
    feedback_summary = {
        "total_cases": total_cases,
        "verdict_counts": dict(verdict_counts),
        "unexpected_success_candidate": 0,
        "crash_candidate": int(comparison.get("crash_delta") or 0),
        "behavior_divergence_candidate": 0,
        "interpretation": "stable_safe_negative_baseline",
    }
    patterns = []
    for version in ["v0", "v1"]:
        root = PROJECT_ROOT / "artifacts" / "sprints" / f"pkey_verify_family_{version}"
        if not root.exists():
            continue
        patterns.append(
            {
                "pattern_id": f"PKEY_VERIFY_FAMILY_{version.upper()}",
                "source_path": rel(root),
                "source_type": "feedback_sprint",
                "source_library": "synthetic_framework_controlled",
                "target_library": "openssl",
                "family": "pkey_verify_semantic",
                "subfamily": "wrong_hash_length_pss_saltlen",
                "oracle_type": "safe_reject_baseline",
                "root_cause": "PKEY verification should reject invalid signature, digest, key, padding, or saltlen combinations.",
                "source_api": ["pkey_verify_semantic"],
                "target_api": ["EVP_DigestVerify", "EVP_PKEY_verify"],
                "migration_status": "stable_safe_negative",
                "current_verdict": "stable_safe_negative",
                "confidence": "high",
                "has_controlled_template": True,
                "has_render_matrix": (root / "render_matrix.yaml").exists(),
                "has_feedback": version == "v1",
                "has_rag_evidence": (root / "evidence_with_feedback" / "candidates_with_evidence.yaml").exists(),
                "priority_score": 0.45 if version == "v1" else 0.4,
                "priority_reasons": [
                    "stable_safe_negative_baseline",
                    "controlled_template_available",
                ],
                "feedback_summary": feedback_summary,
                "scheduler_hint": {
                    "action": "deprioritize_repeated_safe_negative",
                    "keep_for_boundary_deepening": [
                        "wrong_hash_length",
                        "pss_saltlen_mismatch",
                        "padding_mismatch",
                    ],
                },
                "evidence_files": [
                    rel(root / "results" / "run.summary.json"),
                    rel(root / "results" / "behavior_summary.json"),
                ],
                "notes": [
                    "PKEY v0/v1 form a stable safe-negative regression baseline.",
                    "Feedback-guided v1 changed mutation coverage without producing a vulnerability candidate.",
                ],
            }
        )
    return feedback_summary, patterns


def load_der_feedback_summary() -> Dict[str, Any]:
    feedback_path = PROJECT_ROOT / "artifacts" / "feedback" / "der_full_consumption_feedback.jsonl"
    summary_path = (
        PROJECT_ROOT
        / "artifacts"
        / "sprints"
        / "der_full_consumption_v2"
        / "results"
        / "run.summary.json"
    )
    behavior_path = (
        PROJECT_ROOT
        / "artifacts"
        / "sprints"
        / "der_full_consumption_v2"
        / "results"
        / "behavior_summary.json"
    )
    rows = read_jsonl(feedback_path)
    summary = read_json(summary_path)
    verdict_counts = summary.get("verdict_counts") or {}
    return {
        "total_cases": int(summary.get("total_cases") or 0),
        "feedback_rows": len(rows),
        "verdict_counts": verdict_counts,
        "app_level_validation_gap_candidate": int(verdict_counts.get("app_level_validation_gap_candidate") or 0),
        "strict_reject": int(verdict_counts.get("strict_reject") or 0),
        "valid_baseline_success": int(verdict_counts.get("valid_baseline_success") or 0),
        "malformed_baseline_reject": int(verdict_counts.get("malformed_baseline_reject") or 0),
        "expected_prefix_accept_behavior": int(verdict_counts.get("expected_prefix_accept_behavior") or 0),
        "interpretation": "app_level_validation_gap_candidate",
        "evidence_files": [
            rel(feedback_path),
            rel(summary_path),
            rel(behavior_path),
        ],
    }


def apply_der_feedback_to_core10(
    core10_patterns: List[Dict[str, Any]],
    der_feedback_summary: Dict[str, Any],
) -> None:
    if not der_feedback_summary.get("feedback_rows"):
        return
    for pattern in core10_patterns:
        if pattern.get("pattern_id") != "MBEDTLS-POC-0020":
            continue
        pattern["has_feedback"] = True
        pattern["has_render_matrix"] = True
        pattern["current_verdict"] = "app_level_validation_gap_candidate"
        pattern["migration_status"] = "migrated_candidate"
        pattern["priority_score"] = max(float(pattern.get("priority_score", 0.0)), 0.9)
        reasons = set(pattern.get("priority_reasons") or [])
        reasons.update(
            {
                "der_v2_feedback",
                "app_level_validation_gap_candidate",
                "controlled_app_level_wrapper",
            }
        )
        pattern["priority_reasons"] = sorted(reasons)
        pattern["feedback_summary"] = der_feedback_summary
        evidence = list(pattern.get("evidence_files") or [])
        for path in der_feedback_summary.get("evidence_files", []):
            if path not in evidence:
                evidence.append(path)
        pattern["evidence_files"] = evidence
        notes = list(pattern.get("notes") or [])
        notes.append(
            "DER v2 controlled app-level sprint observed valid DER prefix plus malformed trailing bytes accepted with output artifacts; this is not crash evidence and not a confirmed CVE."
        )
        pattern["notes"] = notes


def score_pattern(
    *,
    family: str,
    oracle_type: str,
    migration_status: str,
    current_verdict: str,
    has_controlled_template: bool,
    has_rag_evidence: bool,
    has_feedback: bool,
) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    if current_verdict in {"behavior_divergence_candidate", "unexpected_success_candidate", "crash_or_sanitizer"}:
        score += 0.30
        reasons.append("has_candidate_signal")
    if oracle_type not in {UNKNOWN, PENDING_INFERENCE}:
        score += 0.20
        reasons.append("clear_oracle")
    if has_controlled_template:
        score += 0.15
        reasons.append("has_controlled_template_or_artifact")
    if has_rag_evidence:
        score += 0.15
        reasons.append("has_rag_evidence")
    if has_feedback:
        score += 0.10
        reasons.append("has_feedback")
    if family not in {UNKNOWN, PENDING_CLASSIFICATION}:
        score += 0.10
        reasons.append("reusable_family")
    if migration_status == "stable_safe_negative":
        score -= 0.20
        reasons.append("stable_safe_negative_deprioritized")
    if migration_status == "projection_limitation":
        score -= 0.25
        reasons.append("projection_limitation_observed")
    if family == PENDING_CLASSIFICATION:
        score -= 0.10
        reasons.append("needs_classification")
    return round(max(0.0, min(1.0, score)), 2), reasons or ["needs_classification"]


def build_scheduler_seed(patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for pattern in patterns:
        grouped[pattern["family"]].append(pattern)

    families: Dict[str, Dict[str, Any]] = {}
    for family, items in sorted(grouped.items()):
        if family in {UNKNOWN, PENDING_CLASSIFICATION}:
            continue
        base_score = max(float(item.get("priority_score", 0.0)) for item in items)
        reasons = sorted({r for item in items for r in item.get("priority_reasons", [])})
        pattern_ids = [item["pattern_id"] for item in items]
        recommended = "manual_classification"
        if family == "der_full_consumption":
            recommended = "der_full_consumption_v2"
        elif family == "mac_lifecycle":
            recommended = "build_mac_lifecycle_family_v1"
        elif family == "pkey_verify_semantic":
            recommended = "pkey_v2_boundary_deepening"
        elif family == "bn_mpi_arithmetic":
            recommended = "low_priority_followup"
        elif family == "cipher_aead_lifecycle":
            recommended = "cipher_aead_lifecycle_family_v1"
        elif family in {"x509_parsing", "asn1_nested_boundary"}:
            recommended = f"{family}_triage_v1"
        elif family == "api_state_machine":
            recommended = "api_state_machine_family_v1"

        if family == "pkey_verify_semantic":
            base_score = min(base_score, 0.45)
            reasons.append("stable_safe_negative_baseline")
        families[family] = {
            "priority_score": round(base_score, 2),
            "patterns": pattern_ids,
            "reasons": sorted(set(reasons)),
            "recommended_next_action": recommended,
        }

    ordered = dict(sorted(families.items(), key=lambda kv: kv[1]["priority_score"], reverse=True))
    return {"families": ordered}


def pattern_markdown(pattern: Dict[str, Any]) -> str:
    feedback = pattern.get("feedback_summary")
    feedback_text = "none"
    if isinstance(feedback, dict):
        feedback_text = (
            f"{feedback.get('interpretation', UNKNOWN)}; "
            f"total_cases={feedback.get('total_cases', 0)}; "
            f"verdict_counts={feedback.get('verdict_counts', {})}"
        )
    notes = " ".join(pattern.get("notes", [])[:3])
    return (
        f"## {pattern['pattern_id']}\n\n"
        f"- Source: {pattern['source_path']}\n"
        f"- Family: {pattern['family']}\n"
        f"- Oracle type: {pattern['oracle_type']}\n"
        f"- Root cause: {pattern['root_cause']}\n"
        f"- Source API: {', '.join(pattern.get('source_api', [UNKNOWN]))}\n"
        f"- Target API: {', '.join(pattern.get('target_api', [UNKNOWN]))}\n"
        f"- Historical verdict: {pattern.get('current_verdict', UNKNOWN)}\n"
        f"- Feedback summary: {feedback_text}\n"
        f"- Scheduler priority: {pattern.get('priority_score', 0.0)} "
        f"({', '.join(pattern.get('priority_reasons', []))})\n"
        f"- Notes: {notes}\n\n"
    )


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def write_markdown(path: Path, patterns: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "# Pattern Bank RAG Notes\n\n",
        "Generated by `knowledge.build_pattern_bank`. These notes are evidence summaries, not batch PoC reproductions.\n\n",
    ]
    for pattern in patterns:
        body.append(pattern_markdown(pattern))
    path.write_text("".join(body), encoding="utf-8")


def distribution(patterns: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    return dict(Counter(str(p.get(key, UNKNOWN)) for p in patterns))


def build_readme(
    core10_patterns: List[Dict[str, Any]],
    openssl_patterns: List[Dict[str, Any]],
    unified_patterns: List[Dict[str, Any]],
    scheduler_seed: Dict[str, Any],
) -> str:
    family_dist = distribution(unified_patterns, "family")
    oracle_dist = distribution(unified_patterns, "oracle_type")
    status_dist = distribution(unified_patterns, "migration_status")
    top_families = list(scheduler_seed.get("families", {}).items())[:6]
    pending = [
        p["pattern_id"]
        for p in unified_patterns
        if p.get("family") == PENDING_CLASSIFICATION
        or p.get("oracle_type") == PENDING_INFERENCE
        or p.get("migration_status") == PENDING_CLASSIFICATION
    ]
    next_family = top_families[0][0] if top_families else UNKNOWN
    lines = [
        "# Historical Pattern Bank Summary\n\n",
        "This run scanned `data/pocs/core10/` and `datasets/openssl/poc_artifacts/`.\n\n",
        f"- core10 patterns: {len(core10_patterns)}\n",
        f"- OpenSSL issue artifact patterns: {len(openssl_patterns)}\n",
        f"- unified patterns: {len(unified_patterns)}\n",
        f"- family distribution: {family_dist}\n",
        f"- oracle_type distribution: {oracle_dist}\n",
        f"- migration_status distribution: {status_dist}\n",
        "- top scheduler families:\n",
    ]
    for family, info in top_families:
        lines.append(
            f"  - {family}: {info.get('priority_score')} -> {info.get('recommended_next_action')}\n"
        )
    lines.extend(
        [
            f"- patterns needing manual confirmation: {pending[:20]}"
            + (" ..." if len(pending) > 20 else "")
            + "\n",
            f"- recommended next family: {next_family}\n",
            "- this run did not batch-render, compile, or execute all PoCs.\n",
        ]
    )
    return "".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a unified vulnerability pattern bank.")
    parser.add_argument("--core10-root", type=Path, default=CORE10_ROOT)
    parser.add_argument("--openssl-root", type=Path, default=OPENSSL_ARTIFACT_ROOT)
    parser.add_argument("--out-root", type=Path, default=PATTERN_BANK_ROOT)
    parser.add_argument("--poc-patterns-root", type=Path, default=POC_PATTERNS_ROOT)
    args = parser.parse_args()

    all_artifact_files = collect_artifact_files()
    summary_rows = load_openssl_summary_rows()

    core10_patterns = [
        build_core10_pattern(path, all_artifact_files)
        for path in sorted(args.core10_root.glob("MBEDTLS-POC-*"))
        if path.is_dir()
    ]
    der_feedback_summary = load_der_feedback_summary()
    apply_der_feedback_to_core10(core10_patterns, der_feedback_summary)
    openssl_patterns = [
        build_openssl_pattern(path, summary_rows, all_artifact_files)
        for path in sorted(args.openssl_root.glob("issue_*"))
        if path.is_dir()
    ]
    pkey_feedback_summary, feedback_patterns = load_pkey_feedback_summary()

    unified_patterns = core10_patterns + openssl_patterns + feedback_patterns
    scheduler_seed = build_scheduler_seed(unified_patterns)

    args.out_root.mkdir(parents=True, exist_ok=True)
    args.poc_patterns_root.mkdir(parents=True, exist_ok=True)

    write_yaml(args.out_root / "core10_pattern_inventory.yaml", {"patterns": core10_patterns})
    write_yaml(args.out_root / "openssl_issue_pattern_inventory.yaml", {"patterns": openssl_patterns})
    write_yaml(
        args.out_root / "unified_pattern_bank.yaml",
        {
            "schema_version": 1,
            "core10_count": len(core10_patterns),
            "openssl_issue_count": len(openssl_patterns),
            "feedback_pattern_count": len(feedback_patterns),
            "feedback_summary": {
                "pkey_verify_semantic": pkey_feedback_summary,
                "der_full_consumption": der_feedback_summary,
            },
            "patterns": unified_patterns,
        },
    )
    write_yaml(args.out_root / "scheduler_seed.yaml", scheduler_seed)

    write_markdown(args.poc_patterns_root / "core10_patterns.md", core10_patterns)
    write_markdown(args.poc_patterns_root / "openssl_issue_patterns.md", openssl_patterns)
    write_markdown(args.poc_patterns_root / "unified_patterns.md", unified_patterns)

    (args.out_root / "README.md").write_text(
        build_readme(core10_patterns, openssl_patterns, unified_patterns, scheduler_seed),
        encoding="utf-8",
    )

    print(f"core10_patterns: {len(core10_patterns)}")
    print(f"openssl_issue_patterns: {len(openssl_patterns)}")
    print(f"feedback_patterns: {len(feedback_patterns)}")
    print(f"unified_patterns: {len(unified_patterns)}")
    print(f"family_distribution: {distribution(unified_patterns, 'family')}")
    print(f"oracle_distribution: {distribution(unified_patterns, 'oracle_type')}")
    print(f"migration_status_distribution: {distribution(unified_patterns, 'migration_status')}")
    print(f"output_root: {rel(args.out_root)}")


if __name__ == "__main__":
    main()
