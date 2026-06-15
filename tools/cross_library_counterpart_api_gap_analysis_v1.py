#!/usr/bin/env python3
"""Analyze OpenSSL/mbedTLS counterpart API-card gaps for wolfSSL top families.

Read-only with respect to knowledge_raw and knowledge_base. Outputs sprint
reports under --out-dir only.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


TOP_FAMILIES = [
    "tls_protocol_state_lifecycle",
    "asn1_nested_boundary",
    "pkcs_container_parsing",
    "x509_parsing",
    "secure_heap_state_lifecycle",
]


COUNTERPARTS = {
    "tls_protocol_state_lifecycle": {
        "wolfssl": [
            "wolfSSL_CTX_new",
            "wolfSSL_CTX_free",
            "wolfSSL_new",
            "wolfSSL_free",
            "wolfSSL_connect",
            "wolfSSL_accept",
            "wolfSSL_read",
            "wolfSSL_write",
        ],
        "openssl": [
            "SSL_CTX_new",
            "SSL_CTX_free",
            "SSL_new",
            "SSL_free",
            "SSL_connect",
            "SSL_accept",
            "SSL_read",
            "SSL_write",
        ],
        "mbedtls": [
            "mbedtls_ssl_config_init",
            "mbedtls_ssl_config_free",
            "mbedtls_ssl_init",
            "mbedtls_ssl_free",
            "mbedtls_ssl_setup",
            "mbedtls_ssl_handshake",
            "mbedtls_ssl_read",
            "mbedtls_ssl_write",
        ],
    },
    "x509_parsing": {
        "wolfssl": [
            "wolfSSL_X509_load_certificate_file",
            "wolfSSL_X509_free",
            "wc_InitDecodedCert",
            "wc_ParseCert",
            "wc_FreeDecodedCert",
        ],
        "openssl": [
            "d2i_X509",
            "PEM_read_bio_X509",
            "X509_free",
            "ASN1_item_d2i",
            "d2i_ASN1_SEQUENCE_ANY",
        ],
        "mbedtls": [
            "mbedtls_x509_crt_init",
            "mbedtls_x509_crt_parse",
            "mbedtls_x509_crt_parse_der",
            "mbedtls_x509_crt_free",
        ],
    },
    "asn1_nested_boundary": {
        "wolfssl": [
            "wc_InitDecodedCert",
            "wc_ParseCert",
            "wc_FreeDecodedCert",
        ],
        "openssl": [
            "ASN1_item_d2i",
            "d2i_ASN1_SEQUENCE_ANY",
            "d2i_X509",
        ],
        "mbedtls": [
            "mbedtls_x509_crt_init",
            "mbedtls_x509_crt_parse",
            "mbedtls_x509_crt_parse_der",
            "mbedtls_x509_crt_free",
        ],
    },
    "pkcs_container_parsing": {
        "wolfssl": [
            "wc_PKCS7_Init",
            "wc_PKCS7_Free",
            "wc_PKCS7_VerifySignedData",
            "wc_PKCS12_parse",
        ],
        "openssl": [
            "d2i_PKCS7",
            "PKCS7_free",
            "PKCS7_verify",
            "d2i_PKCS12",
            "PKCS12_free",
            "PKCS12_parse",
        ],
        "mbedtls": [],
    },
    "secure_heap_state_lifecycle": {
        "wolfssl": [
            "XMALLOC",
            "XFREE",
            "wolfSSL_Malloc",
            "wolfSSL_Free",
            "wolfSSL_SetAllocators",
        ],
        "openssl": [
            "CRYPTO_secure_malloc_init",
            "CRYPTO_secure_malloc",
            "CRYPTO_secure_free",
            "OPENSSL_secure_malloc",
            "OPENSSL_secure_free",
        ],
        "mbedtls": [
            "mbedtls_platform_set_calloc_free",
            "mbedtls_calloc",
            "mbedtls_free",
        ],
    },
}


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def md_list(items: list[str]) -> str:
    return "".join(f"- `{x}`\n" for x in items) if items else "- none\n"


def load_wolfssl_cards(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    return data.get("wolfssl_api_cards_api_card_v0") or data.get("wolfssl_api_cards") or []


def load_mappings(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    return data.get("wolfssl_cross_library_mapping_candidates") or data.get("cross_library_mapping_candidates") or []


def collect_api_cards(roots: list[Path]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.yaml")):
            if path.name == "schema.yaml":
                continue
            data = load_yaml(path)
            records = []
            if isinstance(data, dict):
                if "wolfssl_api_cards_api_card_v0" in data:
                    records = data["wolfssl_api_cards_api_card_v0"]
                elif "wolfssl_api_cards" in data:
                    records = data["wolfssl_api_cards"]
                else:
                    records = [data]
            elif isinstance(data, list):
                records = data
            for obj in records:
                if not isinstance(obj, dict):
                    continue
                api = str(obj.get("api") or obj.get("api_name") or path.stem)
                library = str(obj.get("library") or infer_library(path))
                index[api].append(
                    {
                        "api": api,
                        "library": library,
                        "family": obj.get("family") or (obj.get("family_relevance") or [""])[0],
                        "path": str(path),
                    }
                )
    return index


def infer_library(path: Path) -> str:
    s = str(path).lower()
    if "openssl" in s:
        return "openssl"
    if "mbedtls" in s:
        return "mbedtls"
    if "wolfssl" in s:
        return "wolfssl"
    return "unknown"


def collect_constraints(root: Path) -> dict[str, list[str]]:
    index: dict[str, list[str]] = defaultdict(list)
    if not root.exists():
        return index
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml", ".md", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        # path stem is often a useful API name; also rely on substring matching later.
        stem = path.stem
        index[stem].append(str(path))
        for family in COUNTERPARTS.values():
            for apis in family.values():
                for api in apis:
                    if api in text or api == stem:
                        index[api].append(str(path))
    return {k: sorted(set(v)) for k, v in index.items()}


def card_exists(api_cards: dict[str, list[dict[str, Any]]], api: str, library: str) -> tuple[bool, str]:
    for item in api_cards.get(api, []):
        if item.get("library") == library:
            return True, item.get("path", "")
    return False, ""


def constraint_exists(constraints: dict[str, list[str]], api: str, library: str) -> tuple[bool, str]:
    hits = [p for p in constraints.get(api, []) if library in p.lower()]
    if hits:
        return True, hits[0]
    return False, ""


def source_dirs_status() -> list[dict[str, Any]]:
    clean_root = Path(os.environ.get("CLEAN_SOURCES_ROOT", str(Path.home() / "work/clean_sources")))
    candidates = [
        clean_root / "openssl-3.5.5-clean",
        clean_root / "mbedtls-4.1-clean",
        Path.home() / "work/openssl-3.5.5-clean",
        Path.home() / "work/mbedtls-4.1-clean",
    ]
    out = []
    for path in candidates:
        out.append({"path": str(path), "exists": path.exists()})
    return out


def coverage_for_library(api_cards: dict[str, list[dict[str, Any]]], constraints: dict[str, list[str]], target_library: str) -> list[dict[str, Any]]:
    rows = []
    for family in TOP_FAMILIES:
        wolf_apis = COUNTERPARTS.get(family, {}).get("wolfssl", [])
        target_apis = COUNTERPARTS.get(family, {}).get(target_library, [])
        if not target_apis:
            for wolf_api in wolf_apis:
                rows.append(
                    {
                        "family": family,
                        "wolfssl_api": wolf_api,
                        "candidate_api": "",
                        "target_library": target_library,
                        "api_card_exists": False,
                        "api_constraint_exists": False,
                        "evidence_file": "",
                        "confidence": "low",
                        "gap": "no_direct_counterpart",
                    }
                )
            continue
        # Pair by position, then include extras with nearest family API.
        max_len = max(len(wolf_apis), len(target_apis))
        for idx in range(max_len):
            wolf_api = wolf_apis[min(idx, len(wolf_apis) - 1)] if wolf_apis else ""
            api = target_apis[idx] if idx < len(target_apis) else target_apis[-1]
            has_card, card_path = card_exists(api_cards, api, target_library)
            has_constraint, constraint_path = constraint_exists(constraints, api, target_library)
            evidence = card_path or constraint_path
            if has_card and has_constraint:
                gap = "no_gap"
                confidence = "high"
            elif has_card and not has_constraint:
                gap = "missing_constraint"
                confidence = "medium"
            elif not has_card and has_constraint:
                gap = "missing_api_card"
                confidence = "medium"
            else:
                gap = "missing_api_card"
                confidence = "low"
            rows.append(
                {
                    "family": family,
                    "wolfssl_api": wolf_api,
                    "candidate_api": api,
                    "target_library": target_library,
                    "api_card_exists": has_card,
                    "api_constraint_exists": has_constraint,
                    "evidence_file": evidence,
                    "confidence": confidence,
                    "gap": gap,
                }
            )
    return sorted(rows, key=lambda x: (x["family"], x["wolfssl_api"], x["candidate_api"]))


def summarize_source_cards(cards: list[dict[str, Any]]) -> dict[str, Any]:
    by_family = Counter(str(c.get("family") or "unknown") for c in cards)
    lifecycle, parser, cleanup, weak = [], [], [], []
    for c in cards:
        api = str(c.get("api"))
        family = str(c.get("family"))
        if family == "tls_protocol_state_lifecycle" or any(x in api for x in ["CTX", "connect", "accept", "read", "write"]):
            lifecycle.append(api)
        if family in {"asn1_nested_boundary", "pkcs_container_parsing", "x509_parsing"} or any(x in api for x in ["Parse", "PKCS", "X509", "DecodedCert"]):
            parser.append(api)
        cleanup_apis = (c.get("lifecycle") or {}).get("cleanup") or []
        if "free" in api.lower() or "Free" in api or cleanup_apis:
            cleanup.append(api)
        if c.get("confidence") != "high":
            weak.append(api)
    return {
        "source_api_summary": {
            "total_wolfssl_cards": len(cards),
            "by_family": dict(sorted(by_family.items())),
            "lifecycle_apis": sorted(set(lifecycle)),
            "parser_apis": sorted(set(parser)),
            "cleanup_apis": sorted(set(cleanup)),
            "weak_or_review_needed": sorted(set(weak)),
        }
    }


def review_mappings(mappings: list[dict[str, Any]], cards: list[dict[str, Any]], api_cards: dict[str, list[dict[str, Any]]], constraints: dict[str, list[str]]) -> list[dict[str, Any]]:
    source_card_apis = {str(c.get("api")) for c in cards}
    rows = []
    for m in mappings:
        for target_lib, target_api in [("openssl", m.get("openssl_candidate_api")), ("mbedtls", m.get("mbedtls_candidate_api"))]:
            if not target_api:
                rows.append(
                    {
                        "source_api": m.get("wolfssl_api"),
                        "target_api": "",
                        "target_library": target_lib,
                        "current_confidence": m.get("confidence"),
                        "has_source_card": m.get("wolfssl_api") in source_card_apis,
                        "has_target_card": False,
                        "has_target_constraint": False,
                        "mapping_evidence_sufficient": False,
                        "review_status": "no_direct_counterpart",
                        "reason": "No target API candidate listed.",
                    }
                )
                continue
            has_card, card_path = card_exists(api_cards, str(target_api), target_lib)
            has_constraint, con_path = constraint_exists(constraints, str(target_api), target_lib)
            if m.get("mapping_type") == "weak_name_match":
                status = "weak_name_match_only"
            elif has_card and has_constraint and m.get("confidence") in {"high", "medium"}:
                status = "usable_for_rag_gate"
            elif not has_card:
                status = "needs_target_card"
            else:
                status = "manual_review"
            rows.append(
                {
                    "source_api": m.get("wolfssl_api"),
                    "target_api": target_api,
                    "target_library": target_lib,
                    "current_confidence": m.get("confidence"),
                    "has_source_card": m.get("wolfssl_api") in source_card_apis,
                    "has_target_card": has_card,
                    "has_target_constraint": has_constraint,
                    "mapping_evidence_sufficient": status == "usable_for_rag_gate",
                    "review_status": status,
                    "reason": card_path or con_path or "Target-side card/constraint evidence missing or incomplete.",
                }
            )
    return sorted(rows, key=lambda x: (x["target_library"], x["source_api"], x["target_api"]))


def make_gap_summary(openssl_rows: list[dict[str, Any]], mbedtls_rows: list[dict[str, Any]], mapping_review: list[dict[str, Any]]) -> dict[str, Any]:
    def apis(rows: list[dict[str, Any]], gap: str) -> list[str]:
        return sorted({r["candidate_api"] for r in rows if r["gap"] == gap and r["candidate_api"]})

    family_gap_counts = defaultdict(Counter)
    for row in openssl_rows + mbedtls_rows:
        family_gap_counts[row["family"]][row["gap"]] += 1
    need_priority = sorted(
        family_gap_counts,
        key=lambda fam: (
            family_gap_counts[fam]["missing_api_card"]
            + family_gap_counts[fam]["missing_constraint"]
            + family_gap_counts[fam]["no_direct_counterpart"]
        ),
        reverse=True,
    )
    return {
        "counterpart_gap_summary": {
            "openssl_existing_cards": sorted({r["candidate_api"] for r in openssl_rows if r["api_card_exists"]}),
            "openssl_missing_api_cards": apis(openssl_rows, "missing_api_card"),
            "openssl_missing_constraints": apis(openssl_rows, "missing_constraint"),
            "mbedtls_existing_cards": sorted({r["candidate_api"] for r in mbedtls_rows if r["api_card_exists"]}),
            "mbedtls_missing_api_cards": apis(mbedtls_rows, "missing_api_card"),
            "mbedtls_missing_constraints": apis(mbedtls_rows, "missing_constraint"),
            "wolfssl_without_direct_mbedtls_counterpart": sorted({r["wolfssl_api"] for r in mbedtls_rows if r["gap"] == "no_direct_counterpart"}),
            "weak_name_match_mappings": [r for r in mapping_review if r["review_status"] == "weak_name_match_only"],
            "families_needing_target_side_knowledge": need_priority,
            "family_gap_counts": {fam: dict(counts) for fam, counts in sorted(family_gap_counts.items())},
        }
    }


def make_enrichment_plan(openssl_rows: list[dict[str, Any]], mbedtls_rows: list[dict[str, Any]]) -> dict[str, Any]:
    priority = []
    order = {
        ("openssl", "pkcs_container_parsing"): 0,
        ("openssl", "x509_parsing"): 1,
        ("openssl", "asn1_nested_boundary"): 2,
        ("mbedtls", "x509_parsing"): 3,
        ("mbedtls", "tls_protocol_state_lifecycle"): 4,
        ("openssl", "secure_heap_state_lifecycle"): 5,
        ("mbedtls", "secure_heap_state_lifecycle"): 6,
    }
    for row in openssl_rows + mbedtls_rows:
        if row["gap"] in {"missing_api_card", "missing_constraint"} and row["candidate_api"]:
            priority.append(
                {
                    "target_library": row["target_library"],
                    "family": row["family"],
                    "api": row["candidate_api"],
                    "reason": row["gap"],
                    "required_fields": [
                        "signature",
                        "parameter_semantics",
                        "return_value_semantics",
                        "state_preconditions",
                        "cleanup",
                        "oracle_observables",
                    ],
                    "_sort": order.get((row["target_library"], row["family"]), 99),
                }
            )
    # Deduplicate by library/api/family.
    dedup = {}
    for item in priority:
        key = (item["target_library"], item["family"], item["api"])
        if key not in dedup or item["_sort"] < dedup[key]["_sort"]:
            dedup[key] = item
    priority_targets = sorted(dedup.values(), key=lambda x: (x.pop("_sort"), x["target_library"], x["family"], x["api"]))
    low = []
    for row in mbedtls_rows:
        if row["gap"] == "no_direct_counterpart":
            low.append({"api": row["wolfssl_api"], "reason": "mbedTLS direct PKCS7/PKCS12 counterpart not identified; do not force a weak mapping."})
    return {
        "enrichment_plan": {
            "recommended_next_task": "api_card_enrichment_for_cross_library_counterparts_v1",
            "priority_targets": priority_targets,
            "skip_or_low_priority": low,
        }
    }


def write_reports(out: Path, data: dict[str, Any]) -> None:
    dump_yaml(out / "input/counterpart_gap_input_summary.yaml", data["input_summary"])
    write_text(out / "input/counterpart_gap_input_summary.md", "# Counterpart Gap Input Summary\n\n" + md_list(data["input_summary"]["inputs_read"]))

    dump_yaml(out / "source_cards/wolfssl_source_api_summary.yaml", data["source_summary"])
    s = data["source_summary"]["source_api_summary"]
    write_text(out / "source_cards/wolfssl_source_api_summary.md", f"# wolfSSL Source API Summary\n\n- total: `{s['total_wolfssl_cards']}`\n- families: `{s['by_family']}`\n")

    dump_yaml(out / "target_inventory/openssl_counterpart_coverage.yaml", {"counterpart_coverage": data["openssl_rows"]})
    dump_yaml(out / "target_inventory/mbedtls_counterpart_coverage.yaml", {"counterpart_coverage": data["mbedtls_rows"]})
    for lib, rows in [("openssl", data["openssl_rows"]), ("mbedtls", data["mbedtls_rows"])]:
        counts = Counter(r["gap"] for r in rows)
        write_text(out / f"target_inventory/{lib}_counterpart_coverage.md", f"# {lib} Counterpart Coverage\n\n" + "\n".join(f"- {k}: `{v}`" for k, v in sorted(counts.items())) + "\n")

    dump_yaml(out / "mapping_review/cross_mapping_gap_review.yaml", {"mapping_review": data["mapping_review"]})
    counts = Counter(r["review_status"] for r in data["mapping_review"])
    write_text(out / "mapping_review/cross_mapping_gap_review.md", "# Cross Mapping Gap Review\n\n" + "\n".join(f"- {k}: `{v}`" for k, v in sorted(counts.items())) + "\n")

    dump_yaml(out / "gap_analysis/counterpart_gap_summary.yaml", data["gap_summary"])
    gs = data["gap_summary"]["counterpart_gap_summary"]
    write_text(
        out / "gap_analysis/counterpart_gap_summary.md",
        "# Counterpart Gap Summary\n\n"
        f"## OpenSSL missing API cards\n{md_list(gs['openssl_missing_api_cards'])}\n"
        f"## mbedTLS missing API cards\n{md_list(gs['mbedtls_missing_api_cards'])}\n"
        f"## Families needing target-side knowledge\n{md_list(gs['families_needing_target_side_knowledge'])}\n",
    )

    dump_yaml(out / "enrichment_plan/api_card_enrichment_for_cross_library_counterparts_plan.yaml", data["enrichment_plan"])
    ep = data["enrichment_plan"]["enrichment_plan"]
    write_text(
        out / "enrichment_plan/api_card_enrichment_for_cross_library_counterparts_plan.md",
        "# API Card Enrichment For Cross-Library Counterparts Plan\n\n"
        f"- recommended_next_task: `{ep['recommended_next_task']}`\n"
        "## Priority targets\n"
        + md_list([f"{x['target_library']}:{x['family']}:{x['api']}:{x['reason']}" for x in ep["priority_targets"][:80]]),
    )

    if data["decision"] == "api_card_enrichment_for_cross_library_counterparts_v1":
        why = "OpenSSL/mbedTLS counterpart card and constraint gaps are obvious."
    elif data["decision"] == "cross_library_mapping_refinement_v1":
        why = "Most mappings are weak-name only and need semantic refinement first."
    else:
        why = "Counterpart coverage appears sufficient for template schema inventory."
    next_action = {"next_task_name": data["decision"], "why": why}
    dump_yaml(out / "reports/next_action_after_counterpart_gap_analysis.yaml", next_action)
    write_text(out / "reports/next_action_after_counterpart_gap_analysis.md", f"# Next Action\n\n- next_task_name: `{data['decision']}`\n- why: {why}\n")

    report = data["report"]
    dump_yaml(out / "reports/cross_library_counterpart_api_gap_analysis_report.yaml", report)
    write_text(
        out / "reports/cross_library_counterpart_api_gap_analysis_report.md",
        "# Cross-Library Counterpart API Gap Analysis Report\n\n"
        f"- wolfSSL source cards: `{report['wolfssl_source_cards']}`\n"
        f"- OpenSSL gap counts: `{report['openssl_gap_counts']}`\n"
        f"- mbedTLS gap counts: `{report['mbedtls_gap_counts']}`\n"
        f"- next task: `{report['next_task_name']}`\n"
        "- knowledge_raw / knowledge_base / RAG rebuild: `false`\n",
    )
    write_text(out / "README.md", "# cross_library_counterpart_api_gap_analysis_v1\n\nRead-only analysis of OpenSSL/mbedTLS counterpart API-card gaps for current top wolfSSL migration families.\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wolfssl-cards", required=True)
    parser.add_argument("--wolfssl-constraints", required=True)
    parser.add_argument("--wolfssl-cross-mapping", required=True)
    parser.add_argument("--api-card-roots", nargs="+", required=True)
    parser.add_argument("--api-constraint-root", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out = Path(args.out_dir)
    for sub in ["input", "source_cards", "target_inventory", "gap_analysis", "mapping_review", "enrichment_plan", "reports", "logs", "validation"]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    cards = load_wolfssl_cards(Path(args.wolfssl_cards))
    mappings = load_mappings(Path(args.wolfssl_cross_mapping))
    api_cards = collect_api_cards([Path(p) for p in args.api_card_roots])
    constraints = collect_constraints(Path(args.api_constraint_root))
    openssl_rows = coverage_for_library(api_cards, constraints, "openssl")
    mbedtls_rows = coverage_for_library(api_cards, constraints, "mbedtls")
    mapping_review = review_mappings(mappings, cards, api_cards, constraints)
    gap_summary = make_gap_summary(openssl_rows, mbedtls_rows, mapping_review)
    enrichment_plan = make_enrichment_plan(openssl_rows, mbedtls_rows)
    weak_count = sum(1 for r in mapping_review if r["review_status"] == "weak_name_match_only")
    missing_count = sum(1 for r in openssl_rows + mbedtls_rows if r["gap"] in {"missing_api_card", "missing_constraint", "no_direct_counterpart"})
    if weak_count > len(mapping_review) / 2:
        decision = "cross_library_mapping_refinement_v1"
    elif missing_count:
        decision = "api_card_enrichment_for_cross_library_counterparts_v1"
    else:
        decision = "template_schema_inventory_v1"

    source_summary = summarize_source_cards(cards)
    input_summary = {
        "task": "cross_library_counterpart_api_gap_analysis_v1",
        "inputs_read": [
            args.wolfssl_cards,
            args.wolfssl_constraints,
            args.wolfssl_cross_mapping,
            *args.api_card_roots,
            args.api_constraint_root,
            "artifacts/sprints/rag_rebuild_and_query_eval_v1/reports/rag_rebuild_and_query_eval_report.yaml",
            "artifacts/sprints/rag_rebuild_and_query_eval_v1/query_eval/query_eval_summary.yaml",
            "artifacts/sprints/api_card_import_to_knowledge_raw_v1/reports/api_card_import_to_knowledge_raw_report.yaml",
            "artifacts/sprints/manual_review_family_corrections_v1/corrections/corrected_family_distribution.yaml",
            "artifacts/sprints/manual_review_family_corrections_v1/scheduler/corrected_reviewed_scheduler_seed_candidates.yaml",
        ],
        "source_dirs_checked": source_dirs_status(),
        "scope": {
            "read_only": True,
            "write_knowledge_raw": False,
            "write_knowledge_base": False,
            "rag_rebuild": False,
            "run_poc": False,
            "glm": False,
            "template_generated": False,
        },
    }
    report = {
        "task": "cross_library_counterpart_api_gap_analysis_v1",
        "wolfssl_source_cards": len(cards),
        "openssl_gap_counts": dict(Counter(r["gap"] for r in openssl_rows)),
        "mbedtls_gap_counts": dict(Counter(r["gap"] for r in mbedtls_rows)),
        "openssl_missing_api_cards": gap_summary["counterpart_gap_summary"]["openssl_missing_api_cards"],
        "mbedtls_missing_api_cards": gap_summary["counterpart_gap_summary"]["mbedtls_missing_api_cards"],
        "weak_name_match_mappings": len(gap_summary["counterpart_gap_summary"]["weak_name_match_mappings"]),
        "families_needing_target_side_api_cards": gap_summary["counterpart_gap_summary"]["families_needing_target_side_knowledge"],
        "knowledge_raw_modified": False,
        "knowledge_base_modified": False,
        "rag_rebuild": False,
        "run_poc": False,
        "glm": False,
        "render": False,
        "template_generated": False,
        "next_task_name": decision,
    }
    data = {
        "input_summary": input_summary,
        "source_summary": source_summary,
        "openssl_rows": openssl_rows,
        "mbedtls_rows": mbedtls_rows,
        "mapping_review": mapping_review,
        "gap_summary": gap_summary,
        "enrichment_plan": enrichment_plan,
        "decision": decision,
        "report": report,
    }
    write_reports(out, data)
    print(json.dumps({"wolfssl_cards": len(cards), "openssl_gap_counts": report["openssl_gap_counts"], "mbedtls_gap_counts": report["mbedtls_gap_counts"], "next_task": decision}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
