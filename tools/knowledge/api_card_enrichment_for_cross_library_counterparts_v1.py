#!/usr/bin/env python3
"""Stage counterpart API-card enrichment drafts for OpenSSL and mbedTLS.

This tool intentionally writes only to the requested sprint --out-dir. It does
not import into knowledge_raw or knowledge_base, does not rebuild RAG, and does
not generate harness/template artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


OPENSSL_TARGETS = {
    "tls_protocol_state_lifecycle": [
        "SSL_CTX_new",
        "SSL_CTX_free",
        "SSL_new",
        "SSL_free",
        "SSL_connect",
        "SSL_accept",
        "SSL_read",
        "SSL_write",
    ],
    "x509_parsing": [
        "d2i_X509",
        "PEM_read_bio_X509",
        "X509_free",
    ],
    "asn1_nested_boundary": [
        "ASN1_item_d2i",
        "d2i_ASN1_SEQUENCE_ANY",
    ],
    "pkcs_container_parsing": [
        "d2i_PKCS7",
        "PKCS7_free",
        "PKCS7_verify",
        "d2i_PKCS12",
        "PKCS12_free",
        "PKCS12_parse",
    ],
    "secure_heap_state_lifecycle": [
        "CRYPTO_secure_malloc_init",
        "CRYPTO_secure_malloc",
        "CRYPTO_secure_free",
        "OPENSSL_secure_malloc",
        "OPENSSL_secure_free",
    ],
}

MBEDTLS_TARGETS = {
    "tls_protocol_state_lifecycle": [
        "mbedtls_ssl_config_init",
        "mbedtls_ssl_config_free",
        "mbedtls_ssl_init",
        "mbedtls_ssl_free",
        "mbedtls_ssl_setup",
        "mbedtls_ssl_handshake",
        "mbedtls_ssl_read",
        "mbedtls_ssl_write",
    ],
    "x509_parsing": [
        "mbedtls_x509_crt_init",
        "mbedtls_x509_crt_parse",
        "mbedtls_x509_crt_parse_der",
        "mbedtls_x509_crt_free",
    ],
    "asn1_nested_boundary": [],
    "pkcs_container_parsing": [],
    "secure_heap_state_lifecycle": [
        "mbedtls_platform_set_calloc_free",
        "mbedtls_calloc",
        "mbedtls_free",
    ],
}

MBEDTLS_NO_DIRECT = {
    "pkcs_container_parsing": [
        "wc_PKCS7_Init",
        "wc_PKCS7_Free",
        "wc_PKCS7_VerifySignedData",
        "wc_PKCS12_parse",
    ],
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


def flatten_targets(targets: dict[str, list[str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for family, apis in targets.items():
        for api in apis:
            if api not in seen:
                out.append((family, api))
                seen.add(api)
    return out


def infer_library(path: Path) -> str:
    s = str(path).lower()
    if "openssl" in s:
        return "openssl"
    if "mbedtls" in s:
        return "mbedtls"
    if "wolfssl" in s:
        return "wolfssl"
    return "unknown"


def collect_existing_cards(roots: list[Path]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.yaml")):
            if path.name == "schema.yaml":
                continue
            data = load_yaml(path)
            records = data if isinstance(data, list) else None
            if isinstance(data, dict):
                records = (
                    data.get("wolfssl_api_cards_api_card_v0")
                    or data.get("wolfssl_api_cards")
                    or [data]
                )
            if not isinstance(records, list):
                continue
            for obj in records:
                if not isinstance(obj, dict):
                    continue
                api = str(obj.get("api") or obj.get("api_name") or path.stem)
                library = str(obj.get("library") or infer_library(path))
                index[(library, api)].append({"path": str(path), "api": api, "library": library})
    return index


def collect_constraints(root: Path) -> dict[tuple[str, str], list[dict[str, str]]]:
    index: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    if not root.exists():
        return index
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in {".md", ".yaml", ".yml"}:
            continue
        library = infer_library(path)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for api in set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", path.stem + "\n" + text)):
            if len(api) < 4:
                continue
            index[(library, api)].append({"path": str(path)})
    return index


def source_roots() -> dict[str, list[Path]]:
    candidates = {
        "openssl": [
            Path(os.environ.get("CLEAN_SOURCES_ROOT", "")) / "openssl-3.5.5",
            Path(os.environ.get("CLEAN_SOURCES_ROOT", "")) / "openssl-3.5.5-clean",
            Path("/home/wen/work/openssl-3.5.5-clean"),
        ],
        "mbedtls": [
            Path(os.environ.get("CLEAN_SOURCES_ROOT", "")) / "mbedtls-4.1.0",
            Path(os.environ.get("CLEAN_SOURCES_ROOT", "")) / "mbedtls-4.1-clean",
            Path("/home/wen/work/mbedtls-4.1-clean"),
        ],
    }
    return {lib: [p for p in paths if p.exists()] for lib, paths in candidates.items()}


def collect_source_refs(api: str, library: str, roots: dict[str, list[Path]]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for root in roots.get(library, []):
        for path in sorted(root.rglob("*")):
            if len(refs) >= 8:
                return refs
            if not path.is_file() or path.suffix not in {".h", ".c", ".hpp", ".cpp", ".md", ".txt"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if api in text:
                refs.append({"path": str(path), "source_root": str(root)})
    return refs


def purpose_for(api: str, family: str) -> str:
    if family == "tls_protocol_state_lifecycle":
        return "TLS context/session lifecycle or record I/O counterpart API."
    if family == "x509_parsing":
        return "Certificate parsing or X509 object lifecycle counterpart API."
    if family == "asn1_nested_boundary":
        return "ASN.1/DER nested object decoding counterpart API."
    if family == "pkcs_container_parsing":
        return "PKCS#7/PKCS#12 container parsing or lifecycle counterpart API."
    if family == "secure_heap_state_lifecycle":
        return "Secure heap or allocator state lifecycle counterpart API."
    return "Cross-library counterpart API."


def observables_for(api: str, family: str) -> list[str]:
    if family in {"x509_parsing", "asn1_nested_boundary", "pkcs_container_parsing"}:
        return ["return_code_or_object_pointer", "input_consumption", "safe_rejection"]
    if family == "tls_protocol_state_lifecycle":
        return ["return_code", "object_state", "error_path_state"]
    if family == "secure_heap_state_lifecycle":
        return ["return_value", "allocator_state", "null_or_uninitialized_state"]
    return ["return_code"]


def mutation_slots_for(family: str) -> list[str]:
    return {
        "tls_protocol_state_lifecycle": ["init_order", "missing_setup", "read_write_state"],
        "x509_parsing": ["der_length", "nested_asn1_length", "trailing_bytes"],
        "asn1_nested_boundary": ["inner_length", "tag_length_mismatch", "truncated_nested_object"],
        "pkcs_container_parsing": ["container_length", "inner_content_type", "trailing_bytes"],
        "secure_heap_state_lifecycle": ["allocator_initialized", "secure_heap_size", "null_state_query"],
    }.get(family, ["input_boundary"])


def make_card(
    api: str,
    family: str,
    library: str,
    existing_cards: dict[tuple[str, str], list[dict[str, Any]]],
    constraints: dict[tuple[str, str], list[dict[str, str]]],
    roots: dict[str, list[Path]],
) -> dict[str, Any]:
    card_refs = existing_cards.get((library, api), [])
    constraint_refs = constraints.get((library, api), [])
    source_refs = collect_source_refs(api, library, roots)
    if card_refs:
        confidence = "high"
    elif constraint_refs or source_refs:
        confidence = "medium"
    else:
        confidence = "low"
    return {
        "library": library,
        "api": api,
        "family": family,
        "purpose": purpose_for(api, family),
        "staging_status": "staged_counterpart_card",
        "evidence_confidence": confidence,
        "observables": observables_for(api, family),
        "mutation_relevant_slots": mutation_slots_for(family),
        "existing_api_card_refs": card_refs,
        "existing_constraint_refs": constraint_refs[:8],
        "source_refs": source_refs,
        "import_recommendation": "ready_for_manual_review" if confidence in {"high", "medium"} else "needs_evidence_review",
    }


def make_no_direct_cards() -> list[dict[str, Any]]:
    cards = []
    for family, apis in MBEDTLS_NO_DIRECT.items():
        for api in apis:
            cards.append(
                {
                    "library": "mbedtls",
                    "source_api": api,
                    "api": "",
                    "family": family,
                    "staging_status": "no_direct_counterpart",
                    "evidence_confidence": "not_found",
                    "reason": "mbedTLS has no direct PKCS#7/PKCS#12 counterpart in the current target set.",
                    "import_recommendation": "do_not_import_as_api_card",
                }
            )
    return cards


def make_constraint(card: dict[str, Any]) -> dict[str, Any] | None:
    if card.get("staging_status") == "no_direct_counterpart":
        return None
    api = str(card["api"])
    family = str(card["family"])
    return {
        "library": card["library"],
        "api": api,
        "family": family,
        "constraint_status": "staged_constraint_candidate",
        "constraint_kind": {
            "tls_protocol_state_lifecycle": "lifecycle_order_and_state",
            "x509_parsing": "parser_boundary_and_object_lifecycle",
            "asn1_nested_boundary": "nested_der_boundary",
            "pkcs_container_parsing": "container_boundary_and_parse_result",
            "secure_heap_state_lifecycle": "allocator_state_lifecycle",
        }.get(family, "api_semantics"),
        "required_observables": card.get("observables", []),
        "mutation_relevant_slots": card.get("mutation_relevant_slots", []),
        "evidence_confidence": card.get("evidence_confidence", "low"),
        "source_refs": card.get("source_refs", []),
        "existing_constraint_refs": card.get("existing_constraint_refs", []),
    }


def make_sequences(library: str, cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    staged = {c.get("api") for c in cards if c.get("api")}
    candidates = {
        "openssl": [
            {
                "family": "tls_protocol_state_lifecycle",
                "sequence_name": "openssl_tls_context_session_io_lifecycle",
                "apis": ["SSL_CTX_new", "SSL_new", "SSL_connect", "SSL_read", "SSL_write", "SSL_free", "SSL_CTX_free"],
            },
            {
                "family": "x509_parsing",
                "sequence_name": "openssl_x509_der_parse_lifecycle",
                "apis": ["d2i_X509", "X509_free"],
            },
            {
                "family": "pkcs_container_parsing",
                "sequence_name": "openssl_pkcs7_der_verify_lifecycle",
                "apis": ["d2i_PKCS7", "PKCS7_verify", "PKCS7_free"],
            },
            {
                "family": "secure_heap_state_lifecycle",
                "sequence_name": "openssl_secure_heap_alloc_free_lifecycle",
                "apis": ["CRYPTO_secure_malloc_init", "OPENSSL_secure_malloc", "OPENSSL_secure_free"],
            },
        ],
        "mbedtls": [
            {
                "family": "tls_protocol_state_lifecycle",
                "sequence_name": "mbedtls_tls_config_session_io_lifecycle",
                "apis": [
                    "mbedtls_ssl_config_init",
                    "mbedtls_ssl_init",
                    "mbedtls_ssl_setup",
                    "mbedtls_ssl_handshake",
                    "mbedtls_ssl_read",
                    "mbedtls_ssl_write",
                    "mbedtls_ssl_free",
                    "mbedtls_ssl_config_free",
                ],
            },
            {
                "family": "x509_parsing",
                "sequence_name": "mbedtls_x509_der_parse_lifecycle",
                "apis": ["mbedtls_x509_crt_init", "mbedtls_x509_crt_parse_der", "mbedtls_x509_crt_free"],
            },
            {
                "family": "secure_heap_state_lifecycle",
                "sequence_name": "mbedtls_allocator_hook_lifecycle",
                "apis": ["mbedtls_platform_set_calloc_free", "mbedtls_calloc", "mbedtls_free"],
            },
        ],
    }
    seqs = []
    for seq in candidates.get(library, []):
        missing = [api for api in seq["apis"] if api not in staged]
        item = dict(seq)
        item["sequence_status"] = "complete_staged_sequence" if not missing else "incomplete_staged_sequence"
        item["missing_apis"] = missing
        seqs.append(item)
    return seqs


def make_mapping_support(
    rows: list[dict[str, Any]],
    cards: dict[tuple[str, str], dict[str, Any]],
    constraints: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    support = []
    for row in rows:
        target_library = str(row.get("target_library") or "")
        target_api = str(row.get("target_api") or "")
        if not target_api:
            status = "no_direct_counterpart"
        else:
            card = cards.get((target_library, target_api))
            constraint = constraints.get((target_library, target_api))
            if card and constraint and row.get("has_source_card"):
                status = "ready_for_import"
            elif card:
                status = "needs_manual_review"
            else:
                status = "weak_evidence"
        support.append(
            {
                "source_api": row.get("source_api"),
                "target_library": target_library,
                "target_api": target_api,
                "previous_review_status": row.get("review_status"),
                "current_confidence": row.get("current_confidence"),
                "support_status_after_staging": status,
                "has_staged_target_card": bool(target_api and (target_library, target_api) in cards),
                "has_staged_target_constraint": bool(target_api and (target_library, target_api) in constraints),
                "has_source_card": bool(row.get("has_source_card")),
                "reason": row.get("reason"),
            }
        )
    return support


def count_cards(cards: list[dict[str, Any]]) -> dict[str, Any]:
    confidence = Counter(c.get("evidence_confidence", "unknown") for c in cards)
    status = Counter(c.get("staging_status", "unknown") for c in cards)
    families = sorted({str(c.get("family")) for c in cards if c.get("family")})
    return {
        "total": len(cards),
        "confidence_counts": dict(confidence),
        "status_counts": dict(status),
        "families": families,
        "representative_apis": [c.get("api") or c.get("source_api") for c in cards[:8]],
    }


def markdown_table(items: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for item in items:
        lines.append("| " + " | ".join(str(item.get(f, "")) for f in fields) + " |")
    return "\n".join(lines) + "\n"


def write_outputs(out: Path, data: dict[str, Any]) -> None:
    dump_yaml(out / "input/counterpart_enrichment_input_summary.yaml", data["input_summary"])
    write_text(out / "input/counterpart_enrichment_input_summary.md", "# Input Summary\n\n" + json.dumps(data["input_summary"], indent=2) + "\n")
    dump_yaml(out / "existing_schema/existing_counterpart_schema_summary.yaml", data["schema_summary"])
    write_text(out / "existing_schema/existing_counterpart_schema_summary.md", "# Existing Schema Summary\n\n" + json.dumps(data["schema_summary"], indent=2) + "\n")
    dump_yaml(out / "source_inventory/source_roots_inventory.yaml", data["source_inventory"])
    write_text(out / "source_inventory/source_roots_inventory.md", "# Source Roots Inventory\n\n" + json.dumps(data["source_inventory"], indent=2) + "\n")

    dump_yaml(out / "api_cards/staged_openssl_counterpart_api_cards.yaml", {"staged_api_cards": data["openssl_cards"]})
    dump_yaml(out / "api_cards/staged_mbedtls_counterpart_api_cards.yaml", {"staged_api_cards": data["mbedtls_cards"]})
    write_text(out / "api_cards/staged_openssl_counterpart_api_cards.md", markdown_table(data["openssl_cards"], ["api", "family", "evidence_confidence", "import_recommendation"]))
    write_text(out / "api_cards/staged_mbedtls_counterpart_api_cards.md", markdown_table(data["mbedtls_cards"], ["api", "source_api", "family", "evidence_confidence", "staging_status"]))

    dump_yaml(out / "constraints/openssl_counterpart_api_constraints.yaml", {"staged_api_constraints": data["openssl_constraints"]})
    dump_yaml(out / "constraints/mbedtls_counterpart_api_constraints.yaml", {"staged_api_constraints": data["mbedtls_constraints"]})
    write_text(out / "constraints/openssl_counterpart_api_constraints.md", markdown_table(data["openssl_constraints"], ["api", "family", "constraint_kind", "evidence_confidence"]))
    write_text(out / "constraints/mbedtls_counterpart_api_constraints.md", markdown_table(data["mbedtls_constraints"], ["api", "family", "constraint_kind", "evidence_confidence"]))

    dump_yaml(out / "call_sequences/openssl_counterpart_call_sequences.yaml", {"staged_call_sequences": data["openssl_sequences"]})
    dump_yaml(out / "call_sequences/mbedtls_counterpart_call_sequences.yaml", {"staged_call_sequences": data["mbedtls_sequences"]})
    write_text(out / "call_sequences/openssl_counterpart_call_sequences.md", markdown_table(data["openssl_sequences"], ["sequence_name", "family", "sequence_status"]))
    write_text(out / "call_sequences/mbedtls_counterpart_call_sequences.md", markdown_table(data["mbedtls_sequences"], ["sequence_name", "family", "sequence_status"]))

    dump_yaml(out / "mapping_support/cross_library_mapping_support_after_counterpart_enrichment.yaml", {"mapping_support": data["mapping_support"]})
    write_text(out / "mapping_support/cross_library_mapping_support_after_counterpart_enrichment.md", markdown_table(data["mapping_support"], ["source_api", "target_library", "target_api", "support_status_after_staging"]))

    dump_yaml(out / "enrichment_plan/counterpart_api_card_import_plan.yaml", data["import_plan"])
    write_text(out / "enrichment_plan/counterpart_api_card_import_plan.md", "# Import Plan\n\n" + json.dumps(data["import_plan"], indent=2) + "\n")
    dump_yaml(out / "reports/next_action_after_counterpart_enrichment.yaml", data["next_action"])
    write_text(out / "reports/next_action_after_counterpart_enrichment.md", "# Next Action\n\n" + json.dumps(data["next_action"], indent=2) + "\n")
    dump_yaml(out / "reports/api_card_enrichment_for_cross_library_counterparts_report.yaml", data["report"])
    write_text(out / "reports/api_card_enrichment_for_cross_library_counterparts_report.md", "# Counterpart Enrichment Report\n\n" + json.dumps(data["report"], indent=2) + "\n")
    write_text(out / "README.md", "# API Card Enrichment for Cross-Library Counterparts v1\n\nStaged drafts only. No knowledge import, RAG rebuild, PoC run, GLM call, render, or harness generation was performed.\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gap-summary", required=True)
    parser.add_argument("--enrichment-plan", required=True)
    parser.add_argument("--mapping-review", required=True)
    parser.add_argument("--api-card-roots", nargs="+", required=True)
    parser.add_argument("--api-constraint-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-knowledge-raw", default="false")
    parser.add_argument("--write-knowledge-base", default="false")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.write_knowledge_raw.lower() != "false" or args.write_knowledge_base.lower() != "false":
        raise SystemExit("refusing to write knowledge_raw or knowledge_base in staging mode")

    out = Path(args.out_dir)
    gap_summary = load_yaml(Path(args.gap_summary))
    enrichment_plan = load_yaml(Path(args.enrichment_plan))
    mapping_review_doc = load_yaml(Path(args.mapping_review))
    mapping_review = mapping_review_doc.get("mapping_review", [])

    existing_cards = collect_existing_cards([Path(p) for p in args.api_card_roots])
    constraints = collect_constraints(Path(args.api_constraint_root))
    roots = source_roots()

    openssl_cards = [
        make_card(api, family, "openssl", existing_cards, constraints, roots)
        for family, api in flatten_targets(OPENSSL_TARGETS)
    ]
    mbedtls_cards = [
        make_card(api, family, "mbedtls", existing_cards, constraints, roots)
        for family, api in flatten_targets(MBEDTLS_TARGETS)
    ] + make_no_direct_cards()

    openssl_constraints = [c for c in (make_constraint(card) for card in openssl_cards) if c]
    mbedtls_constraints = [c for c in (make_constraint(card) for card in mbedtls_cards) if c]
    openssl_sequences = make_sequences("openssl", openssl_cards)
    mbedtls_sequences = make_sequences("mbedtls", mbedtls_cards)

    card_index = {
        (str(card.get("library")), str(card.get("api"))): card
        for card in openssl_cards + mbedtls_cards
        if card.get("api")
    }
    constraint_index = {
        (str(item.get("library")), str(item.get("api"))): item
        for item in openssl_constraints + mbedtls_constraints
    }
    mapping_support = make_mapping_support(mapping_review, card_index, constraint_index)
    mapping_counts = Counter(item["support_status_after_staging"] for item in mapping_support)

    data = {
        "input_summary": {
            "task": "api_card_enrichment_for_cross_library_counterparts_v1",
            "gap_summary": args.gap_summary,
            "enrichment_plan": args.enrichment_plan,
            "mapping_review": args.mapping_review,
            "write_knowledge_raw": False,
            "write_knowledge_base": False,
            "rag_rebuild": False,
            "glm": False,
            "poc_run": False,
            "render": False,
        },
        "schema_summary": {
            "existing_card_count": sum(len(v) for v in existing_cards.values()),
            "existing_constraint_api_count": len(constraints),
            "api_card_roots": args.api_card_roots,
            "api_constraint_root": args.api_constraint_root,
        },
        "source_inventory": {
            lib: [{"path": str(p), "exists": p.exists()} for p in paths]
            for lib, paths in roots.items()
        },
        "openssl_cards": openssl_cards,
        "mbedtls_cards": mbedtls_cards,
        "openssl_constraints": openssl_constraints,
        "mbedtls_constraints": mbedtls_constraints,
        "openssl_sequences": openssl_sequences,
        "mbedtls_sequences": mbedtls_sequences,
        "mapping_support": mapping_support,
    }
    data["import_plan"] = {
        "recommended_next_task": "manual_review_then_import_counterpart_api_cards_to_knowledge_raw",
        "should_import_to_knowledge_raw_now": False,
        "reason": "This sprint produced staged drafts only; medium/low evidence cards should be reviewed before import.",
        "rebuild_required_after_import": True,
        "source_gap_summary": gap_summary.get("counterpart_gap_summary", {}),
        "source_enrichment_plan": enrichment_plan,
    }
    data["next_action"] = {
        "next_task_name": "manual_review_counterpart_staged_cards_before_import_v1",
        "why": "Counterpart coverage is materially improved on paper, but staged cards should be checked before knowledge_raw import and RAG rebuild.",
    }
    data["report"] = {
        "openssl": count_cards(openssl_cards),
        "mbedtls": count_cards(mbedtls_cards),
        "constraints": {
            "openssl": len(openssl_constraints),
            "mbedtls": len(mbedtls_constraints),
        },
        "call_sequences": {
            "openssl": len(openssl_sequences),
            "mbedtls": len(mbedtls_sequences),
        },
        "mapping_support_counts": dict(mapping_counts),
        "knowledge_raw_modified": False,
        "knowledge_base_modified": False,
        "rag_rebuild": False,
        "pattern_bank_modified": False,
        "scheduler_seed_modified": False,
        "poc_run": False,
        "compile_run": False,
        "glm": False,
        "render": False,
        "template_generated": False,
    }
    write_outputs(out, data)
    print(f"[OK] wrote staged counterpart enrichment to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
