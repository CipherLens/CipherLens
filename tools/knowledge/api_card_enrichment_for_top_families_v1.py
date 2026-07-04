#!/usr/bin/env python3
"""Stage wolfSSL API-card enrichment drafts for top migration families.

This script is intentionally read-only with respect to knowledge_raw and
knowledge_base. It scans local wolfSSL headers/source/tests and writes only
staged sprint artifacts under --out-dir.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
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


API_TARGETS = [
    # TLS / DTLS
    ("wolfSSL_CTX_new", "tls_protocol_state_lifecycle"),
    ("wolfSSL_CTX_free", "tls_protocol_state_lifecycle"),
    ("wolfSSL_new", "tls_protocol_state_lifecycle"),
    ("wolfSSL_free", "tls_protocol_state_lifecycle"),
    ("wolfSSL_connect", "tls_protocol_state_lifecycle"),
    ("wolfSSL_accept", "tls_protocol_state_lifecycle"),
    ("wolfSSL_read", "tls_protocol_state_lifecycle"),
    ("wolfSSL_write", "tls_protocol_state_lifecycle"),
    ("wolfSSL_shutdown", "tls_protocol_state_lifecycle"),
    ("wolfSSL_dtls", "tls_protocol_state_lifecycle"),
    ("wolfSSL_dtls_set_peer", "tls_protocol_state_lifecycle"),
    ("wolfSSL_CTX_set_verify", "tls_protocol_state_lifecycle"),
    ("wolfSSL_use_certificate_file", "tls_protocol_state_lifecycle"),
    ("wolfSSL_use_PrivateKey_file", "tls_protocol_state_lifecycle"),
    # X509 / ASN.1
    ("wolfSSL_X509_load_certificate_file", "x509_parsing"),
    ("wolfSSL_X509_free", "x509_parsing"),
    ("wolfSSL_X509_get_der", "x509_parsing"),
    ("wolfSSL_X509_get_subject_name", "x509_parsing"),
    ("wolfSSL_X509_get_issuer_name", "x509_parsing"),
    ("wolfSSL_X509_verify", "x509_parsing"),
    ("wc_InitDecodedCert", "asn1_nested_boundary"),
    ("wc_ParseCert", "asn1_nested_boundary"),
    ("wc_FreeDecodedCert", "asn1_nested_boundary"),
    ("wc_GetSubjectCN", "asn1_nested_boundary"),
    ("DecodedCert", "asn1_nested_boundary"),
    # PKCS
    ("wc_PKCS7_Init", "pkcs_container_parsing"),
    ("wc_PKCS7_Free", "pkcs_container_parsing"),
    ("wc_PKCS7_VerifySignedData", "pkcs_container_parsing"),
    ("wc_PKCS7_DecodeSignedData", "pkcs_container_parsing"),
    ("wc_PKCS12_parse", "pkcs_container_parsing"),
    ("wc_d2i_PKCS12_bio", "pkcs_container_parsing"),
    # Secure heap / memory
    ("XMALLOC", "secure_heap_state_lifecycle"),
    ("XFREE", "secure_heap_state_lifecycle"),
    ("wolfSSL_Malloc", "secure_heap_state_lifecycle"),
    ("wolfSSL_Free", "secure_heap_state_lifecycle"),
    ("wolfSSL_SetAllocators", "secure_heap_state_lifecycle"),
]


SCAN_SUFFIXES = {".h", ".hpp", ".c", ".cc", ".cpp", ".inc", ".txt", ".md"}
HEADER_SUFFIXES = {".h", ".hpp"}
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".inc"}
TEXT_LIMIT = 2_500_000


def parse_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


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


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def run_git(root: Path, args: list[str]) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def iter_scan_files(root: Path, subdirs: list[str]) -> list[Path]:
    files: list[Path] = []
    for sub in subdirs:
        base = root / sub
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in SCAN_SUFFIXES:
                files.append(path)
    return sorted(files, key=lambda p: str(p))


def safe_read(path: Path) -> str:
    try:
        if path.stat().st_size > TEXT_LIMIT:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def grep_refs(files: list[Path], root: Path, api_names: list[str]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    refs: dict[str, dict[str, list[dict[str, Any]]]] = {
        name: {"header": [], "source": [], "test": [], "doc": []} for name in api_names
    }
    patterns = {name: re.compile(r"\b" + re.escape(name) + r"\b") for name in api_names}
    for path in files:
        text = safe_read(path)
        if not text:
            continue
        path_s = str(path)
        if "/tests/" in path_s or "/examples/" in path_s:
            bucket = "test"
        elif path.suffix.lower() in HEADER_SUFFIXES:
            bucket = "header"
        elif path.suffix.lower() in SOURCE_SUFFIXES:
            bucket = "source"
        else:
            bucket = "doc"
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for name, pat in patterns.items():
                if pat.search(line):
                    refs[name][bucket].append(
                        {"file": rel(path, root), "line": i, "text": line.strip()[:220]}
                    )
    for name in refs:
        for bucket in refs[name]:
            refs[name][bucket] = refs[name][bucket][:12]
    return refs


def extract_signature_candidates(api_name: str, refs: dict[str, list[dict[str, Any]]]) -> list[str]:
    candidates: list[str] = []
    for bucket in ("header", "source"):
        for ref in refs.get(bucket, []):
            text = ref.get("text", "")
            if "(" in text and ")" in text and not text.lstrip().startswith(("*", "//")):
                candidates.append(text)
    dedup = []
    for item in candidates:
        if item not in dedup:
            dedup.append(item)
    return dedup[:5]


def confidence_for(refs: dict[str, list[dict[str, Any]]]) -> str:
    if not any(refs.values()):
        return "not_found_in_source"
    if refs.get("header") and refs.get("test"):
        return "high"
    if refs.get("header") or (refs.get("source") and refs.get("test")):
        return "medium"
    return "low"


def purpose_for(api: str, family: str) -> str:
    if family == "tls_protocol_state_lifecycle":
        if api.endswith("_new") or api == "wolfSSL_new":
            return "Create TLS/DTLS context or session object used by wolfSSL protocol state APIs."
        if api.endswith("_free") or api == "wolfSSL_free":
            return "Release TLS/DTLS context or session object allocated by wolfSSL."
        return "Participate in wolfSSL TLS/DTLS session setup, I/O, verification, or shutdown lifecycle."
    if family == "x509_parsing":
        return "Load, inspect, verify, or free wolfSSL X.509 certificate objects."
    if family == "asn1_nested_boundary":
        return "Initialize, parse, inspect, or free lower-level wolfSSL ASN.1 DecodedCert state."
    if family == "pkcs_container_parsing":
        return "Initialize, decode, verify, parse, or free wolfSSL PKCS7/PKCS12 container state."
    if family == "secure_heap_state_lifecycle":
        return "Allocate, free, or configure wolfSSL memory allocation hooks."
    return "wolfSSL API candidate for pattern-guided migration."


def related_apis(api: str, family: str) -> list[str]:
    groups = {
        "tls_protocol_state_lifecycle": [
            "wolfSSL_CTX_new",
            "wolfSSL_CTX_free",
            "wolfSSL_new",
            "wolfSSL_free",
            "wolfSSL_connect",
            "wolfSSL_accept",
            "wolfSSL_read",
            "wolfSSL_write",
            "wolfSSL_shutdown",
        ],
        "x509_parsing": [
            "wolfSSL_X509_load_certificate_file",
            "wolfSSL_X509_get_der",
            "wolfSSL_X509_verify",
            "wolfSSL_X509_free",
        ],
        "asn1_nested_boundary": [
            "wc_InitDecodedCert",
            "wc_ParseCert",
            "wc_GetSubjectCN",
            "wc_FreeDecodedCert",
            "DecodedCert",
        ],
        "pkcs_container_parsing": [
            "wc_PKCS7_Init",
            "wc_PKCS7_DecodeSignedData",
            "wc_PKCS7_VerifySignedData",
            "wc_PKCS7_Free",
            "wc_PKCS12_parse",
        ],
        "secure_heap_state_lifecycle": [
            "XMALLOC",
            "XFREE",
            "wolfSSL_Malloc",
            "wolfSSL_Free",
            "wolfSSL_SetAllocators",
        ],
    }
    return [x for x in groups.get(family, []) if x != api]


def lifecycle_constraints(api: str, family: str) -> list[str]:
    if "Free" in api or api.endswith("_free") or api == "XFREE":
        return ["cleanup API; object or pointer must have compatible allocation provenance"]
    if "Init" in api or api.endswith("_new") or api == "wolfSSL_new":
        return ["must precede dependent operations on the created or initialized object"]
    if "Parse" in api or "Decode" in api or "Verify" in api:
        return ["input buffers and parser context must remain valid for the parse/verify call"]
    if family == "tls_protocol_state_lifecycle":
        return ["TLS/DTLS context and session state must be initialized before protocol I/O"]
    return ["lifecycle relation inferred from API family; requires manual review before formal import"]


def input_constraints(api: str, family: str) -> list[str]:
    if family in {"x509_parsing", "asn1_nested_boundary"}:
        return ["certificate or DER/PEM input must be well-formed enough for the selected parser path"]
    if family == "pkcs_container_parsing":
        return ["PKCS7/PKCS12 container bytes and lengths must match the selected decode/verify API"]
    if family == "tls_protocol_state_lifecycle":
        return ["context, session, certificates, keys, and peer/socket state must match selected protocol mode"]
    if family == "secure_heap_state_lifecycle":
        return ["allocator hooks and allocation/free pairs must preserve ownership and lifetime"]
    return ["unknown"]


def make_cards(api_refs: dict[str, dict[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    cards = []
    for api, family in sorted(API_TARGETS, key=lambda x: (x[1], x[0])):
        refs = api_refs[api]
        confidence = confidence_for(refs)
        card = {
            "api_name": api,
            "library": "wolfssl",
            "family_relevance": [family],
            "headers": sorted({r["file"] for r in refs.get("header", [])})[:6],
            "source_locations": sorted({r["file"] for r in refs.get("source", [])})[:8],
            "signature_candidates": extract_signature_candidates(api, refs),
            "purpose": purpose_for(api, family),
            "preconditions": lifecycle_constraints(api, family),
            "postconditions": ["return value and output state must be checked by harness oracle where observable"],
            "lifecycle_constraints": lifecycle_constraints(api, family),
            "input_constraints": input_constraints(api, family),
            "ownership_and_lifetime": [
                "ownership/lifetime inferred from paired APIs and must be manually reviewed before formal import"
            ],
            "return_value_semantics": [
                "staged draft only; exact success/failure values require documentation or source review"
            ],
            "cleanup_requirements": [
                x for x in related_apis(api, family) if "free" in x.lower() or "Free" in x or x == "XFREE"
            ],
            "related_apis": related_apis(api, family),
            "example_call_sequences": [],
            "poison_pitfalls": [
                "api_misuse_risk: lifecycle misuse can be confused with migrated vulnerability behavior",
                "false_positive_risk: grep-level evidence is not semantic equivalence",
            ],
            "evidence": {
                "header_refs": refs.get("header", [])[:5],
                "source_refs": refs.get("source", [])[:5],
                "test_refs": refs.get("test", [])[:5],
                "doc_refs": refs.get("doc", [])[:5],
            },
            "confidence": confidence,
            "notes": [
                "Generated as staged draft; not written to knowledge_raw or knowledge_base.",
                "Do not claim vulnerability from this API card without runner/analyzer evidence.",
            ],
        }
        if confidence == "not_found_in_source":
            card["notes"].append("API name was not observed in scanned wolfSSL source/header/test/example files.")
        elif confidence == "medium":
            card["notes"].append("Evidence is mostly header/source grep; confidence is capped at medium.")
        cards.append(card)
    return cards


def make_constraints(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    constraints = []
    for card in cards:
        if card["confidence"] == "not_found_in_source":
            continue
        api = card["api_name"]
        family = card["family_relevance"][0]
        types: list[str] = []
        if "Init" in api or api.endswith("_new") or api in {"wolfSSL_new", "wolfSSL_SetAllocators"}:
            types.append("must_init_before_use")
        if "Free" in api or "free" in api.lower() or api in {"XFREE", "wolfSSL_Free"}:
            types.append("cleanup_required")
        if family in {"x509_parsing", "asn1_nested_boundary", "pkcs_container_parsing"}:
            types.append("input_must_be_der_or_pem")
            types.append("parser_must_reject_malformed")
        if family == "tls_protocol_state_lifecycle":
            types.append("ctx_session_lifecycle")
            types.append("return_code_check")
        if family == "secure_heap_state_lifecycle":
            types.append("ownership_transfer")
        if not types:
            types.append("unknown")
        for ctype in sorted(set(types)):
            constraints.append(
                {
                    "api_name": api,
                    "constraint_type": ctype,
                    "constraint_summary": f"{api} participates in {family}; staged constraint requires manual review before import.",
                    "family_relevance": [family],
                    "evidence": {
                        "header": card["evidence"]["header_refs"][:3],
                        "source": card["evidence"]["source_refs"][:3],
                        "tests": card["evidence"]["test_refs"][:3],
                        "docs": card["evidence"]["doc_refs"][:3],
                    },
                    "confidence": "medium" if card["confidence"] == "high" else card["confidence"],
                    "false_positive_risk": "medium: inferred from API names and grep evidence, not formal docs",
                    "notes": "Use as RAG draft/downstream review input only.",
                }
            )
    return sorted(constraints, key=lambda x: (x["family_relevance"][0], x["api_name"], x["constraint_type"]))


def find_sequences(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    templates = [
        (
            "wolfssl_tls_lifecycle",
            "tls_protocol_state_lifecycle",
            ["wolfSSL_CTX_new", "wolfSSL_new", "wolfSSL_connect", "wolfSSL_read", "wolfSSL_write", "wolfSSL_free", "wolfSSL_CTX_free"],
        ),
        (
            "wolfssl_tls_accept_lifecycle",
            "tls_protocol_state_lifecycle",
            ["wolfSSL_CTX_new", "wolfSSL_new", "wolfSSL_accept", "wolfSSL_read", "wolfSSL_write", "wolfSSL_free", "wolfSSL_CTX_free"],
        ),
        (
            "wolfssl_x509_load_inspect_free",
            "x509_parsing",
            ["wolfSSL_X509_load_certificate_file", "wolfSSL_X509_get_subject_name", "wolfSSL_X509_free"],
        ),
        (
            "wolfssl_decodedcert_parse_free",
            "asn1_nested_boundary",
            ["wc_InitDecodedCert", "wc_ParseCert", "wc_FreeDecodedCert"],
        ),
        (
            "wolfssl_pkcs7_init_decode_free",
            "pkcs_container_parsing",
            ["wc_PKCS7_Init", "wc_PKCS7_DecodeSignedData", "wc_PKCS7_Free"],
        ),
        (
            "wolfssl_pkcs7_init_verify_free",
            "pkcs_container_parsing",
            ["wc_PKCS7_Init", "wc_PKCS7_VerifySignedData", "wc_PKCS7_Free"],
        ),
    ]
    test_files = [p for p in files if "/tests/" in str(p) or "/examples/" in str(p)]
    sequences: list[dict[str, Any]] = []
    for seq_name, family, api_sequence in templates:
        for path in test_files:
            text = safe_read(path)
            if not text:
                continue
            present = [api for api in api_sequence if re.search(r"\b" + re.escape(api) + r"\b", text)]
            if len(present) < 2:
                continue
            refs = []
            for i, line in enumerate(text.splitlines(), 1):
                if any(re.search(r"\b" + re.escape(api) + r"\b", line) for api in present):
                    refs.append({"line": i, "text": line.strip()[:220]})
                if len(refs) >= 12:
                    break
            sequences.append(
                {
                    "sequence_id": f"{seq_name}_{len(sequences)+1:03d}",
                    "library": "wolfssl",
                    "family_relevance": [family],
                    "source_file": rel(path, root),
                    "api_sequence": present,
                    "resource_lifecycle": " -> ".join(present),
                    "cleanup_sequence": [api for api in present if "free" in api.lower() or "Free" in api],
                    "evidence_lines_or_refs": refs,
                    "confidence": "high" if len(present) >= 4 else "medium",
                    "notes": "Sequence inferred from tests/examples; use as staged RAG evidence only.",
                }
            )
            break
    return sorted(sequences, key=lambda x: (x["family_relevance"][0], x["sequence_id"]))


def make_cross_mappings(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found = {card["api_name"]: card for card in cards if card["confidence"] != "not_found_in_source"}
    static = [
        ("tls_protocol_state_lifecycle", "wolfSSL_CTX_new", "SSL_CTX_new", "mbedtls_ssl_config_init", "lifecycle_equivalent"),
        ("tls_protocol_state_lifecycle", "wolfSSL_new", "SSL_new", "mbedtls_ssl_init", "lifecycle_equivalent"),
        ("tls_protocol_state_lifecycle", "wolfSSL_connect", "SSL_connect", "mbedtls_ssl_handshake", "semantic_related"),
        ("tls_protocol_state_lifecycle", "wolfSSL_accept", "SSL_accept", "mbedtls_ssl_handshake", "semantic_related"),
        ("tls_protocol_state_lifecycle", "wolfSSL_read", "SSL_read", "mbedtls_ssl_read", "semantic_related"),
        ("tls_protocol_state_lifecycle", "wolfSSL_write", "SSL_write", "mbedtls_ssl_write", "semantic_related"),
        ("tls_protocol_state_lifecycle", "wolfSSL_free", "SSL_free", "mbedtls_ssl_free", "cleanup_equivalent"),
        ("x509_parsing", "wolfSSL_X509_load_certificate_file", "PEM_read_X509", "mbedtls_x509_crt_parse_file", "parser_equivalent"),
        ("x509_parsing", "wolfSSL_X509_verify", "X509_verify", "mbedtls_x509_crt_verify", "semantic_related"),
        ("x509_parsing", "wolfSSL_X509_free", "X509_free", "mbedtls_x509_crt_free", "cleanup_equivalent"),
        ("asn1_nested_boundary", "wc_InitDecodedCert", "ASN1_item_d2i", "mbedtls_x509_crt_parse_der", "semantic_related"),
        ("asn1_nested_boundary", "wc_ParseCert", "d2i_X509", "mbedtls_x509_crt_parse_der", "parser_equivalent"),
        ("pkcs_container_parsing", "wc_PKCS7_VerifySignedData", "PKCS7_verify", "", "parser_equivalent"),
        ("pkcs_container_parsing", "wc_PKCS7_DecodeSignedData", "d2i_PKCS7", "", "parser_equivalent"),
        ("pkcs_container_parsing", "wc_PKCS12_parse", "PKCS12_parse", "", "parser_equivalent"),
        ("secure_heap_state_lifecycle", "wolfSSL_SetAllocators", "CRYPTO_set_mem_functions", "mbedtls_platform_set_calloc_free", "semantic_related"),
        ("secure_heap_state_lifecycle", "wolfSSL_Malloc", "OPENSSL_malloc", "mbedtls_calloc", "semantic_related"),
        ("secure_heap_state_lifecycle", "wolfSSL_Free", "OPENSSL_free", "mbedtls_free", "cleanup_equivalent"),
    ]
    mappings = []
    for family, wolf_api, ossl, mbed, mtype in static:
        confidence = "medium" if wolf_api in found else "low"
        mappings.append(
            {
                "family": family,
                "wolfssl_api": wolf_api,
                "openssl_candidate_api": ossl,
                "mbedtls_candidate_api": mbed,
                "mapping_type": mtype,
                "confidence": confidence,
                "evidence": {
                    "wolfssl_card_confidence": found.get(wolf_api, {}).get("confidence", "not_found_in_source"),
                    "basis": "static top-family mapping plus staged wolfSSL grep evidence",
                },
                "notes": "Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG evidence gate.",
            }
        )
    return sorted(mappings, key=lambda x: (x["family"], x["wolfssl_api"], x["openssl_candidate_api"]))


def scan_existing_schema(project_root: Path) -> dict[str, Any]:
    roots = [
        project_root / "knowledge_base/api_cards",
        project_root / "knowledge_raw/api_knowledge_cards",
        project_root / "knowledge_raw/api_constraints",
    ]
    files = []
    for root in roots:
        if root.exists():
            files.extend(sorted([p for p in root.rglob("*") if p.is_file()]))
    sampled = []
    observed_fields = set()
    observed_constraint_fields = set()
    for path in files:
        if len(sampled) >= 10:
            break
        if path.suffix not in {".yaml", ".yml", ".md"}:
            continue
        text = safe_read(path)
        if not text:
            continue
        sampled.append(str(path.relative_to(project_root)))
        if path.suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text) or {}
            if isinstance(data, dict):
                observed_fields.update(data.keys())
                for key in ("return_value_semantics", "known_pitfalls", "valid_invalid_ranges"):
                    if key in data:
                        observed_constraint_fields.add(key)
        else:
            for field in ("must_call_before", "must_call_after", "invalid_inputs", "ownership", "memory_lifetime"):
                if field in text:
                    observed_constraint_fields.add(field)
    schema = load_yaml(project_root / "knowledge_base/api_cards/schema.yaml")
    canonical = [
        "api_name",
        "library",
        "family_relevance",
        "headers",
        "source_locations",
        "signature_candidates",
        "purpose",
        "preconditions",
        "postconditions",
        "lifecycle_constraints",
        "input_constraints",
        "ownership_and_lifetime",
        "return_value_semantics",
        "cleanup_requirements",
        "related_apis",
        "example_call_sequences",
        "poison_pitfalls",
        "evidence",
        "confidence",
        "notes",
    ]
    return {
        "sampled_files": sampled,
        "observed_api_card_fields": sorted(observed_fields),
        "observed_constraint_fields": sorted(observed_constraint_fields),
        "formal_schema_file": "knowledge_base/api_cards/schema.yaml" if schema else "",
        "formal_schema": schema,
        "canonical_staged_schema": canonical,
        "schema_note": "Existing api cards use api_card_v0 fields; staged drafts keep richer review fields and require normalization before import.",
    }


def make_inventory(root: Path, install: Path, scan_files: list[Path]) -> dict[str, Any]:
    version = run_git(root, ["describe", "--tags", "--always"])
    commit = run_git(root, ["rev-parse", "HEAD"])
    headers = [p for p in scan_files if p.suffix.lower() in HEADER_SUFFIXES]
    source_files = [p for p in scan_files if p.suffix.lower() in SOURCE_SUFFIXES and ("/src/" in str(p) or "/wolfcrypt/" in str(p))]
    test_examples = [p for p in scan_files if "/tests/" in str(p) or "/examples/" in str(p)]
    docs = [p for p in scan_files if p.suffix.lower() in {".md", ".txt"}]
    return {
        "wolfssl_inventory": {
            "version": version,
            "commit": commit,
            "headers": len(headers),
            "source_files": len(source_files),
            "tests_examples": len(test_examples),
            "docs": len(docs),
            "install_prefix": str(install),
            "include_dir": str(install / "include"),
            "lib_dir": str(install / "lib"),
            "headers_usable": (install / "include").exists(),
            "libs_usable": (install / "lib").exists(),
            "sample_headers": [rel(p, root) for p in headers[:20]],
            "sample_sources": [rel(p, root) for p in source_files[:20]],
            "sample_tests_examples": [rel(p, root) for p in test_examples[:20]],
        }
    }


def md_list(items: list[Any]) -> str:
    if not items:
        return "- none\n"
    return "".join(f"- `{item}`\n" for item in items)


def write_reports(out: Path, data: dict[str, Any]) -> None:
    cards = data["cards"]["wolfssl_api_cards"]
    constraints = data["constraints"]["wolfssl_api_constraint_candidates"]
    sequences = data["sequences"]["wolfssl_call_sequence_candidates"]
    mappings = data["mappings"]["cross_library_api_mapping_candidates"]
    conf = Counter(card["confidence"] for card in cards)
    family_cov = defaultdict(int)
    for card in cards:
        if card["confidence"] != "not_found_in_source":
            for fam in card["family_relevance"]:
                family_cov[fam] += 1

    input_summary = {
        "task": "api_card_enrichment_for_top_families_v1",
        "wolfssl_api_card_coverage_before": 0,
        "top_families": TOP_FAMILIES,
        "why_api_cards_needed": [
            "wolfSSL had zero API-card coverage in the RAG inventory.",
            "Top corrected families need API semantics, lifecycle constraints, call sequences, and false-positive notes before RAG import.",
        ],
        "staged_only": True,
        "write_knowledge_raw": False,
        "write_knowledge_base": False,
        "rag_rebuild": False,
        "read_inputs": data["read_inputs"],
    }
    dump_yaml(out / "input/api_card_enrichment_input_summary.yaml", input_summary)
    write_text(
        out / "input/api_card_enrichment_input_summary.md",
        "# API Card Enrichment Input Summary\n\n"
        "- wolfSSL API card coverage before this sprint: `0`.\n"
        "- Top families need API cards to support candidate scoring, lifecycle constraints, and RAG evidence gates.\n"
        "- This sprint writes staged drafts only.\n"
        "- This sprint does not write `knowledge_raw` or `knowledge_base`.\n"
        "- This sprint does not rebuild RAG.\n",
    )

    schema = data["schema"]
    dump_yaml(out / "existing_schema/api_card_schema_summary.yaml", schema)
    write_text(
        out / "existing_schema/api_card_schema_summary.md",
        "# API Card Schema Summary\n\n"
        "## Sampled Files\n"
        + md_list(schema["sampled_files"])
        + "\n## Observed API Card Fields\n"
        + md_list(schema["observed_api_card_fields"])
        + "\n## Canonical Staged Schema\n"
        + md_list(schema["canonical_staged_schema"])
        + "\nExisting API cards use `api_card_v0`; staged drafts need manual normalization before import.\n",
    )

    inventory = data["inventory"]
    dump_yaml(out / "wolfssl_inventory/wolfssl_header_inventory.yaml", {"headers": inventory["wolfssl_inventory"]["headers"], "sample_headers": inventory["wolfssl_inventory"]["sample_headers"]})
    dump_yaml(out / "wolfssl_inventory/wolfssl_source_inventory.yaml", {"source_files": inventory["wolfssl_inventory"]["source_files"], "sample_sources": inventory["wolfssl_inventory"]["sample_sources"]})
    dump_yaml(out / "wolfssl_inventory/wolfssl_tests_examples_inventory.yaml", {"tests_examples": inventory["wolfssl_inventory"]["tests_examples"], "sample_tests_examples": inventory["wolfssl_inventory"]["sample_tests_examples"]})
    write_text(
        out / "wolfssl_inventory/wolfssl_inventory.md",
        "# wolfSSL Inventory\n\n"
        f"- version: `{inventory['wolfssl_inventory']['version']}`\n"
        f"- commit: `{inventory['wolfssl_inventory']['commit']}`\n"
        f"- headers: `{inventory['wolfssl_inventory']['headers']}`\n"
        f"- source_files: `{inventory['wolfssl_inventory']['source_files']}`\n"
        f"- tests_examples: `{inventory['wolfssl_inventory']['tests_examples']}`\n"
        f"- install_prefix: `{inventory['wolfssl_inventory']['install_prefix']}`\n",
    )

    dump_yaml(out / "api_cards/staged_wolfssl_api_cards.yaml", data["cards"])
    write_text(
        out / "api_cards/staged_wolfssl_api_cards.md",
        "# Staged wolfSSL API Cards\n\n"
        f"- total: `{len(cards)}`\n"
        f"- high: `{conf.get('high', 0)}`\n"
        f"- medium: `{conf.get('medium', 0)}`\n"
        f"- low: `{conf.get('low', 0)}`\n"
        f"- not_found: `{conf.get('not_found_in_source', 0)}`\n\n"
        "## Cards\n"
        + "".join(f"- `{c['api_name']}`: {c['confidence']} ({', '.join(c['family_relevance'])})\n" for c in cards),
    )

    dump_yaml(out / "constraints/wolfssl_api_constraint_candidates.yaml", data["constraints"])
    write_text(
        out / "constraints/wolfssl_api_constraint_candidates.md",
        "# wolfSSL API Constraint Candidates\n\n"
        f"- total: `{len(constraints)}`\n\n"
        + "".join(f"- `{c['api_name']}` `{c['constraint_type']}`: {c['confidence']}\n" for c in constraints[:120]),
    )

    dump_yaml(out / "call_sequences/wolfssl_call_sequence_candidates.yaml", data["sequences"])
    write_text(
        out / "call_sequences/wolfssl_call_sequence_candidates.md",
        "# wolfSSL Call Sequence Candidates\n\n"
        f"- total: `{len(sequences)}`\n\n"
        + "".join(f"- `{s['sequence_id']}` `{s['source_file']}`: {' -> '.join(s['api_sequence'])}\n" for s in sequences),
    )

    dump_yaml(out / "cross_mapping/cross_library_api_mapping_candidates.yaml", data["mappings"])
    write_text(
        out / "cross_mapping/cross_library_api_mapping_candidates.md",
        "# Cross-Library API Mapping Candidates\n\n"
        f"- total: `{len(mappings)}`\n\n"
        + "".join(
            f"- `{m['family']}` `{m['wolfssl_api']}` -> OpenSSL `{m['openssl_candidate_api']}`, mbedTLS `{m['mbedtls_candidate_api']}` ({m['confidence']})\n"
            for m in mappings
        ),
    )

    high = [c["api_name"] for c in cards if c["confidence"] == "high"]
    medium = [c["api_name"] for c in cards if c["confidence"] == "medium"]
    low = [c["api_name"] for c in cards if c["confidence"] == "low"]
    not_found = [c["api_name"] for c in cards if c["confidence"] == "not_found_in_source"]
    recommended = "api_card_manual_review_v1" if len(high) < 5 else "api_card_import_to_knowledge_raw_v1"
    import_draft = {
        "staged_wolfssl_api_cards": cards,
        "staged_wolfssl_api_constraints": constraints,
        "staged_wolfssl_call_sequences": sequences,
        "staged_cross_library_mapping_candidates": mappings,
        "negative_feedback_reminders": [
            "Do not treat weak_name_match or grep evidence as semantic equivalence.",
            "Import blocked seeds and negative feedback as down-ranking evidence, not vulnerability evidence.",
            "Do not report staged API cards as confirmed vulnerabilities.",
        ],
    }
    dump_yaml(out / "import_plan/staged_knowledge_raw_import_draft.yaml", import_draft)
    write_text(
        out / "import_plan/staged_knowledge_raw_import_draft.md",
        "# Staged Knowledge Raw Import Draft\n\n"
        "## staged wolfSSL API cards\n"
        + md_list([c["api_name"] for c in cards])
        + "\n## staged wolfSSL API constraints\n"
        + md_list([f"{c['api_name']}:{c['constraint_type']}" for c in constraints[:80]])
        + "\n## staged wolfSSL call sequences\n"
        + md_list([s["sequence_id"] for s in sequences])
        + "\n## staged cross-library mapping candidates\n"
        + md_list([f"{m['family']}:{m['wolfssl_api']}" for m in mappings])
        + "\n## negative feedback reminders\n- Import as down-ranking evidence only.\n",
    )
    reason = (
        "High-confidence staged cards are sufficient for a formal import task; still review not_found and medium-confidence entries before import."
        if recommended == "api_card_import_to_knowledge_raw_v1"
        else "Manual review is preferred when high-confidence cards are limited or grep-only evidence dominates."
    )
    formal_plan = {
        "formal_import_plan": {
            "recommended_next_task": recommended,
            "high_confidence_cards": high,
            "medium_confidence_cards": medium,
            "low_confidence_cards": low,
            "not_found_apis": not_found,
            "suggested_targets": {
                "knowledge_raw_api_cards": "knowledge_raw/api_knowledge_cards/wolfssl/top_families/",
                "knowledge_raw_api_constraints": "knowledge_raw/api_constraints/wolfssl/5.9.1/",
                "knowledge_raw_cross_mapping": "knowledge_raw/cross_lib_equivalence/wolfssl_top_families.md",
            },
            "rebuild_required_after_import": True,
            "should_import_to_knowledge_raw_now": recommended == "api_card_import_to_knowledge_raw_v1",
            "reason": reason,
        }
    }
    dump_yaml(out / "import_plan/api_card_formal_import_plan.yaml", formal_plan)
    write_text(
        out / "import_plan/api_card_formal_import_plan.md",
        "# API Card Formal Import Plan\n\n"
        f"- recommended_next_task: `{recommended}`\n"
        f"- high_confidence_cards: `{len(high)}`\n"
        f"- medium_confidence_cards: `{len(medium)}`\n"
        f"- low_confidence_cards: `{len(low)}`\n"
        f"- not_found_apis: `{len(not_found)}`\n"
        "- rebuild_required_after_import: `true`\n",
    )

    report = {
        "task": "api_card_enrichment_for_top_families_v1",
        "wolfssl_source_usable": True,
        "wolfssl_install_usable": inventory["wolfssl_inventory"]["headers_usable"] and inventory["wolfssl_inventory"]["libs_usable"],
        "wolfssl_version": inventory["wolfssl_inventory"]["version"],
        "wolfssl_commit": inventory["wolfssl_inventory"]["commit"],
        "sampled_schema_files": schema["sampled_files"],
        "staged_api_cards_total": len(cards),
        "confidence_counts": dict(conf),
        "api_constraint_candidates_total": len(constraints),
        "call_sequence_candidates_total": len(sequences),
        "cross_library_mapping_candidates_total": len(mappings),
        "top_families_coverage": dict(sorted(family_cov.items())),
        "write_knowledge_raw": False,
        "write_knowledge_base": False,
        "rag_rebuild": False,
        "run_poc": False,
        "glm": False,
        "render": False,
        "next_task_name": recommended,
    }
    dump_yaml(out / "reports/api_card_enrichment_for_top_families_report.yaml", report)
    write_text(
        out / "reports/api_card_enrichment_for_top_families_report.md",
        "# API Card Enrichment For Top Families Report\n\n"
        f"- wolfSSL source usable: `{report['wolfssl_source_usable']}`\n"
        f"- wolfSSL install usable: `{report['wolfssl_install_usable']}`\n"
        f"- staged wolfSSL API cards: `{len(cards)}`\n"
        f"- high / medium / low / not_found: `{conf.get('high', 0)}` / `{conf.get('medium', 0)}` / `{conf.get('low', 0)}` / `{conf.get('not_found_in_source', 0)}`\n"
        f"- API constraint candidates: `{len(constraints)}`\n"
        f"- call sequence candidates: `{len(sequences)}`\n"
        f"- cross-library mapping candidates: `{len(mappings)}`\n"
        f"- formal knowledge_raw write: `false`\n"
        f"- formal knowledge_base write: `false`\n"
        f"- RAG rebuild: `false`\n"
        f"- PoC / GLM / render: `false`\n"
        f"- next task: `{recommended}`\n",
    )
    write_text(
        out / "README.md",
        "# api_card_enrichment_for_top_families_v1\n\n"
        "Staged wolfSSL API-card, constraint, call-sequence, and cross-library mapping drafts.\n"
        "No formal RAG write, no RAG rebuild, no GLM, no PoC execution, and no harness rendering were performed.\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wolfssl-src", required=True)
    parser.add_argument("--wolfssl-install", required=True)
    parser.add_argument("--corrected-candidates", required=True)
    parser.add_argument("--rag-inventory", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-knowledge-raw", default="false")
    parser.add_argument("--write-knowledge-base", default="false")
    args = parser.parse_args()

    if parse_bool(args.write_knowledge_raw) or parse_bool(args.write_knowledge_base):
        raise SystemExit("This staging script refuses to write knowledge_raw or knowledge_base.")

    project_root = Path.cwd()
    wolfssl_src = Path(args.wolfssl_src)
    wolfssl_install = Path(args.wolfssl_install)
    out = Path(args.out_dir)
    for sub in [
        "input",
        "existing_schema",
        "wolfssl_inventory",
        "api_cards",
        "constraints",
        "call_sequences",
        "cross_mapping",
        "import_plan",
        "reports",
        "logs",
        "validation",
    ]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    read_inputs = {
        "rag_inventory": args.rag_inventory,
        "corrected_candidates": args.corrected_candidates,
        "api_card_coverage": "artifacts/sprints/rag_knowledge_inventory_v1/coverage/api_card_coverage.yaml",
        "poc_pattern_coverage": "artifacts/sprints/rag_knowledge_inventory_v1/coverage/poc_pattern_coverage.yaml",
        "rag_tooling_inventory": "artifacts/sprints/rag_knowledge_inventory_v1/inventory/rag_tooling_inventory.yaml",
        "rag_enrichment_plan": "artifacts/sprints/rag_knowledge_inventory_v1/reports/rag_enrichment_plan_after_inventory.yaml",
        "family_correction_plan": "artifacts/sprints/manual_review_family_corrections_v1/rag_plan/rag_enrichment_after_family_correction_plan.yaml",
        "wolfssl_collect": "data/wolfssl_collect/",
    }
    # Load to ensure parseability when files exist; missing optional dirs are recorded, not fatal.
    for p in read_inputs.values():
        path = project_root / p
        if path.suffix in {".yaml", ".yml"} and path.exists():
            load_yaml(path)

    files = iter_scan_files(
        wolfssl_src,
        ["wolfssl", "src", "wolfcrypt", "tests", "examples", "doc", "docs"],
    )
    api_names = [api for api, _family in API_TARGETS]
    api_refs = grep_refs(files, wolfssl_src, api_names)
    cards = make_cards(api_refs)
    constraints = make_constraints(cards)
    sequences = find_sequences(wolfssl_src, files)
    mappings = make_cross_mappings(cards)
    schema = scan_existing_schema(project_root)
    inventory = make_inventory(wolfssl_src, wolfssl_install, files)
    data = {
        "read_inputs": read_inputs,
        "schema": schema,
        "inventory": inventory,
        "cards": {"wolfssl_api_cards": cards},
        "constraints": {"wolfssl_api_constraint_candidates": constraints},
        "sequences": {"wolfssl_call_sequence_candidates": sequences},
        "mappings": {"cross_library_api_mapping_candidates": mappings},
    }
    write_reports(out, data)

    summary = {
        "staged_api_cards_total": len(cards),
        "confidence_counts": dict(Counter(card["confidence"] for card in cards)),
        "api_constraint_candidates_total": len(constraints),
        "call_sequence_candidates_total": len(sequences),
        "cross_library_mapping_candidates_total": len(mappings),
        "write_knowledge_raw": False,
        "write_knowledge_base": False,
        "rag_rebuild": False,
        "glm": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
