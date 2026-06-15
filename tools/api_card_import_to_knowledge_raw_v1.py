#!/usr/bin/env python3
"""Import high-confidence staged wolfSSL API cards into knowledge_raw.

This tool normalizes staged sprint drafts into structured raw knowledge files.
It deliberately refuses to write knowledge_base and does not rebuild any index.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


SPRINT_NAME = "api_card_import_to_knowledge_raw_v1"
ENRICHMENT_SPRINT = "api_card_enrichment_for_top_families_v1"
WOLFSSL_VERSION = "v5.9.1-stable"
WOLFSSL_COMMIT = "1d363f3adceba9d1478230ede476a37b0dcdef24"


def parse_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def short_refs(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for ref in refs[:5]:
        out.append(
            {
                "file": ref.get("file", ""),
                "line": ref.get("line", ""),
                "summary": str(ref.get("text", ""))[:180],
            }
        )
    return out


def normalize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "header_refs": short_refs(evidence.get("header_refs", []) or evidence.get("header", [])),
        "source_refs": short_refs(evidence.get("source_refs", []) or evidence.get("source", [])),
        "test_refs": short_refs(evidence.get("test_refs", []) or evidence.get("tests", [])),
        "doc_refs": short_refs(evidence.get("doc_refs", []) or evidence.get("docs", [])),
    }


def has_evidence(obj: dict[str, Any]) -> bool:
    evidence = obj.get("evidence", {})
    for value in evidence.values():
        if value:
            return True
    return False


def primary_family(card: dict[str, Any]) -> str:
    families = card.get("family_relevance") or []
    return families[0] if families else "unknown"


def infer_parameter_semantics(signature: str) -> dict[str, str]:
    if not signature or "(" not in signature or ")" not in signature:
        return {}
    inside = signature.split("(", 1)[1].rsplit(")", 1)[0]
    params = {}
    if inside.strip() in {"void", ""}:
        return params
    for raw in inside.split(","):
        raw = raw.strip()
        if not raw:
            continue
        name = raw.replace("*", " ").split()[-1].strip("[]")
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            continue
        lower = name.lower()
        if "ctx" in lower:
            role = "context/session object"
        elif "cert" in lower or "x509" in lower:
            role = "certificate object or certificate input"
        elif "der" in lower or "pem" in lower or "buf" in lower or "in" == lower:
            role = "input buffer"
        elif "len" in lower or "sz" in lower or "size" in lower:
            role = "input/output length"
        elif "out" in lower:
            role = "output buffer or output parameter"
        else:
            role = "API parameter; semantics require manual review"
        params[name] = role
    return params


def oracle_observables_for(family: str) -> list[str]:
    mapping = {
        "tls_protocol_state_lifecycle": ["return_code", "session_state", "error_code", "sanitizer_signal"],
        "asn1_nested_boundary": ["return_code", "parser_state", "consumed_input_or_error", "sanitizer_signal"],
        "x509_parsing": ["return_code", "certificate_object", "error_code", "sanitizer_signal"],
        "pkcs_container_parsing": ["return_code", "parser_state", "container_object", "sanitizer_signal"],
        "secure_heap_state_lifecycle": ["return_code", "allocation_state", "ownership_lifetime", "sanitizer_signal"],
    }
    return mapping.get(family, ["return_code", "sanitizer_signal"])


def normalize_card(card: dict[str, Any], staged_file: str) -> dict[str, Any]:
    family = primary_family(card)
    signature_candidates = card.get("signature_candidates") or []
    signature = signature_candidates[0] if signature_candidates else ""
    notes = list(card.get("notes") or [])
    notes.extend(card.get("poison_pitfalls") or [])
    notes.append("Imported as structured raw knowledge, not as vulnerability confirmation.")
    notes.append("parser_must_reject_malformed and similar constraints are oracle candidates, not confirmed bugs.")
    mutation_hints = []
    mutation_hints.extend(card.get("lifecycle_constraints") or [])
    mutation_hints.extend(card.get("input_constraints") or [])
    mutation_hints.extend(card.get("poison_pitfalls") or [])
    return {
        "schema": "api_card_v0",
        "api": card.get("api_name"),
        "library": "wolfssl",
        "family": family,
        "families": card.get("family_relevance") or [family],
        "signature": signature,
        "signature_candidates": signature_candidates,
        "parameter_semantics": infer_parameter_semantics(signature),
        "return_value_semantics": {
            "summary": card.get("return_value_semantics") or [],
            "review_required": True,
        },
        "state_preconditions": card.get("preconditions") or [],
        "valid_invalid_ranges": {
            "valid": card.get("postconditions") or [],
            "invalid": card.get("input_constraints") or [],
            "manual_review_required": True,
        },
        "mutation_hints": mutation_hints,
        "oracle_observables": oracle_observables_for(family),
        "lifecycle": {
            "init": [x for x in card.get("related_apis", []) if "init" in x.lower() or x.endswith("_new")],
            "use": [card.get("api_name")],
            "cleanup": card.get("cleanup_requirements") or [x for x in card.get("related_apis", []) if "free" in x.lower()],
        },
        "related_apis": card.get("related_apis") or [],
        "evidence": normalize_evidence(card.get("evidence") or {}),
        "confidence": card.get("confidence"),
        "import_source": {
            "sprint": SPRINT_NAME,
            "staged_file": staged_file,
            "wolfssl_version": WOLFSSL_VERSION,
            "wolfssl_commit": WOLFSSL_COMMIT,
        },
        "notes": notes,
    }


def normalize_constraint(item: dict[str, Any]) -> dict[str, Any]:
    family = (item.get("family_relevance") or ["unknown"])[0]
    return {
        "library": "wolfssl",
        "api": item.get("api_name"),
        "family": family,
        "constraint_type": item.get("constraint_type"),
        "constraint_summary": item.get("constraint_summary"),
        "false_positive_risk": item.get("false_positive_risk"),
        "oracle_relevance": "constraint_candidate_not_confirmed",
        "evidence": normalize_evidence(item.get("evidence") or {}),
        "confidence": item.get("confidence"),
        "import_source": {
            "sprint": SPRINT_NAME,
            "source": "api_card_enrichment_for_top_families_v1 constraints",
        },
        "notes": [
            item.get("notes", ""),
            "constraint_candidate_not_confirmed",
            "Do not classify as vulnerability without runner/analyzer evidence.",
        ],
    }


def normalize_sequence(item: dict[str, Any]) -> dict[str, Any]:
    family = (item.get("family_relevance") or ["unknown"])[0]
    seq = item.get("api_sequence") or []
    if family == "tls_protocol_state_lifecycle":
        role = "lifecycle_example"
    elif any("free" in api.lower() for api in seq):
        role = "cleanup_example"
    elif family in {"asn1_nested_boundary", "x509_parsing", "pkcs_container_parsing"}:
        role = "parser_example"
    else:
        role = "weak_sequence"
    return {
        "library": "wolfssl",
        "sequence_id": item.get("sequence_id"),
        "family": family,
        "api_sequence": seq,
        "resource_lifecycle": item.get("resource_lifecycle"),
        "cleanup_sequence": item.get("cleanup_sequence") or [],
        "evidence": {
            "source_file": item.get("source_file"),
            "refs": short_refs(item.get("evidence_lines_or_refs") or []),
        },
        "confidence": item.get("confidence"),
        "usage_role": role,
        "notes": [
            item.get("notes", ""),
            "Usage sequence candidate only; not a generated harness.",
        ],
    }


def normalize_mapping(item: dict[str, Any]) -> dict[str, Any]:
    confidence = item.get("confidence", "low")
    if item.get("mapping_type") == "weak_name_match":
        confidence = "low"
    return {
        "schema": "cross_library_mapping_candidate_v0",
        "family": item.get("family"),
        "wolfssl_api": item.get("wolfssl_api"),
        "openssl_candidate_api": item.get("openssl_candidate_api"),
        "mbedtls_candidate_api": item.get("mbedtls_candidate_api"),
        "mapping_type": item.get("mapping_type"),
        "confidence": confidence,
        "evidence": item.get("evidence") or {},
        "status": "candidate_only",
        "notes": [
            item.get("notes", ""),
            "Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.",
        ],
    }


def md_list(items: list[str]) -> str:
    return "".join(f"- `{x}`\n" for x in items) if items else "- none\n"


def write_api_cards_md(path: Path, cards: list[dict[str, Any]]) -> None:
    lines = ["# wolfSSL Top Family API Cards\n", "Imported high-confidence staged cards in `api_card_v0` shape.\n"]
    for card in cards:
        lines.append(f"\n## {card['api']}\n")
        lines.append(f"- family: `{card['family']}`\n")
        lines.append(f"- confidence: `{card['confidence']}`\n")
        lines.append(f"- signature: `{card['signature']}`\n")
        lines.append("- status: structured raw knowledge, not vulnerability confirmation\n")
    write_text(path, "\n".join(lines))


def write_simple_md(path: Path, title: str, rows: list[str]) -> None:
    write_text(path, f"# {title}\n\n" + md_list(rows))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--staged-cards", required=True)
    parser.add_argument("--constraints", required=True)
    parser.add_argument("--call-sequences", required=True)
    parser.add_argument("--cross-mapping", required=True)
    parser.add_argument("--knowledge-raw-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-knowledge-raw", default="true")
    parser.add_argument("--write-knowledge-base", default="false")
    args = parser.parse_args()

    if parse_bool(args.write_knowledge_base):
        raise SystemExit("Refusing to write knowledge_base in this task.")
    write_knowledge_raw = parse_bool(args.write_knowledge_raw)

    staged_path = Path(args.staged_cards)
    out = Path(args.out_dir)
    knowledge_raw = Path(args.knowledge_raw_root)
    for sub in [
        "input",
        "schema",
        "normalized_cards",
        "normalized_constraints",
        "normalized_call_sequences",
        "normalized_cross_mapping",
        "knowledge_raw_draft",
        "imported",
        "reports",
        "logs",
        "validation",
    ]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    staged_cards = load_yaml(staged_path).get("wolfssl_api_cards", [])
    constraints = load_yaml(Path(args.constraints)).get("wolfssl_api_constraint_candidates", [])
    sequences = load_yaml(Path(args.call_sequences)).get("wolfssl_call_sequence_candidates", [])
    mappings = load_yaml(Path(args.cross_mapping)).get("cross_library_api_mapping_candidates", [])

    high_cards_raw = sorted(
        [c for c in staged_cards if c.get("library") == "wolfssl" and c.get("confidence") == "high"],
        key=lambda c: (primary_family(c), c.get("api_name", "")),
    )
    skipped_cards = sorted(
        [c for c in staged_cards if c not in high_cards_raw],
        key=lambda c: (str(c.get("confidence")), primary_family(c), c.get("api_name", "")),
    )
    normalized_cards = [normalize_card(c, str(staged_path)) for c in high_cards_raw]
    high_api_names = {c["api"] for c in normalized_cards}

    normalized_constraints = []
    weak_constraints = []
    for item in sorted(constraints, key=lambda x: ((x.get("family_relevance") or [""])[0], x.get("api_name", ""), x.get("constraint_type", ""))):
        explicit_evidence = has_evidence(item)
        if item.get("confidence") in {"high", "medium"} and explicit_evidence:
            normalized_constraints.append(normalize_constraint(item))
        else:
            weak_constraints.append(item)

    normalized_sequences = [normalize_sequence(s) for s in sorted(sequences, key=lambda x: (x.get("family_relevance", [""])[0], x.get("sequence_id", "")))]
    normalized_mappings = [normalize_mapping(m) for m in sorted(mappings, key=lambda x: (x.get("family", ""), x.get("wolfssl_api", ""), x.get("openssl_candidate_api", "")))]
    low_mappings = [m for m in normalized_mappings if m.get("confidence") == "low"]

    input_summary = {
        "task": SPRINT_NAME,
        "input_sprint": ENRICHMENT_SPRINT,
        "staged_cards": len(staged_cards),
        "high_confidence_imported": len(normalized_cards),
        "medium_skipped": len([c for c in skipped_cards if c.get("confidence") == "medium"]),
        "not_found_skipped": len([c for c in skipped_cards if c.get("confidence") == "not_found_in_source"]),
        "write_knowledge_raw": write_knowledge_raw,
        "write_knowledge_base": False,
        "rag_rebuild": False,
        "notes": [
            "Only high-confidence staged wolfSSL API cards are imported.",
            "Medium and not_found cards are routed to manual review.",
            "This task writes knowledge_raw structured summaries only.",
            "This task does not write knowledge_base or rebuild RAG.",
        ],
    }
    dump_yaml(out / "input/import_input_summary.yaml", input_summary)
    write_text(
        out / "input/import_input_summary.md",
        "# API Card Import Input Summary\n\n"
        f"- input sprint: `{ENRICHMENT_SPRINT}`\n"
        f"- staged cards: `{len(staged_cards)}`\n"
        f"- high-confidence imported: `{len(normalized_cards)}`\n"
        f"- medium / not_found routed to manual review: `{input_summary['medium_skipped']}` / `{input_summary['not_found_skipped']}`\n"
        "- writes `knowledge_raw` only; does not write `knowledge_base`; does not rebuild RAG.\n",
    )

    schema_summary = {
        "target_schema": "api_card_v0",
        "required_fields": [
            "schema",
            "api",
            "library",
            "family",
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "valid_invalid_ranges",
            "mutation_hints",
            "oracle_observables",
        ],
        "normalization_notes": [
            "family_relevance is preserved as families and first element selected as primary family.",
            "signature_candidates are preserved; first candidate is used as signature.",
            "poison_pitfalls are folded into mutation_hints and notes.",
            "evidence is stored as short path/line/summary refs only.",
        ],
    }
    dump_yaml(out / "schema/api_card_v0_normalization_schema.yaml", schema_summary)
    write_simple_md(out / "schema/api_card_v0_normalization_schema.md", "api_card_v0 normalization schema", schema_summary["required_fields"])

    normalized_cards_doc = {"wolfssl_api_cards_api_card_v0": normalized_cards}
    normalized_constraints_doc = {"wolfssl_api_constraints_normalized": normalized_constraints}
    normalized_sequences_doc = {"wolfssl_call_sequences_normalized": normalized_sequences}
    normalized_mappings_doc = {"wolfssl_cross_library_mapping_candidates": normalized_mappings}

    dump_yaml(out / "normalized_cards/wolfssl_api_cards_api_card_v0.yaml", normalized_cards_doc)
    write_api_cards_md(out / "normalized_cards/wolfssl_api_cards_api_card_v0.md", normalized_cards)
    dump_yaml(out / "normalized_constraints/wolfssl_api_constraints_normalized.yaml", normalized_constraints_doc)
    write_simple_md(
        out / "normalized_constraints/wolfssl_api_constraints_normalized.md",
        "wolfSSL API constraints normalized",
        [f"{c['family']}:{c['api']}:{c['constraint_type']}:{c['confidence']}" for c in normalized_constraints],
    )
    dump_yaml(out / "normalized_call_sequences/wolfssl_call_sequences_normalized.yaml", normalized_sequences_doc)
    write_simple_md(
        out / "normalized_call_sequences/wolfssl_call_sequences_normalized.md",
        "wolfSSL call sequences normalized",
        [f"{s['family']}:{s['sequence_id']}:{' -> '.join(s['api_sequence'])}" for s in normalized_sequences],
    )
    dump_yaml(out / "normalized_cross_mapping/wolfssl_cross_library_mapping_candidates.yaml", normalized_mappings_doc)
    write_simple_md(
        out / "normalized_cross_mapping/wolfssl_cross_library_mapping_candidates.md",
        "wolfSSL cross-library mapping candidates",
        [f"{m['family']}:{m['wolfssl_api']}:{m['mapping_type']}:{m['confidence']}:{m['status']}" for m in normalized_mappings],
    )

    raw_files = [
        (knowledge_raw / "api_knowledge_cards/wolfssl_top_family_api_cards.yaml", normalized_cards_doc, "api_cards", len(normalized_cards)),
        (knowledge_raw / "api_constraints/wolfssl_top_family_api_constraints.yaml", normalized_constraints_doc, "api_constraints", len(normalized_constraints)),
        (knowledge_raw / "api_constraints/wolfssl_call_sequences.yaml", normalized_sequences_doc, "call_sequences", len(normalized_sequences)),
        (knowledge_raw / "cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml", normalized_mappings_doc, "cross_mapping_candidates", len(normalized_mappings)),
    ]
    written = []
    if write_knowledge_raw:
        for path, data, typ, records in raw_files:
            dump_yaml(path, data)
            written.append({"path": str(path), "type": typ, "records": records, "notes": "structured summary only"})
        write_api_cards_md(knowledge_raw / "api_knowledge_cards/wolfssl_top_family_api_cards.md", normalized_cards)
        write_simple_md(
            knowledge_raw / "api_constraints/wolfssl_top_family_api_constraints.md",
            "wolfSSL top-family API constraints",
            [f"{c['api']}:{c['constraint_type']}" for c in normalized_constraints],
        )
        write_simple_md(
            knowledge_raw / "api_constraints/wolfssl_call_sequences.md",
            "wolfSSL call sequences",
            [f"{s['sequence_id']}:{' -> '.join(s['api_sequence'])}" for s in normalized_sequences],
        )
        write_simple_md(
            knowledge_raw / "cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.md",
            "wolfSSL cross-library mapping candidates",
            [f"{m['wolfssl_api']} -> {m['openssl_candidate_api']} / {m['mbedtls_candidate_api']}" for m in normalized_mappings],
        )
    imported = {
        "written_files": written,
        "not_written": [
            {"item": c.get("api_name"), "reason": f"api card confidence={c.get('confidence')} routed to manual review"}
            for c in skipped_cards
        ]
        + [
            {"item": c.get("api_name"), "reason": "constraint missing explicit evidence or unsupported confidence"}
            for c in weak_constraints
        ],
    }
    dump_yaml(out / "imported/imported_knowledge_raw_files.yaml", imported)
    write_simple_md(
        out / "imported/imported_knowledge_raw_files.md",
        "Imported knowledge_raw files",
        [f"{x['path']} ({x['records']} records)" for x in written],
    )

    manual_review = {
        "medium_api_cards": [c.get("api_name") for c in skipped_cards if c.get("confidence") == "medium"],
        "not_found_api_cards": [c.get("api_name") for c in skipped_cards if c.get("confidence") == "not_found_in_source"],
        "low_confidence_cross_library_mappings": low_mappings,
        "constraints_without_enough_evidence": [
            {"api": c.get("api_name"), "constraint_type": c.get("constraint_type"), "confidence": c.get("confidence")}
            for c in weak_constraints
        ],
        "required_items_present": {
            "wc_GetSubjectCN": any(c.get("api_name") == "wc_GetSubjectCN" for c in skipped_cards),
            "wc_PKCS7_DecodeSignedData": any(c.get("api_name") == "wc_PKCS7_DecodeSignedData" for c in skipped_cards),
            "wc_d2i_PKCS12_bio": any(c.get("api_name") == "wc_d2i_PKCS12_bio" for c in skipped_cards),
        },
    }
    dump_yaml(out / "reports/manual_review_items.yaml", manual_review)
    write_text(
        out / "reports/manual_review_items.md",
        "# Manual Review Items\n\n"
        "## Medium API Cards\n"
        + md_list(manual_review["medium_api_cards"])
        + "\n## Not Found API Cards\n"
        + md_list(manual_review["not_found_api_cards"])
        + "\n## Low-Confidence Cross-Library Mappings\n"
        + md_list([f"{m['wolfssl_api']}:{m['mapping_type']}" for m in low_mappings])
        + "\nRequired not-found review items include `wc_GetSubjectCN`, `wc_PKCS7_DecodeSignedData`, and `wc_d2i_PKCS12_bio`.\n",
    )

    rebuild_plan = {
        "recommended_next_task": "rag_rebuild_and_query_eval_v1",
        "reason": [
            "knowledge_raw has new wolfSSL API cards and constraints.",
            "knowledge_base index must be rebuilt to include the new raw knowledge.",
            "query eval should verify TLS, ASN.1, PKCS, and X509 retrieval quality.",
        ],
        "queries_to_eval": [
            "wolfSSL PKCS7 VerifySignedData cleanup",
            "wolfSSL DecodedCert parse free lifecycle",
            "wolfSSL TLS context new free lifecycle",
            "wolfSSL X509 load certificate free",
            "wolfSSL cross library mapping OpenSSL PKCS7",
        ],
        "rebuild_executed": False,
    }
    dump_yaml(out / "reports/rag_rebuild_plan_after_api_card_import.yaml", rebuild_plan)
    write_simple_md(out / "reports/rag_rebuild_plan_after_api_card_import.md", "RAG rebuild plan after API card import", rebuild_plan["queries_to_eval"])

    family_counts = Counter(card["family"] for card in normalized_cards)
    report = {
        "task": SPRINT_NAME,
        "staged_cards_read": len(staged_cards),
        "high_confidence_imported": len(normalized_cards),
        "medium_skipped": len(manual_review["medium_api_cards"]),
        "not_found_skipped": len(manual_review["not_found_api_cards"]),
        "knowledge_raw_written_files": written,
        "api_card_v0_normalized": True,
        "constraints_written": len(normalized_constraints),
        "call_sequences_written": len(normalized_sequences),
        "cross_mapping_candidates_written": len(normalized_mappings),
        "knowledge_base_written": False,
        "rag_rebuild": False,
        "run_poc": False,
        "glm": False,
        "render": False,
        "pattern_bank_modified": False,
        "scheduler_seed_modified": False,
        "families_covered": dict(sorted(family_counts.items())),
        "next_task_name": "rag_rebuild_and_query_eval_v1",
    }
    dump_yaml(out / "reports/api_card_import_to_knowledge_raw_report.yaml", report)
    write_text(
        out / "reports/api_card_import_to_knowledge_raw_report.md",
        "# API Card Import To Knowledge Raw Report\n\n"
        f"- staged cards read: `{len(staged_cards)}`\n"
        f"- high-confidence imported: `{len(normalized_cards)}`\n"
        f"- medium skipped: `{report['medium_skipped']}`\n"
        f"- not_found skipped: `{report['not_found_skipped']}`\n"
        f"- constraints written: `{len(normalized_constraints)}`\n"
        f"- call sequences written: `{len(normalized_sequences)}`\n"
        f"- mapping candidates written: `{len(normalized_mappings)}`\n"
        "- knowledge_base written: `false`\n"
        "- RAG rebuild: `false`\n"
        "- PoC / GLM / render: `false`\n"
        "- next task: `rag_rebuild_and_query_eval_v1`\n",
    )
    write_text(
        out / "README.md",
        "# api_card_import_to_knowledge_raw_v1\n\n"
        "Imported high-confidence staged wolfSSL API cards into `knowledge_raw` as structured summaries. "
        "Medium/not_found cards were routed to manual review. No `knowledge_base` write, RAG rebuild, GLM, PoC run, or render was performed.\n",
    )

    print(
        json.dumps(
            {
                "staged_cards_read": len(staged_cards),
                "high_confidence_imported": len(normalized_cards),
                "medium_skipped": report["medium_skipped"],
                "not_found_skipped": report["not_found_skipped"],
                "constraints_written": len(normalized_constraints),
                "call_sequences_written": len(normalized_sequences),
                "cross_mapping_candidates_written": len(normalized_mappings),
                "knowledge_base_written": False,
                "rag_rebuild": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
