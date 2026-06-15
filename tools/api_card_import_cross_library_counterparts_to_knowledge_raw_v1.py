#!/usr/bin/env python3
"""Import reviewed cross-library counterpart knowledge into knowledge_raw.

Only imports reviewed import_now API cards and candidate constraints, synthetic
call sequences, and candidate mappings. Does not touch knowledge_base or rebuild
RAG.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


SPRINT = "api_card_import_cross_library_counterparts_to_knowledge_raw_v1"


def load_yaml(path: Path) -> Any:
    if not path.exists():
        raise SystemExit(f"missing required input: {path}")
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def first_records(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    for key in (
        "reviewed_api_cards",
        "reviewed_api_constraints",
        "reviewed_call_sequences",
        "reviewed_mapping_support",
    ):
        if isinstance(data.get(key), list):
            return [x for x in data[key] if isinstance(x, dict)]
    raise SystemExit(f"input does not contain recognized records: {path}")


def review(card: dict[str, Any]) -> dict[str, Any]:
    return card.get("review", {}) if isinstance(card.get("review"), dict) else {}


def sort_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("library") or item.get("target_library") or ""),
        str(item.get("family") or ""),
        str(item.get("api") or item.get("target_api") or item.get("sequence_name") or item.get("wolfssl_api") or ""),
    )


def split_evidence_refs(refs: list[str]) -> dict[str, list[str]]:
    out = {"header_refs": [], "source_refs": [], "test_refs": [], "doc_refs": []}
    for ref in refs:
        if ":" in ref:
            kind, path = ref.split(":", 1)
        else:
            kind, path = "", ref
        if "header" in kind:
            out["header_refs"].append(path)
        elif "test" in kind or "example" in kind:
            out["test_refs"].append(path)
        elif path.endswith(".md") or "doc" in path.lower():
            out["doc_refs"].append(path)
        else:
            out["source_refs"].append(path)
    return out


def lifecycle_for(api: str, family: str) -> dict[str, list[str]]:
    if family == "tls_protocol_state_lifecycle":
        if api.endswith("_new") or api.endswith("_init") or "CTX_new" in api or "config_init" in api:
            return {"init": [api], "use": [], "cleanup": []}
        if api.endswith("_free") or "free" in api.lower():
            return {"init": [], "use": [], "cleanup": [api]}
        return {"init": [], "use": [api], "cleanup": []}
    if family in {"x509_parsing", "asn1_nested_boundary", "pkcs_container_parsing"}:
        cleanup = [api] if api.endswith("_free") or api.endswith("_Free") else []
        use = [] if cleanup else [api]
        return {"init": [], "use": use, "cleanup": cleanup}
    if family == "secure_heap_state_lifecycle":
        if "init" in api or "set_calloc_free" in api:
            return {"init": [api], "use": [], "cleanup": []}
        if "free" in api.lower():
            return {"init": [], "use": [], "cleanup": [api]}
        return {"init": [], "use": [api], "cleanup": []}
    return {"init": [], "use": [api], "cleanup": []}


def normalize_card(card: dict[str, Any], reviewed_file: str) -> dict[str, Any]:
    api = str(card.get("api"))
    family = str(card.get("family"))
    rv = review(card)
    evidence = split_evidence_refs([str(x) for x in rv.get("source_evidence_refs", [])])
    return {
        "schema": "api_card_v0",
        "api": api,
        "library": card.get("library"),
        "family": family,
        "signature": "see evidence.header_refs; signature normalization deferred to RAG import/indexing pass",
        "parameter_semantics": {
            "summary": card.get("purpose", "counterpart API semantic card"),
            "mutation_relevant_slots": card.get("mutation_relevant_slots", []),
        },
        "return_value_semantics": {
            "observables": card.get("observables", []),
            "notes": "Imported from reviewed counterpart card; not vulnerability confirmation.",
        },
        "state_preconditions": {
            "family": family,
            "candidate_preconditions": card.get("mutation_relevant_slots", []),
        },
        "valid_invalid_ranges": {
            "valid": "API-family valid inputs and lifecycle state",
            "invalid": "mutation-relevant malformed input or invalid lifecycle state",
        },
        "mutation_hints": card.get("mutation_relevant_slots", []),
        "oracle_observables": card.get("observables", []),
        "lifecycle": lifecycle_for(api, family),
        "related_apis": [],
        "evidence": evidence,
        "confidence": rv.get("reviewed_confidence"),
        "review": {
            "reviewed_confidence": rv.get("reviewed_confidence"),
            "review_status": rv.get("review_status"),
            "evidence_strength": rv.get("evidence_strength"),
            "import_recommendation": rv.get("import_recommendation"),
        },
        "import_source": {
            "sprint": SPRINT,
            "reviewed_file": reviewed_file,
            "target_library": card.get("library"),
        },
        "notes": rv.get("notes", "candidate target-side semantic knowledge"),
    }


def normalize_constraint(item: dict[str, Any]) -> dict[str, Any]:
    rv = review(item)
    return {
        "library": item.get("library"),
        "api": item.get("api"),
        "family": item.get("family"),
        "constraint_type": item.get("constraint_kind"),
        "constraint_summary": f"Candidate {item.get('constraint_kind')} semantics for {item.get('api')}",
        "status": "candidate_constraint",
        "false_positive_risk": "medium",
        "oracle_relevance": item.get("required_observables", []),
        "evidence": {
            "source_refs": item.get("source_refs", []),
            "existing_constraint_refs": item.get("existing_constraint_refs", []),
        },
        "confidence": rv.get("evidence_strength"),
        "review_status": rv.get("constraint_review_status"),
        "import_source": {"sprint": SPRINT},
        "notes": rv.get("notes", "candidate constraint only"),
    }


def normalize_sequence(item: dict[str, Any]) -> dict[str, Any]:
    rv = review(item)
    apis = item.get("apis", [])
    return {
        "library": "openssl" if str(item.get("sequence_name", "")).startswith("openssl_") else "mbedtls",
        "sequence_id": item.get("sequence_name"),
        "family": item.get("family"),
        "api_sequence": apis,
        "resource_lifecycle": {
            "init_or_parse": apis[:1],
            "use": apis[1:-1] if len(apis) > 2 else [],
        },
        "cleanup_sequence": apis[-1:] if apis else [],
        "status": "synthetic_lifecycle_sequence",
        "evidence": {
            "test_or_example_supported_apis": rv.get("test_or_example_supported_apis", []),
        },
        "confidence": "candidate",
        "review_status": rv.get("call_sequence_review_status"),
        "import_source": {"sprint": SPRINT},
        "notes": rv.get("notes", "synthetic lifecycle sequence; not confirmed usage"),
    }


def normalize_mapping(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "cross_library_mapping_candidate_v0",
        "family": item.get("family"),
        "wolfssl_api": item.get("wolfssl_api"),
        "target_library": item.get("target_library"),
        "target_api": item.get("target_api"),
        "mapping_type": "candidate_counterpart",
        "status": "candidate_mapping",
        "mapping_confidence": item.get("mapping_confidence_reviewed"),
        "source_card_exists": item.get("source_card_exists"),
        "target_card_exists": item.get("target_card_reviewed"),
        "target_constraint_exists": item.get("target_constraint_reviewed"),
        "evidence": {
            "before_status": item.get("before_status"),
            "after_review_status": item.get("after_review_status"),
        },
        "review_status": item.get("status"),
        "import_source": {"sprint": SPRINT},
        "notes": "candidate mapping only; not confirmed equivalence",
    }


def md_table(items: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for item in items:
        row = []
        for field in fields:
            value: Any = item
            for part in field.split("."):
                value = value.get(part, "") if isinstance(value, dict) else ""
            row.append(str(value))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def write_pair(path_yaml: Path, path_md: Path, key: str, records: list[dict[str, Any]], fields: list[str]) -> None:
    dump_yaml(path_yaml, {key: records})
    write_text(path_md, md_table(records, fields))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reviewed-openssl-cards", required=True)
    parser.add_argument("--reviewed-mbedtls-cards", required=True)
    parser.add_argument("--reviewed-constraints", required=True)
    parser.add_argument("--reviewed-call-sequences", required=True)
    parser.add_argument("--reviewed-mapping-support", required=True)
    parser.add_argument("--import-decision", required=True)
    parser.add_argument("--knowledge-raw-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-knowledge-raw", default="false")
    parser.add_argument("--write-knowledge-base", default="false")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.write_knowledge_raw.lower() != "true":
        raise SystemExit("refusing to run: --write-knowledge-raw true is required")
    if args.write_knowledge_base.lower() != "false":
        raise SystemExit("refusing to write knowledge_base")

    out = Path(args.out_dir)
    kr = Path(args.knowledge_raw_root)
    openssl_reviewed = first_records(Path(args.reviewed_openssl_cards))
    mbedtls_reviewed = first_records(Path(args.reviewed_mbedtls_cards))
    constraints_reviewed = first_records(Path(args.reviewed_constraints))
    sequences_reviewed = first_records(Path(args.reviewed_call_sequences))
    mappings_reviewed = first_records(Path(args.reviewed_mapping_support))
    import_decision = load_yaml(Path(args.import_decision))

    openssl_cards = [
        normalize_card(card, args.reviewed_openssl_cards)
        for card in openssl_reviewed
        if review(card).get("import_recommendation") == "import_now"
    ]
    mbedtls_cards = [
        normalize_card(card, args.reviewed_mbedtls_cards)
        for card in mbedtls_reviewed
        if review(card).get("import_recommendation") == "import_now"
    ]
    constraints = [
        normalize_constraint(item)
        for item in constraints_reviewed
        if review(item).get("import_recommendation") == "import_as_candidate"
        and review(item).get("constraint_review_status") == "candidate_constraint"
    ]
    sequences = [
        normalize_sequence(item)
        for item in sequences_reviewed
        if review(item).get("import_recommendation") == "import_as_candidate"
        and review(item).get("call_sequence_review_status") == "synthetic_lifecycle_sequence"
    ]
    mappings = [
        normalize_mapping(item)
        for item in mappings_reviewed
        if item.get("status") == "import_ready_candidate_mapping"
    ]
    openssl_cards.sort(key=sort_key)
    mbedtls_cards.sort(key=sort_key)
    constraints.sort(key=sort_key)
    sequences.sort(key=sort_key)
    mappings.sort(key=sort_key)

    skipped_openssl = [card for card in openssl_reviewed if review(card).get("import_recommendation") != "import_now"]
    skipped_mbedtls = [card for card in mbedtls_reviewed if review(card).get("import_recommendation") != "import_now"]
    skipped_mappings = [item for item in mappings_reviewed if item.get("status") != "import_ready_candidate_mapping"]
    not_imported = {
        "openssl_skip_manual_review": [
            {"api": item.get("api"), "reason": review(item).get("review_status")}
            for item in skipped_openssl
        ],
        "mbedtls_skip_manual_review": [
            {"api": item.get("api") or item.get("source_api"), "reason": review(item).get("review_status")}
            for item in skipped_mbedtls
            if review(item).get("review_status") != "no_direct_counterpart"
        ],
        "mbedtls_no_direct_counterpart": [
            {"source_api": item.get("source_api"), "reason": review(item).get("review_status")}
            for item in skipped_mbedtls
            if review(item).get("review_status") == "no_direct_counterpart"
        ],
        "mapping_needs_manual_review": [
            {"wolfssl_api": item.get("wolfssl_api"), "target_library": item.get("target_library"), "target_api": item.get("target_api")}
            for item in skipped_mappings
            if item.get("status") == "needs_manual_review"
        ],
        "mapping_no_direct_counterpart": [
            {"wolfssl_api": item.get("wolfssl_api"), "target_library": item.get("target_library")}
            for item in skipped_mappings
            if item.get("status") == "no_direct_counterpart"
        ],
        "mapping_weak_evidence": [
            {"wolfssl_api": item.get("wolfssl_api"), "target_library": item.get("target_library"), "target_api": item.get("target_api")}
            for item in skipped_mappings
            if item.get("status") == "weak_evidence"
        ],
    }

    input_summary = {
        "task": SPRINT,
        "reviewed_openssl_cards": args.reviewed_openssl_cards,
        "reviewed_mbedtls_cards": args.reviewed_mbedtls_cards,
        "reviewed_constraints": args.reviewed_constraints,
        "reviewed_call_sequences": args.reviewed_call_sequences,
        "reviewed_mapping_support": args.reviewed_mapping_support,
        "input_policy": [
            "input comes from reviewed counterpart cards",
            "only import import_now API cards",
            "constraints, call sequences, and mappings are imported with candidate labels",
            "no_direct_counterpart, weak_evidence, and needs_manual_review are not imported as usable mappings",
            "RAG is not rebuilt in this task",
        ],
        "write_knowledge_raw": True,
        "write_knowledge_base": False,
        "rag_rebuild": False,
    }
    dump_yaml(out / "input/import_cross_library_counterpart_input_summary.yaml", input_summary)
    write_text(out / "input/import_cross_library_counterpart_input_summary.md", "# Input Summary\n\n" + json.dumps(input_summary, indent=2) + "\n")

    write_pair(out / "normalized_cards/openssl_counterpart_api_cards_api_card_v0.yaml", out / "normalized_cards/openssl_counterpart_api_cards_api_card_v0.md", "api_cards", openssl_cards, ["library", "api", "family", "confidence"])
    write_pair(out / "normalized_cards/mbedtls_counterpart_api_cards_api_card_v0.yaml", out / "normalized_cards/mbedtls_counterpart_api_cards_api_card_v0.md", "api_cards", mbedtls_cards, ["library", "api", "family", "confidence"])
    write_pair(out / "normalized_constraints/cross_library_counterpart_constraints_normalized.yaml", out / "normalized_constraints/cross_library_counterpart_constraints_normalized.md", "api_constraints", constraints, ["library", "api", "family", "status"])
    write_pair(out / "normalized_call_sequences/cross_library_counterpart_call_sequences_normalized.yaml", out / "normalized_call_sequences/cross_library_counterpart_call_sequences_normalized.md", "call_sequences", sequences, ["library", "sequence_id", "family", "status"])
    write_pair(out / "normalized_mappings/cross_library_counterpart_mapping_candidates.yaml", out / "normalized_mappings/cross_library_counterpart_mapping_candidates.md", "mapping_candidates", mappings, ["wolfssl_api", "target_library", "target_api", "status"])

    written_files = []
    targets = [
        (kr / "api_knowledge_cards/openssl_counterpart_api_cards.yaml", kr / "api_knowledge_cards/openssl_counterpart_api_cards.md", "api_cards", openssl_cards, ["library", "api", "family", "confidence"], "openssl_api_cards"),
        (kr / "api_knowledge_cards/mbedtls_counterpart_api_cards.yaml", kr / "api_knowledge_cards/mbedtls_counterpart_api_cards.md", "api_cards", mbedtls_cards, ["library", "api", "family", "confidence"], "mbedtls_api_cards"),
        (kr / "api_constraints/cross_library_counterpart_api_constraints.yaml", kr / "api_constraints/cross_library_counterpart_api_constraints.md", "api_constraints", constraints, ["library", "api", "family", "status"], "candidate_constraints"),
        (kr / "api_constraints/cross_library_counterpart_call_sequences.yaml", kr / "api_constraints/cross_library_counterpart_call_sequences.md", "call_sequences", sequences, ["library", "sequence_id", "family", "status"], "candidate_call_sequences"),
        (kr / "cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml", kr / "cross_lib_equivalence/cross_library_counterpart_mapping_candidates.md", "mapping_candidates", mappings, ["wolfssl_api", "target_library", "target_api", "status"], "candidate_mappings"),
    ]
    for yaml_path, md_path, key, records, fields, typ in targets:
        write_pair(yaml_path, md_path, key, records, fields)
        written_files.append({"path": str(yaml_path), "type": typ, "records": len(records), "notes": "structured knowledge_raw import"})
        written_files.append({"path": str(md_path), "type": typ, "records": len(records), "notes": "human-readable mirror"})

    imported = {
        "written_files": written_files,
        "not_written": [
            {"item": "skip/manual_review API cards", "reason": "not import_now"},
            {"item": "no_direct_counterpart mappings", "reason": "not usable mapping"},
            {"item": "weak_evidence mappings", "reason": "not import_ready_candidate_mapping"},
            {"item": "needs_manual_review mappings", "reason": "requires manual review"},
            {"item": "knowledge_base", "reason": "explicitly out of scope"},
        ],
    }
    dump_yaml(out / "imported/imported_knowledge_raw_files.yaml", imported)
    write_text(out / "imported/imported_knowledge_raw_files.md", md_table(imported["written_files"], ["path", "type", "records", "notes"]))

    dump_yaml(out / "reports/not_imported_items.yaml", not_imported)
    write_text(out / "reports/not_imported_items.md", "# Not Imported Items\n\n" + json.dumps(not_imported, indent=2) + "\n")

    rag_plan = {
        "recommended_next_task": "rag_rebuild_and_query_eval_v2",
        "reason": [
            "knowledge_raw added OpenSSL / mbedTLS counterpart API cards",
            "knowledge_raw added cross-library candidate constraints / sequences / mappings",
            "knowledge_base index needs rebuild",
            "query eval should verify wolfSSL to OpenSSL / mbedTLS counterpart retrieval",
        ],
        "queries_to_eval": [
            "wolfSSL wc_ParseCert OpenSSL ASN1_item_d2i mbedTLS x509_crt_parse_der",
            "wolfSSL PKCS7 VerifySignedData OpenSSL PKCS7_verify",
            "wolfSSL TLS context lifecycle OpenSSL SSL_CTX_new mbedTLS ssl_config_init",
            "wolfSSL secure heap OpenSSL secure malloc mbedTLS platform calloc free",
            "cross library candidate mapping no_direct_counterpart PKCS7 mbedTLS",
        ],
    }
    dump_yaml(out / "reports/rag_rebuild_plan_after_cross_library_counterpart_import.yaml", rag_plan)
    write_text(out / "reports/rag_rebuild_plan_after_cross_library_counterpart_import.md", "# RAG Rebuild Plan\n\n" + json.dumps(rag_plan, indent=2) + "\n")

    mapping_counts = Counter(item.get("status") for item in mappings_reviewed)
    report = {
        "openssl_reviewed": len(openssl_reviewed),
        "openssl_imported": len(openssl_cards),
        "openssl_skipped": len(skipped_openssl),
        "mbedtls_reviewed": len(mbedtls_reviewed),
        "mbedtls_imported": len(mbedtls_cards),
        "mbedtls_skipped": len(skipped_mbedtls),
        "no_direct_counterpart": len(not_imported["mbedtls_no_direct_counterpart"]),
        "constraints_imported_as_candidate": len(constraints),
        "call_sequences_imported_as_candidate": len(sequences),
        "synthetic_sequences": len(sequences),
        "mappings_imported_as_candidate": len(mappings),
        "mappings_skipped": len(skipped_mappings),
        "mapping_review_counts": dict(mapping_counts),
        "knowledge_raw_written": True,
        "knowledge_base_written": False,
        "rag_rebuild": False,
        "poc_run": False,
        "compile_run": False,
        "glm": False,
        "render": False,
        "template_generated": False,
        "pattern_bank_modified": False,
        "scheduler_seed_modified": False,
        "next_task_name": "rag_rebuild_and_query_eval_v2",
        "import_decision_source": import_decision.get("import_decision", {}),
    }
    dump_yaml(out / "reports/api_card_import_cross_library_counterparts_to_knowledge_raw_report.yaml", report)
    write_text(out / "reports/api_card_import_cross_library_counterparts_to_knowledge_raw_report.md", "# Import Report\n\n" + json.dumps(report, indent=2) + "\n")
    write_text(out / "README.md", "# api_card_import_cross_library_counterparts_to_knowledge_raw_v1\n\nImported reviewed cross-library counterpart API cards and candidate support artifacts into `knowledge_raw`. No `knowledge_base` writes, RAG rebuild, PoC run, GLM call, render, template generation, commit, or push was performed.\n")
    print(f"[OK] imported cross-library counterpart knowledge into {kr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
