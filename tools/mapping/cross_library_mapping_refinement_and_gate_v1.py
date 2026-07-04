#!/usr/bin/env python3
"""Refine and gate cross-library candidate mappings.

Read-only with respect to knowledge_raw/knowledge_base. Outputs sprint reports
that classify candidate mappings for adapter readiness without claiming
confirmed equivalence.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


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


def records(data: Any, keys: list[str]) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def mapping_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(item.get("family") or ""),
        str(item.get("wolfssl_api") or ""),
        str(item.get("target_library") or ""),
        str(item.get("target_api") or ""),
    )


def sort_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return mapping_key(item)


def normalize_api_cards(path: Path) -> dict[str, dict[str, Any]]:
    data = load_yaml(path)
    out = {}
    for item in records(data, ["api_cards", "wolfssl_api_cards_api_card_v0", "wolfssl_api_cards"]):
        api = str(item.get("api") or "")
        if not api:
            continue
        out[api] = item
        for related in item.get("related_apis", []) or []:
            out.setdefault(str(related), item)
    return out


def normalize_constraints(path: Path) -> dict[str, list[dict[str, Any]]]:
    data = load_yaml(path)
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in records(data, ["api_constraints", "wolfssl_api_constraints_normalized"]):
        api = str(item.get("api") or "")
        if api:
            out[api].append(item)
    return out


def expand_wolfssl_mappings(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    out = []
    for item in records(data, ["wolfssl_cross_library_mapping_candidates", "mapping_candidates"]):
        family = item.get("family", "")
        wolf = item.get("wolfssl_api", "")
        for target_library, key in (("openssl", "openssl_candidate_api"), ("mbedtls", "mbedtls_candidate_api")):
            target_api = item.get(key, "")
            status = "no_direct_counterpart" if not target_api else item.get("status", "candidate_only")
            out.append(
                {
                    "schema": item.get("schema", "cross_library_mapping_candidate_v0"),
                    "family": family,
                    "wolfssl_api": wolf,
                    "target_library": target_library,
                    "target_api": target_api,
                    "mapping_type": item.get("mapping_type", "candidate_mapping"),
                    "original_status": status,
                    "source_files": [str(path)],
                    "confidence": item.get("confidence", ""),
                    "source_card_exists": False,
                    "target_card_exists": False,
                    "source_constraint_exists": False,
                    "target_constraint_exists": False,
                    "notes": item.get("notes", []),
                }
            )
    return out


def load_counterpart_mappings(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    out = []
    for item in records(data, ["mapping_candidates"]):
        out.append(
            {
                "schema": item.get("schema", "cross_library_mapping_candidate_v0"),
                "family": item.get("family", ""),
                "wolfssl_api": item.get("wolfssl_api", ""),
                "target_library": item.get("target_library", ""),
                "target_api": item.get("target_api", ""),
                "mapping_type": item.get("mapping_type", "candidate_mapping"),
                "original_status": item.get("review_status") or item.get("status") or "candidate_mapping",
                "source_files": [str(path)],
                "confidence": item.get("mapping_confidence", ""),
                "source_card_exists": bool(item.get("source_card_exists")),
                "target_card_exists": bool(item.get("target_card_exists")),
                "source_constraint_exists": False,
                "target_constraint_exists": bool(item.get("target_constraint_exists")),
                "notes": item.get("notes", ""),
            }
        )
    return out


def merge_mappings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in items:
        key = mapping_key(item)
        if key not in merged:
            merged[key] = dict(item)
            continue
        cur = merged[key]
        cur["source_files"] = sorted(set(cur.get("source_files", []) + item.get("source_files", [])))
        for flag in ("source_card_exists", "target_card_exists", "source_constraint_exists", "target_constraint_exists"):
            cur[flag] = bool(cur.get(flag)) or bool(item.get(flag))
        if str(item.get("confidence", "")).lower() == "high":
            cur["confidence"] = item.get("confidence")
        if item.get("original_status") == "candidate_mapping":
            cur["original_status"] = item.get("original_status")
    return sorted(merged.values(), key=sort_key)


def query_eval_index(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = load_yaml(path)
    rows = records(data, ["query_results"])
    haystacks = []
    for row in rows:
        text = " ".join(
            [
                str(row.get("query", "")),
                " ".join(row.get("expected_terms_found", []) or []),
                " ".join(row.get("missing_expected_terms", []) or []),
                json.dumps(row.get("top_hits_summary", []), ensure_ascii=False),
                " ".join(row.get("retrieved_sources", []) or []),
            ]
        )
        haystacks.append({"row": row, "text": text.lower()})
    q3 = next((r for r in rows if r.get("query_id") == "q3_x509_asn1_parse_mapping"), {})
    q7 = next((r for r in rows if r.get("query_id") == "q7_no_direct_counterpart_mbedtls_pkcs"), {})
    return rows, {
        "q3_wc_parsecert_weak": "wc_ParseCert" in (q3.get("missing_expected_terms") or []),
        "q7_no_direct_counterpart_label_weak": "no_direct_counterpart" in (q7.get("missing_expected_terms") or []),
        "haystacks": haystacks,
    }


def query_support(mapping: dict[str, Any], qidx: dict[str, Any]) -> dict[str, Any]:
    terms = [mapping.get("wolfssl_api"), mapping.get("target_api"), mapping.get("family")]
    hits = []
    missing_terms = []
    for term in terms:
        if not term:
            continue
        found_in = [h["row"].get("query_id") for h in qidx["haystacks"] if str(term).lower() in h["text"]]
        if found_in:
            hits.extend(found_in)
        else:
            missing_terms.append(str(term))
    return {"hits": sorted(set(hits)), "missing_terms": missing_terms}


def oracle_style(family: str, mapping_type: str, target_api: str) -> str:
    if not target_api:
        return "no_adapter"
    if family == "tls_protocol_state_lifecycle":
        return "lifecycle_state"
    if family in {"x509_parsing", "asn1_nested_boundary", "pkcs_container_parsing"}:
        return "parser_reject_accept"
    if family == "secure_heap_state_lifecycle":
        return "cleanup_required" if "free" in target_api.lower() else "lifecycle_state"
    if "consumption" in mapping_type:
        return "full_consumption"
    return "return_code_semantics"


def adapter_slot_hint(family: str) -> str:
    return {
        "tls_protocol_state_lifecycle": "init/use/cleanup lifecycle slots",
        "x509_parsing": "parser input and object cleanup slots",
        "asn1_nested_boundary": "DER input, length, parser result slots",
        "pkcs_container_parsing": "container input, parser/verify, cleanup slots",
        "secure_heap_state_lifecycle": "allocator setup/use/free slots",
    }.get(family, "semantic API slots")


def build_inventory(
    mappings: list[dict[str, Any]],
    cards: dict[tuple[str, str], dict[str, Any]],
    constraints: dict[tuple[str, str], list[dict[str, Any]]],
    qidx: dict[str, Any],
) -> list[dict[str, Any]]:
    out = []
    for idx, item in enumerate(mappings, start=1):
        lib = str(item.get("target_library"))
        wolf = str(item.get("wolfssl_api"))
        target = str(item.get("target_api") or "")
        qsup = query_support(item, qidx)
        source_card = bool(cards.get(("wolfssl", wolf)))
        target_card = bool(target and cards.get((lib, target)))
        source_constraint = bool(constraints.get(("wolfssl", wolf)))
        target_constraint = bool(target and constraints.get((lib, target)))
        out.append(
            {
                "mapping_id": f"map_{idx:03d}",
                "family": item.get("family", ""),
                "wolfssl_api": wolf,
                "target_library": lib,
                "target_api": target,
                "mapping_type": item.get("mapping_type", ""),
                "original_status": item.get("original_status", ""),
                "source_files": item.get("source_files", []),
                "source_card_exists": source_card,
                "target_card_exists": target_card,
                "source_constraint_exists": source_constraint,
                "target_constraint_exists": target_constraint,
                "query_eval_support": qsup,
                "notes": item.get("notes", ""),
                "source_confidence": item.get("confidence", ""),
            }
        )
    return out


def evidence_for(inv: dict[str, Any], qidx: dict[str, Any]) -> dict[str, Any]:
    known = []
    if inv["wolfssl_api"] == "wc_ParseCert" and qidx.get("q3_wc_parsecert_weak"):
        known.append("wc_ParseCert_recall_weak")
    if inv["target_library"] == "mbedtls" and not inv["target_api"] and inv["family"] == "pkcs_container_parsing":
        known.append("no_direct_counterpart_label_recall_weak" if qidx.get("q7_no_direct_counterpart_label_weak") else "no_direct_counterpart")
    score = sum(
        [
            bool(inv["source_card_exists"]),
            bool(inv["target_card_exists"]),
            bool(inv["source_constraint_exists"] or inv["target_constraint_exists"]),
            bool(inv["query_eval_support"]["hits"]),
        ]
    )
    if not inv["target_api"]:
        strength = "none"
    elif score >= 4:
        strength = "strong"
    elif score >= 2:
        strength = "moderate"
    elif score == 1:
        strength = "weak"
    else:
        strength = "none"
    return {
        "mapping_id": inv["mapping_id"],
        "wolfssl_api": inv["wolfssl_api"],
        "target_library": inv["target_library"],
        "target_api": inv["target_api"],
        "evidence": {
            "source_api_card": inv["source_card_exists"],
            "target_api_card": inv["target_card_exists"],
            "source_constraints": inv["source_constraint_exists"],
            "target_constraints": inv["target_constraint_exists"],
            "call_sequences": bool(inv["query_eval_support"]["hits"]),
            "query_eval_hits": inv["query_eval_support"]["hits"],
            "query_eval_missing_terms": inv["query_eval_support"]["missing_terms"],
        },
        "evidence_strength": strength,
        "known_weaknesses": known,
        "notes": "candidate mapping evidence only; not confirmed equivalence",
    }


def gate(inv: dict[str, Any], ev: dict[str, Any]) -> dict[str, Any]:
    family = inv["family"]
    target = inv["target_api"]
    original = str(inv["original_status"])
    if not target:
        status = "no_direct_counterpart"
    elif original == "weak_evidence":
        status = "weak_evidence"
    elif "wc_ParseCert_recall_weak" in ev["known_weaknesses"]:
        status = "needs_manual_review"
    elif ev["evidence_strength"] == "strong":
        status = "usable_for_adapter"
    elif ev["evidence_strength"] == "moderate":
        status = "candidate_only"
    elif ev["evidence_strength"] == "weak":
        status = "weak_evidence"
    else:
        status = "blocked"
    if status == "no_direct_counterpart" and family == "pkcs_container_parsing" and inv["target_library"] == "mbedtls":
        blocked_status = "no_direct_counterpart"
    else:
        blocked_status = status
    return {
        "mapping_id": inv["mapping_id"],
        "family": family,
        "wolfssl_api": inv["wolfssl_api"],
        "target_library": inv["target_library"],
        "target_api": target,
        "mapping_type": inv["mapping_type"],
        "gate_status": blocked_status,
        "adapter_usable": blocked_status in {"usable_for_adapter", "candidate_only"},
        "candidate_mapping_only": True,
        "confidence_after_gate": {
            "strong": "high",
            "moderate": "medium",
            "weak": "low",
            "none": "none",
        }.get(ev["evidence_strength"], "low"),
        "evidence_strength": ev["evidence_strength"],
        "required_oracle_style": oracle_style(family, inv["mapping_type"], target),
        "notes": "usable_for_adapter still means adapter-usable candidate, not confirmed equivalence",
    }


def inventory_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total_mappings": len(items),
        "by_target_library": dict(Counter(x["target_library"] for x in items)),
        "by_family": dict(Counter(x["family"] for x in items)),
        "with_source_card": sum(1 for x in items if x["source_card_exists"]),
        "with_target_card": sum(1 for x in items if x["target_card_exists"]),
        "with_constraints": sum(1 for x in items if x["source_constraint_exists"] or x["target_constraint_exists"]),
        "no_direct_counterpart": sum(1 for x in items if not x["target_api"]),
        "weak_evidence": sum(1 for x in items if x["original_status"] == "weak_evidence" or not x["target_card_exists"]),
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


def write_pair(yaml_path: Path, md_path: Path, key: str, data: Any, fields: list[str] | None = None) -> None:
    dump_yaml(yaml_path, data if isinstance(data, dict) else {key: data})
    if isinstance(data, list) and fields:
        write_text(md_path, md_table(data, fields))
    else:
        write_text(md_path, "# Report\n\n```yaml\n" + yaml.safe_dump(data, sort_keys=False, allow_unicode=False) + "```\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wolfssl-mapping", required=True)
    parser.add_argument("--counterpart-mapping", required=True)
    parser.add_argument("--wolfssl-cards", required=True)
    parser.add_argument("--openssl-cards", required=True)
    parser.add_argument("--mbedtls-cards", required=True)
    parser.add_argument("--wolfssl-constraints", required=True)
    parser.add_argument("--counterpart-constraints", required=True)
    parser.add_argument("--query-eval", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    cards = {
        ("wolfssl", api): obj for api, obj in normalize_api_cards(Path(args.wolfssl_cards)).items()
    }
    cards.update({("openssl", api): obj for api, obj in normalize_api_cards(Path(args.openssl_cards)).items()})
    cards.update({("mbedtls", api): obj for api, obj in normalize_api_cards(Path(args.mbedtls_cards)).items()})
    constraints = {
        ("wolfssl", api): vals for api, vals in normalize_constraints(Path(args.wolfssl_constraints)).items()
    }
    counterpart_constraints = normalize_constraints(Path(args.counterpart_constraints))
    for api, vals in counterpart_constraints.items():
        for item in vals:
            constraints.setdefault((str(item.get("library")), api), []).append(item)

    qrows, qidx = query_eval_index(Path(args.query_eval))
    mappings = merge_mappings(expand_wolfssl_mappings(Path(args.wolfssl_mapping)) + load_counterpart_mappings(Path(args.counterpart_mapping)))
    inventory = build_inventory(mappings, cards, constraints, qidx)
    evidence = [evidence_for(inv, qidx) for inv in inventory]
    ev_by_id = {x["mapping_id"]: x for x in evidence}
    gates = [gate(inv, ev_by_id[inv["mapping_id"]]) for inv in inventory]

    adapter_ready = []
    for item in gates:
        if item["gate_status"] not in {"usable_for_adapter", "candidate_only"}:
            continue
        adapter_ready.append(
            {
                "family": item["family"],
                "source_library": "wolfssl",
                "target_library": item["target_library"],
                "wolfssl_api": item["wolfssl_api"],
                "target_api": item["target_api"],
                "mapping_type": item["mapping_type"],
                "required_oracle_style": item["required_oracle_style"],
                "adapter_slot_hint": adapter_slot_hint(item["family"]),
                "cleanup_mapping_hint": "cleanup required" if item["required_oracle_style"] == "cleanup_required" else "family-specific cleanup if object allocated",
                "lifecycle_hint": "candidate lifecycle must be verified by generated harness",
                "risk_notes": "candidate mapping only; compile/run/analyze still required",
            }
        )
    blocked = []
    for item in gates:
        if item["gate_status"] in {"usable_for_adapter", "candidate_only"}:
            continue
        recommendation = "do_not_generate_adapter" if item["gate_status"] in {"blocked", "no_direct_counterpart"} else "manual_review_before_adapter"
        if item["gate_status"] == "no_direct_counterpart":
            recommendation = "needs_new_target_strategy"
        blocked.append(
            {
                "family": item["family"],
                "wolfssl_api": item["wolfssl_api"],
                "target_library": item["target_library"],
                "target_api": item["target_api"],
                "reason": item["gate_status"],
                "recommendation": recommendation,
                "notes": "not adapter-ready under current evidence gate",
            }
        )

    inv_summary = inventory_summary(inventory)
    input_summary = {
        "task": "cross_library_mapping_refinement_and_gate_v1",
        "based_on_rag_v2_pass": True,
        "scope": "mapping refinement / gate only",
        "writes_knowledge_raw": False,
        "rebuilds_rag": False,
        "known_weaknesses": ["q3 wc_ParseCert recall weak", "q7 no_direct_counterpart label recall weak"],
        "inputs": vars(args),
    }
    refinement_plan = {
        "known_weaknesses": [
            "wc_ParseCert recall weak in X509/ASN1 query",
            "no_direct_counterpart label recall weak",
        ],
        "recommended_actions": [
            "add alias/keyword summary for wc_ParseCert / DecodedCert / X509 ASN1 parse",
            "add explicit no_direct_counterpart summary for mbedTLS PKCS7/PKCS12",
            "keep these as backlog unless template adapter stage requires them",
        ],
        "recommended_next_task_if_needed": ["rag_alias_and_negative_mapping_refinement_v1"],
    }
    gate_counts = Counter(x["gate_status"] for x in gates)
    priority_families = [fam for fam, _ in Counter(x["family"] for x in adapter_ready).most_common()]
    next_task = "template_schema_inventory_v1" if gate_counts.get("usable_for_adapter", 0) >= 8 else "rag_alias_and_negative_mapping_refinement_v1"
    next_action = {
        "next_task_name": next_task,
        "why": f"adapter-ready mappings={len(adapter_ready)}, usable_for_adapter={gate_counts.get('usable_for_adapter', 0)}, blocked/no-direct clear={gate_counts.get('no_direct_counterpart', 0) + gate_counts.get('blocked', 0)}",
    }
    report = {
        "total_mappings": len(inventory),
        "usable_for_adapter": gate_counts.get("usable_for_adapter", 0),
        "candidate_only": gate_counts.get("candidate_only", 0),
        "weak_evidence": gate_counts.get("weak_evidence", 0),
        "no_direct_counterpart": gate_counts.get("no_direct_counterpart", 0),
        "blocked": gate_counts.get("blocked", 0),
        "needs_manual_review": gate_counts.get("needs_manual_review", 0),
        "priority_families": priority_families,
        "q3_wc_ParseCert_handling": "wc_ParseCert-dependent mapping is marked needs_manual_review when recall weakness affects gate.",
        "q7_no_direct_counterpart_handling": "mbedTLS PKCS7/PKCS12 empty-target mappings remain no_direct_counterpart and are blocked from adapter generation.",
        "knowledge_raw_modified": False,
        "knowledge_base_modified": False,
        "rag_rebuild": False,
        "poc_run": False,
        "compile_run": False,
        "glm": False,
        "render": False,
        "template_generated": False,
        "next_task_name": next_task,
    }
    write_pair(out / "input/mapping_gate_input_summary.yaml", out / "input/mapping_gate_input_summary.md", "input_summary", input_summary)
    write_pair(out / "mapping_inventory/cross_library_mapping_inventory.yaml", out / "mapping_inventory/cross_library_mapping_inventory.md", "mapping_inventory", {"mapping_inventory_summary": inv_summary, "mappings": inventory})
    write_pair(out / "rag_evidence/mapping_rag_evidence_summary.yaml", out / "rag_evidence/mapping_rag_evidence_summary.md", "mapping_rag_evidence", evidence, ["mapping_id", "wolfssl_api", "target_library", "target_api", "evidence_strength"])
    write_pair(out / "gate_results/cross_library_mapping_gate_results.yaml", out / "gate_results/cross_library_mapping_gate_results.md", "gate_results", gates, ["mapping_id", "family", "wolfssl_api", "target_library", "target_api", "gate_status", "required_oracle_style"])
    write_pair(out / "adapter_ready/adapter_ready_mapping_candidates.yaml", out / "adapter_ready/adapter_ready_mapping_candidates.md", "adapter_ready_mapping_candidates", adapter_ready, ["family", "wolfssl_api", "target_library", "target_api", "required_oracle_style"])
    write_pair(out / "blocked_mappings/blocked_or_no_direct_counterpart_mappings.yaml", out / "blocked_mappings/blocked_or_no_direct_counterpart_mappings.md", "blocked_or_no_direct_counterpart_mappings", blocked, ["family", "wolfssl_api", "target_library", "target_api", "reason", "recommendation"])
    write_pair(out / "refinement_plan/rag_mapping_refinement_plan.yaml", out / "refinement_plan/rag_mapping_refinement_plan.md", "refinement_plan", refinement_plan)
    write_pair(out / "reports/next_action_after_mapping_gate.yaml", out / "reports/next_action_after_mapping_gate.md", "next_action", next_action)
    write_pair(out / "reports/cross_library_mapping_refinement_and_gate_report.yaml", out / "reports/cross_library_mapping_refinement_and_gate_report.md", "report", report)
    write_text(out / "README.md", "# cross_library_mapping_refinement_and_gate_v1\n\nRead-only mapping refinement and gate over candidate cross-library mappings. No knowledge_raw writes, RAG rebuild, PoC run, GLM call, render, template generation, commit, or push was performed.\n")
    print(f"[OK] wrote mapping gate outputs to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
