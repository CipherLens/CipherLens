#!/usr/bin/env python3
"""Review and conservatively correct ingestion-derived family classifications."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
    return sorted(rows, key=lambda r: (str(r.get("source_library", "")), str(r.get("poc_id", "")), str(r.get("artifact_path", ""))))


def load_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if yaml is None:
        return json.loads(text)
    return yaml.safe_load(text)


def dump_yaml(path: Path, obj: Any) -> None:
    if yaml is None:
        path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(v).replace("\n", " ") for v in row) + " |")
    return "\n".join(out) + "\n"


def flat(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(flat(v) for v in value)
    if isinstance(value, dict):
        return " ".join(flat(v) for _, v in sorted(value.items()))
    return str(value)


def index_by_identity(items: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        out[(str(item.get("source_library", "")), str(item.get("poc_id", "")), str(item.get("artifact_path", "")))] = item
    return out


def evidence_blob(record: dict[str, Any]) -> str:
    meta = record.get("metadata_summary") or {}
    ast = record.get("ast_summary") or {}
    files = record.get("artifact_files") or {}
    parts = [
        meta.get("component"),
        meta.get("critical_api_or_function"),
        meta.get("trigger_behavior"),
        meta.get("root_cause"),
        ast.get("api_call_sequence"),
        ast.get("include_headers"),
        ast.get("source_files"),
        files.get("poc_c_files"),
        files.get("poc_dir"),
        record.get("artifact_path"),
    ]
    return flat(parts).lower()


def harness_for_family(family: str, original: str) -> str:
    mapping = {
        "bignum_serialization_boundary": "buffer_canary_boundary",
        "bignum_arithmetic_precondition": "return_code_outlen_semantic",
        "x509_parsing": "x509_asn1_inner_boundary",
        "asn1_nested_boundary": "x509_asn1_inner_boundary",
        "pkcs_container_parsing": "x509_asn1_inner_boundary",
        "tls_protocol_state_lifecycle": "object_state_lifecycle",
        "secure_heap_state_lifecycle": "object_state_lifecycle",
        "mac_lifecycle": "object_state_lifecycle",
        "cipher_aead_lifecycle": "object_state_lifecycle",
        "cipher_padding_output_length": "return_code_outlen_semantic",
        "needs_review": "needs_review",
    }
    return mapping.get(family, original or "needs_review")


def route_for_family(family: str, original: str) -> str:
    if family in {"x509_parsing", "asn1_nested_boundary", "pkcs_container_parsing"}:
        return "C_app_level_validation_gap"
    if family in {"tls_protocol_state_lifecycle", "secure_heap_state_lifecycle", "mac_lifecycle", "cipher_aead_lifecycle"}:
        return "B_controlled_family_mutation"
    if family == "cipher_padding_output_length":
        return "A_recipe_slot_cross_library_migration"
    if family.startswith("bignum"):
        return original or "A_recipe_slot_cross_library_migration"
    return original or "needs_more_evidence"


def suggest_family(record: dict[str, Any]) -> tuple[str, str, str]:
    blob = evidence_blob(record)
    original = (record.get("pattern_candidate") or {}).get("family_guess") or "needs_review"
    if re.search(r"\b(BN|BIGNUM|MPI|mp_|mbedtls_mpi|bignum)\b", blob, flags=re.I):
        if any(x in blob for x in ("sub_abs", "bn_usub", "bn_sub", "subtraction", "arithmetic")):
            return "bignum_arithmetic_precondition", "high", "API/component evidence contains bignum arithmetic terms"
        return "bignum_serialization_boundary", "high", "API/component evidence contains BN/BIGNUM/MPI terms"
    if any(x in blob for x in ("pkcs7", "pkcs12", "cms", "signedattrs", "oid")):
        return "pkcs_container_parsing", "high", "API/component evidence contains PKCS/CMS/OID container terms"
    if any(x in blob for x in ("x509", "cert", "certificate", "verify", "crl", "asn1", "asn.1")):
        if any(x in blob for x in ("asn1", "asn.1", "d2i", "der")):
            return "asn1_nested_boundary", "medium", "certificate/ASN.1 evidence suggests nested parser boundary"
        return "x509_parsing", "medium", "API/component evidence contains X509/certificate/verify terms"
    if any(x in blob for x in ("dtls", "tls", "handshake", "record", " ack", "ssl_")):
        return "tls_protocol_state_lifecycle", "high", "API/component evidence contains TLS/DTLS state terms"
    if any(x in blob for x in ("secure heap", "crypto_secure", "bio_s_secmem", "secmem")):
        return "secure_heap_state_lifecycle", "high", "API/component evidence contains secure heap terms"
    if any(x in blob for x in ("hmac", "cmac", "evp_mac", " mac", "digest finish", "mac_final")):
        return "mac_lifecycle", "high", "API/component evidence contains MAC lifecycle terms"
    if any(x in blob for x in ("aead", "gcm", "ccm", " tag")):
        return "cipher_aead_lifecycle", "high", "API/component evidence contains AEAD/tag terms"
    if any(x in blob for x in ("padding", "outlen", "decryptfinal", "cipher_finish")):
        return "cipher_padding_output_length", "medium", "API/component evidence contains padding/output-length terms"
    return "needs_review", "needs_review", f"insufficient evidence to keep or correct original family={original}"


def review_targets(records: list[dict[str, Any]], sanity: dict[str, Any], rerank: dict[str, Any]) -> list[dict[str, Any]]:
    correction_ids = {x.get("poc_id") for x in sanity.get("correction_suggestions", [])}
    top_ids = set()
    for family in (rerank.get("families") or [])[:3]:
        top_ids.update(family.get("representative_pocs") or [])
    explicit_top = {"WOLFSSL-POC-0007", "WOLFSSL-POC-0006", "WOLFSSL-POC-0004"}
    top_ids.update(explicit_top)
    rows = []
    for r in records:
        pattern = r.get("pattern_candidate") or {}
        current_family = pattern.get("family_guess")
        reasons: list[str] = []
        if current_family == "bignum_serialization_boundary":
            reasons.append("family=bignum_serialization_boundary")
        if r.get("poc_id") in correction_ids:
            reasons.append("previous correction suggestion")
        if r.get("poc_id") == "WOLFSSL-POC-0002":
            reasons.append("wolfSSL bignum suspicious")
        if r.get("source_library") == "openssl" and current_family == "bignum_serialization_boundary":
            reasons.append("OpenSSL issue in bignum bucket")
        if r.get("poc_id") in top_ids:
            reasons.append("scheduler top candidate")
        if not reasons:
            continue
        meta = r.get("metadata_summary") or {}
        ast = r.get("ast_summary") or {}
        rows.append(
            {
                "poc_id": r.get("poc_id"),
                "source_library": r.get("source_library"),
                "artifact_path": r.get("artifact_path"),
                "current_family": current_family,
                "current_harness_family": pattern.get("harness_family_guess"),
                "current_route": pattern.get("route_guess"),
                "reason_for_review": sorted(set(reasons)),
                "metadata_component": meta.get("component"),
                "critical_api": meta.get("critical_api_or_function"),
                "api_call_sequence": ast.get("api_call_sequence") or [],
                "trigger_behavior": meta.get("trigger_behavior"),
            }
        )
    return sorted(rows, key=lambda x: (x["source_library"], x["poc_id"], x.get("artifact_path") or ""))


def correction_results(records: list[dict[str, Any]], target_keys: set[tuple[str, str, str]]) -> list[dict[str, Any]]:
    rows = []
    for r in records:
        key = (str(r.get("source_library")), str(r.get("poc_id")), str(r.get("artifact_path")))
        pattern = r.get("pattern_candidate") or {}
        original_family = pattern.get("family_guess") or "needs_review"
        original_harness = pattern.get("harness_family_guess") or "needs_review"
        original_route = pattern.get("route_guess") or "needs_more_evidence"
        if key in target_keys:
            corrected_family, confidence, reason = suggest_family(r)
        else:
            corrected_family, confidence, reason = original_family, "medium", "not in targeted correction set; preserved original staging family"
        corrected_harness = harness_for_family(corrected_family, original_harness)
        corrected_route = route_for_family(corrected_family, original_route)
        meta = r.get("metadata_summary") or {}
        ast = r.get("ast_summary") or {}
        files = r.get("artifact_files") or {}
        rows.append(
            {
                "poc_id": r.get("poc_id"),
                "source_library": r.get("source_library"),
                "artifact_path": r.get("artifact_path"),
                "original_family": original_family,
                "corrected_family": corrected_family,
                "original_harness_family": original_harness,
                "corrected_harness_family": corrected_harness,
                "original_route": original_route,
                "corrected_route": corrected_route,
                "confidence": confidence,
                "correction_reason": reason,
                "evidence": {
                    "component": meta.get("component"),
                    "critical_api": meta.get("critical_api_or_function"),
                    "api_call_sequence": ast.get("api_call_sequence") or [],
                    "source_file_names": (ast.get("source_files") or []) + (files.get("poc_c_files") or []),
                    "trigger_behavior": meta.get("trigger_behavior"),
                },
            }
        )
    return sorted(rows, key=lambda x: (x["source_library"], x["poc_id"], x.get("artifact_path") or ""))


def correction_summary(rows: list[dict[str, Any]], targets: list[dict[str, Any]]) -> dict[str, Any]:
    before = Counter(r["original_family"] for r in rows)
    after = Counter(r["corrected_family"] for r in rows)
    return {
        "total_reviewed": len(targets),
        "changed": sum(1 for r in rows if r["original_family"] != r["corrected_family"]),
        "unchanged": sum(1 for r in rows if r["original_family"] == r["corrected_family"]),
        "needs_review": sum(1 for r in rows if r["corrected_family"] == "needs_review" or r["confidence"] == "needs_review"),
        "bignum_before": before.get("bignum_serialization_boundary", 0),
        "bignum_after": after.get("bignum_serialization_boundary", 0),
        "pkcs_container_after": after.get("pkcs_container_parsing", 0),
        "x509_after": after.get("x509_parsing", 0) + after.get("asn1_nested_boundary", 0),
        "tls_after": after.get("tls_protocol_state_lifecycle", 0),
        "family_counts_after": dict(after),
    }


def corrected_scheduler(reviewed: list[dict[str, Any]], corrections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    corr = {(c["source_library"], c["poc_id"], c.get("artifact_path")): c for c in corrections}
    out = []
    for item in reviewed:
        key = (item.get("source_library"), item.get("poc_id"), item.get("artifact_path"))
        c = corr.get(key)
        family = c["corrected_family"] if c else item.get("family")
        harness = c["corrected_harness_family"] if c else item.get("harness_family")
        route = c["corrected_route"] if c else item.get("route_guess")
        conf = c["confidence"] if c else "medium"
        applied = bool(c and (c["original_family"] != c["corrected_family"] or c["original_harness_family"] != c["corrected_harness_family"]))
        scheduler_action = item.get("scheduler_action")
        import_status = item.get("import_status")
        if family == "needs_review" or conf == "needs_review":
            scheduler_action = "needs_review"
            import_status = "needs_manual_review"
        out.append(
            {
                "poc_id": item.get("poc_id"),
                "source_library": item.get("source_library"),
                "artifact_path": item.get("artifact_path"),
                "family": family,
                "harness_family": harness,
                "route_guess": route,
                "quality_confidence": item.get("quality_confidence"),
                "evidence_strength": item.get("evidence_strength"),
                "template_candidate": item.get("template_candidate"),
                "import_status": import_status,
                "correction_applied": applied,
                "correction_confidence": conf,
                "scheduler_action": scheduler_action,
                "recommended_next_action": "manual_review_family_corrections_v1" if family == "needs_review" else item.get("recommended_next_action"),
                "allow_glm": False,
                "allow_render": False,
                "allow_run": False,
                "reason": c["correction_reason"] if c else item.get("reason"),
            }
        )
    return sorted(out, key=lambda x: (x["source_library"], x["poc_id"], x.get("artifact_path") or ""))


def corrected_distribution(items: list[dict[str, Any]]) -> dict[str, Any]:
    family = Counter(i["family"] for i in items)
    by_lib = defaultdict(Counter)
    for i in items:
        by_lib[i["source_library"]][i["family"]] += 1
    top = family.most_common(8)
    bignum = family.get("bignum_serialization_boundary", 0)
    return {
        "family_counts": dict(family),
        "source_library_family_counts": {k: dict(v) for k, v in sorted(by_lib.items())},
        "top_families": top,
        "bignum_still_concentrated": bignum >= 15,
        "pkcs_container_is_top": bool(top and top[0][0] == "pkcs_container_parsing"),
        "x509_count": family.get("x509_parsing", 0) + family.get("asn1_nested_boundary", 0),
        "tls_protocol_state_lifecycle_count": family.get("tls_protocol_state_lifecycle", 0),
        "secure_heap_state_lifecycle_count": family.get("secure_heap_state_lifecycle", 0),
        "mac_lifecycle_count": family.get("mac_lifecycle", 0),
        "cipher_aead_lifecycle_count": family.get("cipher_aead_lifecycle", 0),
        "wolfssl_family_contribution": dict(by_lib.get("wolfssl", {})),
        "needs_historical_ingestion_rules_refinement": bignum >= 15,
    }


def write_input_summary(out: Path, sanity: dict[str, Any]) -> None:
    obj = {
        "why_family_correction": "Previous review found suspicious bignum concentration and 24 correction suggestions.",
        "bignum_concentration_risk": "Over-broad bignum assignment can bury parser/protocol/security-state families and mislead scheduler ordering.",
        "why_not_rag_now": "RAG enrichment should consume corrected structured summaries after family correction, not raw/possibly-misclassified records.",
        "why_not_templates_now": "Template generation requires stable family/template schema selection first.",
        "safety_constraints": {"allow_glm": False, "allow_render": False, "allow_run": False},
        "previous_correction_suggestions": len(sanity.get("correction_suggestions", [])),
    }
    dump_yaml(out / "input" / "family_correction_input_summary.yaml", obj)
    (out / "input" / "family_correction_input_summary.md").write_text(
        "# family correction input summary\n\n"
        + "\n".join(f"- {k}: {v}" for k, v in obj.items() if not isinstance(v, dict))
        + "\n- allow_glm/render/run: false\n",
        encoding="utf-8",
    )


def write_review_targets(out: Path, targets: list[dict[str, Any]]) -> None:
    dump_yaml(out / "review" / "review_target_list.yaml", {"review_targets": targets})
    (out / "review" / "review_target_list.md").write_text(
        "# review target list\n\n"
        + md_table(["poc_id", "library", "current_family", "reason"], [[t["poc_id"], t["source_library"], t["current_family"], ", ".join(t["reason_for_review"])] for t in targets]),
        encoding="utf-8",
    )


def write_corrections(out: Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    dump_yaml(out / "corrections" / "family_correction_results.yaml", {"correction_summary": summary, "items": rows})
    (out / "corrections" / "family_correction_results.md").write_text(
        "# family correction results\n\n"
        + md_table(["metric", "value"], [[k, v] for k, v in summary.items() if k != "family_counts_after"])
        + "\n## items\n\n"
        + md_table(["poc_id", "library", "original", "corrected", "confidence", "reason"], [[r["poc_id"], r["source_library"], r["original_family"], r["corrected_family"], r["confidence"], r["correction_reason"]] for r in rows]),
        encoding="utf-8",
    )


def write_scheduler(out: Path, items: list[dict[str, Any]]) -> None:
    dump_yaml(out / "scheduler" / "corrected_reviewed_scheduler_seed_candidates.yaml", {"corrected_reviewed_scheduler_seed_candidates": items})
    (out / "scheduler" / "corrected_reviewed_scheduler_seed_candidates.md").write_text(
        "# corrected reviewed scheduler seed candidates\n\n"
        + md_table(["poc_id", "library", "family", "confidence", "action", "allow_run"], [[i["poc_id"], i["source_library"], i["family"], i["correction_confidence"], i["scheduler_action"], i["allow_run"]] for i in items]),
        encoding="utf-8",
    )


def write_distribution(out: Path, dist: dict[str, Any]) -> None:
    dump_yaml(out / "corrections" / "corrected_family_distribution.yaml", dist)
    (out / "corrections" / "corrected_family_distribution.md").write_text(
        "# corrected family distribution\n\n"
        + md_table(["family", "count"], [[k, v] for k, v in Counter(dist["family_counts"]).most_common()])
        + "\n## answers\n\n"
        + md_table(
            ["question", "answer"],
            [
                ["bignum_serialization_boundary 是否仍然异常集中", dist["bignum_still_concentrated"]],
                ["pkcs_container_parsing 是否仍然 top", dist["pkcs_container_is_top"]],
                ["x509/asn1 count", dist["x509_count"]],
                ["tls count", dist["tls_protocol_state_lifecycle_count"]],
                ["secure_heap count", dist["secure_heap_state_lifecycle_count"]],
                ["mac count", dist["mac_lifecycle_count"]],
                ["aead count", dist["cipher_aead_lifecycle_count"]],
                ["是否还需要 ingestion rules refinement", dist["needs_historical_ingestion_rules_refinement"]],
            ],
        ),
        encoding="utf-8",
    )


def rag_plan(corrected: list[dict[str, Any]]) -> dict[str, Any]:
    high = [i for i in corrected if i.get("quality_confidence") == "high" and i.get("family") != "needs_review"]
    blocked = [i for i in corrected if i.get("import_status") in {"blocked", "needs_manual_review"}]
    return {
        "next_rag_task": "rag_knowledge_inventory_v1",
        "read_before_enrichment": ["knowledge/", "knowledge_base/", "knowledge_collectors/", "knowledge_raw/"],
        "formal_knowledge_raw_write": False,
        "allowed_import_fields": ["poc_id", "family", "critical_api", "root_cause_hypothesis", "mutation_points", "oracle_candidate", "seed_status", "evidence_strength"],
        "forbidden_imports": ["raw HTML", "raw logs", "raw poc.c full text"],
        "must_mark_seed_flags": ["placeholder", "synthetic", "source_vector"],
        "negative_feedback_policy": "blocked seed and negative feedback should be imported as down-ranking evidence, not vulnerability-pattern evidence",
        "high_confidence_structured_candidates": len(high),
        "blocked_or_negative_candidates": len(blocked),
    }


def template_plan(corrected: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [i for i in corrected if i.get("template_candidate") and i.get("family") != "needs_review"]
    return {
        "next_template_task": "template_schema_inventory_v1",
        "read_before_generalization": ["normalized_templates/", "templates/", "enriched_templates/", "generated_templates/"],
        "reference_template_files": ["template_meta.yaml", "mask_report.yaml", "ast_mask_report.yaml", "selected_mask_units.yaml", "tmpl_<source_library>.c", "poc_original.c"],
        "generate_templates_now": False,
        "call_ast_sister_now": False,
        "candidate_count_after_correction": len(candidates),
    }


def next_action(summary: dict[str, Any], dist: dict[str, Any], rag: dict[str, Any]) -> dict[str, Any]:
    if summary["bignum_after"] >= 15 and summary["needs_review"] > 5:
        task = "historical_poc_ingestion_rules_refinement_v1"
        why = "bignum remains concentrated and many records still need review"
    else:
        task = "rag_knowledge_inventory_v1"
        why = "corrected top families are stable enough for RAG inventory; parser/protocol candidates need API constraints before migration"
    return {
        "next_task_name": task,
        "why": why,
        "bignum_after": summary["bignum_after"],
        "needs_review": summary["needs_review"],
        "rag_plan_next_task": rag["next_rag_task"],
        "template_plan_next_task": "template_schema_inventory_v1",
    }


def write_plan_files(out: Path, rag: dict[str, Any], tmpl: dict[str, Any], nxt: dict[str, Any]) -> None:
    dump_yaml(out / "rag_plan" / "rag_enrichment_after_family_correction_plan.yaml", rag)
    (out / "rag_plan" / "rag_enrichment_after_family_correction_plan.md").write_text(
        "# RAG enrichment after family correction plan\n\n"
        + md_table(["field", "value"], [[k, v] for k, v in rag.items()]),
        encoding="utf-8",
    )
    dump_yaml(out / "template_plan" / "template_generalization_after_family_correction_plan.yaml", tmpl)
    (out / "template_plan" / "template_generalization_after_family_correction_plan.md").write_text(
        "# template generalization after family correction plan\n\n"
        + md_table(["field", "value"], [[k, v] for k, v in tmpl.items()]),
        encoding="utf-8",
    )
    dump_yaml(out / "reports" / "next_action_after_family_correction.yaml", nxt)
    (out / "reports" / "next_action_after_family_correction.md").write_text(
        "# next action after family correction\n\n" + md_table(["field", "value"], [[k, v] for k, v in nxt.items()]),
        encoding="utf-8",
    )


def write_report(out: Path, targets: list[dict[str, Any]], summary: dict[str, Any], dist: dict[str, Any], corrected: list[dict[str, Any]], nxt: dict[str, Any]) -> dict[str, Any]:
    top_families = dist["top_families"][:5]
    top_pocs = ["WOLFSSL-POC-0007", "WOLFSSL-POC-0006", "WOLFSSL-POC-0004"]
    still_present = [p for p in top_pocs if any(i["poc_id"] == p and i["family"] != "needs_review" for i in corrected)]
    needs_review = [i["poc_id"] for i in corrected if i["family"] == "needs_review" or i["scheduler_action"] == "needs_review"]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reviewed_records": len(targets),
        "family_corrections_changed": summary["changed"],
        "bignum_before": summary["bignum_before"],
        "bignum_after": summary["bignum_after"],
        "corrected_top_families": top_families,
        "wolfssl_top_pocs_still_present": still_present,
        "records_still_need_manual_review": needs_review,
        "pattern_bank_modified": False,
        "scheduler_seed_modified": False,
        "knowledge_raw_written": False,
        "templates_generated": False,
        "run_poc": False,
        "glm": False,
        "render": False,
        "next_task_name": nxt["next_task_name"],
    }
    dump_yaml(out / "reports" / "manual_review_family_corrections_report.yaml", report)
    (out / "reports" / "manual_review_family_corrections_report.md").write_text(
        "# manual_review_family_corrections_v1 report\n\n"
        + md_table(["metric", "value"], [[k, v] for k, v in report.items() if not isinstance(v, list)])
        + "\n## corrected top families\n\n"
        + md_table(["family", "count"], [[k, v] for k, v in top_families]),
        encoding="utf-8",
    )
    (out / "README.md").write_text(
        "# manual_review_family_corrections_v1\n\n"
        "Conservative family correction sprint. No PoCs were run, no GLM/render/RAG rebuild/template generation happened, and no formal Pattern Bank or scheduler seed files were modified.\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", required=True)
    ap.add_argument("--quality-review", required=True)
    ap.add_argument("--family-sanity", required=True)
    ap.add_argument("--reviewed-candidates", required=True)
    ap.add_argument("--rerank", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out = Path(args.out_dir)
    for sub in ("input", "review", "corrections", "scheduler", "rag_plan", "template_plan", "reports", "logs", "validation"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    records = load_jsonl(Path(args.records))
    load_yaml(Path(args.quality_review))
    sanity = load_yaml(Path(args.family_sanity))
    reviewed_obj = load_yaml(Path(args.reviewed_candidates))
    reviewed = reviewed_obj.get("reviewed_scheduler_seed_candidates", [])
    rerank = load_yaml(Path(args.rerank))
    write_input_summary(out, sanity)
    targets = review_targets(records, sanity, rerank)
    write_review_targets(out, targets)
    target_keys = {(t["source_library"], t["poc_id"], t.get("artifact_path")) for t in targets}
    corrections = correction_results(records, target_keys)
    summary = correction_summary(corrections, targets)
    write_corrections(out, corrections, summary)
    corrected = corrected_scheduler(reviewed, corrections)
    write_scheduler(out, corrected)
    dist = corrected_distribution(corrected)
    write_distribution(out, dist)
    rag = rag_plan(corrected)
    tmpl = template_plan(corrected)
    nxt = next_action(summary, dist, rag)
    write_plan_files(out, rag, tmpl, nxt)
    report = write_report(out, targets, summary, dist, corrected, nxt)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
