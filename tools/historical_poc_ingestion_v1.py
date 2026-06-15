#!/usr/bin/env python3
"""Convert ready corpus inventory rows into normalized PoC records.

This tool is intentionally read-only with respect to original PoC artifacts.
It does not run PoCs, compile harnesses, render cases, call GLM/LLM, or update
Pattern Bank / scheduler seed files.
"""

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


KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "case",
    "do",
    "else",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
    return sorted(rows, key=lambda r: (str(r.get("source_library", "")), str(r.get("poc_id", ""))))


def dump_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def dump_yaml(path: Path, obj: Any) -> None:
    if yaml is None:
        dump_json(path, obj)
        return
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(v).replace("\n", " ") for v in row) + " |")
    return "\n".join(out) + "\n"


def flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(flatten_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(flatten_text(v) for _, v in sorted(value.items()))
    return str(value)


def rel_source_paths(row: dict[str, Any]) -> list[str]:
    files = row.get("artifact_files") or {}
    paths: list[str] = []
    for key in ("poc_c_files",):
        paths.extend(files.get(key) or [])
    return sorted(set(paths))


def read_source_text(row: dict[str, Any]) -> tuple[list[str], str]:
    artifact = Path(str(row.get("artifact_path", "")))
    sources = rel_source_paths(row)
    chunks: list[str] = []
    existing: list[str] = []
    for rel in sources:
        path = artifact / rel
        if path.is_file():
            try:
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
                existing.append(rel)
            except OSError:
                pass
    return existing, "\n".join(chunks)


def regex_ast_summary(row: dict[str, Any], normalized_template_root: Path) -> dict[str, Any]:
    source_files, text = read_source_text(row)
    files = row.get("artifact_files") or {}
    metadata = row.get("metadata_summary") or {}
    include_headers = sorted(set(re.findall(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", text, flags=re.M)))
    calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    calls = [c for c in calls if c not in KEYWORDS]
    api_call_sequence: list[str] = []
    for c in calls:
        if c not in api_call_sequence and (
            c.startswith(("mbedtls_", "wolf", "wc_", "CRYPTO_", "BIO_", "EVP_", "ASN1_", "X509", "d2i_", "i2d_", "BN_", "RSA_", "SSL_", "PKCS", "CMS_"))
            or c in {"fopen", "fread", "read", "memcpy", "memset", "malloc", "free"}
        ):
            api_call_sequence.append(c)
    functions = sorted(set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_*\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{", text)))
    string_literals = sorted(set(re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)))[:80]
    numeric_literals = sorted(set(re.findall(r"(?<![A-Za-z_])(?:0x[0-9A-Fa-f]+|\d+)(?![A-Za-z_])", text)))[:80]
    external_terms = re.search(r"\b(argv|argc|fopen|fread|read|BIO_new_file|PEM_read|SSL_CTX_use_.*_file)\b", text)
    input_files = files.get("inputs") or []
    input_status = flatten_text(metadata.get("input_status")).lower()
    no_external = "no_external_input_required" in input_status or "embedded" in input_status
    selected_available = any(
        p.name == "selected_mask_units.yaml" and row.get("poc_id", "").lower() in str(p).lower()
        for p in normalized_template_root.rglob("selected_mask_units.yaml")
    ) if normalized_template_root.exists() else False
    crash_keywords = bool(re.search(r"\b(asan|ubsan|segv|sigsegv|crash|heap-buffer-overflow|stack-buffer-overflow|null deref|null_dereference)\b", text, flags=re.I))
    ast_ready = bool(source_files and text.strip())
    ast_mask_candidate = bool(ast_ready and api_call_sequence)
    notes: list[str] = []
    if crash_keywords:
        notes.append("source_or_comments_contain_crash_keywords")
    if not ast_ready:
        notes.append("no C source available for lightweight AST summary")
    return {
        "ast_ready": ast_ready,
        "parser": "lightweight_regex",
        "source_files": source_files,
        "include_headers": include_headers,
        "api_call_sequence": api_call_sequence,
        "functions": functions,
        "constants": {
            "string_literals": string_literals,
            "numeric_literals": numeric_literals,
        },
        "external_input_required": bool((external_terms or input_files) and not no_external),
        "selected_mask_units_available": selected_available,
        "ast_mask_candidate": ast_mask_candidate,
        "notes": notes,
    }


def classify_family(row: dict[str, Any], ast: dict[str, Any]) -> tuple[str, str]:
    meta = row.get("metadata_summary") or {}
    text = " ".join(
        [
            flatten_text(meta),
            flatten_text(ast.get("include_headers")),
            flatten_text(ast.get("api_call_sequence")),
            row.get("poc_id", ""),
        ]
    ).lower()
    if any(x in text for x in ("crypto_secure", "secure heap", "bio_s_secmem", "secmem")):
        return "secure_heap_state_lifecycle", "object_state_lifecycle"
    if any(x in text for x in ("evp_decryptfinal", "padding", "outlen", "cipher_finish")):
        return "cipher_padding_output_length", "return_code_outlen_semantic"
    if any(x in text for x in ("aead", "gcm", "ccm", "tag")):
        return "cipher_aead_lifecycle", "object_state_lifecycle"
    if any(x in text for x in ("hmac", "cmac", " mac", "evp_mac", "mac_final", "mac finish")):
        return "mac_lifecycle", "object_state_lifecycle"
    if any(x in text for x in ("bn_", "bignum", "mpi", "mbedtls_mpi")):
        if any(x in text for x in ("write_string", "serialization", "serialize", "bn2bin", "bn2hex", "bn2dec")):
            return "bignum_serialization_boundary", "buffer_canary_boundary"
        if any(x in text for x in ("sub_abs", "bn_usub", "bn_sub", "arithmetic", "subtraction")):
            return "bignum_arithmetic_precondition", "return_code_outlen_semantic"
        return "bignum_serialization_boundary", "buffer_canary_boundary"
    if any(x in text for x in ("pkcs7", "pkcs12", "cms")):
        return "pkcs_container_parsing", "x509_asn1_inner_boundary"
    if re.search(r"\b(dtls|tls|record|handshake)\b", text) or "ssl_" in text:
        return "tls_protocol_state_lifecycle", "object_state_lifecycle"
    if any(x in text for x in ("x509", "certificate", "cert", "verify", "crl")):
        return "x509_parsing", "x509_asn1_inner_boundary"
    if any(x in text for x in ("d2i_", "der", "asn1", "trailing", "consumed pointer")):
        return "asn1_nested_boundary", "x509_asn1_inner_boundary"
    if any(x in text for x in ("pkey", "rsa", "sign", "verify")):
        return "pkey_verify_semantic", "object_state_lifecycle"
    return "needs_review", "needs_review"


def oracle_candidate(row: dict[str, Any], ast: dict[str, Any], family: str) -> str:
    meta = row.get("metadata_summary") or {}
    text = " ".join([flatten_text(meta), flatten_text(ast), family]).lower()
    if any(x in text for x in ("segv", "sigsegv", "crash", "asan", "ubsan", "heap-buffer-overflow", "stack-buffer-overflow")):
        return "crash_sanitizer_oracle"
    if any(x in text for x in ("d2i", "der", "consumed", "trailing")):
        return "pointer_consumption_semantic_oracle"
    if any(x in text for x in ("x509", "verify", "purpose", "crl", "app")):
        return "app_level_validation_gap"
    if any(x in text for x in ("padding", "outlen", "final")):
        return "return_code_outlen_semantic"
    if any(x in text for x in ("buffer", "length", "overflow", "canary")):
        return "buffer_canary_boundary"
    if any(x in text for x in ("state", "init", "finish", "update", "free", "reuse")):
        return "object_state_lifecycle"
    return "needs_review"


def seed_status(row: dict[str, Any], ast: dict[str, Any]) -> dict[str, Any]:
    files = row.get("artifact_files") or {}
    meta = row.get("metadata_summary") or {}
    artifact_path = Path(str(row.get("artifact_path", "")))
    input_files = sorted(files.get("inputs") or [])
    meta_input = meta.get("input_artifact")
    input_status = flatten_text(meta.get("input_status")).lower()
    meta_all = flatten_text(meta).lower()
    path_all = str(artifact_path).lower()
    no_external = "no_external_input_required" in input_status or "embedded" in input_status
    if not no_external and meta.get("poc_type") and "c_api" in flatten_text(meta.get("poc_type")).lower() and not ast.get("external_input_required"):
        no_external = True
    placeholder = "placeholder" in meta_all or "placeholder" in path_all
    synthetic = any(x in meta_all or x in path_all for x in ("synthetic", "generated"))
    source_vector = any("test" in p.lower() or "cert" in p.lower() or "clean_sources" in p.lower() for p in input_files + files.get("sources", []))
    evidence: list[str] = []
    if meta_input:
        evidence.append("metadata_input_artifact_present")
    if input_files:
        evidence.append("input_dir_present")
    if no_external:
        evidence.append("no_external_input_required_or_embedded")
    if placeholder:
        evidence.append("placeholder_detected")
    if synthetic:
        evidence.append("synthetic_or_generated_detected")
    return {
        "original_seed": bool((meta_input or input_files) and not placeholder and not synthetic),
        "placeholder": placeholder,
        "synthetic": synthetic,
        "source_vector": source_vector,
        "no_external_input_required": no_external,
        "input_files": input_files,
        "evidence": evidence,
    }


def route_guess(row: dict[str, Any], ast: dict[str, Any], seed: dict[str, Any], oracle: str, family: str) -> str:
    meta = row.get("metadata_summary") or {}
    text = " ".join([flatten_text(meta), flatten_text(ast)]).lower()
    if row.get("status") != "ready_for_ingestion" or not ast.get("ast_ready"):
        return "needs_more_evidence"
    if "openssl x509" in text or "openssl verify" in text or "openssl crl" in text:
        return "C_app_level_validation_gap"
    if oracle == "crash_sanitizer_oracle":
        return "D_crash_sanitizer_evidence_audit"
    if seed.get("no_external_input_required") and "c_api" in flatten_text(meta.get("poc_type")).lower():
        return "B_controlled_family_mutation"
    if family != "needs_review" and ast.get("api_call_sequence"):
        return "A_recipe_slot_cross_library_migration"
    if ast.get("external_input_required") and not seed.get("input_files"):
        return "blocked_seed_missing"
    return "needs_more_evidence"


def evidence_strength(row: dict[str, Any], ast: dict[str, Any], seed: dict[str, Any], family: str) -> str:
    meta = row.get("metadata_summary") or {}
    strong = meta.get("strict_reproduction") is True or "true" == flatten_text(meta.get("strict_reproduction")).lower()
    compiled = meta.get("local_compile") is True or "true" == flatten_text(meta.get("local_compile")).lower()
    if strong and ast.get("ast_ready") and family != "needs_review":
        return "high"
    if (compiled or ast.get("ast_ready")) and family != "needs_review":
        return "medium"
    if seed.get("input_files") or seed.get("no_external_input_required"):
        return "low"
    return "needs_review"


def suggested_template_root(normalized_root: Path, row: dict[str, Any]) -> str:
    lib = str(row.get("source_library", "unknown")).lower()
    poc = str(row.get("poc_id", "unknown")).lower().replace("_", "-")
    return str(normalized_root / lib / poc)


def template_candidate(row: dict[str, Any], ast: dict[str, Any], family: str, harness: str, normalized_root: Path) -> dict[str, Any]:
    can_generate = bool(ast.get("ast_ready") and ast.get("api_call_sequence") and family != "needs_review")
    reason = "C source and API call sequence are available" if can_generate else "needs manual review before source template generation"
    return {
        "can_generate_source_template": can_generate,
        "needs_manual_review": not can_generate,
        "reason": reason,
        "suggested_template_root": suggested_template_root(normalized_root, row),
        "recommended_tool_chain": [
            "template_maker.mask",
            "template_maker.ast_mask_lite",
            "template_maker.ast_mask_select",
        ],
    }


def scheduler_fields(row: dict[str, Any], ast: dict[str, Any], seed: dict[str, Any], tmpl: dict[str, Any], route: str, strength: str, family: str) -> dict[str, Any]:
    if row.get("status") != "ready_for_ingestion":
        action = "needs_review"
        next_action = "manual_review"
    elif ast.get("external_input_required") and not seed.get("input_files") and not seed.get("original_seed"):
        action = "block"
        next_action = "seed_recovery_v1"
    elif tmpl.get("can_generate_source_template") and strength in {"high", "medium"}:
        action = "promote" if strength == "high" else "keep"
        next_action = "template_generalizer_v1"
    elif family == "needs_review":
        action = "needs_review"
        next_action = "manual_family_triage_v1"
    else:
        action = "keep"
        next_action = "template_generalizer_v1"
    return {
        "evidence_strength": strength,
        "recommended_next_action": next_action,
        "allow_glm": False,
        "allow_render": False,
        "allow_run": False,
        "reason": f"ingestion-only candidate; route={route}; action={action}",
        "scheduler_action": action,
    }


def normalize_record(row: dict[str, Any], normalized_root: Path) -> dict[str, Any]:
    meta = row.get("metadata_summary") or {}
    ast = regex_ast_summary(row, normalized_root)
    family, harness = classify_family(row, ast)
    oracle = oracle_candidate(row, ast, family)
    seed = seed_status(row, ast)
    route = route_guess(row, ast, seed, oracle, family)
    tmpl = template_candidate(row, ast, family, harness, normalized_root)
    strength = evidence_strength(row, ast, seed, family)
    sched = scheduler_fields(row, ast, seed, tmpl, route, strength, family)
    return {
        "poc_id": row.get("poc_id"),
        "source_library": row.get("source_library"),
        "artifact_path": row.get("artifact_path"),
        "artifact_files": row.get("artifact_files") or {},
        "metadata_summary": {
            key: meta.get(key)
            for key in [
                "component",
                "trigger_behavior",
                "critical_api_or_function",
                "root_cause",
                "input_status",
                "strict_reproduction",
                "local_compile",
                "local_run",
                "poc_type",
                "quality",
                "affected_version",
                "fix_evidence",
                "local_test_result",
                "validation_notes",
            ]
        },
        "ast_summary": ast,
        "pattern_candidate": {
            "family_guess": family,
            "harness_family_guess": harness,
            "root_cause_hypothesis": meta.get("root_cause") or "needs_review",
            "mutation_points": ast.get("api_call_sequence")[:12],
            "oracle_candidate": oracle,
            "route_guess": route,
        },
        "seed_status": seed,
        "template_candidate": tmpl,
        "scheduler": sched,
    }


def write_input_summary(out: Path, total: int, ready: int, skipped: list[dict[str, Any]]) -> None:
    obj = {
        "input_source": "poc_corpus_inventory_v1",
        "inventory_jsonl": "artifacts/sprints/poc_corpus_inventory_v1/inventory/unified_poc_corpus_inventory.jsonl",
        "total_artifacts": total,
        "ready_for_ingestion": ready,
        "manual_review_records": [{"poc_id": r.get("poc_id"), "status": r.get("status"), "artifact_path": r.get("artifact_path")} for r in skipped],
        "constraints": {
            "only_process_ready_for_ingestion": True,
            "mbedtls_poc_0027_manual_review": True,
            "run_poc": False,
            "call_glm": False,
            "render": False,
        },
    }
    dump_yaml(out / "input" / "ingestion_input_summary.yaml", obj)
    (out / "input" / "ingestion_input_summary.md").write_text(
        "# ingestion input summary\n\n"
        "- 本轮输入来自 `poc_corpus_inventory_v1`。\n"
        "- 本轮只处理 `status=ready_for_ingestion` artifact。\n"
        "- `MBEDTLS-POC-0027` 进入 manual review，不进入自动 ingestion。\n"
        "- 本轮不运行 PoC、不调用 GLM、不 render。\n\n"
        + md_table(
            ["metric", "value"],
            [["total_artifacts", total], ["ready_for_ingestion", ready], ["manual_review", len(skipped)]],
        ),
        encoding="utf-8",
    )


def write_records(out: Path, records: list[dict[str, Any]]) -> None:
    dump_json(out / "records" / "normalized_poc_records.json", {"records": records})
    (out / "records" / "normalized_poc_records.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in records), encoding="utf-8"
    )
    dump_yaml(out / "records" / "normalized_poc_records.yaml", {"records": records})
    (out / "records" / "normalized_poc_records.md").write_text(
        "# normalized_poc_records\n\n"
        + md_table(
            ["poc_id", "library", "family", "harness_family", "route", "template_candidate"],
            [
                [
                    r["poc_id"],
                    r["source_library"],
                    r["pattern_candidate"]["family_guess"],
                    r["pattern_candidate"]["harness_family_guess"],
                    r["pattern_candidate"]["route_guess"],
                    r["template_candidate"]["can_generate_source_template"],
                ]
                for r in records
            ],
        ),
        encoding="utf-8",
    )


def write_ast_report(out: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    asts = [r["ast_summary"] for r in records]
    obj = {
        "parser": "lightweight_regex",
        "record_count": len(records),
        "success_count": sum(1 for a in asts if a["ast_ready"]),
        "source_files_analyzed": sum(len(a["source_files"]) for a in asts),
        "external_input_required_count": sum(1 for a in asts if a["external_input_required"]),
        "ast_mask_candidate_count": sum(1 for a in asts if a["ast_mask_candidate"]),
        "records": [
            {
                "poc_id": r["poc_id"],
                "source_files": r["ast_summary"]["source_files"],
                "api_call_sequence": r["ast_summary"]["api_call_sequence"],
                "ast_ready": r["ast_summary"]["ast_ready"],
                "external_input_required": r["ast_summary"]["external_input_required"],
                "ast_mask_candidate": r["ast_summary"]["ast_mask_candidate"],
            }
            for r in records
        ],
    }
    dump_yaml(out / "ast" / "ast_summary_report.yaml", obj)
    (out / "ast" / "ast_summary_report.md").write_text(
        "# AST summary report\n\n"
        + md_table(
            ["metric", "value"],
            [
                ["parser", obj["parser"]],
                ["success_count", obj["success_count"]],
                ["source_files_analyzed", obj["source_files_analyzed"]],
                ["external_input_required_count", obj["external_input_required_count"]],
                ["ast_mask_candidate_count", obj["ast_mask_candidate_count"]],
            ],
        ),
        encoding="utf-8",
    )
    return obj


def write_family_inventory(out: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    family_counts = Counter(r["pattern_candidate"]["family_guess"] for r in records)
    harness_counts = Counter(r["pattern_candidate"]["harness_family_guess"] for r in records)
    source_family: dict[str, dict[str, int]] = defaultdict(dict)
    for r in records:
        source_family[r["source_library"]][r["pattern_candidate"]["family_guess"]] = source_family[r["source_library"]].get(r["pattern_candidate"]["family_guess"], 0) + 1
    obj = {
        "family_counts": dict(family_counts),
        "harness_family_counts": dict(harness_counts),
        "source_library_family_counts": {k: dict(v) for k, v in source_family.items()},
        "needs_review_count": family_counts.get("needs_review", 0) + harness_counts.get("needs_review", 0),
        "top_families": family_counts.most_common(10),
    }
    dump_yaml(out / "families" / "family_inventory.yaml", obj)
    (out / "families" / "family_inventory.md").write_text(
        "# family inventory\n\n"
        + md_table(["family", "count"], [[k, v] for k, v in family_counts.most_common()])
        + "\n## harness family\n\n"
        + md_table(["harness_family", "count"], [[k, v] for k, v in harness_counts.most_common()]),
        encoding="utf-8",
    )
    return obj


def write_template_inventory(out: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    items = []
    for r in records:
        tmpl = r["template_candidate"]
        lib = r["source_library"]
        items.append(
            {
                "poc_id": r["poc_id"],
                "source_library": lib,
                "source_files": r["ast_summary"]["source_files"],
                "family_guess": r["pattern_candidate"]["family_guess"],
                "harness_family_guess": r["pattern_candidate"]["harness_family_guess"],
                "can_generate_source_template": tmpl["can_generate_source_template"],
                "needs_manual_review": tmpl["needs_manual_review"],
                "reason": tmpl["reason"],
                "suggested_template_root": tmpl["suggested_template_root"],
                "suggested_template_files": [
                    "poc_original.c",
                    f"tmpl_{lib}.c",
                    "template_meta.yaml",
                    "mask_report.yaml",
                    "ast_mask_report.yaml",
                    "selected_mask_units.yaml",
                ],
                "recommended_tool_chain": tmpl["recommended_tool_chain"],
            }
        )
    obj = {"template_candidate_count": len(items), "items": items}
    dump_yaml(out / "templates" / "template_candidate_inventory.yaml", obj)
    (out / "templates" / "template_candidate_inventory.md").write_text(
        "# template candidate inventory\n\n"
        + md_table(
            ["poc_id", "family", "can_generate", "needs_review", "suggested_template_root"],
            [[i["poc_id"], i["family_guess"], i["can_generate_source_template"], i["needs_manual_review"], i["suggested_template_root"]] for i in items],
        ),
        encoding="utf-8",
    )
    return obj


def write_scheduler_candidates(out: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    items = []
    for r in records:
        sched = r["scheduler"]
        seed = r["seed_status"]
        items.append(
            {
                "poc_id": r["poc_id"],
                "family": r["pattern_candidate"]["family_guess"],
                "harness_family": r["pattern_candidate"]["harness_family_guess"],
                "route_guess": r["pattern_candidate"]["route_guess"],
                "evidence_strength": sched["evidence_strength"],
                "seed_status_summary": {
                    "original_seed": seed["original_seed"],
                    "placeholder": seed["placeholder"],
                    "synthetic": seed["synthetic"],
                    "no_external_input_required": seed["no_external_input_required"],
                    "input_file_count": len(seed["input_files"]),
                },
                "template_candidate": r["template_candidate"]["can_generate_source_template"],
                "scheduler_action": sched["scheduler_action"],
                "recommended_next_action": sched["recommended_next_action"],
                "allow_glm": False,
                "allow_render": False,
                "allow_run": False,
                "reason": sched["reason"],
            }
        )
    obj = {"scheduler_seed_candidate_count": len(items), "items": items}
    dump_yaml(out / "scheduler" / "scheduler_seed_candidates.yaml", obj)
    (out / "scheduler" / "scheduler_seed_candidates.md").write_text(
        "# scheduler seed candidates\n\n"
        + md_table(
            ["poc_id", "family", "route", "action", "next_action"],
            [[i["poc_id"], i["family"], i["route_guess"], i["scheduler_action"], i["recommended_next_action"]] for i in items],
        ),
        encoding="utf-8",
    )
    return obj


def write_final_report(
    out: Path,
    total: int,
    records: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
    ast_report: dict[str, Any],
    family_report: dict[str, Any],
    template_report: dict[str, Any],
    scheduler_report: dict[str, Any],
) -> dict[str, Any]:
    by_library = Counter(r["source_library"] for r in records)
    action_counts = Counter(i["scheduler_action"] for i in scheduler_report["items"])
    obj = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_corpus_artifacts": total,
        "ready_records_ingested": len(records),
        "manual_review_skipped": len(skipped),
        "by_library": dict(by_library),
        "ast_summary_success": ast_report["success_count"],
        "family_counts": family_report["family_counts"],
        "harness_family_counts": family_report["harness_family_counts"],
        "template_candidate_count": template_report["template_candidate_count"],
        "scheduler_seed_candidate_count": scheduler_report["scheduler_seed_candidate_count"],
        "scheduler_action_counts": dict(action_counts),
        "allow_glm_all_false": all(not i["allow_glm"] for i in scheduler_report["items"]),
        "allow_render_all_false": all(not i["allow_render"] for i in scheduler_report["items"]),
        "allow_run_all_false": all(not i["allow_run"] for i in scheduler_report["items"]),
        "pattern_bank_modified": False,
        "run_poc": False,
        "next_task_name": "template_generalizer_v1",
    }
    dump_yaml(out / "reports" / "historical_poc_ingestion_report.yaml", obj)
    (out / "reports" / "historical_poc_ingestion_report.md").write_text(
        "# historical_poc_ingestion_v1 report\n\n"
        + md_table(
            ["metric", "value"],
            [
                ["total_corpus_artifacts", obj["total_corpus_artifacts"]],
                ["ready_records_ingested", obj["ready_records_ingested"]],
                ["manual_review_skipped", obj["manual_review_skipped"]],
                ["ast_summary_success", obj["ast_summary_success"]],
                ["template_candidate_count", obj["template_candidate_count"]],
                ["scheduler_seed_candidate_count", obj["scheduler_seed_candidate_count"]],
                ["allow_glm_all_false", obj["allow_glm_all_false"]],
                ["allow_render_all_false", obj["allow_render_all_false"]],
                ["allow_run_all_false", obj["allow_run_all_false"]],
                ["pattern_bank_modified", obj["pattern_bank_modified"]],
                ["run_poc", obj["run_poc"]],
                ["next_task_name", obj["next_task_name"]],
            ],
        ),
        encoding="utf-8",
    )
    (out / "README.md").write_text(
        "# historical_poc_ingestion_v1\n\n"
        "Generated normalized PoC records and candidate inventories from `poc_corpus_inventory_v1`. "
        "This sprint did not run PoCs, compile/run harnesses, render cases, call GLM/LLM, or modify Pattern Bank / scheduler seed files.\n",
        encoding="utf-8",
    )
    return obj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--normalized-template-root", required=True)
    ap.add_argument("--max-pocs", type=int, default=0)
    args = ap.parse_args()

    out = Path(args.out_dir)
    for sub in ("input", "records", "families", "templates", "scheduler", "ast", "reports", "logs", "validation"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    rows = load_jsonl(Path(args.inventory))
    ready = [r for r in rows if r.get("status") == "ready_for_ingestion"]
    skipped = [r for r in rows if r.get("status") != "ready_for_ingestion"]
    if args.max_pocs and args.max_pocs > 0:
        ready = ready[: args.max_pocs]

    normalized_root = Path(args.normalized_template_root)
    records = [normalize_record(r, normalized_root) for r in ready]
    write_input_summary(out, len(rows), len(ready), skipped)
    write_records(out, records)
    ast_report = write_ast_report(out, records)
    family_report = write_family_inventory(out, records)
    template_report = write_template_inventory(out, records)
    scheduler_report = write_scheduler_candidates(out, records)
    report = write_final_report(out, len(rows), records, skipped, ast_report, family_report, template_report, scheduler_report)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
