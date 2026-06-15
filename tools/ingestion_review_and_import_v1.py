#!/usr/bin/env python3
"""Review normalized PoC records and produce staging import candidates."""

from __future__ import annotations

import argparse
import json
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
    return sorted(rows, key=lambda r: (str(r.get("source_library", "")), str(r.get("poc_id", ""))))


def load_yaml(path: Path) -> Any:
    if yaml is None:
        return json.loads(path.read_text(encoding="utf-8"))
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def dump_yaml(path: Path, obj: Any) -> None:
    if yaml is None:
        path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")


def dump_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(v).replace("\n", " ") for v in row) + " |")
    return "\n".join(out) + "\n"


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(text(v) for _, v in sorted(value.items()))
    return str(value)


def metadata_complete(record: dict[str, Any]) -> bool:
    meta = record.get("metadata_summary") or {}
    required = ["component", "trigger_behavior", "critical_api_or_function", "poc_type"]
    present = sum(1 for key in required if meta.get(key) not in (None, "", [], {}))
    return present >= 3


def source_available(record: dict[str, Any]) -> bool:
    files = record.get("artifact_files") or {}
    ast = record.get("ast_summary") or {}
    return bool(ast.get("source_files") or files.get("poc_c_files") or files.get("poc_dir"))


def seed_contradictory(record: dict[str, Any]) -> bool:
    seed = record.get("seed_status") or {}
    if seed.get("original_seed") and (seed.get("placeholder") or seed.get("synthetic")):
        return True
    if seed.get("no_external_input_required") and seed.get("input_files") and seed.get("placeholder"):
        return True
    return False


def route_reasonable(record: dict[str, Any]) -> bool:
    route = (record.get("pattern_candidate") or {}).get("route_guess")
    family = (record.get("pattern_candidate") or {}).get("family_guess")
    oracle = (record.get("pattern_candidate") or {}).get("oracle_candidate")
    if route in (None, "", "needs_more_evidence", "blocked_seed_missing"):
        return False
    if family in (None, "", "needs_review") or oracle in (None, "", "needs_review"):
        return False
    return True


def quality_gate(record: dict[str, Any]) -> dict[str, Any]:
    pattern = record.get("pattern_candidate") or {}
    ast = record.get("ast_summary") or {}
    seed = record.get("seed_status") or {}
    tmpl = record.get("template_candidate") or {}
    scheduler = record.get("scheduler") or {}
    gate = {
        "metadata_complete": metadata_complete(record),
        "poc_source_available": source_available(record),
        "ast_summary_available": bool(ast.get("ast_ready")),
        "family_guess_confident": pattern.get("family_guess") not in (None, "", "needs_review"),
        "harness_family_confident": pattern.get("harness_family_guess") not in (None, "", "needs_review"),
        "oracle_candidate_confident": pattern.get("oracle_candidate") not in (None, "", "needs_review"),
        "seed_status_not_contradictory": not seed_contradictory(record),
        "template_candidate_available": bool(tmpl.get("can_generate_source_template")),
        "route_guess_reasonable": route_reasonable(record),
    }
    block_reasons: list[str] = []
    if scheduler.get("scheduler_action") == "block":
        block_reasons.append("previous scheduler candidate was blocked")
    if ast.get("external_input_required") and not seed.get("input_files") and not seed.get("original_seed"):
        block_reasons.append("external input appears required but no seed/input file is available")
    if not gate["poc_source_available"] or not gate["ast_summary_available"]:
        block_reasons.append("source or AST summary unavailable")
    if not gate["seed_status_not_contradictory"]:
        block_reasons.append("seed status contradiction")

    if block_reasons:
        confidence = "blocked"
    else:
        score = sum(1 for v in gate.values() if v)
        if score >= 9:
            confidence = "high"
        elif score >= 7:
            confidence = "medium"
        elif score >= 5:
            confidence = "low"
        else:
            confidence = "blocked"
    gate["confidence"] = confidence
    gate["block_reasons"] = block_reasons
    return gate


def import_status(confidence: str) -> str:
    return {
        "high": "high_confidence_import_candidate",
        "medium": "medium_confidence_staging",
        "low": "needs_manual_review",
        "blocked": "blocked",
    }[confidence]


def reviewed_action(record: dict[str, Any], gate: dict[str, Any]) -> tuple[str, str]:
    confidence = gate["confidence"]
    if confidence == "blocked":
        return "block", "manual_seed_or_source_triage_v1"
    if confidence == "low":
        return "needs_review", "manual_review_before_scheduler"
    if confidence == "high":
        return "promote", "auto_scheduler_v1_rerun_with_ingestion_candidates"
    return "keep", "rag_enrichment_from_ingestion_v1"


def review_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reviewed: list[dict[str, Any]] = []
    for record in records:
        gate = quality_gate(record)
        action, next_action = reviewed_action(record, gate)
        pattern = record.get("pattern_candidate") or {}
        scheduler = record.get("scheduler") or {}
        seed = record.get("seed_status") or {}
        reviewed.append(
            {
                "poc_id": record.get("poc_id"),
                "source_library": record.get("source_library"),
                "artifact_path": record.get("artifact_path"),
                "family": pattern.get("family_guess"),
                "harness_family": pattern.get("harness_family_guess"),
                "route_guess": pattern.get("route_guess"),
                "evidence_strength": scheduler.get("evidence_strength"),
                "quality_confidence": gate["confidence"],
                "quality_gate": gate,
                "seed_status_summary": {
                    "original_seed": seed.get("original_seed"),
                    "placeholder": seed.get("placeholder"),
                    "synthetic": seed.get("synthetic"),
                    "source_vector": seed.get("source_vector"),
                    "no_external_input_required": seed.get("no_external_input_required"),
                    "input_file_count": len(seed.get("input_files") or []),
                },
                "template_candidate": bool((record.get("template_candidate") or {}).get("can_generate_source_template")),
                "scheduler_action": action,
                "recommended_next_action": next_action,
                "allow_glm": False,
                "allow_render": False,
                "allow_run": False,
                "import_status": import_status(gate["confidence"]),
                "reason": "; ".join(gate.get("block_reasons") or [f"quality confidence={gate['confidence']}"]),
            }
        )
    return sorted(reviewed, key=lambda r: (r["source_library"], r["poc_id"]))


def correction_suggestion(record: dict[str, Any]) -> str:
    lib = record.get("source_library")
    family = (record.get("pattern_candidate") or {}).get("family_guess")
    api = text((record.get("metadata_summary") or {}).get("critical_api_or_function")).lower()
    calls = text((record.get("ast_summary") or {}).get("api_call_sequence")).lower()
    blob = f"{api} {calls}"
    if family == "bignum_serialization_boundary" and lib == "wolfssl":
        return "review: wolfSSL bignum classification is suspicious unless API evidence contains BN/MPI serialization"
    if family == "bignum_serialization_boundary" and not any(x in blob for x in ("bn", "bignum", "mpi")):
        return "review: bignum_serialization_boundary may be over-broad; verify critical API"
    if family == "tls_protocol_state_lifecycle" and lib != "wolfssl" and not any(x in blob for x in ("ssl", "tls", "dtls", "record", "handshake")):
        return "review: TLS lifecycle classification may be too broad"
    return ""


def family_sanity(records: list[dict[str, Any]], reviewed: list[dict[str, Any]]) -> dict[str, Any]:
    family_counts = Counter((r.get("pattern_candidate") or {}).get("family_guess") for r in records)
    lib_family = defaultdict(Counter)
    suggestions = []
    for r in records:
        lib_family[r.get("source_library")][(r.get("pattern_candidate") or {}).get("family_guess")] += 1
        s = correction_suggestion(r)
        if s:
            suggestions.append({"poc_id": r.get("poc_id"), "source_library": r.get("source_library"), "suggestion": s})
    wolf_bignum = [
        r.get("poc_id")
        for r in records
        if r.get("source_library") == "wolfssl" and (r.get("pattern_candidate") or {}).get("family_guess") == "bignum_serialization_boundary"
    ]
    tls_total = family_counts.get("tls_protocol_state_lifecycle", 0)
    tls_wolf = lib_family["wolfssl"].get("tls_protocol_state_lifecycle", 0)
    excluded = [r["poc_id"] for r in reviewed if r["import_status"] in {"needs_manual_review", "blocked"}]
    return {
        "family_counts": dict(family_counts),
        "source_library_family_counts": {k: dict(v) for k, v in sorted(lib_family.items())},
        "suspicious_family_concentration": {
            "bignum_serialization_boundary_count": family_counts.get("bignum_serialization_boundary", 0),
            "possible_over_broad": family_counts.get("bignum_serialization_boundary", 0) > 20,
            "reason": "The bignum bucket is large and should be rechecked against critical API evidence before formal import.",
        },
        "wolfssl_bignum_records": wolf_bignum,
        "wolfssl_bignum_suspicious": bool(wolf_bignum),
        "tls_protocol_state_lifecycle_count": tls_total,
        "tls_protocol_state_lifecycle_from_wolfssl": tls_wolf,
        "tls_mainly_from_wolfssl": tls_total > 0 and tls_wolf / tls_total >= 0.6,
        "openssl_classification_note": "OpenSSL issue records are usable as staging candidates, but high-volume bignum/secure-heap buckets need API-level review before formal Pattern Bank import.",
        "correction_suggestions": suggestions,
        "records_needing_manual_review": excluded,
        "records_can_enter_scheduler": [r["poc_id"] for r in reviewed if r["import_status"] in {"high_confidence_import_candidate", "medium_confidence_staging"}],
        "high_confidence_families": dict(Counter(r["family"] for r in reviewed if r["quality_confidence"] == "high")),
    }


def rag_snippet(record: dict[str, Any], reviewed: dict[str, Any]) -> dict[str, Any]:
    meta = record.get("metadata_summary") or {}
    pattern = record.get("pattern_candidate") or {}
    seed = record.get("seed_status") or {}
    return {
        "poc_id": record.get("poc_id"),
        "source_library": record.get("source_library"),
        "family_guess": pattern.get("family_guess"),
        "harness_family_guess": pattern.get("harness_family_guess"),
        "route_guess": pattern.get("route_guess"),
        "critical_api": meta.get("critical_api_or_function"),
        "root_cause_hypothesis": pattern.get("root_cause_hypothesis"),
        "trigger_behavior": meta.get("trigger_behavior"),
        "mutation_points": pattern.get("mutation_points"),
        "oracle_candidate": pattern.get("oracle_candidate"),
        "seed_status": {
            "original_seed": seed.get("original_seed"),
            "placeholder": seed.get("placeholder"),
            "synthetic": seed.get("synthetic"),
            "source_vector": seed.get("source_vector"),
            "no_external_input_required": seed.get("no_external_input_required"),
        },
        "template_candidate": bool((record.get("template_candidate") or {}).get("can_generate_source_template")),
        "evidence_strength": reviewed.get("evidence_strength"),
        "import_status": reviewed.get("import_status"),
        "notes": "staged structured summary only; no raw HTML/log/poc.c body imported",
    }


def write_input_summary(out: Path, records: list[dict[str, Any]]) -> None:
    obj = {
        "input_source": "historical_poc_ingestion_v1",
        "record_count": len(records),
        "constraints": {
            "not_template_generation": True,
            "not_full_rag_import": True,
            "goal": "select high-confidence records and generate scheduler/RAG candidates",
            "run_poc": False,
            "glm": False,
            "render": False,
        },
    }
    dump_yaml(out / "input" / "review_input_summary.yaml", obj)
    (out / "input" / "review_input_summary.md").write_text(
        "# review input summary\n\n"
        "- 本轮输入来自 `historical_poc_ingestion_v1`。\n"
        "- 本轮不是 template generation。\n"
        "- 本轮不是 RAG 全量补充。\n"
        "- 本轮目标是筛选 high-confidence records 并生成 scheduler/RAG 候选。\n\n"
        + md_table([ "metric", "value" ], [["input_records", len(records)]]),
        encoding="utf-8",
    )


def write_quality_review(out: Path, reviewed: list[dict[str, Any]]) -> None:
    obj = {
        "confidence_counts": dict(Counter(r["quality_confidence"] for r in reviewed)),
        "items": [
            {
                "poc_id": r["poc_id"],
                "source_library": r["source_library"],
                "quality_gate": r["quality_gate"],
                "import_status": r["import_status"],
                "reason": r["reason"],
            }
            for r in reviewed
        ],
    }
    dump_yaml(out / "review" / "record_quality_review.yaml", obj)
    (out / "review" / "record_quality_review.md").write_text(
        "# record quality review\n\n"
        + md_table(["confidence", "count"], [[k, v] for k, v in Counter(r["quality_confidence"] for r in reviewed).items()])
        + "\n"
        + md_table(["poc_id", "library", "confidence", "import_status", "reason"], [[r["poc_id"], r["source_library"], r["quality_confidence"], r["import_status"], r["reason"]] for r in reviewed]),
        encoding="utf-8",
    )


def write_scheduler(out: Path, reviewed: list[dict[str, Any]]) -> dict[str, Any]:
    obj = {"reviewed_scheduler_seed_candidates": reviewed}
    dump_yaml(out / "scheduler" / "reviewed_scheduler_seed_candidates.yaml", obj)
    (out / "scheduler" / "reviewed_scheduler_seed_candidates.md").write_text(
        "# reviewed scheduler seed candidates\n\n"
        + md_table(
            ["poc_id", "library", "family", "confidence", "import_status", "action", "next_action"],
            [[r["poc_id"], r["source_library"], r["family"], r["quality_confidence"], r["import_status"], r["scheduler_action"], r["recommended_next_action"]] for r in reviewed],
        ),
        encoding="utf-8",
    )
    return obj


def write_rag(out: Path, records: list[dict[str, Any]], reviewed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {(r["source_library"], r["poc_id"], r["artifact_path"]): r for r in reviewed}
    snippets = [
        rag_snippet(record, by_id[(record["source_library"], record["poc_id"], record["artifact_path"])])
        for record in records
        if by_id[(record["source_library"], record["poc_id"], record["artifact_path"])]["import_status"] in {"high_confidence_import_candidate", "medium_confidence_staging", "needs_manual_review", "blocked"}
    ]
    snippets = sorted(snippets, key=lambda r: (r["source_library"], r["poc_id"]))
    (out / "rag" / "rag_candidate_snippets.jsonl").write_text(
        "".join(json.dumps(s, sort_keys=True, ensure_ascii=False) + "\n" for s in snippets), encoding="utf-8"
    )
    dump_yaml(out / "rag" / "rag_candidate_snippets.yaml", {"snippets": snippets})
    (out / "rag" / "rag_candidate_snippets.md").write_text(
        "# RAG candidate snippets\n\n"
        + md_table(["poc_id", "library", "family", "import_status", "notes"], [[s["poc_id"], s["source_library"], s["family_guess"], s["import_status"], s["notes"]] for s in snippets]),
        encoding="utf-8",
    )
    grouped = defaultdict(list)
    for s in snippets:
        grouped[s["source_library"]].append(s)
    draft = {
        "title": "Ingested PoC Pattern Candidates",
        "formal_write_performed": False,
        "libraries": {lib: items for lib, items in sorted(grouped.items())},
    }
    dump_yaml(out / "rag" / "knowledge_raw_import_draft.yaml", draft)
    parts = ["# Ingested PoC Pattern Candidates\n"]
    for lib in ("mbedtls", "wolfssl", "openssl"):
        parts.append(f"\n## {lib}\n")
        for s in grouped.get(lib, []):
            parts.append(f"- `{s['poc_id']}`: family=`{s['family_guess']}`, oracle=`{s['oracle_candidate']}`, import_status=`{s['import_status']}`\n")
    (out / "rag" / "knowledge_raw_import_draft.md").write_text("".join(parts), encoding="utf-8")
    return snippets


def write_family_sanity(out: Path, sanity: dict[str, Any]) -> None:
    dump_yaml(out / "quality" / "family_classification_sanity_check.yaml", sanity)
    (out / "quality" / "family_classification_sanity_check.md").write_text(
        "# family classification sanity check\n\n"
        + md_table(
            ["question", "answer"],
            [
                ["bignum_serialization_boundary=28 是否可能过宽", sanity["suspicious_family_concentration"]["possible_over_broad"]],
                ["wolfSSL PoC 是否被误分到 bignum", sanity["wolfssl_bignum_suspicious"]],
                ["tls_protocol_state_lifecycle=11 是否主要来自 wolfSSL", sanity["tls_mainly_from_wolfssl"]],
                ["OpenSSL issue 是否分类合理", sanity["openssl_classification_note"]],
                ["records 需要人工 review", len(sanity["records_needing_manual_review"])],
                ["records 可以进入 scheduler", len(sanity["records_can_enter_scheduler"])],
            ],
        )
        + "\n## correction suggestions\n\n"
        + "\n".join(f"- `{x['poc_id']}`: {x['suggestion']}" for x in sanity["correction_suggestions"])
        + ("\n" if sanity["correction_suggestions"] else "- none\n"),
        encoding="utf-8",
    )


def write_import_plan(out: Path, reviewed: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(r["import_status"] for r in reviewed)
    blocked = statuses.get("blocked", 0)
    needs = statuses.get("needs_manual_review", 0)
    high = statuses.get("high_confidence_import_candidate", 0)
    medium = statuses.get("medium_confidence_staging", 0)
    recommended = "auto_scheduler_v1_rerun_with_ingestion_candidates" if high or medium else "manual_review_before_scheduler"
    obj = {
        "scheduler_import_plan": {
            "high_confidence_count": high,
            "medium_staging_count": medium,
            "needs_manual_review_count": needs,
            "blocked_count": blocked,
            "recommended_next_task": recommended,
            "import_mode": "staging_only",
        }
    }
    dump_yaml(out / "scheduler" / "auto_scheduler_import_plan.yaml", obj)
    (out / "scheduler" / "auto_scheduler_import_plan.md").write_text(
        "# auto scheduler import plan\n\n"
        + md_table(["metric", "value"], [[k, v] for k, v in obj["scheduler_import_plan"].items()]),
        encoding="utf-8",
    )
    return obj


def write_report(out: Path, records: list[dict[str, Any]], reviewed: list[dict[str, Any]], snippets: list[dict[str, Any]], sanity: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    confidence = Counter(r["quality_confidence"] for r in reviewed)
    statuses = Counter(r["import_status"] for r in reviewed)
    obj = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_records": len(records),
        "confidence_counts": dict(confidence),
        "import_status_counts": dict(statuses),
        "family_sanity": {
            "suspicious_family_concentration": sanity["suspicious_family_concentration"],
            "wolfssl_bignum_suspicious": sanity["wolfssl_bignum_suspicious"],
            "tls_mainly_from_wolfssl": sanity["tls_mainly_from_wolfssl"],
            "correction_suggestion_count": len(sanity["correction_suggestions"]),
        },
        "scheduler_import_candidate_count": statuses.get("high_confidence_import_candidate", 0) + statuses.get("medium_confidence_staging", 0),
        "manual_review_count": statuses.get("needs_manual_review", 0),
        "blocked_count": statuses.get("blocked", 0),
        "rag_candidate_snippet_count": len(snippets),
        "knowledge_raw_import_draft_generated": True,
        "formal_knowledge_raw_modified": False,
        "pattern_bank_modified": False,
        "run_poc": False,
        "glm_called": False,
        "render": False,
        "confirmed_vulnerability": False,
        "candidate_only": True,
        "next_task_name": plan["scheduler_import_plan"]["recommended_next_task"],
    }
    dump_yaml(out / "reports" / "ingestion_review_and_import_report.yaml", obj)
    (out / "reports" / "ingestion_review_and_import_report.md").write_text(
        "# ingestion_review_and_import_v1 report\n\n"
        + md_table(["metric", "value"], [[k, v] for k, v in obj.items() if not isinstance(v, dict)])
        + "\n## confidence\n\n"
        + md_table(["confidence", "count"], [[k, v] for k, v in confidence.items()])
        + "\n## import status\n\n"
        + md_table(["import_status", "count"], [[k, v] for k, v in statuses.items()]),
        encoding="utf-8",
    )
    (out / "README.md").write_text(
        "# ingestion_review_and_import_v1\n\n"
        "Reviewed normalized PoC records and generated staging scheduler/RAG candidates. "
        "No PoCs were run, no GLM/LLM was called, no rendering was performed, and no formal Pattern Bank or knowledge_raw files were modified.\n",
        encoding="utf-8",
    )
    return obj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", required=True)
    ap.add_argument("--template-candidates", required=True)
    ap.add_argument("--scheduler-candidates", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--write-knowledge-raw", choices=["true", "false"], default="false")
    ap.add_argument("--write-pattern-bank", choices=["true", "false"], default="false")
    args = ap.parse_args()

    out = Path(args.out_dir)
    for sub in ("input", "review", "scheduler", "rag", "quality", "reports", "logs", "validation"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    if args.write_knowledge_raw != "false" or args.write_pattern_bank != "false":
        raise SystemExit("This sprint run must use --write-knowledge-raw false and --write-pattern-bank false")

    records = load_jsonl(Path(args.records))
    load_yaml(Path(args.template_candidates))
    load_yaml(Path(args.scheduler_candidates))
    write_input_summary(out, records)
    reviewed = review_records(records)
    write_quality_review(out, reviewed)
    write_scheduler(out, reviewed)
    sanity = family_sanity(records, reviewed)
    write_family_sanity(out, sanity)
    snippets = write_rag(out, records, reviewed)
    plan = write_import_plan(out, reviewed)
    report = write_report(out, records, reviewed, snippets, sanity, plan)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
