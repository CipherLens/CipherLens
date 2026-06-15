#!/usr/bin/env python3
"""Read-only inventory for RAG and knowledge assets."""

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


KNOWLEDGE_TYPES = [
    "api_card",
    "api_constraint",
    "api_documentation",
    "api_usage",
    "poc_pattern",
    "issue_pattern",
    "negative_feedback",
    "cross_library_mapping",
    "adapter_recipe",
    "embedding_index",
    "rag_script",
    "collector_script",
    "unknown",
]
LIBRARIES = ["openssl", "mbedtls", "wolfssl", "botan", "generic", "unknown"]
TOP_FAMILIES = ["tls_protocol_state_lifecycle", "asn1_nested_boundary", "pkcs_container_parsing", "x509_parsing"]


def load_yaml(path: Path) -> Any:
    if yaml is None:
        return json.loads(path.read_text(encoding="utf-8"))
    return yaml.safe_load(path.read_text(encoding="utf-8"))


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


def safe_read(path: Path, limit: int = 20000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def all_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for root in paths:
        if root.exists():
            out.extend(p for p in root.rglob("*") if p.is_file())
    return sorted(out)


def classify_library(path: Path, text: str = "") -> str:
    hay = f"{path.as_posix()} {text[:1000]}".lower()
    for lib in ("openssl", "mbedtls", "wolfssl", "botan"):
        if lib in hay:
            return lib
    if "psa_" in hay:
        return "mbedtls"
    if "crypto" in hay or "api" in hay:
        return "generic"
    return "unknown"


def classify_type(path: Path) -> str:
    s = path.as_posix().lower()
    name = path.name.lower()
    if "knowledge_base/api_cards" in s or "/api_cards/" in s:
        return "api_card"
    if "api_constraints" in s:
        return "api_constraint"
    if "api_knowledge_cards" in s:
        return "api_documentation"
    if "unit_tests" in s:
        return "api_usage"
    if "poc_patterns" in s and "issue" in name:
        return "issue_pattern"
    if "poc_patterns" in s:
        return "poc_pattern"
    if "feedback" in s:
        return "negative_feedback"
    if "cross_lib_equivalence" in s or "cross_lib" in s:
        return "cross_library_mapping"
    if "adapter_recipes" in s:
        return "adapter_recipe"
    if "chroma" in s or name.endswith((".sqlite3", ".parquet", ".bin")):
        return "embedding_index"
    if "knowledge/rag_" in s or name in {"rag_builder.py", "rag_query.py"}:
        return "rag_script"
    if "knowledge_collectors" in s:
        return "collector_script"
    return "unknown"


def inventory_files(roots: list[Path], feedback_dir: Path) -> list[dict[str, Any]]:
    files = all_files(roots)
    if feedback_dir.exists():
        files.extend(sorted(p for p in feedback_dir.glob("*.jsonl") if p.is_file()))
    rows = []
    for p in sorted(set(files)):
        txt = safe_read(p, 4000) if p.suffix.lower() in {".md", ".yaml", ".yml", ".txt", ".py", ".jsonl"} else ""
        rows.append(
            {
                "path": str(p),
                "suffix": p.suffix.lower() or "<none>",
                "knowledge_type": classify_type(p),
                "library": classify_library(p, txt),
                "size_bytes": p.stat().st_size,
            }
        )
    return rows


def root_structure(roots: dict[str, Path]) -> dict[str, Any]:
    out = {}
    for name, root in roots.items():
        files = [p for p in root.rglob("*") if p.is_file()] if root.exists() else []
        dirs = [p for p in root.rglob("*") if p.is_dir()] if root.exists() else []
        out[name] = {
            "path": str(root),
            "exists": root.exists(),
            "file_count": len(files),
            "dir_count": len(dirs),
            "suffix_counts": dict(Counter(p.suffix.lower() or "<none>" for p in files)),
        }
    return out


def api_card_coverage(kb: Path, raw: Path) -> dict[str, Any]:
    paths = []
    for root in [kb / "api_cards", raw / "api_knowledge_cards"]:
        if root.exists():
            paths.extend(sorted(root.rglob("*.yaml")))
            paths.extend(sorted(root.rglob("*.yml")))
    by_lib: dict[str, list[str]] = {lib: [] for lib in ("openssl", "mbedtls", "wolfssl", "botan")}
    for p in sorted(set(paths)):
        if p.name == "schema.yaml":
            continue
        txt = safe_read(p, 4000)
        lib = classify_library(p, txt)
        if lib in by_lib:
            by_lib[lib].append(str(p))
    sparse = [lib for lib, items in by_lib.items() if len(items) < 3]
    all_names = " ".join(paths_i for items in by_lib.values() for paths_i in items).lower()
    gap_terms = {
        "tls": "tls" not in all_names and "ssl" not in all_names,
        "dtls": "dtls" not in all_names,
        "asn1": "asn1" not in all_names and "asn.1" not in all_names,
        "x509": "x509" not in all_names,
        "pkcs7": "pkcs7" not in all_names,
        "pkcs12": "pkcs12" not in all_names,
        "secure_heap": "secure" not in all_names and "secmem" not in all_names,
    }
    return {
        "api_card_coverage": {
            lib: {"count": len(items), "examples": items[:8]} for lib, items in by_lib.items()
        },
        "missing_or_sparse_libraries": sparse,
        "has_wolfssl_api_cards": bool(by_lib["wolfssl"]),
        "openssl_mbedtls_bias_note": "OpenSSL/mbedTLS cards are present and currently skew toward BN, MAC, PKEY, DER/X509 and store APIs; wolfSSL is absent.",
        "top_family_gaps": {k: v for k, v in gap_terms.items() if v},
        "needs_wolfssl_constraints": not bool(by_lib["wolfssl"]),
        "needs_top_family_api_cards": any(gap_terms.values()),
    }


def corrected_candidates(path: Path) -> list[dict[str, Any]]:
    obj = load_yaml(path)
    return obj.get("corrected_reviewed_scheduler_seed_candidates", []) if isinstance(obj, dict) else []


def poc_pattern_coverage(raw: Path, feedback_dir: Path, corrected: list[dict[str, Any]]) -> dict[str, Any]:
    poc_dir = raw / "poc_patterns"
    files = sorted(p for p in poc_dir.rglob("*") if p.is_file()) if poc_dir.exists() else []
    text = "\n".join(safe_read(p, 8000) for p in files).lower()
    known = sorted(set(re.findall(r"\b[a-z0-9]+(?:_[a-z0-9]+){1,}\b", text)))
    known_families = [f for f in known if any(x in f for x in ("lifecycle", "boundary", "parsing", "consumption", "semantic", "container", "asn1", "x509", "tls", "mac", "aead", "heap"))]
    corrected_fams = sorted(set(i.get("family") for i in corrected if i.get("family") not in {None, "needs_review"}))
    missing = [f for f in corrected_fams if f and f.lower() not in text]
    fb_files = sorted(feedback_dir.glob("*.jsonl")) if feedback_dir.exists() else []
    fb_names = [p.name for p in fb_files]
    fb_text = " ".join(fb_names).lower()
    routes = sorted(set(i.get("route_guess") for i in corrected if i.get("route_guess")))
    return {
        "poc_pattern_coverage": {
            "files": [str(p) for p in files],
            "known_families": known_families[:80],
            "feedback_files": [{"path": str(p), "lines": sum(1 for line in safe_read(p, 200000).splitlines() if line.strip())} for p in fb_files],
            "corrected_top_families": TOP_FAMILIES,
            "covered_routes": routes,
            "missing_families_from_corrected_candidates": missing,
            "top_families_have_pattern_text": {fam: fam in text for fam in TOP_FAMILIES},
            "negative_feedback_coverage": {
                "aead": "aead" in fb_text,
                "der": "der" in fb_text,
                "asn1": "asn1" in fb_text,
                "x509_seed_missing": "x509" in fb_text and "seed" in fb_text,
                "secure_heap": "secure_heap" in fb_text,
                "mac": "mac" in fb_text,
            },
            "needs_ingestion_snippet_import": bool(missing),
        }
    }


def rag_tooling_inventory(knowledge_dir: Path, collectors_dir: Path) -> dict[str, Any]:
    builder = knowledge_dir / "rag_builder.py"
    query = knowledge_dir / "rag_query.py"
    btxt = safe_read(builder, 40000)
    qtxt = safe_read(query, 40000)
    collector_files = sorted(str(p) for p in collectors_dir.rglob("*") if p.is_file()) if collectors_dir.exists() else []
    return {
        "rag_builder": {
            "path": str(builder),
            "exists": builder.exists(),
            "loads": {
                "api_constraints": "api_constraints" in btxt,
                "unit_tests": "unit_tests" in btxt,
                "poc_patterns": "poc_patterns" in btxt,
                "cross_lib_equivalence": "cross_lib_equivalence" in btxt,
                "wycheproof_vectors": "wycheproof" in btxt.lower(),
                "api_cards": "load_api_cards_layer" in btxt,
            },
            "supports_ingested_poc_patterns_md": "poc_patterns" in btxt and ".md" in btxt,
        },
        "rag_query": {
            "path": str(query),
            "exists": query.exists(),
            "cli_flags": {
                "--query": "--query" in qtxt,
                "--top-k": "--top-k" in qtxt,
                "--json": "--json" in qtxt,
            },
            "rerank_features": {
                "api_tokens": "query_api_tokens" in qtxt,
                "family_terms": "query_families" in qtxt,
                "library_match": "library_match" in qtxt,
                "api_cards_bonus": "layer:api_cards" in qtxt,
                "feedback_bonus": "recent_feedback_source" in qtxt,
            },
        },
        "knowledge_collectors": {
            "exists": collectors_dir.exists(),
            "files": collector_files,
            "needs_new_collector": not collector_files,
            "recommendation": "Current builder can index files written under configured knowledge_raw layers; collector is optional unless automated source harvesting is needed.",
        },
    }


def write_project_summary(out: Path) -> None:
    obj = {
        "rag_position": "RAG supplies structured evidence for candidate API mapping, adapter/recipe decisions, route planning, scheduler ranking, and feedback-aware triage.",
        "llm_position": "GLM/LLM should fill structured adapters/slot_bindings after evidence is collected; it should not generate raw C harnesses.",
        "why_not_bulk_poc_import": "Unaudited raw PoCs/logs/HTML can introduce noisy, duplicate, or misleading evidence and blur safe/bug/triage distinctions.",
        "rag_serves_modules": ["candidate_mapper", "adapter_filler", "route_planner", "auto_scheduler", "feedback analysis"],
    }
    dump_yaml(out / "input" / "project_rag_design_summary.yaml", obj)
    (out / "input" / "project_rag_design_summary.md").write_text(
        "# project RAG design summary\n\n" + "\n".join(f"- {k}: {v}" for k, v in obj.items()) + "\n",
        encoding="utf-8",
    )


def write_structure(out: Path, structure: dict[str, Any]) -> None:
    dump_yaml(out / "structure" / "rag_structure_summary.yaml", structure)
    (out / "structure" / "rag_structure_summary.md").write_text(
        "# RAG structure summary\n\n"
        + md_table(["root", "exists", "files", "dirs"], [[k, v["exists"], v["file_count"], v["dir_count"]] for k, v in structure.items()]),
        encoding="utf-8",
    )


def write_type_inventory(out: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    kt = Counter(r["knowledge_type"] for r in rows)
    lib = Counter(r["library"] for r in rows)
    matrix = defaultdict(Counter)
    for r in rows:
        matrix[r["knowledge_type"]][r["library"]] += 1
    obj = {
        "knowledge_type_counts": {k: kt.get(k, 0) for k in KNOWLEDGE_TYPES},
        "library_counts": {k: lib.get(k, 0) for k in LIBRARIES},
        "knowledge_type_by_library": {k: dict(v) for k, v in sorted(matrix.items())},
        "items": rows,
    }
    dump_yaml(out / "classification" / "knowledge_type_inventory.yaml", obj)
    (out / "classification" / "knowledge_type_inventory.md").write_text(
        "# knowledge type inventory\n\n"
        + md_table(["type", "count"], [[k, kt.get(k, 0)] for k in KNOWLEDGE_TYPES])
        + "\n## library\n\n"
        + md_table(["library", "count"], [[k, lib.get(k, 0)] for k in LIBRARIES]),
        encoding="utf-8",
    )
    return obj


def write_api_coverage(out: Path, cov: dict[str, Any]) -> None:
    dump_yaml(out / "coverage" / "api_card_coverage.yaml", cov)
    rows = [[lib, data["count"], ", ".join(Path(x).name for x in data["examples"][:5])] for lib, data in cov["api_card_coverage"].items()]
    (out / "coverage" / "api_card_coverage.md").write_text(
        "# API card coverage\n\n"
        + md_table(["library", "count", "examples"], rows)
        + "\n"
        + md_table(["signal", "value"], [["has_wolfssl_api_cards", cov["has_wolfssl_api_cards"]], ["missing_or_sparse_libraries", cov["missing_or_sparse_libraries"]], ["top_family_gaps", cov["top_family_gaps"]]]),
        encoding="utf-8",
    )


def write_poc_coverage(out: Path, cov: dict[str, Any]) -> None:
    dump_yaml(out / "coverage" / "poc_pattern_coverage.yaml", cov)
    c = cov["poc_pattern_coverage"]
    (out / "coverage" / "poc_pattern_coverage.md").write_text(
        "# PoC pattern / feedback coverage\n\n"
        + md_table(["metric", "value"], [["pattern_files", len(c["files"])], ["known_families", len(c["known_families"])], ["feedback_files", len(c["feedback_files"])], ["missing_families", c["missing_families_from_corrected_candidates"]], ["needs_ingestion_snippet_import", c["needs_ingestion_snippet_import"]]])
        + "\n## top family pattern coverage\n\n"
        + md_table(["family", "covered"], [[k, v] for k, v in c["top_families_have_pattern_text"].items()]),
        encoding="utf-8",
    )


def write_tooling(out: Path, inv: dict[str, Any]) -> None:
    dump_yaml(out / "inventory" / "rag_tooling_inventory.yaml", inv)
    (out / "inventory" / "rag_tooling_inventory.md").write_text(
        "# RAG tooling inventory\n\n"
        + md_table(["builder layer", "supported"], [[k, v] for k, v in inv["rag_builder"]["loads"].items()])
        + "\n## query flags\n\n"
        + md_table(["flag", "supported"], [[k, v] for k, v in inv["rag_query"]["cli_flags"].items()])
        + "\n## collectors\n\n"
        + md_table(["field", "value"], [[k, v] for k, v in inv["knowledge_collectors"].items() if k != "files"]),
        encoding="utf-8",
    )


def promefuzz_mapping(api_cov: dict[str, Any], poc_cov: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    gaps = api_cov.get("top_family_gaps", {})
    missing = poc_cov["poc_pattern_coverage"]["missing_families_from_corrected_candidates"]
    return {
        "promefuzz_mapping": {
            "code_metadata_knowledge": {
                "current_project_sources": ["AST-sister / ast_mask_report", "normalized_poc_records", "api_call_sequence"],
                "current_gap": "No single indexed layer yet combines corrected family, API call sequence, and mask units.",
                "recommended_next_artifacts": ["ingested structured PoC summaries", "API correlation inventory", "selected_mask_units summaries"],
            },
            "documentation_knowledge": {
                "current_project_sources": ["knowledge_raw", "knowledge_base/api_cards", "docs"],
                "current_gap": f"API card gaps for top families: {sorted(gaps)}",
                "recommended_next_artifacts": ["wolfSSL API cards", "TLS/DTLS/ASN.1/PKCS/X509 constraints", "secure heap API cards"],
            },
            "api_correlation_knowledge": {
                "current_project_sources": ["critical_api_or_function", "PoC call sequence", "selected_mask_units", "scheduler feedback"],
                "current_gap": "Cross-library correlations are not yet explicit for corrected TLS/ASN.1/PKCS top families.",
                "recommended_next_artifacts": ["api_correlation_inventory_v1", "cross-library API equivalence notes"],
            },
            "sanitizer_feedback_knowledge": {
                "current_project_sources": ["analyze_results", "feedback jsonl", "negative feedback"],
                "current_gap": f"Corrected candidate missing families in PoC pattern text: {missing}",
                "recommended_next_artifacts": ["negative feedback summaries", "blocked seed down-ranking evidence"],
            },
        }
    }


def enrichment_plan(api_cov: dict[str, Any]) -> dict[str, Any]:
    return {
        "rag_enrichment_plan_after_inventory": [
            {"step": 1, "task": "rag_enrichment_from_ingestion_v1", "action": "Import only high-confidence structured PoC summaries."},
            {"step": 2, "task": "api_card_enrichment_for_top_families_v1", "action": "Add wolfSSL / TLS / DTLS / ASN.1 / PKCS7 / PKCS12 / X509 API cards."},
            {"step": 3, "task": "api_correlation_inventory_v1", "action": "Extract API correlation from corrected candidates and PoC call sequences."},
            {"step": 4, "task": "rag_rebuild_and_query_eval_v1", "action": "Rebuild and evaluate whether queries retrieve correct evidence."},
            {"step": 5, "task": "template_schema_inventory_v1", "action": "Inventory template schemas before template generation."},
        ],
        "principles": [
            "Do not import all raw PoCs, raw HTML, or raw logs.",
            "Import structured summaries only.",
            "Mark placeholder, synthetic, and source-vector seed provenance.",
            "Import negative feedback as down-ranking evidence.",
            "RAG supports gates and adapters; it does not replace analyzers.",
        ],
        "needs_wolfssl_constraints": api_cov["needs_wolfssl_constraints"],
        "needs_top_family_api_cards": api_cov["needs_top_family_api_cards"],
    }


def next_action(api_cov: dict[str, Any], poc_cov: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    builder_ok = bool(tool["rag_builder"]["loads"].get("poc_patterns")) and bool(tool["rag_builder"]["loads"].get("api_cards"))
    missing_top = bool(poc_cov["poc_pattern_coverage"]["missing_families_from_corrected_candidates"])
    if not builder_ok:
        task = "rag_builder_source_integration_v1"
        why = "RAG builder lacks required source support."
    elif api_cov["needs_wolfssl_constraints"] or api_cov["needs_top_family_api_cards"]:
        task = "api_card_enrichment_for_top_families_v1"
        why = "API cards are sparse for wolfSSL/top parser-protocol families."
    elif missing_top:
        task = "rag_enrichment_from_ingestion_v1"
        why = "Corrected top families are not fully represented in PoC pattern knowledge."
    else:
        task = "template_schema_inventory_v1"
        why = "Top corrected families appear covered enough to inventory template schemas."
    return {"next_task_name": task, "why": why, "builder_support_ok": builder_ok, "missing_top_families": missing_top}


def write_report(out: Path, structure: dict[str, Any], type_inv: dict[str, Any], api_cov: dict[str, Any], poc_cov: dict[str, Any], prom: dict[str, Any], plan: dict[str, Any], nxt: dict[str, Any]) -> None:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root_summary": structure,
        "knowledge_type_counts": type_inv["knowledge_type_counts"],
        "library_counts": type_inv["library_counts"],
        "api_card_coverage": api_cov["api_card_coverage"],
        "has_wolfssl_related_knowledge": type_inv["library_counts"].get("wolfssl", 0) > 0,
        "missing_or_sparse_libraries": api_cov["missing_or_sparse_libraries"],
        "top_family_gaps": api_cov["top_family_gaps"],
        "poc_pattern_missing_families": poc_cov["poc_pattern_coverage"]["missing_families_from_corrected_candidates"],
        "promefuzz_mapping_keys": list(prom["promefuzz_mapping"].keys()),
        "rag_modified": False,
        "rag_rebuilt": False,
        "glm_called": False,
        "next_task_name": nxt["next_task_name"],
    }
    dump_yaml(out / "reports" / "rag_knowledge_inventory_report.yaml", report)
    (out / "reports" / "rag_knowledge_inventory_report.md").write_text(
        "# rag_knowledge_inventory_v1 report\n\n"
        + md_table(["root", "files", "dirs"], [[k, v["file_count"], v["dir_count"]] for k, v in structure.items()])
        + "\n## knowledge types\n\n"
        + md_table(["type", "count"], [[k, v] for k, v in type_inv["knowledge_type_counts"].items()])
        + "\n## next action\n\n"
        + md_table(["field", "value"], [[k, v] for k, v in nxt.items()]),
        encoding="utf-8",
    )
    (out / "README.md").write_text(
        "# rag_knowledge_inventory_v1\n\n"
        "Read-only inventory of RAG/knowledge assets. No knowledge_raw/knowledge_base writes, no RAG rebuild, no GLM, no PoC execution, and no template generation occurred.\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--knowledge-dir", required=True)
    ap.add_argument("--knowledge-base-dir", required=True)
    ap.add_argument("--knowledge-collectors-dir", required=True)
    ap.add_argument("--knowledge-raw-dir", required=True)
    ap.add_argument("--feedback-dir", required=True)
    ap.add_argument("--corrected-candidates", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out = Path(args.out_dir)
    for sub in ("input", "structure", "inventory", "coverage", "classification", "reports", "logs", "validation"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    roots = {
        "knowledge": Path(args.knowledge_dir),
        "knowledge_base": Path(args.knowledge_base_dir),
        "knowledge_collectors": Path(args.knowledge_collectors_dir),
        "knowledge_raw": Path(args.knowledge_raw_dir),
    }
    feedback = Path(args.feedback_dir)
    corrected = corrected_candidates(Path(args.corrected_candidates))
    write_project_summary(out)
    structure = root_structure(roots)
    write_structure(out, structure)
    rows = inventory_files(list(roots.values()), feedback)
    type_inv = write_type_inventory(out, rows)
    api_cov = api_card_coverage(roots["knowledge_base"], roots["knowledge_raw"])
    write_api_coverage(out, api_cov)
    poc_cov = poc_pattern_coverage(roots["knowledge_raw"], feedback, corrected)
    write_poc_coverage(out, poc_cov)
    tool = rag_tooling_inventory(roots["knowledge"], roots["knowledge_collectors"])
    write_tooling(out, tool)
    prom = promefuzz_mapping(api_cov, poc_cov, tool)
    dump_yaml(out / "reports" / "promefuzz_mapping_recommendations.yaml", prom)
    (out / "reports" / "promefuzz_mapping_recommendations.md").write_text(
        "# PromeFuzz mapping recommendations\n\n"
        + "\n".join(f"## {k}\n\n- current_gap: {v['current_gap']}\n- recommended_next_artifacts: {v['recommended_next_artifacts']}\n" for k, v in prom["promefuzz_mapping"].items()),
        encoding="utf-8",
    )
    plan = enrichment_plan(api_cov)
    dump_yaml(out / "reports" / "rag_enrichment_plan_after_inventory.yaml", plan)
    (out / "reports" / "rag_enrichment_plan_after_inventory.md").write_text(
        "# RAG enrichment plan after inventory\n\n"
        + md_table(["step", "task", "action"], [[x["step"], x["task"], x["action"]] for x in plan["rag_enrichment_plan_after_inventory"]])
        + "\n## principles\n\n"
        + "\n".join(f"- {p}" for p in plan["principles"])
        + "\n",
        encoding="utf-8",
    )
    nxt = next_action(api_cov, poc_cov, tool)
    dump_yaml(out / "reports" / "next_action_after_rag_inventory.yaml", nxt)
    (out / "reports" / "next_action_after_rag_inventory.md").write_text(
        "# next action after RAG inventory\n\n" + md_table(["field", "value"], [[k, v] for k, v in nxt.items()]),
        encoding="utf-8",
    )
    write_report(out, structure, type_inv, api_cov, poc_cov, prom, plan, nxt)
    print(json.dumps({"next_task_name": nxt["next_task_name"], "knowledge_type_counts": type_inv["knowledge_type_counts"], "library_counts": type_inv["library_counts"], "top_family_gaps": api_cov["top_family_gaps"]}, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
