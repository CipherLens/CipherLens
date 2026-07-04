#!/usr/bin/env python3
"""Build a read-only inventory for historical crypto PoC corpora."""

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
except ImportError:  # pragma: no cover - repository normally depends on PyYAML.
    yaml = None


FILE_BUCKETS = (
    "metadata_json",
    "readme_files",
    "poc_c_files",
    "poc_dir",
    "run_sh",
    "scripts",
    "inputs",
    "logs",
    "sources",
    "notes",
    "patch_files",
    "reproduction_result",
    "version_matrix",
    "quality_report",
    "triage_report",
    "other_files",
)


def _json_load(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _first(obj: dict[str, Any], *keys: str) -> Any:
    cur: Any
    for key in keys:
        cur = obj
        ok = True
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, "", [], {}):
            return cur
    return None


def _stringify(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_stringify(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _stringify(v) for k, v in sorted(value.items())}
    return str(value)


def _rel(root: Path, path: Path) -> str:
    return str(path.relative_to(root))


def _classify_files(root: Path) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {k: [] for k in FILE_BUCKETS}
    all_files = sorted(p for p in root.rglob("*") if p.is_file())
    classified: set[Path] = set()

    def add(bucket: str, path: Path) -> None:
        buckets[bucket].append(_rel(root, path))
        classified.add(path)

    for p in all_files:
        name = p.name.lower()
        parts = {part.lower() for part in p.parts}
        suffix = p.suffix.lower()
        if name == "metadata.json":
            add("metadata_json", p)
        elif name.startswith("readme"):
            add("readme_files", p)
        elif name == "poc.c" or (suffix == ".c" and ("poc" in name or "repro" in name or "trigger" in name)):
            add("poc_c_files", p)
        elif name == "run.sh":
            add("run_sh", p)
        elif "scripts" in parts or suffix in {".sh", ".py"}:
            add("scripts", p)
        elif "inputs" in parts or "input" in name:
            add("inputs", p)
        elif "logs" in parts or suffix == ".log" or "asan" in name or "ubsan" in name:
            add("logs", p)
        elif "sources" in parts or "source" in name:
            add("sources", p)
        elif "notes" in parts or "note" in name:
            add("notes", p)
        elif suffix in {".patch", ".diff"} or "patch" in name:
            add("patch_files", p)
        elif "reproduction" in name or "repro_result" in name:
            add("reproduction_result", p)
        elif "version_matrix" in name or ("version" in name and suffix in {".json", ".yaml", ".yml", ".md"}):
            add("version_matrix", p)
        elif "quality" in name:
            add("quality_report", p)
        elif "triage" in name:
            add("triage_report", p)

    for dname in ("poc", "inputs", "logs", "sources", "scripts", "notes"):
        d = root / dname
        if d.is_dir() and dname == "poc":
            buckets["poc_dir"] = sorted(_rel(root, p) for p in d.rglob("*") if p.is_file())

    for p in all_files:
        if p not in classified:
            add("other_files", p)

    return {k: sorted(v) for k, v in buckets.items()}


def _metadata_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    source = _first(metadata, "source")
    source_url = _first(metadata, "source_url", "issue_url", "url")
    if source_url is None and isinstance(source, dict):
        source_url = _first(source, "url", "issue", "pr", "cve")

    critical = _first(
        metadata,
        "critical_api_or_function",
        "critical_apis",
        "source_api",
        "experiment_fields.source_api",
    )
    root_cause = _first(metadata, "root_cause", "annotation.root_cause", "classification.root_cause")

    return {
        "title": _stringify(_first(metadata, "title", "source.title", "annotation.title")),
        "source_url": _stringify(source_url),
        "state": _stringify(_first(metadata, "state", "source.state")),
        "has_poc": _stringify(_first(metadata, "has_poc", "dataset_status")),
        "poc_type": _stringify(_first(metadata, "poc_type", "classification.poc_type")),
        "quality": _stringify(_first(metadata, "quality", "quality_level", "classification.quality")),
        "component": _stringify(_first(metadata, "component", "source_component", "classification.component")),
        "trigger_behavior": _stringify(_first(metadata, "trigger_behavior", "bug_class", "crash_signal")),
        "affected_version": _stringify(_first(metadata, "affected_version", "affected_versions")),
        "critical_api_or_function": _stringify(critical),
        "root_cause": _stringify(root_cause),
        "reproduction_command": _stringify(_first(metadata, "reproduction_command")),
        "input_artifact": _stringify(_first(metadata, "input_artifact", "input_provenance")),
        "fix_evidence": _stringify(_first(metadata, "fix_evidence", "fix_pr_or_commit")),
        "artifact_class": _stringify(_first(metadata, "artifact_class")),
        "local_compile": _stringify(_first(metadata, "local_compile")),
        "local_run": _stringify(_first(metadata, "local_run")),
        "strict_reproduction": _stringify(_first(metadata, "strict_reproduction")),
        "tested_library": _stringify(_first(metadata, "tested_library")),
        "local_test_result": _stringify(_first(metadata, "local_test_result")),
        "input_status": _stringify(_first(metadata, "input_status", "has_original_input", "uses_placeholder_input")),
        "validation_notes": _stringify(_first(metadata, "validation_notes", "notes")),
    }


def _artifact_id(library: str, path: Path, metadata: dict[str, Any]) -> tuple[str, bool]:
    name = path.name
    if library == "mbedtls":
        m = re.search(r"MBEDTLS-POC-\d+", name)
        return (m.group(0), True) if m else (f"UNKNOWN-{name}", False)
    if library == "wolfssl":
        m = re.search(r"WOLFSSL-POC-\d+", name)
        return (m.group(0), True) if m else (f"UNKNOWN-{name}", False)
    if library == "openssl":
        issue = _first(metadata, "issue_number")
        if issue is not None:
            return f"OPENSSL-ISSUE-{issue}", True
        m = re.search(r"issue_(\d+)", name)
        return (f"OPENSSL-ISSUE-{m.group(1)}", True) if m else (f"UNKNOWN-{name}", False)
    return f"UNKNOWN-{name}", False


def _artifact_status(has_id: bool, files: dict[str, list[str]]) -> str:
    has_metadata = bool(files["metadata_json"])
    has_source = bool(files["poc_c_files"] or files["poc_dir"] or files["run_sh"] or files["scripts"] or files["inputs"])
    if not has_id:
        return "needs_manual_review"
    if has_metadata and has_source:
        return "ready_for_ingestion"
    if has_metadata and not has_source:
        return "metadata_only"
    if not has_metadata and has_source:
        return "missing_metadata"
    return "needs_manual_review"


def _notes(status: str, files: dict[str, list[str]]) -> list[str]:
    notes: list[str] = []
    if not files["metadata_json"]:
        notes.append("metadata.json missing")
    if not (files["poc_c_files"] or files["poc_dir"] or files["run_sh"] or files["scripts"] or files["inputs"]):
        notes.append("PoC source/input signal missing")
    if status == "metadata_only":
        notes.append("metadata exists but no static PoC source/input signal was found")
    return notes


def _scan_roots(mbedtls: Path, wolfssl: Path, openssl: Path) -> list[tuple[str, Path, list[Path]]]:
    roots: list[tuple[str, Path, list[Path]]] = []
    mbed_dirs = sorted(p for p in mbedtls.rglob("*") if p.is_dir() and re.fullmatch(r"MBEDTLS-POC-\d+", p.name))
    wolf_dirs = sorted(p for p in wolfssl.iterdir() if p.is_dir() and re.match(r"WOLFSSL-POC-\d+", p.name))
    openssl_dirs = sorted(p for p in openssl.iterdir() if p.is_dir() and re.match(r"issue_\d+", p.name))
    roots.append(("mbedtls", mbedtls, mbed_dirs))
    roots.append(("wolfssl", wolfssl, wolf_dirs))
    roots.append(("openssl", openssl, openssl_dirs))
    return roots


def _inventory(mbedtls: Path, wolfssl: Path, openssl: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for library, corpus_root, artifact_dirs in _scan_roots(mbedtls, wolfssl, openssl):
        for artifact in artifact_dirs:
            files = _classify_files(artifact)
            metadata = _json_load(artifact / "metadata.json") if (artifact / "metadata.json").exists() else {}
            poc_id, has_id = _artifact_id(library, artifact, metadata)
            status = _artifact_status(has_id, files)
            rows.append(
                {
                    "poc_id": poc_id,
                    "source_library": library,
                    "corpus_root": str(corpus_root),
                    "artifact_path": str(artifact),
                    "directory_name": artifact.name,
                    "artifact_files": files,
                    "metadata_summary": _metadata_summary(metadata),
                    "status": status,
                    "notes": _notes(status, files),
                }
            )
    return sorted(rows, key=lambda r: (r["source_library"], r["poc_id"], r["artifact_path"]))


def _dump_yaml(path: Path, obj: Any) -> None:
    if yaml is None:
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(v).replace("\n", " ") for v in row) + " |")
    return "\n".join(out) + "\n"


def _coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    totals = Counter(r["source_library"] for r in rows)
    statuses = Counter(r["status"] for r in rows)
    meta_found = sum(1 for r in rows if r["artifact_files"]["metadata_json"])
    source_found = sum(
        1
        for r in rows
        if r["artifact_files"]["poc_c_files"]
        or r["artifact_files"]["poc_dir"]
        or r["artifact_files"]["run_sh"]
        or r["artifact_files"]["scripts"]
        or r["artifact_files"]["inputs"]
    )
    by_library: dict[str, Any] = {}
    for lib in sorted(totals):
        subset = [r for r in rows if r["source_library"] == lib]
        by_library[lib] = {
            "total": len(subset),
            "status_counts": dict(Counter(r["status"] for r in subset)),
            "metadata_found": sum(1 for r in subset if r["artifact_files"]["metadata_json"]),
            "poc_source_found": sum(
                1
                for r in subset
                if r["artifact_files"]["poc_c_files"]
                or r["artifact_files"]["poc_dir"]
                or r["artifact_files"]["run_sh"]
                or r["artifact_files"]["scripts"]
                or r["artifact_files"]["inputs"]
            ),
        }
    return {
        "total_artifacts": len(rows),
        "library_counts": dict(totals),
        "status_counts": dict(statuses),
        "metadata_found": meta_found,
        "metadata_missing": len(rows) - meta_found,
        "poc_source_found": source_found,
        "poc_source_missing": len(rows) - source_found,
        "ready_for_ingestion": statuses.get("ready_for_ingestion", 0),
        "needs_manual_review": sum(v for k, v in statuses.items() if k != "ready_for_ingestion"),
        "by_library": by_library,
    }


def _root_status(paths: dict[str, Path]) -> dict[str, Any]:
    result = {}
    for lib, root in paths.items():
        files = [p for p in root.rglob("*") if p.is_file()] if root.exists() else []
        dirs = [p for p in root.rglob("*") if p.is_dir()] if root.exists() else []
        result[lib] = {
            "path": str(root),
            "exists": root.exists(),
            "is_dir": root.is_dir(),
            "file_count": len(files),
            "dir_count": len(dirs),
        }
    return result


def _structure_report(rows: list[dict[str, Any]], roots: dict[str, Path]) -> dict[str, Any]:
    examples = defaultdict(list)
    for r in rows:
        if len(examples[r["source_library"]]) < 5:
            examples[r["source_library"]].append(r["artifact_path"])
    return {
        "library_structures": {
            "mbedtls": {
                "root": str(roots["mbedtls"]),
                "shape": "nested core10/MBEDTLS-POC-XXXX artifacts with metadata.json, README.md, poc/ and evidence files",
                "examples": examples["mbedtls"],
            },
            "wolfssl": {
                "root": str(roots["wolfssl"]),
                "shape": "WOLFSSL-POC-XXXX evidence bundles with inputs/logs/sources/scripts/notes and richer reproduction metadata",
                "examples": examples["wolfssl"],
            },
            "openssl": {
                "root": str(roots["openssl"]),
                "shape": "flat issue_XXXXX artifacts with metadata.json, README.md, poc.c, run.sh and optional inputs",
                "examples": examples["openssl"],
            },
        },
        "ingestion_fallback_requirements": [
            "ID normalization from MBEDTLS-POC-XXXX, WOLFSSL-POC-XXXX, and issue_XXXXX/issue_number.",
            "Metadata key fallback across mbedTLS traceability/classification, wolfSSL harness/oracle fields, and OpenSSL issue artifact fields.",
            "PoC source detection must accept poc.c, poc/ directories, scripts/run.sh, and input-only evidence bundles.",
            "Do not infer vulnerability confirmation from corpus metadata; preserve strict_reproduction/local_test_result as evidence fields only.",
        ],
    }


def _write_library_views(out: Path, rows: list[dict[str, Any]]) -> None:
    names = {"mbedtls": "mbedtls_poc_inventory", "wolfssl": "wolfssl_poc_inventory", "openssl": "openssl_issue_inventory"}
    for lib, stem in names.items():
        subset = [r for r in rows if r["source_library"] == lib]
        _dump_yaml(out / "library_views" / f"{stem}.yaml", {"library": lib, "total": len(subset), "artifacts": subset})
        table = _md_table(
            ["poc_id", "status", "metadata", "source_signal", "artifact_path"],
            [
                [
                    r["poc_id"],
                    r["status"],
                    bool(r["artifact_files"]["metadata_json"]),
                    bool(r["artifact_files"]["poc_c_files"] or r["artifact_files"]["poc_dir"] or r["artifact_files"]["run_sh"] or r["artifact_files"]["scripts"] or r["artifact_files"]["inputs"]),
                    r["artifact_path"],
                ]
                for r in subset
            ],
        )
        (out / "library_views" / f"{stem}.md").write_text(f"# {lib} PoC inventory\n\nTotal: {len(subset)}\n\n{table}", encoding="utf-8")


def _write_reports(out: Path, rows: list[dict[str, Any]], roots: dict[str, Path]) -> None:
    coverage = _coverage(rows)
    structure = _structure_report(rows, roots)
    _dump_yaml(out / "reports" / "metadata_coverage_report.yaml", coverage)
    _dump_yaml(out / "reports" / "corpus_structure_comparison.yaml", structure)
    _dump_yaml(out / "reports" / "poc_corpus_inventory_report.yaml", {"generated_at": datetime.now(timezone.utc).isoformat(), **coverage})
    norm = {
        "recommendations": [
            "Keep original corpus directories immutable and ingest through adapter-specific readers.",
            "Normalize logical IDs and retain original artifact_path for traceability.",
            "Use metadata_summary plus artifact_files as ingestion input; avoid executing run.sh during ingestion.",
            "Represent missing metadata/source as review statuses instead of dropping artifacts.",
        ]
    }
    _dump_yaml(out / "reports" / "directory_normalization_recommendations.yaml", norm)

    (out / "reports" / "metadata_coverage_report.md").write_text(
        "# Metadata coverage report\n\n"
        + _md_table(
            ["metric", "value"],
            [
                ["total_artifacts", coverage["total_artifacts"]],
                ["metadata_found", coverage["metadata_found"]],
                ["metadata_missing", coverage["metadata_missing"]],
                ["poc_source_found", coverage["poc_source_found"]],
                ["poc_source_missing", coverage["poc_source_missing"]],
                ["ready_for_ingestion", coverage["ready_for_ingestion"]],
                ["needs_manual_review", coverage["needs_manual_review"]],
            ],
        ),
        encoding="utf-8",
    )
    (out / "reports" / "corpus_structure_comparison.md").write_text(
        "# Corpus structure comparison\n\n"
        + "\n".join(f"## {lib}\n\n{data['shape']}\n" for lib, data in structure["library_structures"].items())
        + "\n## Ingestion fallback requirements\n\n"
        + "\n".join(f"- {item}" for item in structure["ingestion_fallback_requirements"])
        + "\n",
        encoding="utf-8",
    )
    (out / "reports" / "directory_normalization_recommendations.md").write_text(
        "# Directory normalization recommendations\n\n" + "\n".join(f"- {x}" for x in norm["recommendations"]) + "\n",
        encoding="utf-8",
    )
    (out / "reports" / "poc_corpus_inventory_report.md").write_text(
        "# PoC corpus inventory report\n\n"
        + _md_table(
            ["library", "total", "ready_for_ingestion", "metadata_found", "poc_source_found"],
            [
                [
                    lib,
                    data["total"],
                    data["status_counts"].get("ready_for_ingestion", 0),
                    data["metadata_found"],
                    data["poc_source_found"],
                ]
                for lib, data in sorted(coverage["by_library"].items())
            ],
        ),
        encoding="utf-8",
    )


def _write_inputs(out: Path, roots: dict[str, Path]) -> None:
    constraints = {
        "task": "poc_corpus_inventory_v1",
        "scope": "read-only corpus inventory for historical PoC ingestion",
        "forbidden_actions": [
            "run PoCs",
            "compile/run harnesses",
            "call GLM/LLM",
            "modify Pattern Bank or scheduler",
            "delete/move/overwrite original artifacts",
            "commit/push/git add",
        ],
        "design_constraints": [
            "preserve traceability to original artifact_path",
            "separate corpus inventory from vulnerability confirmation",
            "keep generated inventory deterministic",
        ],
    }
    status = _root_status(roots)
    _dump_yaml(out / "input" / "project_design_constraints.yaml", constraints)
    _dump_yaml(out / "input" / "input_roots_status.yaml", status)
    (out / "input" / "project_design_constraints.md").write_text(
        "# Project design constraints\n\n" + "\n".join(f"- {x}" for x in constraints["forbidden_actions"] + constraints["design_constraints"]) + "\n",
        encoding="utf-8",
    )
    (out / "input" / "input_roots_status.md").write_text(
        "# Input roots status\n\n"
        + _md_table(["library", "path", "exists", "files", "dirs"], [[k, v["path"], v["exists"], v["file_count"], v["dir_count"]] for k, v in status.items()]),
        encoding="utf-8",
    )


def _write_ingestion_config(out: Path, roots: dict[str, Path]) -> None:
    cfg = {
        "task_name": "historical_poc_ingestion_v1",
        "input_inventory": "artifacts/sprints/poc_corpus_inventory_v1/inventory/unified_poc_corpus_inventory.json",
        "input_roots": {k: str(v) for k, v in roots.items()},
        "artifact_selectors": {
            "mbedtls": {"id_pattern": "MBEDTLS-POC-XXXX", "path_glob": "data/pocs/**/MBEDTLS-POC-*"},
            "wolfssl": {"id_pattern": "WOLFSSL-POC-XXXX", "path_glob": "data/wolfssl_collect/WOLFSSL-POC-*"},
            "openssl": {"id_pattern": "OPENSSL-ISSUE-<issue_number>", "path_glob": "datasets/openssl/poc_artifacts/issue_*"},
        },
        "ingestion_rules": [
            "Use status=ready_for_ingestion artifacts first.",
            "Preserve metadata_summary and artifact_files verbatim.",
            "Do not execute run.sh or compile poc.c during ingestion.",
            "Route metadata_only/missing_metadata/needs_manual_review to manual triage.",
        ],
    }
    _dump_yaml(out / "ingestion_config" / "historical_poc_ingestion_input_config.yaml", cfg)
    (out / "ingestion_config" / "historical_poc_ingestion_input_config.md").write_text(
        "# historical_poc_ingestion_v1 input config\n\n"
        + _md_table(["library", "root"], [[k, v] for k, v in cfg["input_roots"].items()])
        + "\n## Rules\n\n"
        + "\n".join(f"- {x}" for x in cfg["ingestion_rules"])
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mbedtls-root", required=True)
    ap.add_argument("--wolfssl-root", required=True)
    ap.add_argument("--openssl-root", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out = Path(args.out_dir)
    for sub in ("input", "inventory", "structure", "library_views", "ingestion_config", "reports", "logs", "validation"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    roots = {
        "mbedtls": Path(args.mbedtls_root),
        "wolfssl": Path(args.wolfssl_root),
        "openssl": Path(args.openssl_root),
    }
    rows = _inventory(roots["mbedtls"], roots["wolfssl"], roots["openssl"])
    coverage = _coverage(rows)

    _write_inputs(out, roots)
    _write_json(out / "inventory" / "unified_poc_corpus_inventory.json", {"artifacts": rows, "summary": coverage})
    (out / "inventory" / "unified_poc_corpus_inventory.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8"
    )
    _dump_yaml(out / "inventory" / "unified_poc_corpus_inventory.yaml", {"artifacts": rows, "summary": coverage})
    (out / "inventory" / "unified_poc_corpus_inventory.md").write_text(
        "# Unified PoC corpus inventory\n\n"
        + _md_table(["poc_id", "library", "status", "artifact_path"], [[r["poc_id"], r["source_library"], r["status"], r["artifact_path"]] for r in rows]),
        encoding="utf-8",
    )
    _write_library_views(out, rows)
    _write_reports(out, rows, roots)
    _write_ingestion_config(out, roots)
    (out / "README.md").write_text(
        "# poc_corpus_inventory_v1\n\n"
        "Read-only inventory of mbedTLS, wolfSSL, and OpenSSL historical PoC artifacts. "
        "This sprint did not run PoCs, compile harnesses, call GLM/LLM, or modify Pattern Bank data.\n",
        encoding="utf-8",
    )
    print(json.dumps(coverage, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
