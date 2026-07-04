#!/usr/bin/env python3
"""Inventory existing template schemas without generating or mutating templates."""

from __future__ import annotations

import argparse
import collections
from pathlib import Path
from typing import Any

import yaml


TOP_FAMILIES = [
    "tls_protocol_state_lifecycle",
    "x509_parsing",
    "secure_heap_state_lifecycle",
    "asn1_nested_boundary",
    "pkcs_container_parsing",
]

PRIORITY_POCS = ["WOLFSSL-POC-0007", "WOLFSSL-POC-0006", "WOLFSSL-POC-0004"]

KEY_TEMPLATE_FILES = [
    "poc_original.c",
    "template_meta.yaml",
    "mask_report.yaml",
    "ast_mask_report.yaml",
    "selected_mask_units.yaml",
]

OUTPUTS = {
    "input": "input/template_inventory_input_summary",
    "structure": "structure/template_directory_inventory",
    "schema": "schema/template_schema_summary",
    "examples": "examples/template_examples_summary",
    "coverage": "coverage/template_family_coverage",
    "candidates": "candidates/template_generalizer_candidate_selection",
    "plan": "reports/template_generalizer_v1_plan",
    "next": "reports/next_action_after_template_inventory",
    "report": "reports/template_schema_inventory_report",
}


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # keep inventory robust on partial artifacts
        return {"_load_error": str(exc)}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def dump_md(path: Path, title: str, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", ""]
    lines.extend(render_md(data))
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def render_md(data: Any, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{pad}- {key}:")
                lines.extend(render_md(value, indent + 1))
            else:
                lines.append(f"{pad}- {key}: {value}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.extend(render_md(item, indent + 1))
            else:
                lines.append(f"{pad}- {item}")
    else:
        lines.append(f"{pad}- {data}")
    return lines


def is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def top_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(k) for k in value.keys())
    return []


def key_union(items: list[Any]) -> list[str]:
    keys: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            keys.update(str(k) for k in item.keys())
    return sorted(keys)


def nested_items(data: Any, names: list[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in names:
                    for item in as_list(value):
                        if isinstance(item, dict):
                            found.append(item)
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return found


def unique_values(items: list[dict[str, Any]], field_names: list[str]) -> list[str]:
    values: set[str] = set()
    for item in items:
        for field in field_names:
            value = item.get(field)
            if isinstance(value, (str, int, float, bool)):
                values.add(str(value))
    return sorted(values)


def find_files(root: Path, name: str) -> list[Path]:
    if not root.exists():
        return []
    return sorted(p for p in root.rglob(name) if p.is_file())


def find_yaml_files(root: Path, patterns: list[str]) -> list[Path]:
    if not root.exists():
        return []
    files: list[Path] = []
    for pattern in patterns:
        files.extend(p for p in root.rglob(pattern) if p.is_file())
    return sorted(set(files))


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def scalar_at(data: Any, path: list[str]) -> Any:
    cur = data
    for part in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def first_scalar(data: Any, paths: list[list[str]], default: str = "") -> str:
    for path in paths:
        value = scalar_at(data, path)
        if isinstance(value, (str, int, float, bool)):
            return str(value)
        if isinstance(value, list) and value:
            return ", ".join(str(x) for x in value[:4])
    return default


def collect_template_dirs(roots: list[Path]) -> list[Path]:
    dirs: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for name in KEY_TEMPLATE_FILES:
            for file_path in find_files(root, name):
                dirs.add(file_path.parent)
        for tmpl in root.rglob("tmpl_*.c"):
            if tmpl.is_file():
                dirs.add(tmpl.parent)
    return sorted(dirs)


def file_presence(template_dir: Path) -> dict[str, bool]:
    return {
        "poc_original_c": (template_dir / "poc_original.c").exists(),
        "tmpl_c": any(template_dir.glob("tmpl_*.c")),
        "template_meta_yaml": (template_dir / "template_meta.yaml").exists(),
        "mask_report_yaml": (template_dir / "mask_report.yaml").exists(),
        "ast_mask_report_yaml": (template_dir / "ast_mask_report.yaml").exists(),
        "selected_mask_units_yaml": (template_dir / "selected_mask_units.yaml").exists(),
        "adapter_yaml": (template_dir / "adapter.yaml").exists(),
    }


def read_template_meta(template_dir: Path) -> dict[str, Any]:
    data = load_yaml(template_dir / "template_meta.yaml")
    return data if isinstance(data, dict) else {}


def template_family(meta: dict[str, Any], template_dir: Path) -> str:
    for field in ("family", "harness_family", "vulnerability_class", "source_component"):
        value = meta.get(field)
        if isinstance(value, str):
            return value
    operation = meta.get("operation")
    if isinstance(operation, dict):
        for field in ("abstract", "api_family"):
            if isinstance(operation.get(field), str):
                return str(operation[field])
    parts = template_dir.parts
    if "normalized_templates" in parts:
        idx = parts.index("normalized_templates")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "unknown"


def summarize_directory(path: Path) -> dict[str, Any]:
    exists = path.exists()
    files = sorted(p for p in path.rglob("*") if p.is_file()) if exists else []
    return {
        "path": str(path),
        "exists": exists,
        "file_count": len(files),
        "key_file_count": sum(
            1
            for p in files
            if p.name in KEY_TEMPLATE_FILES or p.name.startswith("tmpl_") or p.name.startswith("adapter")
        ),
        "sample_files": [rel(p) for p in files[:12]],
    }


def schema_for_files(files: list[Path], item_names: list[str]) -> dict[str, Any]:
    loaded = [load_yaml(p) for p in files]
    docs = [d for d in loaded if isinstance(d, dict)]
    items: list[dict[str, Any]] = []
    for doc in docs:
        items.extend(nested_items(doc, item_names))
    return {
        "observed_files": len(files),
        "sample_files": [rel(p) for p in files[:12]],
        "observed_fields": sorted({k for doc in docs for k in top_keys(doc)}),
        "item_fields": key_union(items),
        "slot_types": unique_values(items, ["type", "mutation_type", "mask_level", "kind", "role"]),
        "priorities": unique_values(items, ["priority"]),
    }


def schema_summary(args: argparse.Namespace) -> dict[str, Any]:
    normalized = Path(args.normalized_templates)
    artifacts = Path("artifacts")
    adapter_roots = [Path(args.adapter_recipes), artifacts]
    template_meta = find_files(normalized, "template_meta.yaml") + find_files(artifacts, "template_meta.yaml")
    mask_report = find_files(normalized, "mask_report.yaml") + find_files(artifacts, "mask_report.yaml")
    ast_report = find_files(normalized, "ast_mask_report.yaml") + find_files(artifacts, "ast_mask_report.yaml")
    selected_units = find_files(normalized, "selected_mask_units.yaml") + find_files(artifacts, "selected_mask_units.yaml")
    adapters = []
    for root in adapter_roots:
        adapters.extend(find_yaml_files(root, ["adapter.yaml", "adapter*.yaml", "*.recipe.yaml"]))
    adapter_docs = [d for d in (load_yaml(p) for p in adapters) if isinstance(d, dict)]
    adapter_slot_items = []
    for doc in adapter_docs:
        adapter_slot_items.extend(nested_items(doc, ["slot_bindings", "allowed_slots", "type_mapping", "constant_mapping"]))

    meta_schema = schema_for_files(template_meta, ["mutation_points", "mask_slots"])
    mask_schema = schema_for_files(mask_report, ["mask_units", "mutation_points", "roles"])
    ast_schema = schema_for_files(ast_report, ["ast_mask_units", "ast_units", "nodes"])
    selected_schema = schema_for_files(selected_units, ["selected_units"])
    return {
        "template_meta_schema": {
            **meta_schema,
            "required_fields_guess": [
                "template_id",
                "pattern_id",
                "source_library/source_api",
                "harness_family",
                "oracle_type",
                "mutation_points or mask_slots",
                "oracle or safe_behavior/bug_behavior",
            ],
            "family_fields": ["family", "harness_family", "operation.abstract", "vulnerability_class"],
            "source_library_fields": ["source_library", "source_api.library", "poc_source.library"],
            "target_library_fields": ["target_library appears mainly in adapters/cross templates"],
            "oracle_fields": ["oracle_type", "oracle", "safe_behavior", "bug_behavior", "triage_behavior", "verdict"],
            "mutation_slot_fields": ["mutation_points", "mask_slots", "name/slot", "type", "default", "values/variants"],
            "seed_input_fields": ["poc_source", "source_api", "source_component", "pattern_id"],
            "notes": "Observed schemas are heterogeneous; canonicalization should preserve both mutation_points and mask_slots while normalizing them to slot records.",
        },
        "mask_report_schema": {
            **mask_schema,
            "mask_unit_fields": mask_schema["item_fields"],
            "mutation_related_fields": ["placeholder", "mutation_name", "mutation_type", "values", "variants", "reason"],
            "notes": "mask_report.yaml mixes role maps, mask_units lists, and embedded PoC pattern evidence.",
        },
        "ast_mask_report_schema": {
            **ast_schema,
            "ast_unit_types": ast_schema["slot_types"],
            "supported_node_types": ast_schema["slot_types"],
            "notes": "AST-lite reports use ast_mask_units, ast_units, or ast_analysis.nodes depending on generation vintage.",
        },
        "selected_mask_units_schema": {
            **selected_schema,
            "selected_units": selected_schema["item_fields"],
            "confidence_fields": ["priority", "selection_score", "selection_reason", "suggested_use", "selected"],
            "notes": "Selection files are the clearest input for mutation slot prioritization.",
        },
        "adapter_schema": {
            "observed_files": len(adapters),
            "sample_files": [rel(p) for p in sorted(adapters)[:16]],
            "observed_fields": sorted({k for doc in adapter_docs for k in top_keys(doc)}),
            "slot_bindings": key_union(adapter_slot_items),
            "api_mapping": [
                "target_library",
                "target_api",
                "source_api",
                "type_mapping",
                "constant_mapping",
                "slot_bindings",
            ],
            "cleanup_mapping": ["cleanup_block", "cleanup_mapping_hint", "fixed_cleanup_sequence", "objects"],
            "oracle_mapping": ["oracle_type", "oracle_strategy", "safe_behavior", "bug_behavior", "return_value_semantics"],
            "validation_fields": ["validation", "status", "errors", "warnings", "_adapter_mode", "_llm_status"],
            "notes": "Recipe-slot adapters should keep LLM output constrained to slot_bindings; free-form block fields are legacy or manually repaired artifacts.",
        },
    }


def load_list_container(path: Path, keys: list[str]) -> list[dict[str, Any]]:
    data = load_yaml(path)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
    return []


def input_summary(args: argparse.Namespace) -> dict[str, Any]:
    input_paths = {
        "mapping_report": "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/reports/cross_library_mapping_refinement_and_gate_report.yaml",
        "adapter_ready": "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/adapter_ready/adapter_ready_mapping_candidates.yaml",
        "blocked_mappings": "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/blocked_mappings/blocked_or_no_direct_counterpart_mappings.yaml",
        "rag_report": "artifacts/sprints/rag_rebuild_and_query_eval_v2/reports/rag_rebuild_and_query_eval_v2_report.yaml",
        "rag_query_eval_summary": "artifacts/sprints/rag_rebuild_and_query_eval_v2/query_eval/query_eval_v2_summary.yaml",
        "corrected_candidates": "artifacts/sprints/manual_review_family_corrections_v1/scheduler/corrected_reviewed_scheduler_seed_candidates.yaml",
        "corrected_family_distribution": "artifacts/sprints/manual_review_family_corrections_v1/corrections/corrected_family_distribution.yaml",
    }
    loaded = {name: load_yaml(Path(path)) for name, path in input_paths.items()}
    ready = load_list_container(Path(args.adapter_ready), ["adapter_ready_mapping_candidates", "items", "mappings"])
    corrected = load_list_container(Path(args.corrected_candidates), ["corrected_reviewed_scheduler_seed_candidates", "items", "candidates"])
    family_counts = collections.Counter(str(x.get("family", "unknown")) for x in ready)
    candidate_counts = collections.Counter(str(x.get("family", "unknown")) for x in corrected)
    return {
        "input_paths": {
            name: {"path": path, "exists": Path(path).exists(), "loaded": loaded[name] is not None}
            for name, path in input_paths.items()
        },
        "adapter_ready_mapping_count": len(ready),
        "adapter_ready_family_counts": dict(sorted(family_counts.items())),
        "corrected_candidate_count": len(corrected),
        "corrected_candidate_family_counts": dict(sorted(candidate_counts.items())),
        "top_families": TOP_FAMILIES,
        "interpretation": [
            "adapter-ready mappings are sufficient to enter the template inventory stage",
            "existing template directories must be read before generalization to avoid schema incompatibility",
            "priority families are driven by corrected candidates, mapping gate, and RAG evaluation",
            "this sprint performs schema inventory only; it does not generate new templates",
        ],
    }


def directory_inventory(args: argparse.Namespace) -> dict[str, Any]:
    roots = {
        "normalized_templates": Path(args.normalized_templates),
        "templates": Path(args.templates),
        "enriched_templates": Path(args.enriched_templates),
        "generated_templates": Path(args.generated_templates),
        "adapter_recipes": Path(args.adapter_recipes),
        "migration_candidates": Path(args.migration_candidates),
        "template_maker": Path(args.template_maker),
    }
    template_dirs = collect_template_dirs(
        [roots["normalized_templates"], roots["templates"], roots["enriched_templates"], roots["generated_templates"], Path("artifacts")]
    )
    by_family: dict[str, list[str]] = collections.defaultdict(list)
    for tdir in template_dirs:
        meta = read_template_meta(tdir)
        by_family[template_family(meta, tdir)].append(rel(tdir))
    return {
        "directories": {name: summarize_directory(path) for name, path in roots.items()},
        "template_directories": {
            "count": len(template_dirs),
            "by_family": {fam: sorted(paths)[:50] for fam, paths in sorted(by_family.items())},
            "sample": [rel(p) for p in template_dirs[:40]],
        },
    }


def extract_slots(meta: dict[str, Any], mask: dict[str, Any], selected: dict[str, Any]) -> list[str]:
    slots: set[str] = set()
    for item in as_list(meta.get("mutation_points")) + as_list(meta.get("mask_slots")):
        if isinstance(item, dict):
            value = item.get("name") or item.get("slot")
            if value:
                slots.add(str(value))
    for item in nested_items(mask, ["mask_units", "mutation_points"]):
        value = item.get("unit_id") or item.get("name") or item.get("slot") or item.get("mutation_name")
        if value:
            slots.add(str(value))
    for item in as_list(selected.get("selected_units")):
        if isinstance(item, dict):
            value = item.get("mutation_name") or item.get("name") or item.get("slot") or item.get("unit_id")
            if value:
                slots.add(str(value))
    return sorted(slots)


def _template_status(paths: list[str]) -> str:
    return "available" if paths else "missing_or_needs_review"


def _family_matches(value: Any, family: str, path: Path | None = None) -> bool:
    if isinstance(value, str) and value == family:
        return True
    if path is not None:
        text = rel(path).lower()
        if family.lower() in text or family.replace("_", "-").lower() in text:
            return True
    return False


def _template_record_for_dir(template_dir: Path) -> dict[str, Any]:
    meta = read_template_meta(template_dir)
    mask = load_yaml(template_dir / "mask_report.yaml") if (template_dir / "mask_report.yaml").exists() else {}
    selected_units = load_yaml(template_dir / "selected_mask_units.yaml") if (template_dir / "selected_mask_units.yaml").exists() else {}
    if not isinstance(mask, dict):
        mask = {}
    if not isinstance(selected_units, dict):
        selected_units = {}
    return {
        "path": rel(template_dir),
        "framework_family": template_family(meta, template_dir),
        "template_id": str(meta.get("template_id", "")),
        "pattern_id": str(meta.get("pattern_id") or meta.get("source_poc") or ""),
        "harness_shape": first_scalar(meta, [["harness_family"], ["operation", "abstract"], ["operation", "api_family"]], ""),
        "mutation_slots": extract_slots(meta, mask, selected_units),
        "oracle_expectation": first_scalar(meta, [["oracle_type"], ["oracle", "type"], ["safe_behavior", "condition"], ["bug_behavior", "condition"]], ""),
    }


def build_template_pack(
    repo_root: Path,
    selected_families: list[str],
    generated_by: str = "template_usage_audit_and_manual_glm_handoff_v1",
) -> dict[str, Any]:
    """Build a small template pack from existing normalized templates and recipes.

    This is intentionally read-only. It records concrete existing paths and marks
    missing families for human review instead of inventing templates.
    """
    repo_root = repo_root.resolve()
    normalized_root = repo_root / "normalized_templates"
    adapter_root = repo_root / "adapter_recipes"
    template_dirs = collect_template_dirs([normalized_root])
    recipes = find_yaml_files(adapter_root, ["*.yaml"])

    template_records = [_template_record_for_dir(path) for path in template_dirs]
    recipe_records = []
    for recipe_path in recipes:
        data = load_yaml(recipe_path)
        data = data if isinstance(data, dict) else {}
        recipe_records.append(
            {
                "path": rel(recipe_path),
                "harness_family": str(data.get("harness_family", "")),
                "target_library": str(data.get("target_library", "")),
                "target_api": str(data.get("target_api", "")),
            }
        )

    sources = []
    for family in selected_families:
        templates = [
            item
            for item in template_records
            if _family_matches(item.get("framework_family"), family, Path(item["path"]))
            or _family_matches(item.get("harness_shape"), family, Path(item["path"]))
        ]
        recipe_hits = [
            item
            for item in recipe_records
            if _family_matches(item.get("harness_family"), family, Path(item["path"]))
            or _family_matches(item.get("path"), family)
        ]
        concrete_patterns = sorted(
            {
                value
                for item in templates
                for value in [item.get("pattern_id"), item.get("template_id")]
                if value
            }
        )
        sources.append(
            {
                "framework_family": family,
                "template_status": _template_status([item["path"] for item in templates]),
                "normalized_template_paths": sorted(item["path"] for item in templates),
                "adapter_recipe_paths": sorted(item["path"] for item in recipe_hits),
                "concrete_patterns": concrete_patterns,
                "harness_shape": sorted({item.get("harness_shape", "") for item in templates if item.get("harness_shape")}),
                "mutation_slots": sorted({slot for item in templates for slot in item.get("mutation_slots", [])}),
                "oracle_expectation": sorted({item.get("oracle_expectation", "") for item in templates if item.get("oracle_expectation")}),
                "needs_human_review": not templates,
                "evidence_note": "template evidence is from normalized_templates; recipe evidence is from adapter_recipes",
            }
        )

    return {
        "schema": "template_pack_v1",
        "generated_by": generated_by,
        "status": "draft",
        "source_dirs": ["normalized_templates", "adapter_recipes"],
        "selected_families": selected_families,
        "template_sources": sources,
        "audit_observation": (
            "normalized_templates currently observed but not fully connected to stage-based runtime path."
        ),
    }


def template_examples(args: argparse.Namespace) -> dict[str, Any]:
    roots = [Path(args.normalized_templates), Path("artifacts/migrations")]
    template_dirs = collect_template_dirs(roots)
    scored: list[tuple[int, Path]] = []
    for tdir in template_dirs:
        meta = read_template_meta(tdir)
        family = template_family(meta, tdir)
        score = 0
        if family in TOP_FAMILIES:
            score += 100
        if file_presence(tdir)["selected_mask_units_yaml"]:
            score += 10
        if file_presence(tdir)["ast_mask_report_yaml"]:
            score += 10
        if "wolf" in str(tdir).lower():
            score += 15
        scored.append((score, tdir))
    selected = [tdir for _, tdir in sorted(scored, key=lambda x: (-x[0], rel(x[1])))[:8]]
    examples = []
    for idx, tdir in enumerate(selected, 1):
        meta = read_template_meta(tdir)
        mask = load_yaml(tdir / "mask_report.yaml") if (tdir / "mask_report.yaml").exists() else {}
        selected_units = load_yaml(tdir / "selected_mask_units.yaml") if (tdir / "selected_mask_units.yaml").exists() else {}
        if not isinstance(mask, dict):
            mask = {}
        if not isinstance(selected_units, dict):
            selected_units = {}
        examples.append(
            {
                "example_id": f"example_{idx:02d}",
                "path": rel(tdir),
                "family": template_family(meta, tdir),
                "source_library": first_scalar(meta, [["source_library"], ["source_api", "library"], ["poc_source", "library"]], "unknown"),
                "target_library": first_scalar(meta, [["target_library"]], "not_declared"),
                "files_present": file_presence(tdir),
                "observed_slots": extract_slots(meta, mask, selected_units)[:30],
                "observed_oracles": [
                    x
                    for x in [
                        meta.get("oracle_type"),
                        "oracle" if "oracle" in meta else None,
                        "safe_behavior" if "safe_behavior" in meta else None,
                        "bug_behavior" if "bug_behavior" in meta else None,
                    ]
                    if x
                ],
                "observed_mutation_points": extract_slots(meta, mask, selected_units)[:20],
                "notes": "Representative existing artifact; no files were generated from it.",
            }
        )
    return {"examples": examples}


def family_coverage(args: argparse.Namespace) -> dict[str, Any]:
    template_dirs = collect_template_dirs([Path(args.normalized_templates), Path(args.templates), Path(args.enriched_templates), Path(args.generated_templates), Path("artifacts/migrations")])
    ready = load_list_container(Path(args.adapter_ready), ["adapter_ready_mapping_candidates", "items", "mappings"])
    corrected = load_list_container(Path(args.corrected_candidates), ["corrected_reviewed_scheduler_seed_candidates", "items", "candidates"])
    recipes = find_yaml_files(Path(args.adapter_recipes), ["*.yaml"])
    coverage: dict[str, Any] = {}
    for family in TOP_FAMILIES:
        dirs = []
        source_libs: set[str] = set()
        target_libs: set[str] = set()
        for tdir in template_dirs:
            meta = read_template_meta(tdir)
            meta_family = template_family(meta, tdir)
            path_text = rel(tdir).lower()
            if family == meta_family or family in path_text or family.replace("_", "-") in path_text:
                dirs.append(rel(tdir))
                src = first_scalar(meta, [["source_library"], ["source_api", "library"], ["poc_source", "library"]], "")
                if src:
                    source_libs.add(src)
                tgt = first_scalar(meta, [["target_library"]], "")
                if tgt:
                    target_libs.add(tgt)
        ready_items = [x for x in ready if x.get("family") == family]
        corrected_items = [x for x in corrected if x.get("family") == family]
        recipe_hits = [rel(p) for p in recipes if family in p.name or family in rel(p)]
        has_template = bool(dirs)
        has_recipe = bool(recipe_hits)
        ready_for_generalization = has_template or has_recipe or bool(ready_items)
        gaps = []
        if not has_template:
            gaps.append("no_existing_template_directory_for_family")
        if not has_recipe:
            gaps.append("no_adapter_recipe_named_for_family")
        if not any("wolf" in p.lower() for p in dirs):
            gaps.append("no_wolfssl_source_template_observed")
        coverage[family] = {
            "existing_templates": sorted(dirs)[:60],
            "template_count": len(dirs),
            "source_libraries": sorted(source_libs),
            "target_libraries": sorted(target_libs),
            "adapter_ready_mapping_count": len(ready_items),
            "corrected_candidate_count": len(corrected_items),
            "recipes": sorted(recipe_hits),
            "ready_for_generalization": ready_for_generalization,
            "gaps": gaps,
        }
    wolf_dirs = [rel(p) for p in template_dirs if "wolf" in rel(p).lower()]
    return {
        "families": coverage,
        "direct_answers": {
            "has_tls_lifecycle_template": coverage["tls_protocol_state_lifecycle"]["template_count"] > 0,
            "has_asn1_x509_pkcs_templates": any(
                coverage[f]["template_count"] > 0 for f in ["asn1_nested_boundary", "x509_parsing", "pkcs_container_parsing"]
            ),
            "has_secure_heap_template": coverage["secure_heap_state_lifecycle"]["template_count"] > 0,
            "has_wolfssl_source_template": bool(wolf_dirs),
            "families_can_enter_template_generalizer": [
                f for f, item in coverage.items() if item["ready_for_generalization"] and item["template_count"] > 0
            ],
            "families_need_template_recipe_first": [
                f for f, item in coverage.items() if item["template_count"] == 0 and not item["recipes"]
            ],
        },
        "wolfssl_template_dirs": wolf_dirs[:80],
    }


def candidate_selection(args: argparse.Namespace, coverage: dict[str, Any]) -> dict[str, Any]:
    corrected = load_list_container(Path(args.corrected_candidates), ["corrected_reviewed_scheduler_seed_candidates", "items", "candidates"])
    ready = load_list_container(Path(args.adapter_ready), ["adapter_ready_mapping_candidates", "items", "mappings"])
    ready_families = {str(x.get("family", "")) for x in ready}
    families = coverage.get("families", {})
    selected = []
    priority_order = {poc: idx for idx, poc in enumerate(PRIORITY_POCS)}
    candidates = sorted(
        corrected,
        key=lambda x: (
            priority_order.get(str(x.get("poc_id")), 99),
            str(x.get("family", "")),
            str(x.get("poc_id", "")),
        ),
    )
    for item in candidates:
        poc_id = str(item.get("poc_id", "unknown"))
        family = str(item.get("family", "unknown"))
        if poc_id not in PRIORITY_POCS and family not in TOP_FAMILIES:
            continue
        fam_cov = families.get(family, {})
        has_template = bool(fam_cov.get("template_count", 0))
        has_adapter_ready = family in ready_families
        blocked = item.get("scheduler_action") == "block" or item.get("import_status") == "blocked"
        if blocked:
            mode = "needs_manual_review"
        elif has_template:
            mode = "adapt_existing_family_template"
        elif has_adapter_ready:
            mode = "source_template_from_poc"
        else:
            mode = "needs_new_family_recipe"
        selected.append(
            {
                "candidate_id": f"template_generalizer_{len(selected)+1:03d}",
                "poc_id": poc_id,
                "source_library": item.get("source_library", "unknown"),
                "family": family,
                "harness_family": item.get("harness_family", "unknown"),
                "route_guess": item.get("route_guess", "unknown"),
                "template_candidate_available": bool(item.get("template_candidate")),
                "existing_template_support": has_template,
                "adapter_ready_support": has_adapter_ready,
                "rag_support": item.get("evidence_strength", "unknown"),
                "blocked_by_no_direct_counterpart": blocked,
                "recommended_generalization_mode": mode,
                "priority": "high" if poc_id in PRIORITY_POCS else "medium",
                "reason": "Selected from corrected candidates, adapter-ready mapping gate, and existing template coverage.",
            }
        )
    return {"top_candidates": selected[:20], "priority_pocs": PRIORITY_POCS}


def generalizer_plan(selection: dict[str, Any]) -> dict[str, Any]:
    source_templates = []
    for cand in selection.get("top_candidates", [])[:8]:
        if cand.get("recommended_generalization_mode") in {"source_template_from_poc", "adapt_existing_family_template"}:
            source_templates.append(
                {
                    "poc_id": cand.get("poc_id"),
                    "source_library": cand.get("source_library"),
                    "family": cand.get("family"),
                    "mode": cand.get("recommended_generalization_mode"),
                    "required_files": [
                        "poc_original.c",
                        f"tmpl_{cand.get('source_library', 'source')}.c",
                        "template_meta.yaml",
                        "mask_report.yaml",
                        "ast_mask_report.yaml",
                        "selected_mask_units.yaml",
                    ],
                }
            )
    return {
        "next_step": "template_generalizer_v1",
        "source_templates_to_generate_next": source_templates,
        "tooling_needed": {
            "template_maker": True,
            "mask_tools": True,
            "ast_sister_or_ast_lite": True,
            "rag_evidence": True,
            "glm_allowed": False,
            "glm_allowed_only_for_future_adapter_slot_filling": True,
        },
        "mutation_point_policy": "Mutation points must come from mask_report/AST selected units, not from GLM free-form generation.",
        "notes": "This plan is descriptive only; this inventory sprint did not create source templates.",
    }


def next_action(schema: dict[str, Any], coverage: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any]:
    has_schema = bool(schema["template_meta_schema"]["observed_files"]) and bool(schema["mask_report_schema"]["observed_files"])
    has_candidates = any(
        c.get("recommended_generalization_mode") in {"source_template_from_poc", "adapt_existing_family_template"}
        for c in selection.get("top_candidates", [])
    )
    if not has_schema:
        task = "template_schema_normalization_v1"
        why = "template_meta/mask_report schema inputs are insufficient or missing."
    elif has_candidates:
        task = "template_generalizer_v1"
        why = "Schema is observable and top candidates have adapter-ready or existing-template support."
    elif coverage.get("direct_answers", {}).get("families_need_template_recipe_first"):
        task = "template_recipe_design_for_top_family_v1"
        why = "Top families lack enough existing template or recipe support."
    else:
        task = "cross_library_mapping_refinement_followup_v1"
        why = "Mapping support is not strong enough for template generalization."
    return {"next_task_name": task, "why": why}


def final_report(
    dirs: dict[str, Any],
    schema: dict[str, Any],
    coverage: dict[str, Any],
    selection: dict[str, Any],
    next_step: dict[str, Any],
) -> dict[str, Any]:
    return {
        "read_template_directories": list(dirs["directories"].keys()),
        "existing_template_schema": {
            "template_meta_fields": schema["template_meta_schema"]["observed_fields"],
            "mask_report_fields": schema["mask_report_schema"]["observed_fields"],
            "ast_mask_report_fields": schema["ast_mask_report_schema"]["observed_fields"],
            "selected_mask_units_fields": schema["selected_mask_units_schema"]["observed_fields"],
            "adapter_fields": schema["adapter_schema"]["observed_fields"],
        },
        "top_family_template_support": coverage["direct_answers"],
        "priority_candidate_answers": {
            poc: next((c for c in selection["top_candidates"] if c.get("poc_id") == poc), {"selected": False})
            for poc in PRIORITY_POCS
        },
        "generated_new_templates": False,
        "ran_poc": False,
        "ran_glm": False,
        "ran_render": False,
        "modified_pattern_bank": False,
        "modified_scheduler_seed": False,
        "modified_knowledge_raw": False,
        "next_task_name": next_step["next_task_name"],
    }


def write_pair(base: Path, title: str, data: Any) -> None:
    dump_yaml(base.with_suffix(".yaml"), data)
    dump_md(base.with_suffix(".md"), title, data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normalized-templates", required=True)
    parser.add_argument("--templates", required=True)
    parser.add_argument("--enriched-templates", required=True)
    parser.add_argument("--generated-templates", required=True)
    parser.add_argument("--adapter-recipes", required=True)
    parser.add_argument("--migration-candidates", required=True)
    parser.add_argument("--template-maker", required=True)
    parser.add_argument("--mapping-gate", required=True)
    parser.add_argument("--adapter-ready", required=True)
    parser.add_argument("--corrected-candidates", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    for subdir in ["input", "structure", "schema", "examples", "coverage", "candidates", "reports", "logs", "validation"]:
        (out / subdir).mkdir(parents=True, exist_ok=True)

    inputs = input_summary(args)
    dirs = directory_inventory(args)
    schema = schema_summary(args)
    examples = template_examples(args)
    coverage = family_coverage(args)
    selection = candidate_selection(args, coverage)
    plan = generalizer_plan(selection)
    next_step = next_action(schema, coverage, selection)
    report = final_report(dirs, schema, coverage, selection, next_step)

    write_pair(out / OUTPUTS["input"], "Template Inventory Input Summary", inputs)
    write_pair(out / OUTPUTS["structure"], "Template Directory Inventory", dirs)
    write_pair(out / OUTPUTS["schema"], "Template Schema Summary", schema)
    write_pair(out / OUTPUTS["examples"], "Template Examples Summary", examples)
    write_pair(out / OUTPUTS["coverage"], "Template Family Coverage", coverage)
    write_pair(out / OUTPUTS["candidates"], "Template Generalizer Candidate Selection", selection)
    write_pair(out / OUTPUTS["plan"], "Template Generalizer V1 Plan", plan)
    write_pair(out / OUTPUTS["next"], "Next Action After Template Inventory", next_step)
    write_pair(out / OUTPUTS["report"], "Template Schema Inventory Report", report)

    readme = {
        "sprint": "template_schema_inventory_v1",
        "purpose": "Read existing template/schema/tooling artifacts and summarize compatibility for template_generalizer_v1.",
        "strict_non_actions": {
            "run_poc": False,
            "compile_run": False,
            "glm": False,
            "render": False,
            "template_generation": False,
            "pattern_bank_modified": False,
            "scheduler_seed_modified": False,
            "knowledge_raw_modified": False,
        },
        "main_outputs": [str(out / (base + ".yaml")) for base in OUTPUTS.values()],
        "next_task_name": next_step["next_task_name"],
    }
    dump_md(out / "README.md", "template_schema_inventory_v1", readme)
    print(f"template_schema_inventory_v1 complete: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
