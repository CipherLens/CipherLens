#!/usr/bin/env python3
"""Inventory AST-SISTER/AST-mask implementation and schema alignment."""

from __future__ import annotations

import argparse
import collections
import re
from pathlib import Path
from typing import Any

import yaml


OUTPUTS = {
    "input": "input/ast_sister_input_summary",
    "repo_search": "repo_search/ast_sister_repo_search_summary",
    "implementation": "implementation/ast_sister_implementation_inventory",
    "schemas": "schemas/ast_sister_output_schema_summary",
    "examples": "examples/ast_sister_examples_summary",
    "alignment": "alignment_plan/ast_sister_recipe_alignment_plan",
    "next": "reports/next_action_after_ast_sister_inventory",
    "report": "reports/ast_sister_inventory_and_alignment_report",
}

AST_TERMS = [
    "ast_sister",
    "ast-sister",
    "AST-SISTER",
    "ast mask",
    "ast_mask",
    "selected_mask",
    "tree-sitter",
    "tree_sitter",
]

RELEVANT_SCRIPT_HINTS = [
    "template_maker/ast_mask.py",
    "template_maker/ast_mask_lite.py",
    "template_maker/ast_mask_tree_sitter.py",
    "template_maker/ast_mask_select.py",
    "template_maker/validate_template.py",
    "template_maker/cross_generator_from_adapters.py",
    "template_maker/render_cases.py",
    "config/harness_family_ast_rules.yaml",
]


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {"_load_error": str(exc)}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False), encoding="utf-8")


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


def dump_md(path: Path, title: str, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", ""]
    lines.extend(render_md(data))
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_pair(base: Path, title: str, data: Any) -> None:
    dump_yaml(base.with_suffix(".yaml"), data)
    dump_md(base.with_suffix(".md"), title, data)


def rel(path: Path, root: Path | None = None) -> str:
    root = root or Path.cwd()
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def top_keys(doc: Any) -> list[str]:
    return sorted(str(k) for k in doc.keys()) if isinstance(doc, dict) else []


def key_union(items: list[dict[str, Any]]) -> list[str]:
    keys: set[str] = set()
    for item in items:
        keys.update(str(k) for k in item.keys())
    return sorted(keys)


def scalar_values(items: list[dict[str, Any]], fields: list[str]) -> list[str]:
    values: set[str] = set()
    for item in items:
        for field in fields:
            value = item.get(field)
            if isinstance(value, (str, int, float, bool)):
                values.add(str(value))
    return sorted(values)


def nested_items(data: Any, names: list[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in names:
                    found.extend(dict_list(value))
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return found


def find_files(root: Path, name: str) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob(name) if path.is_file())


def yaml_docs(files: list[Path]) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for path in files:
        data = load_yaml(path)
        if isinstance(data, dict):
            docs.append(data)
    return docs


def schema_variant(docs: list[dict[str, Any]]) -> dict[str, Any]:
    variants = collections.Counter(tuple(top_keys(doc)) for doc in docs)
    return {
        "variant_count": len(variants),
        "top_variants": [
            {"count": count, "fields": list(fields)}
            for fields, count in variants.most_common(8)
        ],
    }


def summarize_schema(files: list[Path], item_names: list[str]) -> dict[str, Any]:
    docs = yaml_docs(files)
    items: list[dict[str, Any]] = []
    for doc in docs:
        items.extend(nested_items(doc, item_names))
    return {
        "observed_files": len(files),
        "sample_files": [rel(path) for path in files[:12]],
        "observed_fields": sorted({field for doc in docs for field in top_keys(doc)}),
        "variants": schema_variant(docs),
        "unit_fields": key_union(items),
        "slot_fields": sorted(set(key_union(items)) & {"slot", "name", "unit_id", "placeholder", "mutation_name", "type", "mutation_type"}),
        "oracle_fields": sorted(
            field for field in {key for doc in docs for key in top_keys(doc)}
            if "oracle" in field or field in {"safe_behavior", "bug_behavior", "triage_behavior", "verdict"}
        ),
        "node_kind_fields": scalar_values(items, ["kind", "node_type", "mask_level", "role"]),
        "source_range_fields": sorted(set(key_union(items)) & {"line", "line_start", "line_end", "column_start", "column_end", "start_byte", "end_byte"}),
        "confidence_fields": sorted(set(key_union(items)) & {"priority", "selection_score", "selection_reason", "suggested_use", "selected"}),
    }


def repo_search_summary(repo_root: Path, out_dir: Path) -> dict[str, Any]:
    rg_path = out_dir / "repo_search/ast_sister_related_rg.txt"
    files_path = out_dir / "repo_search/ast_sister_related_files.txt"
    code_files_path = out_dir / "repo_search/project_code_and_template_files.txt"
    rg_text = read_text(rg_path)
    files = [line.strip() for line in read_text(files_path).splitlines() if line.strip()]
    code_files = [line.strip() for line in read_text(code_files_path).splitlines() if line.strip()]
    lower = rg_text.lower()
    explicit = any(term in lower for term in ["ast-sister", "ast_sister", "astsister"])
    relevant_scripts = [path for path in RELEVANT_SCRIPT_HINTS if (repo_root / path).exists()]
    historical_artifacts = [
        path for path in files
        if any(name in path for name in ["ast_mask_report.yaml", "selected_mask_units.yaml", "mask_report.yaml"])
    ][:80]
    return {
        "search_files": {
            "rg": {"path": rel(rg_path), "line_count": len(rg_text.splitlines()), "exists": rg_path.exists()},
            "filename_search": {"path": rel(files_path), "line_count": len(files), "exists": files_path.exists()},
            "project_files": {"path": rel(code_files_path), "line_count": len(code_files), "exists": code_files_path.exists()},
        },
        "explicit_ast_sister_name_found": explicit,
        "equivalent_ast_mask_pipeline_found": all((repo_root / p).exists() for p in [
            "template_maker/ast_mask.py",
            "template_maker/ast_mask_lite.py",
            "template_maker/ast_mask_select.py",
        ]),
        "related_scripts": relevant_scripts,
        "tree_sitter_backend_file": "template_maker/ast_mask_tree_sitter.py" if (repo_root / "template_maker/ast_mask_tree_sitter.py").exists() else "",
        "related_historical_artifacts_sample": historical_artifacts,
        "notes": [
            "AST-SISTER appears as a concept/name in project text, but the concrete implementation is named ast_mask/ast_mask_lite/ast_mask_tree_sitter.",
            "The current equivalent pipeline produces ast_mask_report.yaml and selected_mask_units.yaml.",
        ],
    }


def input_summary(template_schema: Path, template_examples: Path, repo_root: Path) -> dict[str, Any]:
    required = {
        "template_schema_report": "artifacts/sprints/template_schema_inventory_v1/reports/template_schema_inventory_report.yaml",
        "template_schema_summary": str(template_schema),
        "template_examples_summary": str(template_examples),
        "template_family_coverage": "artifacts/sprints/template_schema_inventory_v1/coverage/template_family_coverage.yaml",
        "template_generalizer_candidates": "artifacts/sprints/template_schema_inventory_v1/candidates/template_generalizer_candidate_selection.yaml",
    }
    loaded = {name: load_yaml(repo_root / path) for name, path in required.items()}
    return {
        "inputs": {
            name: {"path": path, "exists": (repo_root / path).exists(), "loaded": isinstance(loaded[name], dict)}
            for name, path in required.items()
        },
        "template_schema_context": {
            "template_schema_observable": isinstance(loaded["template_schema_summary"], dict),
            "template_examples_observable": isinstance(loaded["template_examples_summary"], dict),
            "previous_next_task": (loaded["template_schema_report"] or {}).get("next_task_name", ""),
        },
        "purpose": [
            "Confirm AST-SISTER/AST-mask implementation before recipe design.",
            "Align future family recipes with ast_mask_report.yaml and selected_mask_units.yaml.",
            "Do not generate templates, render cases, run PoCs, or call GLM in this sprint.",
        ],
    }


def implementation_inventory(repo_root: Path, search: dict[str, Any]) -> dict[str, Any]:
    scripts = {
        "wrapper": repo_root / "template_maker/ast_mask.py",
        "lite_backend": repo_root / "template_maker/ast_mask_lite.py",
        "tree_sitter_backend": repo_root / "template_maker/ast_mask_tree_sitter.py",
        "selector": repo_root / "template_maker/ast_mask_select.py",
        "validator": repo_root / "template_maker/validate_template.py",
        "cross_generator": repo_root / "template_maker/cross_generator_from_adapters.py",
        "family_rules": repo_root / "config/harness_family_ast_rules.yaml",
    }
    script_text = {name: read_text(path) for name, path in scripts.items()}
    parser_backend: list[str] = []
    if "tree_sitter" in script_text["tree_sitter_backend"] or "tree-sitter" in script_text["tree_sitter_backend"]:
        parser_backend.append("tree-sitter optional C backend")
    if "regex" in script_text["lite_backend"].lower() or "CALL_RE" in script_text["lite_backend"]:
        parser_backend.append("regex/template-aware AST-lite fallback")
    if "pycparser" in "\n".join(script_text.values()).lower():
        parser_backend.append("pycparser reference found")
    if "libclang" in "\n".join(script_text.values()).lower():
        parser_backend.append("libclang reference found")
    relevant_functions = []
    for name, text in script_text.items():
        for fn in re.findall(r"^def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", text, flags=re.MULTILINE):
            if any(term in fn for term in ["build", "select", "run", "validate", "collect", "output_path"]):
                relevant_functions.append(f"{name}.{fn}")
    return {
        "ast_sister_inventory": {
            "explicit_ast_sister_found": search["explicit_ast_sister_name_found"],
            "equivalent_ast_mask_pipeline_found": search["equivalent_ast_mask_pipeline_found"],
            "parser_backend": parser_backend or ["not detected"],
            "relevant_scripts": {name: rel(path, repo_root) for name, path in scripts.items() if path.exists()},
            "relevant_functions": sorted(relevant_functions)[:80],
            "expected_inputs": [
                "template_meta.yaml",
                "mask_report.yaml",
                "tmpl_<library>.c, default tmpl_mbedtls.c",
                "config/harness_family_ast_rules.yaml for selection",
            ],
            "expected_outputs": [
                "ast_mask_report.yaml",
                "ast_mask_report.tree_sitter.yaml or backend-qualified output when requested",
                "selected_mask_units.yaml",
            ],
            "current_limitations": [
                "No module literally named ast_sister was found; implementation is under template_maker.ast_mask*.",
                "tree-sitter backend requires optional tree_sitter and tree_sitter_c dependencies.",
                "AST-lite is regex/template-aware, not a full C parser.",
                "Current default template file is tmpl_mbedtls.c unless --template-file is provided.",
                "Observed historical reports include multiple schema variants.",
            ],
            "notes": [
                "template_maker.ast_mask selects lite or tree-sitter backend.",
                "template_maker.ast_mask_select converts ast_mask_units into selected_units using family-aware rules.",
                "cross_generator_from_adapters validates selected_mask_units before cross-template generation.",
            ],
        }
    }


def schema_summary(repo_root: Path) -> dict[str, Any]:
    roots = [
        repo_root / "normalized_templates",
        repo_root / "templates",
        repo_root / "enriched_templates",
        repo_root / "generated_templates",
        repo_root / "artifacts/migrations",
        repo_root / "artifacts/sprints",
    ]

    def files_named(name: str) -> list[Path]:
        found: list[Path] = []
        for root in roots:
            found.extend(find_files(root, name))
        return sorted(set(found))

    mask_files = files_named("mask_report.yaml")
    ast_files = files_named("ast_mask_report.yaml")
    selected_files = files_named("selected_mask_units.yaml")
    meta_files = files_named("template_meta.yaml")
    mask = summarize_schema(mask_files, ["mask_units", "mutation_points", "roles"])
    ast = summarize_schema(ast_files, ["ast_mask_units", "ast_units", "nodes"])
    selected = summarize_schema(selected_files, ["selected_units"])
    meta = summarize_schema(meta_files, ["mutation_points", "mask_slots"])
    return {
        "mask_report_schema": {
            "observed_files": mask["observed_files"],
            "observed_fields": mask["observed_fields"],
            "unit_fields": mask["unit_fields"],
            "slot_fields": mask["slot_fields"],
            "oracle_fields": mask["oracle_fields"],
            "variants": mask["variants"],
        },
        "ast_mask_report_schema": {
            "observed_files": ast["observed_files"],
            "observed_fields": ast["observed_fields"],
            "ast_unit_fields": ast["unit_fields"],
            "node_kind_fields": ast["node_kind_fields"],
            "source_range_fields": ast["source_range_fields"],
            "confidence_fields": ast["confidence_fields"],
            "variants": ast["variants"],
        },
        "selected_mask_units_schema": {
            "observed_files": selected["observed_files"],
            "observed_fields": selected["observed_fields"],
            "selected_unit_fields": selected["unit_fields"],
            "scoring_fields": selected["confidence_fields"],
            "suggested_use_fields": scalar_values(
                [item for doc in yaml_docs(selected_files) for item in nested_items(doc, ["selected_units"])],
                ["suggested_use"],
            ),
            "variants": selected["variants"],
        },
        "template_meta_schema": {
            "observed_files": meta["observed_files"],
            "observed_fields": meta["observed_fields"],
            "mutation_slot_fields": meta["unit_fields"],
            "oracle_fields": meta["oracle_fields"],
            "variants": meta["variants"],
        },
        "canonical_alignment_recommendation": {
            "ast_mask_report": [
                "Use top-level ast_mask_units as canonical list.",
                "Each unit should include unit_id, mask_level, role, code, source.",
                "When backend provides exact ranges, include node_type, line_start, line_end, column_start, column_end.",
            ],
            "selected_mask_units": [
                "Use top-level selected_units as canonical list.",
                "Carry unit_id linkage back to ast_mask_units.",
                "Include suggested_use with migrate_api_call and preserve_oracle/oracle coverage.",
                "Keep selection_summary for downstream validators.",
            ],
            "mask_report": [
                "Keep existing role and mask_units variants readable.",
                "Expose mutation slot names/placeholders in a normalized list for family recipes.",
            ],
        },
    }


def file_presence(path: Path) -> dict[str, bool]:
    return {
        "template_meta": (path / "template_meta.yaml").exists(),
        "mask_report": (path / "mask_report.yaml").exists(),
        "ast_mask_report": (path / "ast_mask_report.yaml").exists(),
        "selected_mask_units": (path / "selected_mask_units.yaml").exists(),
        "adapter": (path / "adapter.yaml").exists(),
    }


def template_family(path: Path) -> str:
    meta = load_yaml(path / "template_meta.yaml")
    if isinstance(meta, dict):
        for key in ["family", "harness_family", "vulnerability_class", "source_component"]:
            value = meta.get(key)
            if isinstance(value, str):
                return value
        operation = meta.get("operation")
        if isinstance(operation, dict):
            for key in ["abstract", "api_family"]:
                if isinstance(operation.get(key), str):
                    return str(operation[key])
    return "unknown"


def extract_unit_names(doc: Any, names: list[str], limit: int = 20) -> list[str]:
    values: list[str] = []
    for item in nested_items(doc, names):
        value = item.get("unit_id") or item.get("slot") or item.get("name") or item.get("mutation_name") or item.get("placeholder")
        if value and str(value) not in values:
            values.append(str(value))
    return values[:limit]


def find_matching_adapters(repo_root: Path, template_id: str) -> list[Path]:
    if not template_id:
        return []
    matches: list[Path] = []
    for path in (repo_root / "artifacts/migrations").rglob("adapter.yaml"):
        doc = load_yaml(path)
        if isinstance(doc, dict) and str(doc.get("template_id") or doc.get("source_template_id") or "") == template_id:
            matches.append(path)
            continue
        if template_id in str(path):
            matches.append(path)
    return sorted(set(matches))


def examples_summary(repo_root: Path) -> dict[str, Any]:
    dirs: set[Path] = set()
    for root in [repo_root / "normalized_templates", repo_root / "artifacts/migrations"]:
        if root.exists():
            for file_name in ["ast_mask_report.yaml", "selected_mask_units.yaml", "adapter.yaml", "template_meta.yaml"]:
                dirs.update(path.parent for path in root.rglob(file_name))
    scored: list[tuple[int, str, Path]] = []
    for path in dirs:
        text = str(path).lower()
        score = 0
        presence = file_presence(path)
        score += 30 if presence["ast_mask_report"] else 0
        score += 30 if presence["selected_mask_units"] else 0
        score += 15 if presence["adapter"] else 0
        score += 15 if any(term in text for term in ["asn1", "x509", "pkcs", "der", "tls", "lifecycle", "mac"]) else 0
        scored.append((score, rel(path, repo_root), path))
    selected_paths = [path for _, _, path in sorted(scored, key=lambda x: (-x[0], x[1]))[:5]]
    examples = []
    adapter_slot_counter: collections.Counter[str] = collections.Counter()
    ast_unit_counter: collections.Counter[str] = collections.Counter()
    mask_slot_counter: collections.Counter[str] = collections.Counter()
    selected_unit_counter: collections.Counter[str] = collections.Counter()
    for idx, path in enumerate(selected_paths, 1):
        meta = load_yaml(path / "template_meta.yaml") if (path / "template_meta.yaml").exists() else {}
        mask = load_yaml(path / "mask_report.yaml") if (path / "mask_report.yaml").exists() else {}
        ast = load_yaml(path / "ast_mask_report.yaml") if (path / "ast_mask_report.yaml").exists() else {}
        selected = load_yaml(path / "selected_mask_units.yaml") if (path / "selected_mask_units.yaml").exists() else {}
        template_id = meta.get("template_id") if isinstance(meta, dict) else ""
        adapter_files = [path / "adapter.yaml"] if (path / "adapter.yaml").exists() else find_matching_adapters(repo_root, str(template_id or ""))[:3]
        adapter_slots: list[str] = []
        for adapter_path in adapter_files:
            adapter = load_yaml(adapter_path)
            if isinstance(adapter, dict):
                slots = adapter.get("slot_bindings")
                if isinstance(slots, dict):
                    adapter_slots.extend(str(k) for k in slots.keys())
        ast_units = extract_unit_names(ast, ["ast_mask_units", "ast_units", "nodes"])
        mask_slots = extract_unit_names(mask, ["mask_units", "mutation_points", "roles"])
        selected_units = extract_unit_names(selected, ["selected_units"])
        ast_unit_counter.update(ast_units)
        mask_slot_counter.update(mask_slots)
        selected_unit_counter.update(selected_units)
        adapter_slot_counter.update(adapter_slots)
        examples.append(
            {
                "example_id": f"example_{idx:02d}",
                "template_path": rel(path, repo_root),
                "family": template_family(path),
                "files_present": file_presence(path),
                "observed_ast_units": ast_units,
                "observed_mask_slots": mask_slots,
                "observed_selected_units": selected_units,
                "observed_adapter_slots": sorted(set(adapter_slots))[:20],
                "notes": "Representative existing artifact; no template or harness was generated.",
            }
        )
    return {
        "examples": examples,
        "common_ast_units": [item for item, _ in ast_unit_counter.most_common(20)],
        "common_mask_slots": [item for item, _ in mask_slot_counter.most_common(20)],
        "common_selected_units": [item for item, _ in selected_unit_counter.most_common(20)],
        "common_adapter_slots": [item for item, _ in adapter_slot_counter.most_common(20)],
    }


def alignment_plan() -> dict[str, Any]:
    return {
        "alignment_plan": {
            "recipe_fields_required_by_ast_sister": [
                "must_preserve_semantics",
                "ast_sister_preserve_units",
                "ast_sister_maskable_units",
                "mutation_slots",
                "api_slots",
                "cleanup_slots",
                "oracle_types",
                "harness_family",
                "required_observables",
                "forbidden_mutations",
            ],
            "ast_sister_consumes_from_recipe": [
                "target source template filename",
                "source/target API names",
                "must-preserve trigger calls",
                "oracle variables/functions",
                "cleanup calls",
                "family context keywords",
                "mutation slot definitions",
            ],
            "ast_sister_expected_outputs": [
                "mask_report.yaml",
                "ast_mask_report.yaml",
                "selected_mask_units.yaml",
            ],
            "template_generalizer_consumes": [
                "family_recipe.yaml",
                "template_meta.yaml",
                "mask_report.yaml",
                "ast_mask_report.yaml",
                "selected_mask_units.yaml",
                "mapping_gate_results.yaml",
            ],
            "glm_policy": {
                "allowed_stage": ["adapter_slot_filling"],
                "forbidden_stage": ["ast_selection", "full_c_generation", "source_template_generation", "oracle_rewrite"],
            },
            "schema_compatibility_fields": [
                "ast_mask_units.unit_id",
                "ast_mask_units.mask_level",
                "ast_mask_units.role",
                "ast_mask_units.code",
                "ast_mask_units.source",
                "selected_units.unit_id",
                "selected_units.suggested_use",
                "selection_summary",
                "harness_family",
                "trigger_apis",
            ],
        }
    }


def next_action(implementation: dict[str, Any], schemas: dict[str, Any]) -> dict[str, Any]:
    inv = implementation["ast_sister_inventory"]
    pipeline = bool(inv.get("equivalent_ast_mask_pipeline_found"))
    schema_clear = (
        schemas["ast_mask_report_schema"]["observed_files"] > 0
        and schemas["selected_mask_units_schema"]["observed_files"] > 0
        and "ast_mask_units" in schemas["ast_mask_report_schema"]["observed_fields"]
        and "selected_units" in schemas["selected_mask_units_schema"]["observed_fields"]
    )
    if pipeline and schema_clear:
        task = "template_recipe_design_for_top_wolfssl_families_v1"
        why = "AST mask pipeline exists, tree-sitter/lite backends are identifiable, and output schemas are observable enough for recipe alignment."
    elif pipeline:
        task = "ast_sister_schema_normalization_v1"
        why = "AST mask pipeline exists but schema variants need normalization before recipe design."
    else:
        task = "ast_sister_minimal_extractor_design_v1"
        why = "No equivalent AST mask pipeline was found."
    return {"next_task_name": task, "why": why}


def final_report(
    search: dict[str, Any],
    implementation: dict[str, Any],
    schemas: dict[str, Any],
    alignment: dict[str, Any],
    next_step: dict[str, Any],
) -> dict[str, Any]:
    inv = implementation["ast_sister_inventory"]
    return {
        "explicit_ast_sister_found": inv["explicit_ast_sister_found"],
        "equivalent_ast_mask_pipeline_found": inv["equivalent_ast_mask_pipeline_found"],
        "parser_backend": inv["parser_backend"],
        "mask_report_schema": schemas["mask_report_schema"],
        "ast_mask_report_schema": schemas["ast_mask_report_schema"],
        "selected_mask_units_schema": schemas["selected_mask_units_schema"],
        "template_maker_relationship": [
            "template_maker.ast_mask generates ast_mask_report.yaml via lite or tree-sitter backend.",
            "template_maker.ast_mask_select generates selected_mask_units.yaml from ast_mask_report.yaml.",
            "template_maker.validate_template and cross_generator_from_adapters consume/validate selected units.",
        ],
        "recipe_alignment": alignment["alignment_plan"],
        "generated_new_templates": False,
        "ran_poc": False,
        "ran_glm": False,
        "ran_render": False,
        "modified_pattern_bank": False,
        "modified_scheduler_seed": False,
        "modified_knowledge_raw": False,
        "next_task_name": next_step["next_task_name"],
        "repo_search_summary": {
            "explicit_name_found": search["explicit_ast_sister_name_found"],
            "related_scripts": search["related_scripts"],
        },
    }


def readme(next_step: dict[str, Any]) -> dict[str, Any]:
    return {
        "sprint": "ast_sister_inventory_and_alignment_v1",
        "purpose": "Inventory existing AST-SISTER/AST-mask implementation, schemas, examples, and recipe alignment.",
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
        "next_task_name": next_step["next_task_name"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--template-schema", required=True)
    parser.add_argument("--template-examples", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir)
    for subdir in ["input", "repo_search", "implementation", "schemas", "examples", "integration", "alignment_plan", "reports", "logs", "validation"]:
        (out_dir / subdir).mkdir(parents=True, exist_ok=True)

    search = repo_search_summary(repo_root, out_dir)
    inputs = input_summary(Path(args.template_schema), Path(args.template_examples), repo_root)
    implementation = implementation_inventory(repo_root, search)
    schemas = schema_summary(repo_root)
    examples = examples_summary(repo_root)
    alignment = alignment_plan()
    next_step = next_action(implementation, schemas)
    report = final_report(search, implementation, schemas, alignment, next_step)

    write_pair(out_dir / OUTPUTS["input"], "AST Sister Input Summary", inputs)
    write_pair(out_dir / OUTPUTS["repo_search"], "AST Sister Repo Search Summary", search)
    write_pair(out_dir / OUTPUTS["implementation"], "AST Sister Implementation Inventory", implementation)
    write_pair(out_dir / OUTPUTS["schemas"], "AST Sister Output Schema Summary", schemas)
    write_pair(out_dir / OUTPUTS["examples"], "AST Sister Examples Summary", examples)
    write_pair(out_dir / OUTPUTS["alignment"], "AST Sister Recipe Alignment Plan", alignment)
    write_pair(out_dir / OUTPUTS["next"], "Next Action After AST Sister Inventory", next_step)
    write_pair(out_dir / OUTPUTS["report"], "AST Sister Inventory And Alignment Report", report)
    dump_md(out_dir / "README.md", "ast_sister_inventory_and_alignment_v1", readme(next_step))

    print(f"ast_sister_inventory_and_alignment_v1 complete: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
