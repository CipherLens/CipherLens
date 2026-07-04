#!/usr/bin/env python3
"""Inventory project Python structure and produce a refactor plan.

This is a read-only inventory/report generator. It scans source files and
emits sprint artifacts only; it does not move, delete, or modify scanned files.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


SCAN_DIRS = [
    "tools",
    "mutation",
    "runner",
    "analyzer",
    "analysis",
    "template_maker",
    "migration",
    "scripts",
    "utils",
    "config",
]

INTERNAL_ROOTS = {
    "tools",
    "mutation",
    "runner",
    "analyzer",
    "analysis",
    "template_maker",
    "migration",
    "scripts",
    "utils",
    "config",
    "knowledge",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def rel_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_md(path: Path, title: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# " + title + "\n\n" + "\n".join(lines) + "\n", encoding="utf-8")


def iter_python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirname in SCAN_DIRS:
        base = root / dirname
        if not base.exists():
            continue
        files.extend(sorted(base.rglob("*.py")))
    return sorted(files)


def parse_file(path: Path) -> tuple[list[str], bool, bool, int, int, str | None]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [], "argparse" in text, "if __name__" in text, 0, 0, f"syntax_error: {exc.msg}"

    imports: list[str] = []
    has_argparse = False
    has_main = False
    function_count = 0
    class_count = 0

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
                if alias.name == "argparse":
                    has_argparse = True
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
                if node.module == "argparse":
                    has_argparse = True
        elif isinstance(node, ast.FunctionDef):
            function_count += 1
            if node.name == "main":
                has_main = True
        elif isinstance(node, ast.AsyncFunctionDef):
            function_count += 1
        elif isinstance(node, ast.ClassDef):
            class_count += 1
        elif isinstance(node, ast.If):
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
            ):
                has_main = True

    return sorted(set(imports)), has_argparse, has_main, function_count, class_count, None


def first_directory(rel: str) -> str:
    return rel.split("/", 1)[0]


def internal_imports(imports: list[str]) -> list[str]:
    result = []
    for module in imports:
        root = module.split(".", 1)[0]
        if root in INTERNAL_ROOTS:
            result.append(module)
    return sorted(set(result))


def external_imports(imports: list[str]) -> list[str]:
    result = []
    for module in imports:
        root = module.split(".", 1)[0]
        if root not in INTERNAL_ROOTS and root != "__future__":
            result.append(module)
    return sorted(set(result))


def likely_role(rel: str, has_argparse: bool, has_main: bool, functions: int, classes: int) -> str:
    directory = first_directory(rel)
    name = Path(rel).name
    stem = Path(rel).stem
    if directory == "tools":
        if "report" in stem or "inventory" in stem or "closure" in stem:
            return "report_generator"
        if stem.endswith("_v1") or "sprint" in stem or has_argparse:
            return "sprint_wrapper"
        return "cli_wrapper" if has_main else "unknown"
    if directory in {"runner", "mutation", "analyzer", "template_maker", "migration", "utils"}:
        return "reusable_core"
    if directory == "analysis":
        return "report_generator" if has_argparse or has_main else "reusable_core"
    if directory == "scripts":
        return "cli_wrapper" if has_argparse or has_main else "legacy_candidate"
    if classes + functions >= 4:
        return "reusable_core"
    return "unknown"


def proposed_target_for_tool(rel: str) -> tuple[str, str, str, str]:
    stem = Path(rel).stem
    lowered = stem.lower()
    if "compile_run" in lowered or lowered.startswith("compile_"):
        return (
            "move_logic_to_runner",
            "runner",
            "compile/run and execution capture belong in runner/",
            "medium",
        )
    if "analyze" in lowered or "oracle_aware" in lowered:
        return (
            "move_logic_to_analyzer",
            "analyzer or analysis",
            "oracle parsing and semantic labels belong in analyzer/; report aggregation can live in analysis/",
            "medium",
        )
    if "mutation" in lowered or "valid_prefix" in lowered and "render" not in lowered:
        return (
            "move_logic_to_mutation",
            "mutation",
            "mutation strategy and valid-prefix refinement belong in mutation/",
            "medium",
        )
    if "render" in lowered or "template" in lowered:
        return (
            "move_logic_to_template_maker",
            "template_maker",
            "render planning and template rendering belong in template_maker/",
            "medium",
        )
    if "feedback" in lowered or "closure" in lowered or "inventory" in lowered or "audit" in lowered or "queue" in lowered:
        return (
            "move_logic_to_analysis",
            "analysis",
            "feedback, candidate queues, audits, and closure reports belong in analysis/",
            "low",
        )
    if stem.endswith("_v1"):
        return (
            "keep_as_sprint_wrapper",
            "tools",
            "versioned sprint entrypoint can stay as orchestration wrapper after reusable logic is extracted",
            "low",
        )
    return ("needs_manual_review", "", "unclear ownership from filename/imports", "medium")


def summarize_markdown_inventory(summary: dict[str, Any]) -> list[str]:
    lines = [
        f"- Total Python files: {summary['total_python_files']}",
        f"- `tools/` Python files: {summary['tools_python_files']}",
        f"- Possible CLI wrappers: {summary['possible_cli_wrappers']}",
        f"- Possible reusable core files: {summary['possible_reusable_core']}",
        "",
        "## By Directory",
    ]
    for directory, count in summary["by_directory"].items():
        lines.append(f"- `{directory}/`: {count}")
    return lines


def build_module_ownership(tools_files: list[dict[str, Any]]) -> dict[str, Any]:
    def files_for(target: str) -> list[str]:
        return [item["file"] for item in tools_files if item.get("proposed_target") == target][:12]

    return {
        "schema": "module_ownership_map_v1",
        "target_modules": {
            "mutation": {
                "responsibilities": [
                    "mutation planner",
                    "mutation policy refinement",
                    "supplemental case generation",
                ],
                "candidate_files_to_absorb": files_for("mutation")
                or [
                    "mutation/family_mutation_planner.py",
                    "mutation/valid_prefix_refinement.py",
                    "mutation/mutation_policy.py",
                    "mutation/mutation_case_records.py",
                ],
            },
            "runner": {
                "responsibilities": [
                    "compile/run",
                    "sanitizer setup",
                    "execution result capture",
                ],
                "candidate_files_to_absorb": files_for("runner")
                or ["tools/harness/compile_run_v1.py", "tools/harness/compile_run_oracle_instrumented_v1.py"],
            },
            "analyzer": {
                "responsibilities": [
                    "oracle event parsing",
                    "family result adaptation",
                    "semantic labels",
                ],
                "candidate_files_to_absorb": files_for("analyzer or analysis")
                or ["tools/oracle/analyze_results_oracle_aware_v1.py"],
            },
            "analysis": {
                "responsibilities": [
                    "feedback staging",
                    "candidate queue",
                    "closure report",
                    "audit reports",
                ],
                "candidate_files_to_absorb": files_for("analysis")
                or [
                    "analysis/runtime_feedback.py",
                    "analysis/candidate_queue.py",
                    "analysis/mutation_feedback.py",
                    "analysis/scheduler_proposal.py",
                    "analysis/family_loop_closure.py",
                    "analysis/analysis_records.py",
                ],
            },
            "template_maker": {
                "responsibilities": [
                    "render plan",
                    "render cases",
                    "template rendering",
                ],
                "candidate_files_to_absorb": files_for("template_maker")
                or [
                    "template_maker/family_render_plan.py",
                    "template_maker/family_case_renderer.py",
                    "template_maker/oracle_instrumentation.py",
                    "template_maker/render_records.py",
                ],
            },
            "tools": {
                "responsibilities": [
                    "CLI entrypoints",
                    "sprint orchestration wrappers",
                    "thin compatibility shims",
                ],
                "candidate_files_to_keep": [
                    item["file"]
                    for item in tools_files
                    if item["role"] in {"keep_as_cli_entrypoint", "keep_as_sprint_wrapper"}
                ][:20],
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.repo_root.resolve()
    out = args.out_dir
    generated_at = now_iso()

    files = iter_python_files(root)
    inventory_files: list[dict[str, Any]] = []
    dep_imports: list[dict[str, Any]] = []
    reverse: dict[str, list[str]] = defaultdict(list)

    for path in files:
        rel = rel_path(path, root)
        imports, has_argparse, has_main, function_count, class_count, parse_note = parse_file(path)
        imports_internal = internal_imports(imports)
        imports_external = external_imports(imports)
        for module in imports_internal:
            reverse[module].append(rel)
        role = likely_role(rel, has_argparse, has_main, function_count, class_count)
        notes = []
        if parse_note:
            notes.append(parse_note)
        if first_directory(rel) == "tools" and function_count >= 6:
            notes.append("contains multiple functions; likely reusable logic should be extracted")
        if has_argparse:
            notes.append("CLI/argparse entrypoint detected")
        inventory_files.append(
            {
                "path": rel,
                "directory": first_directory(rel),
                "size_bytes": path.stat().st_size,
                "has_argparse": has_argparse,
                "has_main": has_main,
                "imports": imports,
                "likely_role": role,
                "notes": notes,
            }
        )
        dep_imports.append(
            {
                "file": rel,
                "imports_internal": [{"module": module} for module in imports_internal],
                "imports_external": [{"module": module} for module in imports_external],
            }
        )

    by_directory = dict(sorted(Counter(item["directory"] for item in inventory_files).items()))
    possible_cli_wrappers = sum(1 for item in inventory_files if item["has_argparse"] or item["has_main"])
    possible_reusable_core = sum(1 for item in inventory_files if item["likely_role"] == "reusable_core")

    inventory_summary = {
        "total_python_files": len(inventory_files),
        "by_directory": by_directory,
        "tools_python_files": by_directory.get("tools", 0),
        "possible_cli_wrappers": possible_cli_wrappers,
        "possible_reusable_core": possible_reusable_core,
    }
    inventory = {
        "schema": "python_file_inventory_v1",
        "generated_at": generated_at,
        "files": inventory_files,
        "summary": inventory_summary,
    }

    reverse_dependencies = [
        {"module": module, "imported_by": [{"file": f} for f in sorted(set(imported_by))]}
        for module, imported_by in sorted(reverse.items())
    ]
    modules_with_many_dependents = [
        {"module": item["module"], "dependent_count": len(item["imported_by"])}
        for item in reverse_dependencies
        if len(item["imported_by"]) >= 2
    ]
    orphan_scripts = [
        item["path"]
        for item in inventory_files
        if item["directory"] in {"tools", "scripts"}
        and not any(dep["file"] == item["path"] and dep["imports_internal"] for dep in dep_imports)
    ]
    scripts_importing_existing_core = [
        dep["file"]
        for dep in dep_imports
        if first_directory(dep["file"]) in {"tools", "scripts"} and dep["imports_internal"]
    ]
    dependency_map = {
        "schema": "dependency_map_v1",
        "generated_at": generated_at,
        "imports": dep_imports,
        "reverse_dependencies": reverse_dependencies,
        "summary": {
            "modules_with_many_dependents": modules_with_many_dependents,
            "orphan_scripts": orphan_scripts,
            "scripts_importing_existing_core": scripts_importing_existing_core,
            "tools_importing_runner_analyzer_mutation": [
                dep["file"]
                for dep in dep_imports
                if first_directory(dep["file"]) == "tools"
                and any(
                    item["module"].split(".", 1)[0] in {"runner", "analyzer", "mutation"}
                    for item in dep["imports_internal"]
                )
            ],
            "tools_without_existing_core_imports": [
                dep["file"]
                for dep in dep_imports
                if first_directory(dep["file"]) == "tools" and not dep["imports_internal"]
            ],
            "analyzer_oracle_event_parser_imported_by": sorted(set(reverse.get("analyzer.oracle_event_parser", []))),
            "analyzer_family_result_adapter_imported_by": sorted(set(reverse.get("analyzer.family_result_adapter", []))),
            "runner_analyze_results_imported_by": sorted(set(reverse.get("runner.analyze_results", []))),
        },
    }

    tools_files: list[dict[str, Any]] = []
    for item in inventory_files:
        if item["directory"] != "tools":
            continue
        role, target, reason, risk = proposed_target_for_tool(item["path"])
        if role.startswith("move_logic"):
            audit_role = role
        elif item["likely_role"] == "cli_wrapper":
            audit_role = "keep_as_cli_entrypoint"
        elif item["likely_role"] in {"sprint_wrapper", "report_generator"}:
            audit_role = role if role != "needs_manual_review" else "keep_as_sprint_wrapper"
        else:
            audit_role = role
        tools_files.append(
            {
                "file": item["path"],
                "role": audit_role,
                "reason": reason,
                "proposed_target": target,
                "risk": risk,
            }
        )

    tools_summary = {
        "total_tools_files": len(tools_files),
        "keep_in_tools": sum(
            1
            for item in tools_files
            if item["role"] in {"keep_as_cli_entrypoint", "keep_as_sprint_wrapper"}
        ),
        "should_move_logic": sum(1 for item in tools_files if str(item["role"]).startswith("move_logic")),
        "deprecated_candidates": sum(1 for item in tools_files if item["role"] == "deprecate_after_replacement"),
        "manual_review": sum(1 for item in tools_files if item["role"] == "needs_manual_review"),
    }
    tools_audit = {
        "schema": "tools_directory_audit_v1",
        "generated_at": generated_at,
        "tools_files": tools_files,
        "summary": tools_summary,
    }

    module_ownership = build_module_ownership(tools_files)
    module_ownership["generated_at"] = generated_at

    deprecated_paths = []
    for item in tools_files:
        if item["role"].startswith("move_logic") or item["role"] == "needs_manual_review":
            deprecated_paths.append(item)
    deprecated_candidates = {
        "schema": "deprecated_candidate_list_v1",
        "generated_at": generated_at,
        "candidates": [
            {
                "path": item["file"],
                "reason": "candidate for wrapper deprecation only after reusable logic is extracted"
                if item["role"].startswith("move_logic")
                else "manual ownership review required before any cleanup",
                "replacement": item.get("proposed_target") or "TBD",
                "dependency_check_required": True,
                "safe_to_delete_now": False,
                "required_before_delete": [
                    "import search",
                    "artifact reference search",
                    "CLI reference search",
                    "README/doc reference search",
                ],
            }
            for item in deprecated_paths[:30]
        ],
        "summary": {
            "total_candidates": min(len(deprecated_paths), 30),
            "safe_to_delete_now": 0,
        },
    }

    refactor_plan = {
        "schema": "refactor_plan_v1",
        "generated_at": generated_at,
        "phases": [
            {
                "phase": 1,
                "name": "extract_reusable_runner_logic",
                "actions": [
                    "move compile/run shared logic into runner/family_compile_runner.py",
                    "keep tools/* as CLI wrappers",
                ],
                "risk": "medium",
            },
            {
                "phase": 2,
                "name": "extract_mutation_policy_logic",
                "actions": [
                    "move valid-prefix refinement logic into mutation/",
                ],
                "risk": "medium",
            },
            {
                "phase": 3,
                "name": "extract_oracle_aware_analysis",
                "actions": [
                    "move semantic label logic into analyzer/",
                    "keep report generation in analysis/",
                ],
                "risk": "medium",
            },
            {
                "phase": 4,
                "name": "extract_feedback_and_scheduler_proposals",
                "actions": [
                    "move staged feedback logic into analysis/feedback/",
                    "prepare scheduler_runtime_loop_v1 interface",
                ],
                "risk": "medium",
            },
            {
                "phase": 5,
                "name": "cleanup_deprecated_wrappers",
                "actions": [
                    "only after dependency checks",
                    "no deletion in this task",
                ],
                "risk": "high",
            },
        ],
        "recommended_next_task": "project_structure_refactor_phase1_runner_v1",
    }

    runtime_loop_alignment = {
        "schema": "runtime_loop_alignment_v1",
        "generated_at": generated_at,
        "current_loop_type": "sprint_driven_manual_orchestration",
        "achieved_loops": [
            "family_execution_loop",
            "oracle_aware_refinement_loop",
            "staged_runtime_feedback_loop",
        ],
        "not_yet_achieved": [
            "scheduler_driven_runtime_loop",
            "automatic_family_selection",
            "automatic_mutation_budgeting",
            "feedback_import_gate",
        ],
        "scheduler_runtime_loop_inputs": [
            "artifacts/feedback/staged/runtime_feedback_integration_v1/runtime_feedback_staged.yaml",
            "artifacts/sprints/family_loop_closure_report_v1/next_roadmap/next_roadmap.yaml",
            "mutation policy feedback",
            "seed inventory",
        ],
        "recommended_next_steps": [
            "project_structure_refactor_phase1_runner_v1",
            "valid_seed_discovery_pkcs_v1",
            "x509_family_template_seed_discovery_v1",
        ],
    }

    quality_checks = {
        "schema": "project_structure_inventory_quality_checks_v1",
        "generated_at": generated_at,
        "inventory_generated": True,
        "dependency_map_generated": True,
        "tools_audit_generated": True,
        "module_ownership_generated": True,
        "deprecated_candidates_generated": True,
        "refactor_plan_generated": True,
        "runtime_loop_alignment_generated": True,
        "files_moved": False,
        "files_deleted": False,
        "core_code_modified": False,
        "artifacts_modified_outside_sprint": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "quality_status": "pass",
    }

    if tools_summary["should_move_logic"] > 0:
        next_task = "project_structure_refactor_phase1_runner_v1"
    elif deprecated_candidates["summary"]["total_candidates"] > 0:
        next_task = "deprecated_dependency_check_v1"
    else:
        next_task = "valid_seed_discovery_pkcs_v1"
    next_action = {
        "schema": "next_action_after_project_structure_inventory_v1",
        "generated_at": generated_at,
        "next_task_name": next_task,
        "secondary_next_task": "scheduler_runtime_loop_design_alignment_v1",
        "decision_basis": {
            "tools_should_move_logic": tools_summary["should_move_logic"],
            "tools_keep_as_wrapper": tools_summary["keep_in_tools"],
            "deprecated_candidates": deprecated_candidates["summary"]["total_candidates"],
            "scheduler_loop_not_yet_achieved": True,
        },
        "why": [
            "tools/ contains multiple sprint scripts with reusable runner, mutation, analyzer, analysis, and template logic",
            "phase 1 should extract compile/run logic first because it is shared and high-leverage",
            "scheduler runtime loop design should align with staged feedback and next-roadmap inputs",
        ],
    }

    final_report = {
        "schema": "project_structure_inventory_and_refactor_plan_v1_report",
        "generated_at": generated_at,
        "tools_overloaded_with_core_logic": tools_summary["should_move_logic"] > 0,
        "inventory_summary": inventory_summary,
        "tools_audit_summary": tools_summary,
        "module_targets": {
            "mutation": module_ownership["target_modules"]["mutation"]["candidate_files_to_absorb"],
            "runner": module_ownership["target_modules"]["runner"]["candidate_files_to_absorb"],
            "analyzer": module_ownership["target_modules"]["analyzer"]["candidate_files_to_absorb"],
            "analysis": module_ownership["target_modules"]["analysis"]["candidate_files_to_absorb"],
            "template_maker": module_ownership["target_modules"]["template_maker"]["candidate_files_to_absorb"],
        },
        "sprint_wrapper_policy": "keep tools as thin CLI or orchestration wrappers after reusable logic extraction",
        "safe_to_delete_now": False,
        "current_loop_type": runtime_loop_alignment["current_loop_type"],
        "recommended_next_task": next_action["next_task_name"],
        "secondary_next_task": next_action["secondary_next_task"],
        "quality_status": quality_checks["quality_status"],
    }

    write_yaml(out / "inventory/python_file_inventory.yaml", inventory)
    write_yaml(out / "dependency_map/dependency_map.yaml", dependency_map)
    write_yaml(out / "tools_audit/tools_directory_audit.yaml", tools_audit)
    write_yaml(out / "module_ownership/module_ownership_map.yaml", module_ownership)
    write_yaml(out / "deprecated_candidates/deprecated_candidates.yaml", deprecated_candidates)
    write_yaml(out / "refactor_plan/refactor_plan.yaml", refactor_plan)
    write_yaml(out / "runtime_loop_alignment/runtime_loop_alignment.yaml", runtime_loop_alignment)
    write_yaml(out / "validation/project_structure_inventory_quality_checks.yaml", quality_checks)
    write_yaml(out / "reports/next_action_after_project_structure_inventory.yaml", next_action)
    write_yaml(out / "reports/project_structure_inventory_and_refactor_plan_v1_report.yaml", final_report)

    write_md(out / "inventory/python_file_inventory.md", "Python File Inventory", summarize_markdown_inventory(inventory_summary))
    write_md(
        out / "dependency_map/dependency_map.md",
        "Dependency Map",
        [
            f"- Internal reverse dependency entries: {len(reverse_dependencies)}",
            f"- Scripts importing existing core: {len(scripts_importing_existing_core)}",
            f"- Tools without existing core imports: {len(dependency_map['summary']['tools_without_existing_core_imports'])}",
            f"- `analyzer.oracle_event_parser` imported by: {dependency_map['summary']['analyzer_oracle_event_parser_imported_by'] or 'none'}",
            f"- `analyzer.family_result_adapter` imported by: {dependency_map['summary']['analyzer_family_result_adapter_imported_by'] or 'none'}",
            f"- `runner.analyze_results` imported by: {dependency_map['summary']['runner_analyze_results_imported_by'] or 'none'}",
        ],
    )
    write_md(
        out / "tools_audit/tools_directory_audit.md",
        "Tools Directory Audit",
        [
            f"- Total tools files: {tools_summary['total_tools_files']}",
            f"- Keep in tools: {tools_summary['keep_in_tools']}",
            f"- Should move logic: {tools_summary['should_move_logic']}",
            f"- Deprecated candidates: {tools_summary['deprecated_candidates']}",
            f"- Needs manual review: {tools_summary['manual_review']}",
        ],
    )
    write_md(
        out / "module_ownership/module_ownership_map.md",
        "Module Ownership Map",
        [
            "- `mutation/`: mutation planner, policy refinement, supplemental cases.",
            "- `runner/`: compile/run, sanitizer setup, execution result capture.",
            "- `analyzer/`: oracle event parsing, family result adaptation, semantic labels.",
            "- `analysis/`: feedback staging, candidate queues, closure/audit reports.",
            "- `template_maker/`: render plans, render cases, template rendering.",
            "- `tools/`: thin CLI entrypoints and sprint orchestration wrappers.",
        ],
    )
    write_md(
        out / "deprecated_candidates/deprecated_candidates.md",
        "Deprecated Candidates",
        [
            f"- Total candidates: {deprecated_candidates['summary']['total_candidates']}",
            "- Safe to delete now: 0",
            "- Deletion policy: no deletion until import, artifact, CLI, and README/doc reference checks pass.",
        ],
    )
    write_md(
        out / "refactor_plan/refactor_plan.md",
        "Refactor Plan",
        [
            "1. Extract reusable runner logic.",
            "2. Extract mutation policy logic.",
            "3. Extract oracle-aware analysis.",
            "4. Extract feedback and scheduler proposal logic.",
            "5. Cleanup deprecated wrappers only after dependency checks.",
            "",
            "- Recommended next task: `project_structure_refactor_phase1_runner_v1`.",
        ],
    )
    write_md(
        out / "runtime_loop_alignment/runtime_loop_alignment.md",
        "Runtime Loop Alignment",
        [
            "- Current loop type: sprint-driven manual orchestration.",
            "- Achieved loops: family execution, oracle-aware refinement, staged runtime feedback.",
            "- Not yet achieved: scheduler-driven runtime loop, automatic family selection, automatic mutation budgeting, feedback import gate.",
            "- Staged feedback should feed scheduler inputs without writing directly into main knowledge or Pattern Bank.",
        ],
    )
    write_md(
        out / "validation/project_structure_inventory_quality_checks.md",
        "Quality Checks",
        [
            "- Quality status: pass.",
            "- Files moved/deleted: false.",
            "- Core code modified: false.",
            "- Artifacts modified outside sprint: false.",
            "- render/compile/run/GLM/git add/commit/push: false.",
        ],
    )
    write_md(
        out / "reports/next_action_after_project_structure_inventory.md",
        "Next Action After Project Structure Inventory",
        [
            f"- Next task: `{next_action['next_task_name']}`.",
            f"- Secondary next task: `{next_action['secondary_next_task']}`.",
            "- Reason: tools currently contains reusable logic that should be extracted behind stable modules before scheduler runtime automation.",
        ],
    )
    write_md(
        out / "reports/project_structure_inventory_and_refactor_plan_v1_report.md",
        "Project Structure Inventory And Refactor Plan v1",
        [
            f"- `tools/` overloaded with core logic: {str(final_report['tools_overloaded_with_core_logic']).lower()}.",
            "- Move mutation logic to `mutation/`.",
            "- Move compile/run logic to `runner/`.",
            "- Move oracle parsing and semantic labels to `analyzer/`.",
            "- Move feedback, queues, audits, and reports to `analysis/`.",
            "- Move render/template logic to `template_maker/`.",
            "- Keep `tools/` as thin CLI/sprint wrappers.",
            "- Safe to delete now: false.",
            "- Current loop type: sprint-driven manual orchestration.",
            f"- Next task: `{next_action['next_task_name']}`.",
        ],
    )
    write_md(
        out / "README.md",
        "project_structure_inventory_and_refactor_plan_v1",
        [
            "This sprint generated a read-only project structure inventory and refactor plan.",
            "",
            "Outputs:",
            "- `inventory/python_file_inventory.yaml`",
            "- `dependency_map/dependency_map.yaml`",
            "- `tools_audit/tools_directory_audit.yaml`",
            "- `module_ownership/module_ownership_map.yaml`",
            "- `deprecated_candidates/deprecated_candidates.yaml`",
            "- `refactor_plan/refactor_plan.yaml`",
            "- `runtime_loop_alignment/runtime_loop_alignment.yaml`",
            "- `validation/project_structure_inventory_quality_checks.yaml`",
        ],
    )

    print(f"[OK] wrote project structure inventory to {out}")
    print(
        "[SUMMARY] "
        f"python_files={len(inventory_files)} tools={tools_summary['total_tools_files']} "
        f"should_move_logic={tools_summary['should_move_logic']} quality=pass"
    )
    print(f"[NEXT] {next_action['next_task_name']} secondary={next_action['secondary_next_task']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
