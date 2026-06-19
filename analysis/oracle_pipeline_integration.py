#!/usr/bin/env python3
"""Integrate oracle v1 artifacts into a stable mainline entrypoint.

This module is intentionally lightweight: it reads existing dispatcher,
adapter-registry, and batch-connector artifacts, then emits a reproducible
mainline integration view. It does not run fuzzing, rendering, compilation, or
target binaries.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


DEFAULT_BASE = Path("artifacts/cross_library/mainline")
DISPATCHER_DIR = DEFAULT_BASE / "central_oracle_dispatcher_v1"
REGISTRY_DIR = DEFAULT_BASE / "crypto_oracle_bulk_adapter_registry_v1"
BATCH_DIR = DEFAULT_BASE / "batch_connect_existing_oracle_results_v1"
DEFAULT_OUT_DIR = DEFAULT_BASE / "oracle_pipeline_integration_v1"


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def item_count(data: Any) -> int:
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return len(items)
        count = data.get("count")
        if isinstance(count, int):
            return count
    if isinstance(data, list):
        return len(data)
    return 0


def with_integration_metadata(source_path: Path, data: Any, role: str) -> dict[str, Any]:
    if isinstance(data, dict):
        out = dict(data)
    else:
        out = {"items": data if isinstance(data, list) else []}
    out["integration_metadata"] = {
        "schema": "oracle_pipeline_integrated_artifact_v1",
        "source_path": str(source_path),
        "role": role,
        "large_campaign_run": False,
        "render_compile_run_executed": False,
        "candidate_queue_is_triage_only": role == "candidate_queue",
    }
    return out


def build_entrypoint(
    repo_root: Path,
    out_dir: Path,
    dispatcher_input_schema: dict[str, Any],
    dispatcher_output_schema: dict[str, Any],
    dispatch_rules: dict[str, Any],
    adapter_registry: dict[str, Any],
    bulk_dispatch_mapping: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "oracle_pipeline_entrypoint_v1",
        "entrypoint_name": "oracle_pipeline_integration_v1",
        "repo_root": str(repo_root),
        "out_dir": str(out_dir),
        "purpose": "connect existing oracle v1 artifacts into the mainline automation flow",
        "inputs": {
            "raw_campaign_results": "future campaign output directories",
            "dispatcher_input_schema": str(DISPATCHER_DIR / "dispatcher_input_schema.yaml"),
            "dispatcher_output_schema": str(DISPATCHER_DIR / "dispatcher_output_schema.yaml"),
            "dispatch_rules": str(DISPATCHER_DIR / "dispatch_rules.yaml"),
            "adapter_registry": str(REGISTRY_DIR / "adapter_registry.yaml"),
            "bulk_dispatch_mapping": str(REGISTRY_DIR / "bulk_dispatch_mapping.yaml"),
        },
        "loaded_config_summary": {
            "dispatcher_input_schema_keys": sorted(dispatcher_input_schema.keys()),
            "dispatcher_output_schema_keys": sorted(dispatcher_output_schema.keys()),
            "dispatch_rule_keys": sorted(dispatch_rules.keys()),
            "adapter_registry_keys": sorted(adapter_registry.keys()),
            "bulk_dispatch_mapping_keys": sorted(bulk_dispatch_mapping.keys()),
        },
        "pipeline_steps": [
            "campaign writes raw result artifacts",
            "bulk adapter registry maps raw result shapes into oracle input records",
            "central dispatcher applies oracle taxonomy and dispatch rules",
            "batch connector appends records into unified oracle ledger",
            "integration layer exposes candidate_queue, semantic_observation_queue, and safe_reject_baseline",
        ],
        "outputs": {
            "integrated_oracle_ledger": str(out_dir / "integrated_oracle_ledger.yaml"),
            "integrated_candidate_queue": str(out_dir / "integrated_candidate_queue.yaml"),
            "integrated_safe_reject_baseline": str(out_dir / "integrated_safe_reject_baseline.yaml"),
        },
        "guards": {
            "candidate_queue_is_not_vulnerability_confirmation": True,
            "semantic_observation_requires_triage": True,
            "safe_reject_baseline_is_baseline_evidence": True,
            "no_fuzz_render_compile_run": True,
        },
    }


def build_flow_summary(counts: dict[str, int]) -> str:
    return f"""# Oracle Pipeline Integration v1

本文件说明 oracle v1 在当前 cross-library mainline 中的位置。未来 campaign 只需要输出原始运行结果，bulk adapter registry 负责把不同结果形状整理成 dispatcher 输入，central dispatcher 再依据 taxonomy / dispatch rules 生成统一分类。

当前 integration 层没有运行新的 fuzz、render、compile 或目标程序；它只复用已有 batch connector 输出，形成可复现的主线入口视图。`candidate_queue` 表示需要后续人工或更强 oracle triage 的候选队列，不是漏洞确认结论。

## Integrated Counts

- unified_oracle_ledger: {counts["ledger"]}
- candidate_queue: {counts["candidate"]}
- semantic_observation_queue: {counts["semantic_observation"]}
- safe_reject_baseline: {counts["safe_reject"]}
"""


def run(repo_root: Path, out_dir: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    out_dir = (repo_root / out_dir).resolve() if not out_dir.is_absolute() else out_dir

    config_paths = {
        "dispatcher_input_schema": repo_root / DISPATCHER_DIR / "dispatcher_input_schema.yaml",
        "dispatcher_output_schema": repo_root / DISPATCHER_DIR / "dispatcher_output_schema.yaml",
        "dispatch_rules": repo_root / DISPATCHER_DIR / "dispatch_rules.yaml",
        "adapter_registry": repo_root / REGISTRY_DIR / "adapter_registry.yaml",
        "bulk_dispatch_mapping": repo_root / REGISTRY_DIR / "bulk_dispatch_mapping.yaml",
    }
    batch_paths = {
        "ledger": repo_root / BATCH_DIR / "unified_oracle_ledger.yaml",
        "candidate": repo_root / BATCH_DIR / "candidate_queue.yaml",
        "semantic_observation": repo_root / BATCH_DIR / "semantic_observation_queue.yaml",
        "safe_reject": repo_root / BATCH_DIR / "safe_reject_baseline.yaml",
    }

    configs = {name: load_yaml(path) for name, path in config_paths.items()}
    batches = {name: load_yaml(path) for name, path in batch_paths.items()}
    counts = {name: item_count(data) for name, data in batches.items()}

    generated_files = [
        out_dir / "mainline_flow_summary.md",
        out_dir / "oracle_pipeline_entrypoint.yaml",
        out_dir / "integrated_oracle_ledger.yaml",
        out_dir / "integrated_candidate_queue.yaml",
        out_dir / "integrated_safe_reject_baseline.yaml",
        out_dir / "integration_smoke_report.yaml",
        out_dir / "quality_report.yaml",
    ]

    entrypoint = build_entrypoint(
        repo_root=repo_root,
        out_dir=out_dir,
        dispatcher_input_schema=configs["dispatcher_input_schema"],
        dispatcher_output_schema=configs["dispatcher_output_schema"],
        dispatch_rules=configs["dispatch_rules"],
        adapter_registry=configs["adapter_registry"],
        bulk_dispatch_mapping=configs["bulk_dispatch_mapping"],
    )
    write_yaml(out_dir / "oracle_pipeline_entrypoint.yaml", entrypoint)
    write_yaml(
        out_dir / "integrated_oracle_ledger.yaml",
        with_integration_metadata(batch_paths["ledger"], batches["ledger"], "unified_oracle_ledger"),
    )
    write_yaml(
        out_dir / "integrated_candidate_queue.yaml",
        with_integration_metadata(batch_paths["candidate"], batches["candidate"], "candidate_queue"),
    )
    write_yaml(
        out_dir / "integrated_safe_reject_baseline.yaml",
        with_integration_metadata(batch_paths["safe_reject"], batches["safe_reject"], "safe_reject_baseline"),
    )
    write_text(out_dir / "mainline_flow_summary.md", build_flow_summary(counts))

    missing_inputs = [
        str(path)
        for path in list(config_paths.values()) + list(batch_paths.values())
        if not path.exists()
    ]
    smoke_passed = not missing_inputs and counts["ledger"] > 0
    smoke_report = {
        "schema": "oracle_pipeline_integration_smoke_report_v1",
        "missing_inputs": missing_inputs,
        "config_files_loaded": len(config_paths),
        "batch_outputs_loaded": len(batch_paths),
        "integrated_ledger_count": counts["ledger"],
        "integrated_candidate_count": counts["candidate"],
        "integrated_semantic_observation_count": counts["semantic_observation"],
        "integrated_safe_reject_baseline_count": counts["safe_reject"],
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "large_campaign_run": False,
        "smoke_passed": smoke_passed,
    }
    write_yaml(out_dir / "integration_smoke_report.yaml", smoke_report)

    quality_report = {
        "schema": "oracle_pipeline_integration_quality_report_v1",
        "task_name": "mainline_oracle_integration_cleanup_v1",
        "generated_files": [str(path.relative_to(repo_root)) for path in generated_files],
        "integrated_ledger_count": counts["ledger"],
        "integrated_candidate_count": counts["candidate"],
        "integrated_semantic_observation_count": counts["semantic_observation"],
        "integrated_safe_reject_baseline_count": counts["safe_reject"],
        "candidate_queue_is_not_vulnerability_confirmation": True,
        "network_access_used": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "large_campaign_run": False,
        "smoke_passed": smoke_passed,
        "quality_status": "pass_oracle_pipeline_integration_ready" if smoke_passed else "needs_input_repair",
    }
    write_yaml(out_dir / "quality_report.yaml", quality_report)
    return quality_report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", help="repository root")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="integration output directory")
    args = parser.parse_args()

    report = run(Path(args.repo_root), Path(args.out_dir))
    print(
        "oracle pipeline integration ready:",
        report["quality_status"],
        "ledger=",
        report["integrated_ledger_count"],
        "candidate=",
        report["integrated_candidate_count"],
    )


if __name__ == "__main__":
    main()
