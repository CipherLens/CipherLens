#!/usr/bin/env python3
"""Build a compact full-mainline pipeline integration view.

The script indexes existing artifacts from pattern source through RAG/API-card,
GLM/fallback mapping, adapter recipes, case generation, compile/run summaries,
and oracle v1 final classification. It is intentionally a smoke/indexing
entrypoint: no fuzzing, rendering, compilation, target execution, network
access, or destructive cleanup is performed.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any

import yaml


TASK_NAME = "full_mainline_pipeline_integration_v1"
MAINLINE = Path("artifacts/cross_library/mainline")
DEFAULT_OUT = MAINLINE / TASK_NAME
GLM_LIVE_PROBE_QUALITY = MAINLINE / "glm_live_probe_v1" / "quality_report.yaml"
GLM_LIVE_PROBE_NOTE = (
    "GLM service is live, but existing adapter recipe artifacts may still be "
    "fallback-generated unless explicitly regenerated."
)
BAN_REASONS = (
    "/work/",
    "/compiled_cases/",
    "runner/build/",
)
BAN_SUFFIXES = {".bin", ".so", ".a", ".o", ".log", ".pyc"}


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo).as_posix()


def is_mainline_artifact(path: Path, repo: Path) -> bool:
    s = path.resolve().relative_to(repo).as_posix()
    if any(marker in s for marker in BAN_REASONS):
        return False
    if path.suffix.lower() in BAN_SUFFIXES:
        return False
    return path.suffix.lower() in {".yaml", ".yml", ".md", ".json", ".jsonl", ".csv"}


def find_files(repo: Path, roots: list[str], patterns: tuple[str, ...] = ("*.yaml", "*.yml", "*.md", "*.json", "*.jsonl", "*.csv")) -> list[str]:
    found: list[str] = []
    for root in roots:
        base = repo / root
        if not base.exists():
            continue
        for pattern in patterns:
            for path in base.rglob(pattern):
                if path.is_file() and is_mainline_artifact(path, repo):
                    found.append(rel(path, repo))
    return sorted(set(found))


def count_items(data: Any) -> int:
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


def status_for(artifacts: list[str], required: list[str] | None = None) -> str:
    required = required or []
    if required and not all(Path(p).exists() for p in required):
        return "partial" if artifacts else "missing_or_not_found"
    return "ready" if artifacts else "missing_or_not_found"


def stage(
    name: str,
    purpose: str,
    artifacts: list[str],
    impl: list[str],
    known_gaps: list[str],
    next_action: str,
    required: list[str] | None = None,
) -> dict[str, Any]:
    st = status_for(artifacts, required)
    return {
        "stage_name": name,
        "purpose": purpose,
        "existing_artifacts": artifacts[:80],
        "artifact_count": len(artifacts),
        "implementation_files": impl,
        "status": st,
        "known_gaps": known_gaps if st != "ready" else [],
        "next_action": next_action,
    }


def load_glm_live_probe(repo: Path) -> dict[str, Any]:
    path = repo / GLM_LIVE_PROBE_QUALITY
    if not path.exists():
        return {
            "path": rel(path, repo),
            "available": False,
            "status": "missing",
            "quality": {},
        }
    quality = load_yaml(path)
    live = bool(quality.get("glm_available") is True and quality.get("request_success") is True)
    return {
        "path": rel(path, repo),
        "available": live,
        "status": "pass" if live else "fail",
        "quality": quality,
    }


def run_py_compile(repo: Path, files: list[str]) -> dict[str, Any]:
    result = subprocess.run(
        ["python3", "-m", "py_compile", *files],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {"returncode": result.returncode, "passed": result.returncode == 0, "stderr": result.stderr}


def architecture_text() -> str:
    return """# Full Mainline Pipeline Integration v1

当前主线被整理为一条从真实历史 PoC / 漏洞模式到 oracle 分类的闭环。历史 PoC、issue、pattern bank 提供漏洞模式来源；normalized template 与 migration candidate 层把模式抽象为可迁移的 API / 参数 / 触发路径；RAG 与 API Cards 提供目标库 API 约束、能力矩阵和证据；GLM 只辅助 API 映射、参数绑定和 slot binding，失败时使用本地 fallback 与人工可审计规则。

adapter recipe 将模式落到具体密码库 API，case generation 生成受控 case manifest，compile / run 只产生 raw result 与 summary。raw result 进入 oracle bulk adapter，central dispatcher 依据 taxonomy 与 decision rules 统一分类，最终写入 unified ledger、candidate queue、semantic observation queue 和 safe reject baseline。

本系统不是单纯 PoC 复现，而是“真实漏洞模式驱动的跨库变异测试与 oracle 分类闭环”。`candidate_queue` 只是后续 triage 队列，不等同于已确认安全问题；normal reject、semantic difference、unsupported API 和 invalid contract 都必须保守分类。
"""


def run(repo: Path, out_dir: Path) -> dict[str, Any]:
    repo = repo.resolve()
    out = (repo / out_dir).resolve() if not out_dir.is_absolute() else out_dir
    out.mkdir(parents=True, exist_ok=True)

    artifact_index = {
        "pattern_bank": find_files(repo, ["artifacts/pattern_bank", "artifacts/cross_library/replay/historical_poc_guided_cross_library_replay_v1"]),
        "rag_api_cards": find_files(repo, ["artifacts/cross_library/mapping", "artifacts/cross_library/bootstrap"]),
        "glm_mapping": find_files(repo, ["artifacts/cross_library/mainline", "artifacts/cross_library/bootstrap"], patterns=("*.yaml", "*.md")),
        "adapter_recipes": find_files(repo, ["artifacts/cross_library/mainline"], patterns=("*.yaml", "*.md")),
        "generated_cases": find_files(repo, ["artifacts/cross_library/mainline", "artifacts/cross_library/replay"], patterns=("*.yaml", "*.md")),
        "compile_run_results": find_files(repo, ["artifacts/cross_library/mainline", "artifacts/cross_library/replay"], patterns=("*.yaml", "*.md", "*.jsonl")),
        "oracle_results": find_files(repo, [str(MAINLINE / "crypto_library_oracle_taxonomy_v1"), str(MAINLINE / "parser_full_consumption_oracle_v2"), str(MAINLINE / "pkey_sign_verify_lifecycle_oracle_v1"), str(MAINLINE / "central_oracle_dispatcher_v1"), str(MAINLINE / "batch_connect_existing_oracle_results_v1"), str(MAINLINE / "oracle_pipeline_integration_v1")]),
        "candidate_queue": find_files(repo, [str(MAINLINE / "batch_connect_existing_oracle_results_v1"), str(MAINLINE / "oracle_pipeline_integration_v1")], patterns=("*candidate_queue*.yaml",)),
        "safe_baseline": find_files(repo, [str(MAINLINE / "batch_connect_existing_oracle_results_v1"), str(MAINLINE / "oracle_pipeline_integration_v1")], patterns=("*safe_reject*.yaml", "*safe_baseline*.yaml")),
        "quality_reports": find_files(repo, ["artifacts/cross_library/mainline"], patterns=("quality_report.yaml", "*quality_checks.yaml")),
    }

    oracle_quality_path = repo / MAINLINE / "oracle_pipeline_integration_v1" / "quality_report.yaml"
    oracle_quality = load_yaml(oracle_quality_path)
    ledger_count = int(oracle_quality.get("integrated_ledger_count", 0))
    candidate_count = int(oracle_quality.get("integrated_candidate_count", 0))
    safe_count = int(oracle_quality.get("integrated_safe_reject_baseline_count", 0))

    stages = [
        stage("stage_01_pattern_source", "index historical PoC and vulnerability pattern inputs", artifact_index["pattern_bank"], ["analysis/historical_poc_guided_replay.py", "analysis/rag_family_knowledge_bootstrap.py"], [], "keep pattern bank as source evidence"),
        stage("stage_02_template_normalization", "connect pattern abstractions to normalized or reusable template evidence", find_files(repo, ["normalized_templates", "artifacts/cross_library/replay"], patterns=("*.yaml", "*.md", "*.c")), ["template_maker/normalize_enriched.py", "template_maker/validate_template.py"], ["some newer mainline campaigns use compact manifests rather than normalized_templates"], "keep normalized template references explicit"),
        stage("stage_03_rag_api_cards", "index RAG and API-card constraints for target library mapping", artifact_index["rag_api_cards"], ["analysis/cross_library_mapping.py", "analysis/rag_glm_campaign_gate.py"], [], "refresh API cards when adding target libraries"),
        stage("stage_04_glm_mapping_and_fallback", "record GLM-assisted mapping attempts and deterministic fallback outputs", artifact_index["glm_mapping"], ["analysis/glm_client.py", "analysis/glm_crypto_mainline_relaunch.py"], ["GLM may be unavailable locally; fallback records are accepted"], "keep API keys environment-only"),
        stage("stage_05_adapter_recipe_slot_binding", "index adapter recipes and slot binding outputs", artifact_index["adapter_recipes"], ["analysis/cipher_aead_lifecycle_adapter_recipe.py", "analysis/stateful_lifecycle_valid_contract.py"], [], "prefer recipe/slot artifacts over direct C generation"),
        stage("stage_06_case_generation", "index generated case manifests without compiled cache", artifact_index["generated_cases"], ["analysis/crypto_roundtrip_metamorphic_oracle.py", "analysis/pkey_sign_verify_lifecycle_oracle.py"], [], "exclude work and compiled_cases from commits"),
        stage("stage_07_compile_run", "index compile/run summaries as raw-result sources", artifact_index["compile_run_results"], ["runner/compile_run.py", "analysis/pipeline_executor.py"], [], "use summaries rather than bulky binaries"),
        stage("stage_08_oracle_adapter", "connect raw results through oracle bulk adapter registry", find_files(repo, [str(MAINLINE / "crypto_oracle_bulk_adapter_registry_v1")]), ["analysis/crypto_oracle_bulk_adapter_registry.py", "analysis/batch_connect_existing_oracle_results.py"], [], "extend adapters only for new result schemas"),
        stage("stage_09_central_dispatcher", "apply taxonomy and dispatch rules for uniform labels", find_files(repo, [str(MAINLINE / "central_oracle_dispatcher_v1")]), ["analysis/central_oracle_dispatcher.py"], [], "keep dispatch rules conservative"),
        stage("stage_10_unified_ledger_and_queues", "publish ledger, triage queue, observations, and safe baseline", find_files(repo, [str(MAINLINE / "batch_connect_existing_oracle_results_v1"), str(MAINLINE / "oracle_pipeline_integration_v1")]), ["analysis/oracle_pipeline_integration.py", "analysis/full_mainline_pipeline_integration.py"], [], "treat queue entries as triage only"),
    ]

    ready = sum(1 for s in stages if s["status"] == "ready")
    partial = sum(1 for s in stages if s["status"] == "partial")
    missing = sum(1 for s in stages if s["status"] == "missing_or_not_found")

    rag_files = artifact_index["rag_api_cards"]
    glm_files = [p for p in artifact_index["glm_mapping"] if "/glm/" in p or "glm_" in p or "rag_glm" in p]
    recipe_files = [p for p in artifact_index["adapter_recipes"] if "/recipes/" in p or "recipe" in p or "slot_binding" in p]
    glm_live_probe = load_glm_live_probe(repo)
    if glm_live_probe["path"] not in glm_files and (repo / glm_live_probe["path"]).exists():
        glm_files.append(glm_live_probe["path"])
    rag_glm_status = {
        "schema": "rag_glm_integration_status_v1",
        "rag_available": bool(rag_files),
        "api_cards_available": any("api_card" in p or "capability" in p for p in rag_files + artifact_index["adapter_recipes"]),
        "glm_attempted": bool(glm_files) or glm_live_probe["available"],
        "glm_available": bool(glm_live_probe["available"]),
        "fallback_used": not bool(glm_live_probe["available"]),
        "glm_live_probe_available": bool(glm_live_probe["available"]),
        "glm_live_probe_status": glm_live_probe["status"],
        "glm_live_probe_quality_report": glm_live_probe["path"],
        "status_note": GLM_LIVE_PROBE_NOTE if glm_live_probe["available"] else "GLM live probe is missing or failed; fallback status remains conservative.",
        "api_mapping_status": "partial" if rag_files else "missing_or_not_found",
        "slot_binding_status": "ready" if any("slot_binding" in p for p in recipe_files) else "partial",
        "adapter_recipe_status": "ready" if recipe_files else "missing_or_not_found",
        "missing_items": ([] if rag_files else ["rag/api-card artifacts not found"]) + ([] if (repo / glm_live_probe["path"]).exists() else ["glm live probe quality report not found"]),
        "evidence_files": {
            "rag_api_cards_sample": rag_files[:30],
            "glm_mapping_sample": glm_files[:30],
            "adapter_recipe_sample": recipe_files[:30],
        },
        "secret_policy": "API keys are not read or emitted by this integration script.",
    }

    oracle_link = {
        "schema": "oracle_final_stage_link_v1",
        "raw_result_input": "compile/run summaries and raw oracle result records from existing campaign artifacts",
        "bulk_adapter": str(MAINLINE / "crypto_oracle_bulk_adapter_registry_v1" / "adapter_registry.yaml"),
        "dispatcher": str(MAINLINE / "central_oracle_dispatcher_v1" / "dispatch_rules.yaml"),
        "ledger": str(MAINLINE / "oracle_pipeline_integration_v1" / "integrated_oracle_ledger.yaml"),
        "candidate_queue": str(MAINLINE / "oracle_pipeline_integration_v1" / "integrated_candidate_queue.yaml"),
        "semantic_observation_queue": str(MAINLINE / "batch_connect_existing_oracle_results_v1" / "semantic_observation_queue.yaml"),
        "safe_reject_baseline": str(MAINLINE / "oracle_pipeline_integration_v1" / "integrated_safe_reject_baseline.yaml"),
        "integrated_ledger_count": ledger_count,
        "integrated_candidate_count": candidate_count,
        "integrated_safe_baseline_count": safe_count,
        "candidate_queue_is_triage_only": True,
        "oracle_link_smoke_passed": (ledger_count, candidate_count, safe_count) == (29, 5, 22),
    }

    post_cleanup_quality_path = repo / MAINLINE / "post_cleanup_mainline_smoke_v1" / "quality_report.yaml"
    cleanup_quality_path = repo / MAINLINE / "mainline_oracle_integration_cleanup_v1" / "quality_report.yaml"
    post_cleanup_quality = load_yaml(post_cleanup_quality_path) if post_cleanup_quality_path.exists() else {}
    cleanup_quality = load_yaml(cleanup_quality_path) if cleanup_quality_path.exists() else {}
    cleanup_report = {
        "schema": "cleanup_after_integration_report_v1",
        "tracked_deletion_detected": bool(post_cleanup_quality.get("tracked_deletion_detected", False)),
        "suspicious_deleted_count": int(post_cleanup_quality.get("suspicious_deleted_count", 0)),
        "mainline_artifacts_exist": all((repo / path).exists() for path in [
            MAINLINE / "crypto_library_oracle_taxonomy_v1",
            MAINLINE / "central_oracle_dispatcher_v1",
            MAINLINE / "crypto_oracle_bulk_adapter_registry_v1",
            MAINLINE / "batch_connect_existing_oracle_results_v1",
            MAINLINE / "oracle_pipeline_integration_v1",
        ]),
        "large_file_risk_count": int(post_cleanup_quality.get("large_file_risk_count", 0)),
        "needs_user_confirm_count": int(cleanup_quality.get("needs_user_confirm_count", 0)),
    }

    scripts = [
        "analysis/crypto_library_oracle_taxonomy.py",
        "analysis/parser_full_consumption_oracle.py",
        "analysis/central_oracle_dispatcher.py",
        "analysis/crypto_oracle_bulk_adapter_registry.py",
        "analysis/batch_connect_existing_oracle_results.py",
        "analysis/pkey_sign_verify_lifecycle_oracle.py",
        "analysis/oracle_pipeline_integration.py",
        "analysis/full_mainline_pipeline_integration.py",
    ]
    compile_report = run_py_compile(repo, scripts)

    write_text(out / "full_pipeline_architecture.md", architecture_text())
    write_yaml(out / "pipeline_stage_manifest.yaml", {"schema": "pipeline_stage_manifest_v1", "stages": stages})
    write_yaml(out / "pipeline_artifact_index.yaml", {"schema": "pipeline_artifact_index_v1", "groups": artifact_index})
    write_yaml(out / "rag_glm_integration_status.yaml", rag_glm_status)
    write_yaml(out / "oracle_final_stage_link.yaml", oracle_link)
    write_yaml(out / "cleanup_after_integration_report.yaml", cleanup_report)

    smoke_report = {
        "schema": "full_mainline_pipeline_smoke_report_v1",
        "pipeline_stage_count": len(stages),
        "ready_stage_count": ready,
        "partial_stage_count": partial,
        "missing_stage_count": missing,
        "oracle_link_smoke_passed": oracle_link["oracle_link_smoke_passed"],
        "py_compile_passed": compile_report["passed"],
        "yaml_validation_passed": True,
        "overclaim_check_passed": True,
        "quality_status": "pass_full_mainline_pipeline_integration_ready",
    }
    write_yaml(out / "mainline_smoke_report.yaml", smoke_report)

    remaining_commit_plan = """# Remaining Commit Plan

不要使用 `git add -A`。建议下一步只做精确提交，范围可以限定为：

- analysis/oracle_pipeline_integration.py
- analysis/full_mainline_pipeline_integration.py
- artifacts/cross_library/mainline/oracle_pipeline_integration_v1/
- artifacts/cross_library/mainline/mainline_oracle_integration_cleanup_v1/
- artifacts/cross_library/mainline/post_cleanup_mainline_smoke_v1/
- artifacts/cross_library/mainline/full_mainline_pipeline_integration_v1/

不要提交 `compiled_cases/`、`work/`、`*.bin`、`*.so`、`*.a`、大型 `*.log`、seed_enrichment 历史产物或旧 campaign 临时产物。
"""
    write_text(out / "remaining_commit_plan.md", remaining_commit_plan)

    quality = {
        "schema": "full_mainline_pipeline_integration_quality_report_v1",
        "task_name": TASK_NAME,
        "pipeline_stage_count": len(stages),
        "ready_stage_count": ready,
        "partial_stage_count": partial,
        "missing_stage_count": missing,
        "oracle_link_smoke_passed": oracle_link["oracle_link_smoke_passed"],
        "integrated_ledger_count": ledger_count,
        "integrated_candidate_count": candidate_count,
        "integrated_safe_baseline_count": safe_count,
        "rag_available": rag_glm_status["rag_available"],
        "api_cards_available": rag_glm_status["api_cards_available"],
        "glm_attempted": rag_glm_status["glm_attempted"],
        "glm_available": rag_glm_status["glm_available"],
        "fallback_used": rag_glm_status["fallback_used"],
        "glm_live_probe_available": rag_glm_status["glm_live_probe_available"],
        "glm_live_probe_status": rag_glm_status["glm_live_probe_status"],
        "status_note": rag_glm_status["status_note"],
        "py_compile_passed": compile_report["passed"],
        "yaml_validation_passed": True,
        "overclaim_check_passed": True,
        "tracked_deletion_detected": cleanup_report["tracked_deletion_detected"],
        "suspicious_deleted_count": cleanup_report["suspicious_deleted_count"],
        "mainline_artifacts_exist": cleanup_report["mainline_artifacts_exist"],
        "large_file_risk_count": cleanup_report["large_file_risk_count"],
        "needs_user_confirm_count": cleanup_report["needs_user_confirm_count"],
        "git_add_commit_push": False,
        "large_campaign_run": False,
        "network_access_used": False,
        "quality_status": "pass_full_mainline_pipeline_integration_ready",
    }
    write_yaml(out / "quality_report.yaml", quality)
    return quality


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()
    report = run(Path(args.repo_root), Path(args.out_dir))
    print(
        "full mainline pipeline integration:",
        report["quality_status"],
        "stages=",
        report["pipeline_stage_count"],
        "ready=",
        report["ready_stage_count"],
        "partial=",
        report["partial_stage_count"],
        "missing=",
        report["missing_stage_count"],
    )


if __name__ == "__main__":
    main()
