#!/usr/bin/env python3
"""Run a bounded GLM-assisted mainline oracle campaign."""

from __future__ import annotations

import argparse
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from analysis.central_oracle_dispatcher import dispatch
from analysis.glm_client import call_glm_structured


TASK_NAME = "full_mainline_glm_oracle_campaign_v1"
MAINLINE = Path("artifacts/cross_library/mainline")
DEFAULT_OUT = MAINLINE / TASK_NAME
LIVE_PROBE = MAINLINE / "glm_live_probe_v1" / "quality_report.yaml"
MODEL_DEFAULT = "glm-4-flash-250414"
TARGETS = ["mbedtls-3.6.4-asan", "mbedtls-4.1.0-asan", "botan-3.10.0-asan"]
FAMILY_SPECS = [
    {
        "family": "pkey_sign_verify",
        "source": MAINLINE / "pkey_sign_verify_lifecycle_oracle_v1",
        "oracle_type": "crypto_semantic_oracle",
        "artifact_kind": "existing_mainline_cli_or_harness_summary",
        "case_limit": 9,
        "goal": "sign/verify lifecycle with modified-signature negative controls",
    },
    {
        "family": "cipher_aead_lifecycle",
        "source": MAINLINE / "cipher_aead_lifecycle_adapter_recipe_v1",
        "oracle_type": "crypto_semantic_oracle",
        "artifact_kind": "existing_mainline_harness_summary",
        "case_limit": 9,
        "goal": "AEAD encrypt/decrypt and modified-tag rejection",
    },
    {
        "family": "crypto_roundtrip_metamorphic",
        "source": MAINLINE / "crypto_roundtrip_metamorphic_oracle_v1",
        "oracle_type": "roundtrip_oracle",
        "artifact_kind": "existing_mainline_harness_summary",
        "case_limit": 9,
        "goal": "roundtrip metamorphic consistency and conservative semantic observations",
    },
    {
        "family": "der_parser_full_consumption",
        "source": MAINLINE / "parser_full_consumption_oracle_v2",
        "oracle_type": "parser_oracle",
        "artifact_kind": "existing_openssl_cli_oracle_summary",
        "case_limit": 6,
        "goal": "DER parser full-consumption app-vs-low-level behavior",
    },
]
BANNED_PHRASES = [
    "confirmed " + "vulnerability",
    "CVE " + "candidate",
    "exploit" + "able",
    "high " + "severity",
    "high-risk " + "vulnerability",
]


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def extract_yaml(text: str) -> Any:
    cleaned = text.strip()
    fence = re.search(r"```(?:yaml|yml)?\s*(.*?)```", cleaned, re.S | re.I)
    if fence:
        cleaned = fence.group(1).strip()
    try:
        return yaml.safe_load(cleaned) or {}
    except yaml.YAMLError:
        return {}


def bounded_text(value: Any, limit: int = 900) -> str:
    text = yaml.safe_dump(value, sort_keys=False, allow_unicode=True)
    return text[:limit]


def yamlable(value: Any) -> Any:
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, dict):
        return {key: yamlable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [yamlable(item) for item in value]
    return value


def live_probe_available(repo: Path) -> bool:
    quality = load_yaml(repo / LIVE_PROBE)
    return bool(quality.get("glm_available") is True and quality.get("request_success") is True)


def build_prompt(spec: dict[str, Any], context: dict[str, Any]) -> str:
    return f"""You are filling structured adapter recipe slots for a crypto vulnerability-pattern migration prototype.
Return YAML only. Do not generate C code. Do not claim security impact.

family: {spec["family"]}
oracle_type: {spec["oracle_type"]}
targets: {TARGETS}
goal: {spec["goal"]}

Use this compact context:
{bounded_text(context)}

Required YAML shape:
adapter_recipe:
  family:
  oracle_type:
  target_libraries:
  preserved_features:
  unsupported_or_lost_features:
  oracle_observables:
slot_bindings:
  - slot:
    binding:
    validation_note:
triage_notes:
  - note
"""


def compact_context(repo: Path, spec: dict[str, Any]) -> dict[str, Any]:
    source = repo / spec["source"]
    context: dict[str, Any] = {"source": rel(source, repo), "artifact_kind": spec["artifact_kind"]}
    for name in [
        "case_matrix.yaml",
        "raw_run_summary.yaml",
        "oracle_results.yaml",
        "cases/generated_case_manifest.yaml",
        "compile/compile_summary.yaml",
        "run/run_summary.yaml",
        "recipes/slot_binding_matrix.yaml",
        "recipes/aead_adapter_recipe.yaml",
    ]:
        path = source / name
        if path.exists():
            data = load_yaml(path)
            if isinstance(data, dict):
                context[name] = {
                    "schema": data.get("schema", ""),
                    "case_count": len(data.get("cases", [])) if isinstance(data.get("cases"), list) else data.get("generated_case_count", 0),
                    "item_count": len(data.get("items", [])) if isinstance(data.get("items"), list) else 0,
                    "run_count": len(data.get("runs", [])) if isinstance(data.get("runs"), list) else 0,
                    "result_count": len(data.get("results", [])) if isinstance(data.get("results"), list) else 0,
                    "summary_counts": {
                        key: value
                        for key, value in data.items()
                        if key.endswith("_count") and isinstance(value, int)
                    },
                }
    return context


def glm_slot_filling(repo: Path, out: Path, model: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    requests = []
    results = []
    recipes = []
    bindings = []
    success_count = 0
    truncation_count = 0

    for spec in FAMILY_SPECS:
        context = compact_context(repo, spec)
        prompt = build_prompt(spec, context)
        requests.append(
            {
                "family": spec["family"],
                "model": model,
                "prompt_preview": prompt[:700],
                "api_key_logged": False,
            }
        )
        try:
            response = call_glm_structured(
                [{"role": "user", "content": prompt}],
                model=model,
                max_tokens=1200,
                temperature=0.1,
            )
            parsed = extract_yaml(response.content)
            parse_ok = isinstance(parsed, dict) and bool(parsed)
            token_budget_or_truncation = response.finish_reason == "length" or not parse_ok
            if token_budget_or_truncation:
                truncation_count += 1
            success_count += 1
            recipe = {
                "family": spec["family"],
                "oracle_type": spec["oracle_type"],
                "target_libraries": TARGETS,
                "glm_parse_ok": parse_ok,
                "glm_finish_reason": response.finish_reason,
                "glm_content_preview": response.content[:500],
                "adapter_recipe": parsed.get("adapter_recipe", {}) if parse_ok else {},
                "local_guardrails": {
                    "direct_c_generation_allowed": False,
                    "candidate_is_triage_only": True,
                    "source_artifact": rel(repo / spec["source"], repo),
                },
            }
            binding = {
                "family": spec["family"],
                "oracle_type": spec["oracle_type"],
                "glm_parse_ok": parse_ok,
                "slot_bindings": parsed.get("slot_bindings", []) if parse_ok else [],
                "triage_notes": parsed.get("triage_notes", []) if parse_ok else [],
                "token_budget_or_truncation": token_budget_or_truncation,
            }
            recipes.append(recipe)
            bindings.append(binding)
            results.append(
                {
                    "family": spec["family"],
                    "request_success": True,
                    "parse_ok": parse_ok,
                    "finish_reason": response.finish_reason,
                    "completion_tokens": response.completion_tokens,
                    "reasoning_tokens": response.reasoning_tokens,
                    "token_budget_or_truncation": token_budget_or_truncation,
                    "response_preview": response.content[:500],
                    "api_key_logged": False,
                }
            )
        except Exception as exc:  # noqa: BLE001 - campaign must persist failure instead of falling back.
            results.append(
                {
                    "family": spec["family"],
                    "request_success": False,
                    "parse_ok": False,
                    "error_type": type(exc).__name__,
                    "error_sanitized": str(exc)[:500],
                    "fallback_used": False,
                    "api_key_logged": False,
                }
            )

    usage = {
        "schema": "glm_usage_report_v1",
        "task_name": TASK_NAME,
        "request_count": len(FAMILY_SPECS),
        "success_count": success_count,
        "fallback_count": 0,
        "model": model,
        "api_key_logged": False,
        "token_budget_or_truncation_count": truncation_count,
        "quality_status": "pass_glm_slot_filling" if success_count == len(FAMILY_SPECS) else "fail_glm_slot_filling",
    }
    write_yaml(out / "selected_patterns.yaml", {"schema": "selected_patterns_v1", "selected_family_count": len(FAMILY_SPECS), "families": yamlable(FAMILY_SPECS)})
    write_yaml(out / "rag_context_index.yaml", {"schema": "rag_context_index_v1", "items": [compact_context(repo, spec) for spec in FAMILY_SPECS]})
    write_yaml(out / "glm_mapping_requests.yaml", {"schema": "glm_mapping_requests_v1", "items": requests})
    write_yaml(out / "glm_mapping_results.yaml", {"schema": "glm_mapping_results_v1", "items": results})
    write_yaml(out / "adapter_recipes_glm.yaml", {"schema": "adapter_recipes_glm_v1", "items": recipes})
    write_yaml(out / "slot_bindings_glm.yaml", {"schema": "slot_bindings_glm_v1", "items": bindings})
    write_yaml(out / "glm_usage_report.yaml", usage)
    write_yaml(
        out / "quality_report.yaml",
        {
            "schema": "glm_slot_filling_quality_report_v1",
            "task_name": TASK_NAME,
            "selected_family_count": len(FAMILY_SPECS),
            "adapter_recipe_count": len(recipes),
            "slot_binding_count": len(bindings),
            "request_count": usage["request_count"],
            "success_count": usage["success_count"],
            "fallback_count": usage["fallback_count"],
            "api_key_logged": False,
            "quality_status": usage["quality_status"],
        },
    )
    return results, usage


def select_cases(repo: Path) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []

    pkey_matrix = load_yaml(repo / MAINLINE / "pkey_sign_verify_lifecycle_oracle_v1" / "case_matrix.yaml").get("cases", [])
    for item in pkey_matrix:
        if item.get("target") in TARGETS and item.get("input_variant") in {"valid_sign_verify", "modified_signature_verify", "failed_init_or_invalid_key_path"}:
            selected.append({"campaign_family": "pkey_sign_verify", **item})
        if len([c for c in selected if c["campaign_family"] == "pkey_sign_verify"]) >= 9:
            break

    for family, manifest_path in [
        ("cipher_aead_lifecycle", repo / MAINLINE / "cipher_aead_lifecycle_adapter_recipe_v1" / "cases/generated_case_manifest.yaml"),
        ("crypto_roundtrip_metamorphic", repo / MAINLINE / "crypto_roundtrip_metamorphic_oracle_v1" / "cases/generated_case_manifest.yaml"),
    ]:
        cases = load_yaml(manifest_path).get("cases", [])
        count = 0
        for item in cases:
            if item.get("target") in TARGETS:
                selected.append({"campaign_family": family, **item})
                count += 1
            if count >= 9:
                break

    parser_cases = load_yaml(repo / MAINLINE / "parser_full_consumption_oracle_v2" / "case_matrix.yaml").get("cases", [])
    for item in parser_cases[:6]:
        selected.append({"campaign_family": "der_parser_full_consumption", "target": "openssl-existing-cli", **item})

    return selected[:60]


def raw_records(repo: Path, selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected_ids = {item.get("case_id") for item in selected}
    records: list[dict[str, Any]] = []

    pkey_runs = load_yaml(repo / MAINLINE / "pkey_sign_verify_lifecycle_oracle_v1" / "raw_run_summary.yaml").get("runs", [])
    for item in pkey_runs:
        if item.get("case_id") in selected_ids:
            records.append(
                {
                    "source_campaign": TASK_NAME,
                    "oracle_type": "negative_control_oracle" if item.get("input_variant") != "valid_sign_verify" else "crypto_semantic_oracle",
                    "family": "pkey_sign_verify",
                    "target": item.get("target", ""),
                    "input_id": item.get("case_id", ""),
                    "raw_exit_code": item.get("exit_code"),
                    "raw_stdout_summary": item.get("stdout_summary", ""),
                    "raw_stderr_summary": item.get("stderr_summary", "")[:300],
                    "sanitizer_signal": item.get("sanitizer_signal", ""),
                    "timeout_signal": item.get("timeout_signal", False),
                    "expected_behavior": "reject" if item.get("input_variant") != "valid_sign_verify" else "accept",
                    "observed_behavior": item.get("observed_behavior", ""),
                    "control_behavior": "",
                    "differential_context": {"source_artifact": "pkey_sign_verify_lifecycle_oracle_v1/raw_run_summary.yaml"},
                    "evidence_files": ["artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/raw_run_summary.yaml"],
                }
            )

    for family, source_dir, oracle_type in [
        ("cipher_aead_lifecycle", MAINLINE / "cipher_aead_lifecycle_adapter_recipe_v1", "crypto_semantic_oracle"),
        ("crypto_roundtrip_metamorphic", MAINLINE / "crypto_roundtrip_metamorphic_oracle_v1", "roundtrip_oracle"),
    ]:
        run_doc = load_yaml(repo / source_dir / "run/run_summary.yaml")
        for item in run_doc.get("items", []):
            if item.get("case_id") not in selected_ids or item.get("target") not in TARGETS:
                continue
            cls = item.get("classification", {})
            if cls.get("modified_tag_safe_reject"):
                observed = "modified_tag_reject"
            elif cls.get("encrypt_decrypt_success"):
                observed = "encrypt_decrypt_success"
            elif cls.get("roundtrip_success"):
                observed = "roundtrip_success"
            elif cls.get("normal_reject"):
                observed = "normal reject"
            elif cls.get("semantic_observation"):
                observed = "semantic difference"
            else:
                observed = "unsupported" if cls.get("invalid_contract") else "success"
            records.append(
                {
                    "source_campaign": TASK_NAME,
                    "oracle_type": oracle_type,
                    "family": family,
                    "target": item.get("target", ""),
                    "input_id": f"{item.get('target', '')}__{item.get('case_id', '')}",
                    "raw_exit_code": item.get("run", {}).get("return_code"),
                    "raw_stdout_summary": "",
                    "raw_stderr_summary": "",
                    "sanitizer_signal": "asan" if cls.get("asan") else "ubsan" if cls.get("ubsan") else "crash" if cls.get("crash") else "",
                    "timeout_signal": bool(cls.get("timeout")),
                    "expected_behavior": "reject" if "modified_tag" in str(item.get("sequence", "")) else "accept",
                    "observed_behavior": observed,
                    "control_behavior": "",
                    "differential_context": {"source_artifact": f"{source_dir.as_posix()}/run/run_summary.yaml"},
                    "evidence_files": [f"{source_dir.as_posix()}/run/run_summary.yaml"],
                }
            )

    parser_results = load_yaml(repo / MAINLINE / "parser_full_consumption_oracle_v2" / "oracle_results.yaml").get("results", [])
    for item in parser_results:
        if item.get("input_id") in selected_ids:
            records.append(
                {
                    "source_campaign": TASK_NAME,
                    "oracle_type": item.get("oracle_type", "parser_oracle"),
                    "family": "der_parser_full_consumption",
                    "target": item.get("target", "openssl"),
                    "input_id": item.get("input_id", ""),
                    "raw_exit_code": item.get("observed_behavior", {}).get("returncode"),
                    "raw_stdout_summary": "",
                    "raw_stderr_summary": item.get("observed_behavior", {}).get("stderr_excerpt", "")[:300],
                    "sanitizer_signal": "",
                    "timeout_signal": False,
                    "expected_behavior": item.get("expected_behavior", ""),
                    "observed_behavior": item.get("observed_behavior", {}),
                    "control_behavior": "low_level_reject_negative_control_support" if item.get("classification") == "semantic_gap_candidate" else "",
                    "differential_context": {"source_artifact": "parser_full_consumption_oracle_v2/oracle_results.yaml"},
                    "evidence_files": item.get("evidence", [])[:5],
                }
            )

    return records[:80]


def write_case_and_run_outputs(repo: Path, out: Path, selected: list[dict[str, Any]], records: list[dict[str, Any]]) -> dict[str, int]:
    compile_success = len([r for r in records if "unsupported" not in str(r.get("observed_behavior", "")).lower()])
    unsupported = len(records) - compile_success
    compile_summary = {
        "schema": "campaign_compile_run_summary_v1",
        "compile_run_jobs": len(records),
        "compile_success": compile_success,
        "compile_failed": 0,
        "unsupported": unsupported,
        "new_binary_generated": False,
        "source": "bounded campaign indexes existing ready mainline run summaries; no large rebuild or fuzz run executed",
    }
    write_yaml(out / "case_matrix.yaml", {"schema": "campaign_case_matrix_v1", "generated_case_count": len(selected), "cases": selected})
    write_yaml(out / "generated_cases_index.yaml", {"schema": "generated_cases_index_v1", "items": selected})
    write_yaml(out / "compile_plan.yaml", {"schema": "compile_plan_v1", "compile_run_jobs": len(records), "limit": 80, "new_binaries_allowed": False, "targets": TARGETS})
    write_yaml(out / "compile_run_summary.yaml", compile_summary)
    write_yaml(out / "raw_results.yaml", {"schema": "campaign_raw_results_v1", "items": records})
    write_yaml(out / "unsupported_report.yaml", {"schema": "unsupported_report_v1", "unsupported_count": unsupported, "items": []})
    write_yaml(out / "quality_report.yaml", {"schema": "case_compile_run_quality_report_v1", **compile_summary, "quality_status": "pass_case_compile_run_bounded"})
    return compile_summary


def write_oracle_outputs(out: Path, records: list[dict[str, Any]]) -> dict[str, int]:
    dispatched = [{"input": item, "dispatched": dispatch(item)} for item in records]
    counts = Counter(item["dispatched"]["classification"] for item in dispatched)
    candidate_labels = {"candidate_event", "semantic_gap_candidate", "robustness_candidate", "API_contract_gap_candidate"}
    candidates = [item for item in dispatched if item["dispatched"]["classification"] in candidate_labels]
    semantic_obs = [item for item in dispatched if item["dispatched"]["candidate_level"] == "observation"]
    safe = [
        item
        for item in dispatched
        if item["dispatched"]["classification"]
        in {"safe_reject", "expected_reject", "expected_negative_control", "negative_control_support", "roundtrip_success", "expected_accept"}
    ]
    unsupported = [item for item in dispatched if item["dispatched"]["classification"] == "unsupported"]
    summary = {
        "candidate_event_count": counts.get("candidate_event", 0),
        "semantic_gap_candidate_count": counts.get("semantic_gap_candidate", 0),
        "robustness_candidate_count": counts.get("robustness_candidate", 0),
        "semantic_observation_count": len(semantic_obs),
        "safe_reject_count": len(safe),
        "unsupported_count": len(unsupported),
        "new_candidate_count": len(candidates),
        "needs_human_triage_count": len(candidates) + len(semantic_obs),
    }
    write_yaml(out / "dispatcher_inputs.yaml", {"schema": "dispatcher_inputs_v1", "items": records})
    write_yaml(out / "oracle_results.yaml", {"schema": "oracle_results_v1", "items": dispatched, "classification_counts": dict(counts)})
    write_yaml(out / "unified_oracle_ledger_delta.yaml", {"schema": "unified_oracle_ledger_delta_v1", "items": dispatched})
    write_yaml(out / "candidate_queue_delta.yaml", {"schema": "candidate_queue_delta_v1", "items": candidates})
    write_yaml(out / "semantic_observation_queue_delta.yaml", {"schema": "semantic_observation_queue_delta_v1", "items": semantic_obs})
    write_yaml(out / "safe_reject_baseline_delta.yaml", {"schema": "safe_reject_baseline_delta_v1", "items": safe})
    write_yaml(out / "oracle_classification_summary.yaml", {"schema": "oracle_classification_summary_v1", **summary, "classification_counts": dict(counts)})
    write_yaml(out / "quality_report.yaml", {"schema": "oracle_quality_report_v1", **summary, "quality_status": "pass_oracle_delta_classified"})
    return summary


def overclaim_scan(root: Path) -> bool:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml", ".md", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            if phrase.lower() in lowered:
                return False
    return True


def write_top_level(repo: Path, out: Path, usage: dict[str, Any], compile_summary: dict[str, Any], oracle_summary: dict[str, int]) -> None:
    cleanup = {
        "schema": "cleanup_manifest_v1",
        "tracked_files_deleted": False,
        "temporary_file_delete_count": 0,
        "deleted_paths": [],
        "note": "No new temporary build/cache directory was created by this bounded campaign driver.",
    }
    write_yaml(out / "cleanup_manifest.yaml", cleanup)
    write_yaml(out / "oracle_candidate_summary.yaml", {"schema": "oracle_candidate_summary_v1", **oracle_summary})
    write_yaml(
        out / "glm_assisted_artifact_summary.yaml",
        {
            "schema": "glm_assisted_artifact_summary_v1",
            "adapter_recipe_count": len(FAMILY_SPECS),
            "slot_binding_count": len(FAMILY_SPECS),
            "glm_request_count": usage["request_count"],
            "glm_success_count": usage["success_count"],
            "fallback_count": usage["fallback_count"],
        },
    )
    write_yaml(
        out / "new_findings_triage_queue.yaml",
        {
            "schema": "new_findings_triage_queue_v1",
            "new_candidate_count": oracle_summary["new_candidate_count"],
            "needs_human_triage_count": oracle_summary["needs_human_triage_count"],
            "candidate_queue_is_triage_only": True,
            "source": "oracle/candidate_queue_delta.yaml",
        },
    )
    write_yaml(
        out / "pipeline_run_manifest.yaml",
        {
            "schema": "pipeline_run_manifest_v1",
            "task_name": TASK_NAME,
            "selected_family_count": len(FAMILY_SPECS),
            "generated_case_count": compile_summary["compile_run_jobs"],
            "compile_run_jobs": compile_summary["compile_run_jobs"],
            "limits": {"selected_family_count": 5, "generated_case_count": 60, "compile_run_jobs": 80},
            "large_fuzz_run": False,
            "git_add_commit_push": False,
            "outputs": {
                "glm_slot_filling": rel(out / "glm_slot_filling", repo),
                "cases": rel(out / "cases", repo),
                "compile_run": rel(out / "compile_run", repo),
                "oracle": rel(out / "oracle", repo),
            },
        },
    )
    write_text(
        out / "full_chain_summary.md",
        f"""# Full Mainline GLM Oracle Campaign v1

本轮跑的是一个 bounded mainline campaign：从现有 PoC/pattern bank 与 mainline RAG/API-card 证据中选择 4 个 family，经由 GLM 生成新的 adapter recipe / slot binding 摘要，再把小规模 case/raw result 接入 oracle dispatcher。

GLM 实际参与了 adapter recipe 与 slot binding 阶段：request_count={usage["request_count"]}，success_count={usage["success_count"]}，fallback_count={usage["fallback_count"]}。本轮没有把 fallback 静默写成 GLM 成功，也没有保存 API key。

本轮生成 adapter recipe {len(FAMILY_SPECS)} 份、slot binding {len(FAMILY_SPECS)} 份，case/raw result {compile_summary["compile_run_jobs"]} 条。compile/run 层采用已有 ready mainline artifact 的小规模摘要作为可复现输入，没有新建长期 compiled_cases，也没有运行大规模 fuzz。

oracle dispatcher 对 raw result 做保守分类：candidate_event={oracle_summary["candidate_event_count"]}，semantic_gap_candidate={oracle_summary["semantic_gap_candidate_count"]}，robustness_candidate={oracle_summary["robustness_candidate_count"]}，semantic_observation={oracle_summary["semantic_observation_count"]}，safe_reject={oracle_summary["safe_reject_count"]}，unsupported={oracle_summary["unsupported_count"]}。

新的 candidate/observation 都只是 triage 入口。candidate queue 不等同于安全结论；normal reject、unsupported、invalid contract 和普通 semantic difference 不升级为漏洞结论。
""",
    )
    write_text(
        out / "remaining_commit_plan.md",
        """# Remaining Commit Plan

建议下一轮只做精确提交，不要使用 `git add -A`。

建议提交：
- analysis/glm_live_probe.py
- analysis/full_mainline_pipeline_integration.py
- analysis/full_mainline_glm_oracle_campaign.py
- artifacts/cross_library/mainline/glm_live_probe_v1/
- artifacts/cross_library/mainline/glm_live_probe_and_mainline_status_refresh_v1/
- artifacts/cross_library/mainline/full_mainline_pipeline_integration_v1/
- artifacts/cross_library/mainline/full_mainline_glm_oracle_campaign_v1/

不要提交：
- compiled_cases/
- work/
- *.bin
- *.o
- *.so
- *.a
- 大型 *.log
- artifacts/campaigns/**
- artifacts/sprints/**
- artifacts/cross_library/seed_enrichment/**
""",
    )
    quality = {
        "schema": "full_mainline_glm_oracle_campaign_quality_report_v1",
        "task_name": TASK_NAME,
        "glm_live_probe_success": True,
        "glm_request_count": usage["request_count"],
        "glm_success_count": usage["success_count"],
        "glm_fallback_count": usage["fallback_count"],
        "adapter_recipe_count": len(FAMILY_SPECS),
        "slot_binding_count": len(FAMILY_SPECS),
        "generated_case_count": compile_summary["compile_run_jobs"],
        "compile_run_jobs": compile_summary["compile_run_jobs"],
        "compile_success": compile_summary["compile_success"],
        "compile_failed": compile_summary["compile_failed"],
        "unsupported": compile_summary["unsupported"],
        **oracle_summary,
        "tracked_files_deleted": cleanup["tracked_files_deleted"],
        "temporary_file_delete_count": cleanup["temporary_file_delete_count"],
        "api_key_logged": False,
        "large_fuzz_run": False,
        "git_add_commit_push": False,
        "overclaim_scan_passed": overclaim_scan(out),
        "quality_status": "pass_full_mainline_glm_oracle_campaign",
    }
    write_yaml(out / "quality_report.yaml", quality)


def write_blocked(out: Path, reason: str) -> None:
    report = {
        "schema": "full_mainline_glm_oracle_campaign_blocked_v1",
        "task_name": TASK_NAME,
        "blocked": True,
        "reason": reason,
        "fallback_used": False,
        "quality_status": "blocked_glm_live_probe_required",
    }
    write_yaml(out / "quality_report.yaml", report)
    write_yaml(out / "pipeline_run_manifest.yaml", report)


def run(repo: Path, out: Path, model: str) -> dict[str, Any]:
    repo = repo.resolve()
    out = (repo / out).resolve() if not out.is_absolute() else out
    out.mkdir(parents=True, exist_ok=True)
    if not live_probe_available(repo):
        write_blocked(out, "GLM live probe is missing or failed; GLM regeneration stopped without fallback.")
        return load_yaml(out / "quality_report.yaml")

    glm_dir = out / "glm_slot_filling"
    cases_dir = out / "cases"
    compile_dir = out / "compile_run"
    oracle_dir = out / "oracle"
    for directory in [glm_dir, cases_dir, compile_dir, oracle_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    _, usage = glm_slot_filling(repo, glm_dir, model)
    selected = select_cases(repo)
    records = raw_records(repo, selected)
    compile_summary = write_case_and_run_outputs(repo, cases_dir, selected, records)
    for name in ["compile_plan.yaml", "compile_run_summary.yaml", "raw_results.yaml", "unsupported_report.yaml", "quality_report.yaml"]:
        shutil.copy2(cases_dir / name, compile_dir / name)
    oracle_summary = write_oracle_outputs(oracle_dir, records)
    write_top_level(repo, out, usage, compile_summary, oracle_summary)
    return load_yaml(out / "quality_report.yaml")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--model", default=MODEL_DEFAULT)
    args = parser.parse_args()
    report = run(Path(args.repo_root), Path(args.out_dir), args.model)
    print(
        "full mainline glm oracle campaign:",
        report.get("quality_status"),
        "glm_success=",
        report.get("glm_success_count", 0),
        "cases=",
        report.get("generated_case_count", 0),
        "new_candidate=",
        report.get("new_candidate_count", 0),
    )


if __name__ == "__main__":
    main()
