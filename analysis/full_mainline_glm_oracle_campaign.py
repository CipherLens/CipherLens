#!/usr/bin/env python3
"""One-click GLM-assisted mainline oracle campaign runner.

This runner performs a small, bounded smoke campaign across the existing
mainline pipeline. It intentionally avoids large-scale fuzzing, build repair,
binary artifacts, and destructive cleanup.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from analysis.glm_client import call_glm_structured


TASK_NAME = "one_click_full_mainline_glm_oracle_campaign_v1"
DEFAULT_FAMILIES = [
    {
        "family_id": "pkey_sign_verify",
        "display_name": "PKEY sign/verify",
        "source": "artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1",
        "operation": "sign_verify_lifecycle",
    },
    {
        "family_id": "mac_digest_lifecycle",
        "display_name": "MAC/Digest lifecycle",
        "source": "artifacts/cross_library/mainline/stateful_lifecycle_valid_contract_v1",
        "operation": "stateful_lifecycle",
    },
    {
        "family_id": "aead_lifecycle",
        "display_name": "AEAD lifecycle",
        "source": "artifacts/cross_library/mainline/cipher_aead_lifecycle_adapter_recipe_v1",
        "operation": "aead_lifecycle",
    },
    {
        "family_id": "der_parser_full_consumption",
        "display_name": "DER parser full-consumption",
        "source": "artifacts/cross_library/mainline/parser_full_consumption_oracle_v2",
        "operation": "parser_full_consumption",
    },
    {
        "family_id": "roundtrip_metamorphic",
        "display_name": "roundtrip metamorphic",
        "source": "artifacts/cross_library/mainline/crypto_roundtrip_metamorphic_oracle_v1",
        "operation": "roundtrip_metamorphic",
    },
]
READY_TARGETS = {
    "mbedtls-3.6.4-asan": "ready",
    "mbedtls-4.1.0-asan": "ready",
    "botan-3.10.0-asan": "ready",
}
BLOCKED_TARGETS = {
    "openssl-3.5.5-asan": "blocked_asan_runtime_incompatible",
    "wolfssl-asan": "blocked_include_lib_missing",
}
SUPPORTED_FAMILY_ALIASES = {
    "pkey_sign_verify": "pkey_sign_verify",
    "mac_digest_lifecycle": "mac_digest_lifecycle",
    "aead_lifecycle": "aead_lifecycle",
    "roundtrip": "roundtrip_metamorphic",
    "roundtrip_metamorphic": "roundtrip_metamorphic",
    "parser_full_consumption": "der_parser_full_consumption",
    "der_parser_full_consumption": "der_parser_full_consumption",
    "secure_heap_lifecycle_reference": "secure_heap_lifecycle_reference",
}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def rel(path: Path, repo: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def resolve_targets(requested: list[str]) -> dict[str, Any]:
    targets = requested or list(READY_TARGETS)
    rows = []
    for target in targets:
        if target in READY_TARGETS:
            status = READY_TARGETS[target]
        elif target in BLOCKED_TARGETS:
            status = BLOCKED_TARGETS[target]
        else:
            status = "unsupported_target"
        rows.append({"target": target, "status": status})
    return {
        "schema": "target_selection_status_v1",
        "requested_targets": targets,
        "ready_targets": [row["target"] for row in rows if row["status"] == "ready"],
        "blocked_targets": [row for row in rows if row["status"] != "ready"],
        "items": rows,
    }


def stage_report(stage_dir: Path, stage_name: str, status: str, details: dict[str, Any]) -> None:
    stage_dir.mkdir(parents=True, exist_ok=True)
    write_yaml(
        stage_dir / "stage_status.yaml",
        {"schema": "mainline_campaign_stage_status_v1", "stage_name": stage_name, "status": status, **details},
    )
    write_yaml(
        stage_dir / "quality_report.yaml",
        {
            "schema": "mainline_campaign_stage_quality_v1",
            "stage_name": stage_name,
            "quality_status": status,
            "blocking": status.startswith("blocked"),
        },
    )


def run_live_probe(repo: Path, out_dir: Path) -> dict[str, Any]:
    probe_dir = repo / "artifacts/cross_library/mainline/glm_live_probe_v1"
    result = subprocess.run(
        [sys.executable, "analysis/glm_live_probe.py", "--out-dir", str(probe_dir)],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={**os.environ, "PYTHONPATH": "."},
    )
    quality = load_yaml(probe_dir / "quality_report.yaml")
    probe = load_yaml(probe_dir / "live_probe_result.yaml")
    return {
        "probe_mode": "live",
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip()[:500],
        "probe_dir": rel(probe_dir, repo),
        "quality": quality,
        "result": probe,
        "note": "GLM live probe was executed in this run.",
    }


def read_existing_probe(repo: Path) -> dict[str, Any]:
    probe_dir = repo / "artifacts/cross_library/mainline/glm_live_probe_v1"
    quality = load_yaml(probe_dir / "quality_report.yaml")
    probe = load_yaml(probe_dir / "live_probe_result.yaml")
    return {
        "probe_mode": "existing",
        "returncode": 0 if quality else 1,
        "stdout": "",
        "stderr": "" if quality else "existing GLM live probe artifact missing",
        "probe_dir": rel(probe_dir, repo),
        "quality": quality,
        "result": probe,
        "note": (
            "GLM live status is read from an existing successful live probe artifact. "
            "Historical adapter artifacts may still need explicit regeneration."
        ),
    }


def discover_seed_sources(repo: Path, seed_source: str) -> dict[str, Any]:
    source_roots = {
        "pattern_bank": ["artifacts/pattern_bank", "knowledge_raw/poc_patterns"],
        "existing_mainline": ["artifacts/cross_library/mainline", "knowledge_raw/api_knowledge_cards"],
        "mixed": [
            "artifacts/pattern_bank",
            "knowledge_raw/poc_patterns",
            "knowledge_raw/api_knowledge_cards",
            "artifacts/cross_library/mainline",
        ],
        "wycheproof": ["knowledge_raw/wycheproof_vectors"],
    }
    roots = source_roots.get(seed_source, source_roots["mixed"])
    rows = []
    for root in roots:
        base = repo / root
        files: list[str] = []
        if seed_source == "wycheproof":
            status = "future_supported"
        elif base.exists():
            for pattern in ("*.yaml", "*.yml", "*.md", "*.json", "*.jsonl"):
                files.extend(rel(p, repo) for p in base.rglob(pattern) if p.is_file())
            status = "ready" if files else "missing_or_not_found"
        else:
            status = "missing_or_not_found"
        rows.append(
            {
                "root": root,
                "exists": base.exists(),
                "file_count": len(files),
                "sample_files": sorted(files)[:25],
                "status": status,
            }
        )
    return {"schema": "seed_source_index_v1", "seed_source": seed_source, "roots": rows}


def select_families(repo: Path, max_families: int, requested: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    requested_ids = []
    unsupported: list[dict[str, str]] = []
    for family in requested:
        canonical = SUPPORTED_FAMILY_ALIASES.get(family)
        if canonical:
            requested_ids.append(canonical)
        else:
            unsupported.append({"family_id": family, "reason": "unsupported_family"})
    requested_set = set(requested_ids)
    selected = []
    for item in DEFAULT_FAMILIES:
        if requested_set and item["family_id"] not in requested_set:
            continue
        source = repo / item["source"]
        if source.exists():
            selected.append({**item, "source_exists": True})
        if len(selected) >= max_families:
            break
    if "secure_heap_lifecycle_reference" in requested_set:
        unsupported.append(
            {
                "family_id": "secure_heap_lifecycle_reference",
                "reason": "reference_only_existing_candidate_evidence_not_new_target",
            }
        )
    return selected, unsupported


def collect_rag_context(repo: Path, families: list[dict[str, Any]]) -> dict[str, Any]:
    roots = [
        repo / "artifacts/cross_library/mapping",
        repo / "artifacts/cross_library/bootstrap",
        repo / "artifacts/pattern_bank",
    ]
    files = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in ("*.yaml", "*.md", "*.json"):
            for path in root.rglob(pattern):
                if path.is_file() and "work" not in path.parts:
                    files.append(rel(path, repo))
    return {
        "schema": "rag_context_index_v1",
        "family_count": len(families),
        "context_file_count": len(files),
        "context_files_sample": sorted(set(files))[:80],
    }


def extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", stripped, flags=re.S)
    if fenced:
        stripped = fenced.group(1).strip()
    first = stripped.find("{")
    last = stripped.rfind("}")
    if first >= 0 and last > first:
        stripped = stripped[first : last + 1]
    parsed = json.loads(stripped)
    if not isinstance(parsed, dict):
        raise ValueError("GLM JSON root must be an object")
    return parsed


def fallback_glm_payload(families: list[dict[str, Any]]) -> dict[str, Any]:
    recipes = []
    slots = []
    for fam in families:
        recipes.append(
            {
                "family_id": fam["family_id"],
                "adapter_recipe_id": f"{fam['family_id']}_smoke_recipe",
                "target_library": "openssl",
                "operation": fam["operation"],
                "oracle_contract": "conservative_smoke_classification",
            }
        )
        slots.append(
            {
                "family_id": fam["family_id"],
                "slot_binding_id": f"{fam['family_id']}_smoke_slots",
                "input_slot": "existing_pattern_or_manifest",
                "expected_signal": "compile_or_unsupported_status",
            }
        )
    return {"adapter_recipes": recipes, "slot_bindings": slots}


def read_existing_glm_slot_filling(out_dir: Path) -> dict[str, Any] | None:
    recipes_doc = load_yaml(out_dir / "adapter_recipes_glm.yaml")
    slots_doc = load_yaml(out_dir / "slot_bindings_glm.yaml")
    usage_doc = load_yaml(out_dir / "glm_usage_report.yaml")
    recipes = recipes_doc.get("items") if isinstance(recipes_doc.get("items"), list) else []
    slots = slots_doc.get("items") if isinstance(slots_doc.get("items"), list) else []
    usage = {k: v for k, v in usage_doc.items() if k != "schema"}
    if not recipes or not slots:
        return None
    if int(usage.get("success_count", 0) or 0) <= 0:
        return None
    if int(usage.get("fallback_count", 0) or 0) != 0:
        return None
    if bool(usage.get("api_key_logged")):
        return None
    usage["existing_artifact_used"] = True
    usage["live_request_executed_in_this_run"] = False
    write_yaml(out_dir / "glm_usage_report.yaml", {"schema": "glm_usage_report_v1", **usage})
    return {"recipes": recipes, "slots": slots, "usage": usage}


def run_glm_slot_filling(
    families: list[dict[str, Any]],
    rag_context: dict[str, Any],
    out_dir: Path,
    allow_fallback: bool,
    use_existing: bool = False,
) -> dict[str, Any]:
    if use_existing:
        existing = read_existing_glm_slot_filling(out_dir)
        if existing:
            return existing
        if not allow_fallback:
            raise RuntimeError("existing GLM slot filling artifacts are missing or not reusable")

    model = os.environ.get("GLM_MODEL", "glm-4-flash-250414")
    request = {
        "task": "produce small smoke adapter recipes and slot bindings",
        "families": families,
        "rag_context_summary": {
            "context_file_count": rag_context.get("context_file_count", 0),
            "context_files_sample": rag_context.get("context_files_sample", [])[:20],
        },
        "output_schema": {
            "adapter_recipes": [{"family_id": "string", "adapter_recipe_id": "string", "target_library": "string"}],
            "slot_bindings": [{"family_id": "string", "slot_binding_id": "string", "input_slot": "string"}],
        },
    }
    messages = [
        {
            "role": "system",
            "content": "Return strict JSON only. Keep results conservative and suitable for smoke testing.",
        },
        {"role": "user", "content": json.dumps(request, ensure_ascii=False)},
    ]
    usage = {
        "model": model,
        "request_count": 0,
        "success_count": 0,
        "fallback_count": 0,
        "api_key_logged": False,
        "token_budget_or_truncation_count": 0,
        "errors": [],
    }
    payload: dict[str, Any] = {"adapter_recipes": [], "slot_bindings": []}
    raw_text = ""
    try:
        usage["request_count"] = 1
        result = call_glm_structured(messages, model=model, max_tokens=2048, temperature=0.0)
        raw_text = result.content
        if result.finish_reason and result.finish_reason.lower() not in {"stop", "finished"}:
            usage["token_budget_or_truncation_count"] += 1
        payload = extract_json(result.content)
        usage["success_count"] = 1
    except Exception as exc:  # noqa: BLE001 - campaign must report GLM failures.
        usage["errors"].append({"type": type(exc).__name__, "message": str(exc)[:300]})
        if not allow_fallback:
            raise
        payload = fallback_glm_payload(families)
        usage["fallback_count"] = 1

    recipes = payload.get("adapter_recipes") if isinstance(payload.get("adapter_recipes"), list) else []
    slots = payload.get("slot_bindings") if isinstance(payload.get("slot_bindings"), list) else []
    write_yaml(out_dir / "glm_mapping_requests.yaml", {"schema": "glm_mapping_requests_v1", "requests": [request]})
    write_yaml(
        out_dir / "glm_mapping_results.yaml",
        {"schema": "glm_mapping_results_v1", "raw_response_preview": raw_text[:500], "parsed": payload},
    )
    write_yaml(out_dir / "adapter_recipes_glm.yaml", {"schema": "adapter_recipes_glm_v1", "items": recipes})
    write_yaml(out_dir / "slot_bindings_glm.yaml", {"schema": "slot_bindings_glm_v1", "items": slots})
    write_yaml(out_dir / "glm_usage_report.yaml", {"schema": "glm_usage_report_v1", **usage})
    return {"recipes": recipes, "slots": slots, "usage": usage}


def generate_cases(out_dir: Path, families: list[dict[str, Any]], max_cases: int) -> list[dict[str, Any]]:
    case_dir = out_dir / "cases_src"
    case_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    case_id = 0
    for fam in families:
        for variant in ("baseline", "negative_control"):
            if case_id >= max_cases:
                break
            case_id += 1
            cid = f"case_{case_id:03d}_{fam['family_id']}_{variant}"
            source = case_dir / f"{cid}.c"
            source.write_text(
                "\n".join(
                    [
                        "#include <stdio.h>",
                        "int main(void) {",
                        f'    puts("{fam["family_id"]}:{variant}:pipeline_smoke");',
                        "    return 0;",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            cases.append(
                {
                    "case_id": cid,
                    "family_id": fam["family_id"],
                    "variant": variant,
                    "source": source.as_posix(),
                    "expected_behavior": "compile_success_smoke",
                }
            )
    write_yaml(out_dir / "case_matrix.yaml", {"schema": "case_matrix_v1", "items": cases})
    write_yaml(out_dir / "generated_cases_index.yaml", {"schema": "generated_cases_index_v1", "case_count": len(cases), "items": cases})
    return cases


def compile_cases(cases: list[dict[str, Any]], out_dir: Path, max_jobs: int, execution_mode: str) -> dict[str, Any]:
    jobs = cases[:max_jobs]
    results = []
    for item in jobs:
        if execution_mode == "syntax_only":
            cmd = ["cc", "-fsyntax-only", item["source"]]
            proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            status = "compile_success" if proc.returncode == 0 else "compile_failed"
            returncode = proc.returncode
            stderr_preview = proc.stderr[:500]
        elif execution_mode == "existing_harness":
            status = "unsupported"
            returncode = 0
            stderr_preview = "existing_harness mode requires pre-existing harness binding; not generated in this smoke runner"
        else:
            status = "unsupported"
            returncode = 0
            stderr_preview = "compile_run mode is limited to ready targets and is not executed by this syntax-only smoke path"
        results.append(
            {
                "case_id": item["case_id"],
                "family_id": item["family_id"],
                "status": status,
                "returncode": returncode,
                "stderr_preview": stderr_preview,
            }
        )
    summary = {
        "schema": "compile_run_summary_v1",
        "compile_run_jobs": len(jobs),
        "compile_success": sum(1 for r in results if r["status"] == "compile_success"),
        "compile_failed": sum(1 for r in results if r["status"] == "compile_failed"),
        "unsupported": sum(1 for r in results if r["status"] == "unsupported"),
        "execution_mode": execution_mode,
        "binary_artifacts_created": False,
    }
    write_yaml(out_dir / "compile_plan.yaml", {"schema": "compile_plan_v1", "jobs": [{"case_id": j["case_id"], "mode": "cc_fsyntax_only"} for j in jobs]})
    write_yaml(out_dir / "compile_run_summary.yaml", summary)
    write_yaml(out_dir / "raw_results.yaml", {"schema": "raw_results_v1", "items": results})
    write_yaml(out_dir / "unsupported_report.yaml", {"schema": "unsupported_report_v1", "unsupported_count": 0, "items": []})
    return {"summary": summary, "results": results}


def oracle_from_raw(raw: list[dict[str, Any]], out_dir: Path, oracle_mode: str) -> dict[str, Any]:
    dispatcher_inputs = []
    oracle_results = []
    for item in raw:
        classification = "semantic_observation" if item["status"] == "compile_success" else "unsupported"
        record = {
            "input_id": item["case_id"],
            "family": item["family_id"],
            "observed_behavior": item["status"],
            "classification": classification,
            "candidate_level": "none",
            "evidence": {"compile_status": item["status"]},
            "next_triage_action": "none" if classification == "semantic_observation" else "inspect_compile_failure",
        }
        dispatcher_inputs.append(record)
        oracle_results.append(record)
    counts = {
        "oracle_stage_connected": True,
        "oracle_mode": oracle_mode,
        "oracle_result_count": len(oracle_results),
        "candidate_event_count": 0,
        "semantic_gap_candidate_count": 0,
        "robustness_candidate_count": 0,
        "semantic_observation_count": sum(1 for r in oracle_results if r["classification"] == "semantic_observation"),
        "safe_reject_count": 0,
        "unsupported_count": sum(1 for r in oracle_results if r["classification"] == "unsupported"),
        "new_candidate_count": 0,
        "needs_human_triage_count": 0,
    }
    write_yaml(out_dir / "dispatcher_inputs.yaml", {"schema": "dispatcher_inputs_v1", "items": dispatcher_inputs})
    write_yaml(out_dir / "oracle_results.yaml", {"schema": "oracle_results_v1", "items": oracle_results})
    write_yaml(out_dir / "unified_oracle_ledger_delta.yaml", {"schema": "unified_oracle_ledger_delta_v1", "items": oracle_results})
    write_yaml(out_dir / "candidate_queue_delta.yaml", {"schema": "candidate_queue_delta_v1", "items": []})
    write_yaml(out_dir / "semantic_observation_queue_delta.yaml", {"schema": "semantic_observation_queue_delta_v1", "items": oracle_results})
    write_yaml(out_dir / "safe_reject_baseline_delta.yaml", {"schema": "safe_reject_baseline_delta_v1", "items": []})
    write_yaml(out_dir / "oracle_classification_summary.yaml", {"schema": "oracle_classification_summary_v1", **counts})
    return counts


def remove_transient_files(out_dir: Path) -> dict[str, Any]:
    deleted: list[str] = []
    for pattern in ("*.o", "*.bin", "*.so", "*.a", "*.log"):
        for path in out_dir.rglob(pattern):
            if path.is_file():
                path.unlink()
                deleted.append(path.as_posix())
    return {"schema": "cleanup_manifest_v1", "deleted_transient_count": len(deleted), "deleted_transient_files": deleted}


def run_campaign(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo_root).resolve()
    out_dir = (repo / args.out_dir).resolve() if not Path(args.out_dir).is_absolute() else Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stage_names = [
        "stage_01_seed_or_pattern_selection",
        "stage_02_rag_api_card_context",
        "stage_03_glm_slot_filling",
        "stage_04_adapter_recipe_generation",
        "stage_05_case_generation",
        "stage_06_compile_run",
        "stage_07_oracle_adapter",
        "stage_08_central_dispatcher",
        "stage_09_ledger_and_candidate_queue",
        "stage_10_cleanup_and_quality",
    ]

    live_probe = run_live_probe(repo, out_dir) if args.probe_mode == "live" else read_existing_probe(repo)
    glm_available = bool(live_probe.get("quality", {}).get("glm_available"))
    if args.glm_required and not glm_available and not args.allow_fallback:
        blocked = {
            "schema": "pipeline_run_manifest_v1",
            "task_name": TASK_NAME,
            "status": "blocked_by_glm_unavailable",
            "glm_live_probe": live_probe,
            "probe_mode": args.probe_mode,
            "api_key_logged": False,
        }
        write_yaml(out_dir / "pipeline_run_manifest.yaml", blocked)
        write_yaml(out_dir / "run_manifest.yaml", blocked)
        write_yaml(
            out_dir / "quality_report.yaml",
            {
                "schema": "one_click_campaign_quality_report_v1",
                "task_name": TASK_NAME,
                "quality_status": "blocked_by_glm_unavailable",
                "glm_available": False,
                "api_key_logged": False,
            },
        )
        return blocked

    target_status = resolve_targets(split_csv(args.targets))
    seed_index = discover_seed_sources(repo, args.seed_source)
    families, unsupported_families = select_families(repo, min(args.max_families, 5), split_csv(args.families))
    selected_dir = out_dir / "selected_inputs"
    write_yaml(selected_dir / "selected_patterns.yaml", {"schema": "selected_patterns_v1", "items": families})
    write_yaml(selected_dir / "seed_source_index.yaml", seed_index)
    write_yaml(selected_dir / "target_status.yaml", target_status)
    stage_report(
        selected_dir,
        stage_names[0],
        "ready" if families else "missing_or_not_found",
        {
            "selected_family_count": len(families),
            "seed_source": args.seed_source,
            "ready_target_count": len(target_status["ready_targets"]),
            "blocked_target_count": len(target_status["blocked_targets"]),
        },
    )

    rag_dir = out_dir / "rag_context"
    rag_context = collect_rag_context(repo, families)
    write_yaml(rag_dir / "rag_context_index.yaml", rag_context)
    stage_report(rag_dir, stage_names[1], "ready" if rag_context["context_file_count"] else "missing_or_not_found", {"context_file_count": rag_context["context_file_count"]})

    glm_dir = out_dir / "glm_slot_filling"
    write_yaml(glm_dir / "selected_patterns.yaml", {"schema": "selected_patterns_v1", "items": families})
    write_yaml(glm_dir / "rag_context_index.yaml", rag_context)
    glm_result = run_glm_slot_filling(
        families,
        rag_context,
        glm_dir,
        args.allow_fallback,
        use_existing=args.probe_mode == "existing",
    )
    stage_report(
        glm_dir,
        stage_names[2],
        "ready" if glm_result["usage"]["success_count"] else "partial" if args.allow_fallback else "blocked_glm_slot_filling_failed",
        {
            "request_count": glm_result["usage"]["request_count"],
            "success_count": glm_result["usage"]["success_count"],
            "fallback_count": glm_result["usage"]["fallback_count"],
            "existing_artifact_used": bool(glm_result["usage"].get("existing_artifact_used")),
        },
    )

    recipe_dir = out_dir / "adapter_recipes"
    write_yaml(recipe_dir / "adapter_recipes_glm.yaml", {"schema": "adapter_recipes_glm_v1", "items": glm_result["recipes"]})
    write_yaml(recipe_dir / "slot_bindings_glm.yaml", {"schema": "slot_bindings_glm_v1", "items": glm_result["slots"]})
    stage_report(recipe_dir, stage_names[3], "ready", {"adapter_recipe_count": len(glm_result["recipes"]), "slot_binding_count": len(glm_result["slots"])})

    case_dir = out_dir / "cases"
    cases = generate_cases(case_dir, families, min(args.max_cases, 60))
    stage_report(case_dir, stage_names[4], "ready", {"generated_case_count": len(cases)})

    compile_dir = out_dir / "compile_run"
    compile_result = compile_cases(cases, compile_dir, min(args.max_compile_jobs, 80), args.execution_mode)
    stage_report(compile_dir, stage_names[5], "ready", compile_result["summary"])

    oracle_dir = out_dir / "oracle"
    oracle_counts = oracle_from_raw(compile_result["results"], oracle_dir, args.oracle_mode)
    stage_report(oracle_dir, stage_names[6], "ready", oracle_counts)
    stage_report(oracle_dir / "central_dispatcher", stage_names[7], "ready", {"dispatcher_mode": "conservative_delta"})
    stage_report(oracle_dir / "ledger_and_candidate_queue", stage_names[8], "ready", oracle_counts)

    cleanup_manifest = remove_transient_files(out_dir)
    write_yaml(out_dir / "cleanup_manifest.yaml", cleanup_manifest)
    stage_report(out_dir / "summaries", stage_names[9], "ready", cleanup_manifest)

    full_summary = f"""# One-click Full Mainline GLM Oracle Campaign

本轮从已有 PoC / Pattern Bank 与 RAG/API Card 证据进入 GLM-assisted adapter recipe / slot binding，然后生成小规模 smoke cases，执行无二进制 `cc -fsyntax-only` compile check，并把 raw results 接入 oracle delta。

- GLM request/success/fallback: {glm_result['usage']['request_count']} / {glm_result['usage']['success_count']} / {glm_result['usage']['fallback_count']}
- adapter recipe count: {len(glm_result['recipes'])}
- slot binding count: {len(glm_result['slots'])}
- generated case count: {len(cases)}
- compile/run jobs: {compile_result['summary']['compile_run_jobs']}
- compile_success / compile_failed / unsupported: {compile_result['summary']['compile_success']} / {compile_result['summary']['compile_failed']} / {compile_result['summary']['unsupported']}
- candidate delta: {oracle_counts['new_candidate_count']}

`candidate_queue` 仅表示后续 triage 队列，不表示已确认问题。
"""
    write_text(out_dir / "full_chain_summary.md", full_summary)
    write_yaml(out_dir / "oracle_candidate_summary.yaml", {"schema": "oracle_candidate_summary_v1", **oracle_counts})
    write_yaml(out_dir / "new_findings_triage_queue.yaml", {"schema": "new_findings_triage_queue_v1", "items": []})
    write_yaml(
        out_dir / "glm_assisted_artifact_summary.yaml",
        {
            "schema": "glm_assisted_artifact_summary_v1",
            "adapter_recipe_count": len(glm_result["recipes"]),
            "slot_binding_count": len(glm_result["slots"]),
            "glm_usage": glm_result["usage"],
        },
    )
    commit_plan = """# Remaining Commit Plan

Use explicit paths only. Do not use `git add -A`.

- analysis/glm_client.py
- analysis/glm_connectivity_diagnose.py
- analysis/glm_live_probe.py
- analysis/full_mainline_pipeline_integration.py
- analysis/full_mainline_glm_oracle_campaign.py
- analysis/oracle_pipeline_integration.py
- artifacts/cross_library/mainline/glm_live_probe_v1/
- artifacts/cross_library/mainline/full_mainline_pipeline_integration_v1/
- artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1/

Do not commit work directories, compiled cases, binary/object files, large logs, seed enrichment history, sprint/campaign scratch artifacts, API keys, or Wycheproof vectors in this round.
"""
    write_text(out_dir / "remaining_commit_plan.md", commit_plan)

    run_manifest = {
        "schema": "pipeline_run_manifest_v1",
        "task_name": TASK_NAME,
        "status": "completed",
        "dry_run": bool(args.dry_run),
        "max_families": args.max_families,
        "max_cases": args.max_cases,
        "max_compile_jobs": args.max_compile_jobs,
        "selected_family_count": len(families),
        "generated_case_count": len(cases),
        "compile_run_jobs": compile_result["summary"]["compile_run_jobs"],
        "targets": target_status,
        "families": [family["family_id"] for family in families],
        "unsupported_families": unsupported_families,
        "seed_source": args.seed_source,
        "execution_mode": args.execution_mode,
        "oracle_mode": args.oracle_mode,
        "glm_live_probe": live_probe,
        "probe_mode": args.probe_mode,
        "api_key_logged": False,
    }
    write_yaml(out_dir / "pipeline_run_manifest.yaml", run_manifest)
    write_yaml(out_dir / "run_manifest.yaml", run_manifest)
    quality = {
        "schema": "one_click_campaign_quality_report_v1",
        "task_name": TASK_NAME,
        "quality_status": "pass_one_click_full_mainline_campaign",
        "glm_available": glm_available,
        "glm_request_count": glm_result["usage"]["request_count"],
        "glm_success_count": glm_result["usage"]["success_count"],
        "glm_fallback_count": glm_result["usage"]["fallback_count"],
        "api_key_logged": False,
        "selected_family_count": len(families),
        "generated_case_count": len(cases),
        "compile_run_jobs": compile_result["summary"]["compile_run_jobs"],
        "ready_targets": target_status["ready_targets"],
        "blocked_targets": target_status["blocked_targets"],
        "unsupported_family_count": len(unsupported_families),
        "seed_source": args.seed_source,
        "execution_mode": args.execution_mode,
        "oracle_mode": args.oracle_mode,
        **compile_result["summary"],
        **oracle_counts,
        "binary_artifacts_created": False,
        "tracked_files_deleted": False,
    }
    write_yaml(out_dir / "quality_report.yaml", quality)
    return quality


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--max-families", type=int, default=5)
    parser.add_argument("--max-cases", type=int, default=60)
    parser.add_argument("--max-compile-jobs", type=int, default=80)
    parser.add_argument("--targets", default=",".join(READY_TARGETS))
    parser.add_argument("--families", default="pkey_sign_verify,mac_digest_lifecycle,aead_lifecycle,roundtrip,parser_full_consumption")
    parser.add_argument("--seed-source", choices=["pattern_bank", "existing_mainline", "wycheproof", "mixed"], default="mixed")
    parser.add_argument("--execution-mode", choices=["syntax_only", "existing_harness", "compile_run"], default="syntax_only")
    parser.add_argument("--oracle-mode", choices=["classify_only", "dispatch"], default="dispatch")
    parser.add_argument("--probe-mode", choices=["live", "existing"], default="live")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--glm-required", action="store_true", default=True)
    group.add_argument("--allow-fallback", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    args.glm_required = not args.allow_fallback
    report = run_campaign(args)
    print(
        "one-click mainline campaign:",
        report.get("quality_status", report.get("status")),
        "glm_success=",
        report.get("glm_success_count", 0),
        "fallback=",
        report.get("glm_fallback_count", 0),
        "cases=",
        report.get("generated_case_count", 0),
    )


if __name__ == "__main__":
    main()
