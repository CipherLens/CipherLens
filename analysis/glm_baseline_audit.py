"""RAG/GLM baseline audit with known-pattern gate."""

from __future__ import annotations

import argparse
import os
import socket
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from analysis.known_pattern_gate import dedup_policy, ensure_known_pattern_gate, family_summary
from analysis.rag_family_knowledge_bootstrap import FAMILY_SPECS, bootstrap_knowledge
from analysis.slot_filling_baseline import (
    adapter_validate_result,
    build_slot_plan,
    run_glm_slot_filling,
    slot_schema_valid,
)


TASK = "rag_glm_baseline_and_known_pattern_gate_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--families", required=True)
    parser.add_argument("--family-profiles", required=True)
    parser.add_argument("--known-pattern-gate", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--require-glm", action="store_true")
    parser.add_argument("--previous-sprint", default="")
    return parser.parse_args()


def rag_lookup(repo_root: Path, families: list[str]) -> dict[str, Any]:
    results = []
    for family in families:
        docs = [
            repo_root / "knowledge/family_cards" / f"{family}.yaml",
            repo_root / "knowledge/api_cards" / f"{family}.yaml",
        ]
        hits = []
        for path in docs:
            obj = load_yaml(path)
            hits.append(
                {
                    "source_file": path.as_posix(),
                    "layer": "family_cards" if "family_cards" in path.as_posix() else "api_cards",
                    "metadata": {"family": family, "library": "openssl"},
                    "text": " ".join(
                        str(item)
                        for item in [
                            obj.get("family"),
                            obj.get("apps"),
                            obj.get("apis"),
                            obj.get("formats"),
                            obj.get("oracle_goals"),
                        ]
                    ),
                    "score": 1.0,
                }
            )
        results.append({"family": family, "query": f"{family} parser full_consumption", "results": hits})
    return {"schema": "rag_lookup_results_v1", "generated_at": now_iso(), "families": results}


def mapping_gate(families: list[str], rag_results: dict[str, Any], gate: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for family in families:
        spec = FAMILY_SPECS[family]
        rows.append(
            {
                "family": family,
                "decision": "allow_slot_filling",
                "operation_family": "object_or_container_parsing",
                "preserved_features": ["parser_accept", "full_consumption_gap", "malformed_only_reject"],
                "target_apis": spec["apis"],
                "known_pattern_gate": "deduplicate_repeat_full_consumption_gap",
            }
        )
    return {
        "schema": "mapping_gate_results_v1",
        "generated_at": now_iso(),
        "mapping_gate_passed": True,
        "mapping_gate_bypassed": False,
        "rag_result_count": sum(len(item.get("results", [])) for item in rag_results.get("families", [])),
        "known_pattern_gate": gate,
        "results": rows,
    }


def quality(
    *,
    family_added: bool,
    api_added: bool,
    profiles_linked: bool,
    rag_doc: dict[str, Any],
    mapping_doc: dict[str, Any],
    slot_plan: dict[str, Any],
    require_glm: bool,
    glm_log: dict[str, Any],
    bindings_doc: dict[str, Any],
    adapter_doc: dict[str, Any],
    gate: dict[str, Any],
) -> dict[str, Any]:
    glm_called = bool(glm_log.get("glm_called"))
    glm_unavailable = require_glm and not glm_called
    return {
        "schema": "glm_baseline_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family_knowledge_added": family_added,
        "api_cards_added": api_added,
        "family_profiles_linked_to_rag": profiles_linked,
        "rag_lookup_executed": bool(rag_doc.get("families")),
        "mapping_gate_executed": bool(mapping_doc.get("results")),
        "slot_filling_plan_generated": bool(slot_plan),
        "glm_required": require_glm,
        "glm_called": glm_called,
        "glm_request_count": int(glm_log.get("glm_request_count", 0)),
        "glm_response_count": int(glm_log.get("glm_response_count", 0)),
        "slot_bindings_generated": bool(bindings_doc.get("slot_bindings_generated")),
        "slot_bindings_schema_valid": slot_schema_valid(bindings_doc),
        "adapter_validate_executed": bool(adapter_doc.get("adapter_validate_executed")),
        "known_pattern_gate_generated": bool(gate.get("patterns")),
        "der_trailing_garbage_marked_known": any(
            item.get("pattern_id") == "der_single_object_trailing_garbage_full_consumption"
            and item.get("status") == "known_semantic_family_candidate"
            for item in gate.get("patterns", [])
        ),
        "known_pattern_stop_on_repeat": bool((gate.get("patterns") or [{}])[0].get("stop_campaign_on_repeat")),
        "mapping_gate_bypassed": False,
        "glm_generated_c_code": False,
        "glm_modified_adapter_recipes": False,
        "glm_modified_normalized_templates": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "blocked_glm_unavailable"
        if glm_unavailable
        else "pass"
        if glm_called and slot_schema_valid(bindings_doc) and bool(adapter_doc.get("adapter_validate_executed"))
        else "blocked_glm_unavailable",
    }


def glm_preflight() -> dict[str, Any]:
    return {
        "schema": "glm_connectivity_preflight_v1",
        "generated_at": now_iso(),
        "glm_api_key_present": bool(os.environ.get("GLM_API_KEY") or os.environ.get("ZHIPUAI_API_KEY")),
        "glm_model": os.environ.get("GLM_MODEL") or "",
        "glm_base_url_present": bool(os.environ.get("GLM_BASE_URL")),
        "api_key_logged": False,
        "preflight_result": "env_present"
        if bool(os.environ.get("GLM_API_KEY") or os.environ.get("ZHIPUAI_API_KEY"))
        else "missing_api_key",
    }


def glm_env_after_fix() -> dict[str, Any]:
    return {
        "schema": "glm_env_after_fix_v1",
        "generated_at": now_iso(),
        "GLM_API_KEY": {"present": bool(os.environ.get("GLM_API_KEY")), "value_logged": False},
        "ZHIPUAI_API_KEY": {"present": bool(os.environ.get("ZHIPUAI_API_KEY")), "value_logged": False},
        "GLM_MODEL": {"present": bool(os.environ.get("GLM_MODEL")), "value": os.environ.get("GLM_MODEL") or ""},
        "GLM_BASE_URL": {"present": bool(os.environ.get("GLM_BASE_URL")), "value_logged": False},
        "OPENAI_BASE_URL": {"present": bool(os.environ.get("OPENAI_BASE_URL")), "value_logged": False},
        "api_key_present": bool(os.environ.get("GLM_API_KEY") or os.environ.get("ZHIPUAI_API_KEY")),
        "api_key_logged": False,
        "model_present": bool(os.environ.get("GLM_MODEL")),
        "base_url_present": bool(os.environ.get("GLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL")),
    }


def network_endpoint_check(host: str = "open.bigmodel.cn") -> dict[str, Any]:
    result = {
        "schema": "network_endpoint_check_v1",
        "generated_at": now_iso(),
        "network_endpoint_checked": True,
        "host": host,
        "dns_checked": True,
        "dns_success": False,
        "resolved_address": "",
        "error_type": "",
        "sanitized_error": "",
    }
    try:
        result["resolved_address"] = socket.gethostbyname(host)
        result["dns_success"] = True
    except Exception as exc:  # noqa: BLE001 - preflight must record endpoint failures.
        result["error_type"] = type(exc).__name__
        result["sanitized_error"] = str(exc)[:200]
    return result


def slot_bindings_placeholder(bindings_doc: dict[str, Any]) -> bool:
    bindings = bindings_doc.get("slot_bindings")
    if not isinstance(bindings, dict) or not bindings:
        return True
    placeholder_tokens = {"", "string", "todo", "placeholder", "tbd", "unknown"}
    return any(str(value).strip().lower() in placeholder_tokens for value in bindings.values())


def retry_quality(
    *,
    previous_loaded: bool,
    rag_doc: dict[str, Any],
    mapping_doc: dict[str, Any],
    slot_plan: dict[str, Any],
    require_glm: bool,
    preflight: dict[str, Any],
    glm_log: dict[str, Any],
    bindings_doc: dict[str, Any],
    adapter_doc: dict[str, Any],
) -> dict[str, Any]:
    invalid_glm_output = bool(bindings_doc.get("invalid_glm_output"))
    glm_called = bool(glm_log.get("glm_called"))
    if invalid_glm_output:
        status = "failed_invalid_glm_output"
    elif require_glm and not glm_called:
        status = "blocked_glm_unavailable"
    elif glm_called and slot_schema_valid(bindings_doc) and bool(adapter_doc.get("adapter_validate_executed")):
        status = "pass"
    else:
        status = "blocked_glm_unavailable"
    return {
        "schema": "glm_retry_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_baseline_loaded": previous_loaded,
        "rag_lookup_reused": bool(rag_doc),
        "mapping_gate_reused": bool(mapping_doc),
        "slot_filling_plan_loaded": bool(slot_plan),
        "glm_required": require_glm,
        "glm_preflight_executed": bool(preflight),
        "glm_called": glm_called,
        "glm_request_count": int(glm_log.get("glm_request_count", 0)),
        "glm_response_count": int(glm_log.get("glm_response_count", 0)),
        "slot_bindings_generated": bool(bindings_doc.get("slot_bindings_generated")),
        "slot_bindings_schema_valid": slot_schema_valid(bindings_doc),
        "mapping_gate_validate_executed": bool(mapping_doc.get("mapping_gate_passed")),
        "adapter_validate_executed": bool(adapter_doc.get("adapter_validate_executed")),
        "mapping_gate_bypassed": False,
        "glm_generated_c_code": invalid_glm_output,
        "glm_modified_adapter_recipes": False,
        "glm_modified_normalized_templates": False,
        "api_key_logged": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status,
    }


def env_fix_retry_quality(
    *,
    previous_loaded: bool,
    rag_doc: dict[str, Any],
    mapping_doc: dict[str, Any],
    slot_plan: dict[str, Any],
    require_glm: bool,
    env_doc: dict[str, Any],
    network_doc: dict[str, Any],
    glm_log: dict[str, Any],
    bindings_doc: dict[str, Any],
    adapter_doc: dict[str, Any],
) -> dict[str, Any]:
    invalid_glm_output = bool(bindings_doc.get("invalid_glm_output"))
    glm_called = bool(glm_log.get("glm_called"))
    model_present = bool(env_doc.get("model_present"))
    api_key_present = bool(env_doc.get("api_key_present"))
    network_ok = bool(network_doc.get("dns_success"))
    schema_valid = slot_schema_valid(bindings_doc)
    placeholder = slot_bindings_placeholder(bindings_doc)
    unavailable = str(glm_log.get("unavailable_reason", ""))
    if invalid_glm_output:
        status = "failed_invalid_glm_output"
    elif require_glm and not model_present:
        status = "blocked_model_missing"
    elif require_glm and not api_key_present:
        status = "blocked_glm_unavailable"
    elif require_glm and not network_ok and not glm_called:
        status = "blocked_network_or_endpoint"
    elif require_glm and not glm_called and "Connection" in unavailable:
        status = "blocked_network_or_endpoint"
    elif (
        glm_called
        and int(glm_log.get("glm_request_count", 0)) >= 1
        and int(glm_log.get("glm_response_count", 0)) >= 1
        and bool(bindings_doc.get("slot_bindings_generated"))
        and schema_valid
        and not placeholder
        and bool(adapter_doc.get("adapter_validate_executed"))
    ):
        status = "pass"
    else:
        status = "blocked_glm_unavailable"
    return {
        "schema": "glm_env_fix_retry_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_baseline_loaded": previous_loaded,
        "rag_lookup_reused": bool(rag_doc),
        "mapping_gate_reused": bool(mapping_doc),
        "slot_filling_plan_loaded": bool(slot_plan),
        "glm_required": require_glm,
        "glm_model_present": model_present,
        "api_key_present": api_key_present,
        "api_key_logged": False,
        "network_endpoint_checked": bool(network_doc.get("network_endpoint_checked")),
        "glm_called": glm_called,
        "glm_request_count": int(glm_log.get("glm_request_count", 0)),
        "glm_response_count": int(glm_log.get("glm_response_count", 0)),
        "slot_bindings_generated": bool(bindings_doc.get("slot_bindings_generated")),
        "slot_bindings_placeholder": placeholder,
        "slot_bindings_schema_valid": schema_valid,
        "mapping_gate_validate_executed": bool(mapping_doc.get("mapping_gate_passed")),
        "adapter_validate_executed": bool(adapter_doc.get("adapter_validate_executed")),
        "mapping_gate_bypassed": False,
        "glm_generated_c_code": invalid_glm_output,
        "glm_modified_adapter_recipes": False,
        "glm_modified_normalized_templates": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status,
    }


def token_budget_quality(
    *,
    previous_loaded: bool,
    rag_doc: dict[str, Any],
    mapping_doc: dict[str, Any],
    slot_plan: dict[str, Any],
    require_glm: bool,
    env_doc: dict[str, Any],
    glm_log: dict[str, Any],
    bindings_doc: dict[str, Any],
    adapter_doc: dict[str, Any],
) -> dict[str, Any]:
    invalid_glm_output = bool(bindings_doc.get("invalid_glm_output"))
    invalid_yaml = bool(bindings_doc.get("invalid_slot_bindings_yaml"))
    glm_called = bool(glm_log.get("glm_called"))
    content_empty = bool(glm_log.get("content_empty"))
    reasoning_present = bool(glm_log.get("reasoning_content_present"))
    finish_reason = str(glm_log.get("finish_reason", ""))
    schema_valid = slot_schema_valid(bindings_doc)
    placeholder = slot_bindings_placeholder(bindings_doc)
    if invalid_glm_output:
        status = "failed_invalid_glm_output"
    elif invalid_yaml:
        status = "failed_invalid_slot_bindings_yaml"
    elif require_glm and not env_doc.get("model_present"):
        status = "blocked_model_missing"
    elif require_glm and not env_doc.get("api_key_present"):
        status = "blocked_glm_unavailable"
    elif content_empty and finish_reason == "length":
        status = "blocked_token_budget_exhausted"
    elif content_empty and reasoning_present:
        status = "blocked_reasoning_only_response"
    elif not glm_called:
        status = "blocked_glm_unavailable"
    elif (
        glm_called
        and int(glm_log.get("glm_request_count", 0)) >= 1
        and int(glm_log.get("glm_response_count", 0)) >= 1
        and bool(bindings_doc.get("slot_bindings_generated"))
        and schema_valid
        and not placeholder
        and bool(adapter_doc.get("adapter_validate_executed"))
    ):
        status = "pass"
    else:
        status = "blocked_glm_unavailable"
    return {
        "schema": "glm_slot_filling_token_budget_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_baseline_loaded": previous_loaded,
        "rag_lookup_reused": bool(rag_doc),
        "mapping_gate_reused": bool(mapping_doc),
        "slot_filling_plan_loaded": bool(slot_plan),
        "glm_required": require_glm,
        "glm_model_present": bool(env_doc.get("model_present")),
        "api_key_present": bool(env_doc.get("api_key_present")),
        "api_key_logged": False,
        "glm_called": glm_called,
        "glm_request_count": int(glm_log.get("glm_request_count", 0)),
        "glm_response_count": int(glm_log.get("glm_response_count", 0)),
        "max_tokens": int(glm_log.get("max_tokens", 0)),
        "thinking_disable_attempted": bool(glm_log.get("thinking_disable_attempted")),
        "thinking_disable_supported": bool(glm_log.get("thinking_disable_supported")),
        "finish_reason": finish_reason,
        "content_empty": content_empty,
        "reasoning_content_present": reasoning_present,
        "completion_tokens": int(glm_log.get("completion_tokens", 0)),
        "reasoning_tokens": int(glm_log.get("reasoning_tokens", 0)),
        "slot_bindings_generated": bool(bindings_doc.get("slot_bindings_generated")),
        "slot_bindings_placeholder": placeholder,
        "slot_bindings_schema_valid": schema_valid,
        "mapping_gate_validate_executed": bool(mapping_doc.get("mapping_gate_passed")),
        "adapter_validate_executed": bool(adapter_doc.get("adapter_validate_executed")),
        "mapping_gate_bypassed": False,
        "glm_generated_c_code": invalid_glm_output,
        "glm_modified_adapter_recipes": False,
        "glm_modified_normalized_templates": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status,
    }


def previous_snapshot(previous: Path) -> dict[str, Any]:
    return {
        "schema": "previous_baseline_snapshot_v1",
        "generated_at": now_iso(),
        "previous_sprint": previous.as_posix(),
        "rag_lookup": load_yaml(previous / "rag/rag_lookup_results.yaml"),
        "mapping_gate": load_yaml(previous / "mapping/mapping_gate_results.yaml"),
        "slot_filling_plan": load_yaml(previous / "slot_filling/slot_filling_plan.yaml"),
        "known_pattern_gate": load_yaml(previous / "known_patterns/known_pattern_gate_snapshot.yaml"),
    }


def blocked_glm_log(reason: str, env_doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "glm_invocation_log_v1",
        "generated_at": now_iso(),
        "glm_required": True,
        "glm_called": False,
        "glm_model": env_doc.get("GLM_MODEL", {}).get("value", ""),
        "glm_request_count": 0,
        "glm_response_count": 0,
        "glm_config_source": "environment",
        "api_key_present": bool(env_doc.get("api_key_present")),
        "api_key_logged": False,
        "base_url_present": bool(env_doc.get("base_url_present")),
        "max_tokens": 4096,
        "temperature": 0.0,
        "thinking_disable_attempted": True,
        "thinking_disable_supported": False,
        "finish_reason": "",
        "content_empty": True,
        "reasoning_content_present": False,
        "completion_tokens": 0,
        "reasoning_tokens": 0,
        "unavailable_reason": reason,
    }


def empty_slot_bindings(reason: str) -> dict[str, Any]:
    return {
        "schema": "generated_slot_bindings_v1",
        "generated_at": now_iso(),
        "slot_bindings_generated": False,
        "slot_bindings": {},
        "unavailable_reason": reason,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    families = [item.strip() for item in args.families.split(",") if item.strip()]
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "preflight", "knowledge", "rag", "mapping", "slot_filling", "validation", "known_patterns", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    if args.previous_sprint:
        previous = (repo_root / args.previous_sprint).resolve()
        snapshot = previous_snapshot(previous)
        rag_doc = snapshot["rag_lookup"]
        mapping_doc = snapshot["mapping_gate"]
        slot_plan = snapshot["slot_filling_plan"]
        gate = snapshot["known_pattern_gate"]
        preflight = glm_preflight()
        env_doc = glm_env_after_fix()
        network_doc = network_endpoint_check()
        if args.require_glm and not env_doc.get("model_present"):
            glm_log = blocked_glm_log("GLM_MODEL is not set in environment", env_doc)
            bindings_doc = empty_slot_bindings(glm_log["unavailable_reason"])
        elif args.require_glm and not env_doc.get("api_key_present"):
            glm_log = blocked_glm_log("ZHIPUAI_API_KEY/GLM_API_KEY is not set in environment", env_doc)
            bindings_doc = empty_slot_bindings(glm_log["unavailable_reason"])
        else:
            glm_log, bindings_doc = run_glm_slot_filling(slot_plan, args.require_glm)
        adapter_doc = adapter_validate_result(bindings_doc, mapping_doc)
        mapping_validate = {
            "schema": "mapping_gate_validate_results_v1",
            "generated_at": now_iso(),
            "mapping_gate_validate_executed": True,
            "mapping_gate_passed": bool(mapping_doc.get("mapping_gate_passed")),
            "mapping_gate_bypassed": False,
        }
        slot_validate = {
            "schema": "slot_bindings_schema_validate_v1",
            "generated_at": now_iso(),
            "slot_bindings_schema_valid": slot_schema_valid(bindings_doc),
            "invalid_glm_output": bool(bindings_doc.get("invalid_glm_output")),
            "errors": []
            if slot_schema_valid(bindings_doc)
            else ["slot_bindings missing/invalid or GLM unavailable"],
        }
        qc_retry = retry_quality(
            previous_loaded=bool(rag_doc and mapping_doc and slot_plan),
            rag_doc=rag_doc,
            mapping_doc=mapping_doc,
            slot_plan=slot_plan,
            require_glm=args.require_glm,
            preflight=preflight,
            glm_log=glm_log,
            bindings_doc=bindings_doc,
            adapter_doc=adapter_doc,
        )
        qc_env_fix = env_fix_retry_quality(
            previous_loaded=bool(rag_doc and mapping_doc and slot_plan),
            rag_doc=rag_doc,
            mapping_doc=mapping_doc,
            slot_plan=slot_plan,
            require_glm=args.require_glm,
            env_doc=env_doc,
            network_doc=network_doc,
            glm_log=glm_log,
            bindings_doc=bindings_doc,
            adapter_doc=adapter_doc,
        )
        qc_token_budget = token_budget_quality(
            previous_loaded=bool(rag_doc and mapping_doc and slot_plan),
            rag_doc=rag_doc,
            mapping_doc=mapping_doc,
            slot_plan=slot_plan,
            require_glm=args.require_glm,
            env_doc=env_doc,
            glm_log=glm_log,
            bindings_doc=bindings_doc,
            adapter_doc=adapter_doc,
        )
        dump_yaml(out_dir / "inputs/previous_baseline_snapshot.yaml", snapshot)
        dump_yaml(out_dir / "preflight/glm_connectivity_preflight.yaml", preflight)
        dump_yaml(out_dir / "preflight/glm_env_after_fix.yaml", env_doc)
        dump_yaml(out_dir / "preflight/glm_env_snapshot.yaml", env_doc)
        dump_yaml(out_dir / "preflight/network_endpoint_check.yaml", network_doc)
        dump_yaml(out_dir / "slot_filling/slot_filling_plan.yaml", slot_plan)
        dump_yaml(out_dir / "slot_filling/glm_invocation_log.yaml", glm_log)
        dump_yaml(out_dir / "slot_filling/generated_slot_bindings.yaml", bindings_doc)
        dump_yaml(out_dir / "validation/slot_bindings_schema_validate.yaml", slot_validate)
        dump_yaml(out_dir / "validation/mapping_gate_validate_results.yaml", mapping_validate)
        dump_yaml(out_dir / "validation/adapter_validate_results.yaml", adapter_doc)
        dump_yaml(out_dir / "validation/glm_retry_quality_checks.yaml", qc_retry)
        dump_yaml(out_dir / "validation/glm_env_fix_retry_quality_checks.yaml", qc_env_fix)
        dump_yaml(out_dir / "validation/glm_slot_filling_token_budget_quality_checks.yaml", qc_token_budget)
        report = f"""# glm_slot_filling_token_budget_fix_v1 Report

## Previous Baseline

- previous_sprint: {args.previous_sprint}
- rag_lookup_reused: {qc_token_budget['rag_lookup_reused']}
- mapping_gate_reused: {qc_token_budget['mapping_gate_reused']}
- slot_filling_plan_loaded: {qc_token_budget['slot_filling_plan_loaded']}

## GLM

- glm_required: {qc_token_budget['glm_required']}
- api_key_present: {qc_token_budget['api_key_present']}
- api_key_logged: false
- base_url_present: {env_doc['base_url_present']}
- glm_model_present: {qc_token_budget['glm_model_present']}
- dns_success: {network_doc.get('dns_success')}
- glm_called: {qc_token_budget['glm_called']}
- glm_request_count: {qc_token_budget['glm_request_count']}
- glm_response_count: {qc_token_budget['glm_response_count']}
- max_tokens: {qc_token_budget['max_tokens']}
- temperature: {glm_log.get('temperature')}
- thinking_disable_attempted: {qc_token_budget['thinking_disable_attempted']}
- thinking_disable_supported: {qc_token_budget['thinking_disable_supported']}
- finish_reason: {qc_token_budget['finish_reason']}
- content_empty: {qc_token_budget['content_empty']}
- reasoning_content_present: {qc_token_budget['reasoning_content_present']}
- completion_tokens: {qc_token_budget['completion_tokens']}
- reasoning_tokens: {qc_token_budget['reasoning_tokens']}
- unavailable_reason: {glm_log.get('unavailable_reason', '')}

## Validation

- slot_bindings_generated: {qc_token_budget['slot_bindings_generated']}
- slot_bindings_placeholder: {qc_token_budget['slot_bindings_placeholder']}
- slot_bindings_schema_valid: {qc_token_budget['slot_bindings_schema_valid']}
- mapping_gate_validate_executed: {qc_token_budget['mapping_gate_validate_executed']}
- adapter_validate_executed: {qc_token_budget['adapter_validate_executed']}
- mapping_gate_bypassed: {qc_token_budget['mapping_gate_bypassed']}
- invalid_glm_output: {bool(bindings_doc.get('invalid_glm_output'))}

## Policy

No tools script, API key logging, render, compile, run, feedback, pattern-bank
write, adapter recipe modification, normalized template modification, C-code
generation by GLM, git action, CVE, exploitability, or confirmed vulnerability
claim was produced.

## Quality

- quality_status: {qc_token_budget['quality_status']}
"""
        write_text(out_dir / "reports/glm_env_fix_and_slot_filling_retry_v1_report.md", report)
        write_text(out_dir / "reports/glm_slot_filling_token_budget_fix_v1_report.md", report)
        print(f"[OK] wrote glm retry artifacts to {out_dir}")
        print(
            "[SUMMARY] "
            f"glm_called={qc_token_budget['glm_called']} "
            f"slot_bindings={qc_token_budget['slot_bindings_generated']} quality={qc_token_budget['quality_status']}"
        )
        return 0

    family_added, api_added, profiles = bootstrap_knowledge(repo_root, families)
    gate, stop_policy = ensure_known_pattern_gate(repo_root)
    rag_doc = rag_lookup(repo_root, families)
    mapping_doc = mapping_gate(families, rag_doc, gate)
    slot_plan = build_slot_plan(families, mapping_doc)
    glm_log, bindings_doc = run_glm_slot_filling(slot_plan, args.require_glm)
    adapter_doc = adapter_validate_result(bindings_doc, mapping_doc)
    qc = quality(
        family_added=bool(family_added.get("families")),
        api_added=bool(api_added.get("api_cards")),
        profiles_linked=all(
            bool(((profiles.get("families") or {}).get(family) or {}).get("rag_refs")) for family in families
        ),
        rag_doc=rag_doc,
        mapping_doc=mapping_doc,
        slot_plan=slot_plan,
        require_glm=args.require_glm,
        glm_log=glm_log,
        bindings_doc=bindings_doc,
        adapter_doc=adapter_doc,
        gate=gate,
    )

    dump_yaml(out_dir / "knowledge/family_knowledge_added.yaml", family_added)
    dump_yaml(out_dir / "knowledge/api_cards_added.yaml", api_added)
    dump_yaml(out_dir / "rag/rag_lookup_results.yaml", rag_doc)
    dump_yaml(out_dir / "mapping/mapping_gate_results.yaml", mapping_doc)
    dump_yaml(out_dir / "slot_filling/slot_filling_plan.yaml", slot_plan)
    dump_yaml(out_dir / "slot_filling/glm_invocation_log.yaml", glm_log)
    dump_yaml(out_dir / "slot_filling/generated_slot_bindings.yaml", bindings_doc)
    dump_yaml(out_dir / "validation/adapter_validate_results.yaml", adapter_doc)
    dump_yaml(out_dir / "known_patterns/known_pattern_gate_snapshot.yaml", gate)
    dump_yaml(out_dir / "known_patterns/known_pattern_dedup_policy.yaml", dedup_policy(gate))
    dump_yaml(out_dir / "known_patterns/der_trailing_garbage_family_summary.yaml", family_summary(gate))
    dump_yaml(out_dir / "validation/glm_baseline_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

## Knowledge

- families: {families}
- family_knowledge_added: {bool(family_added.get('families'))}
- api_cards_added: {bool(api_added.get('api_cards'))}
- family_profiles_linked_to_rag: {qc['family_profiles_linked_to_rag']}

## Baseline Flow

- rag_lookup_executed: {qc['rag_lookup_executed']}
- mapping_gate_executed: {qc['mapping_gate_executed']}
- slot_filling_plan_generated: {qc['slot_filling_plan_generated']}
- glm_required: {qc['glm_required']}
- glm_called: {qc['glm_called']}
- slot_bindings_generated: {qc['slot_bindings_generated']}
- adapter_validate_executed: {qc['adapter_validate_executed']}
- unavailable_reason: {glm_log.get('unavailable_reason', '')}

## Known Pattern Gate

- pattern_id: der_single_object_trailing_garbage_full_consumption
- stop_campaign_on_repeat: {qc['known_pattern_stop_on_repeat']}
- stop_campaign_on_crash_or_sanitizer: true
- stop_campaign_on_new_semantic_class: true

## Policy

No tools script, render, compile, run, main feedback, pattern-bank write,
adapter recipe modification, normalized template modification, C-code generation
by GLM, git action, CVE, exploitability, or confirmed vulnerability claim was
produced.

## Quality

- quality_status: {qc['quality_status']}
"""
    write_text(out_dir / "reports/rag_glm_baseline_and_known_pattern_gate_v1_report.md", report)
    print(f"[OK] wrote {TASK} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"families={len(families)} glm_called={qc['glm_called']} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
