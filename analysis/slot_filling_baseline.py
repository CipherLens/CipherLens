"""Slot filling baseline helpers for GLM audit."""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

from analysis.analysis_records import now_iso
from analysis.glm_client import call_glm_structured


ALLOWED_SLOTS = {
    "parser_api": "Target parser API name",
    "input_format": "DER or PEM",
    "object_type": "Target OpenSSL object type",
    "cleanup_api": "Cleanup API",
    "oracle_observable": "Observable used for accepted/full-consumption oracle",
}
MAX_TOKENS = 4096
TEMPERATURE = 0.0


def build_slot_plan(families: list[str], mapping_results: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "slot_filling_plan_v1",
        "generated_at": now_iso(),
        "families": families,
        "allowed_output": "slot_bindings.yaml",
        "allowed_slots": ALLOWED_SLOTS,
        "forbidden_outputs": [
            "complete C harness",
            "adapter_recipes",
            "normalized_templates",
            "knowledge main library writes",
            "mutation engine code",
            "renderer code",
        ],
        "mapping_gate_results": mapping_results,
    }


def glm_available_hint() -> bool:
    return bool(os.environ.get("ZHIPUAI_API_KEY") or os.environ.get("GLM_API_KEY"))


def glm_model_hint() -> str:
    return (os.environ.get("GLM_MODEL") or "").strip()


def strip_code_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_slot_bindings_yaml(text: str) -> tuple[dict[str, str], str]:
    try:
        parsed = yaml.safe_load(strip_code_fence(text))
    except Exception as exc:  # noqa: BLE001 - caller records invalid model output.
        return {}, f"invalid YAML/JSON: {type(exc).__name__}: {exc}"
    if not isinstance(parsed, dict):
        return {}, "top-level output is not a mapping"
    bindings = parsed.get("slot_bindings", parsed)
    if not isinstance(bindings, dict):
        return {}, "slot_bindings is not a mapping"
    return {str(key): str(value) for key, value in bindings.items()}, ""


def run_glm_slot_filling(slot_plan: dict[str, Any], require_glm: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    model = glm_model_hint()
    key_present = glm_available_hint()
    base_url_present = bool(os.environ.get("GLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL"))
    log: dict[str, Any] = {
        "schema": "glm_invocation_log_v1",
        "generated_at": now_iso(),
        "glm_required": require_glm,
        "glm_called": False,
        "glm_model": model,
        "glm_request_count": 0,
        "glm_response_count": 0,
        "glm_config_source": "environment",
        "api_key_present": key_present,
        "api_key_logged": False,
        "base_url_present": base_url_present,
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "thinking_disable_attempted": True,
        "thinking_disable_supported": False,
        "finish_reason": "",
        "content_empty": True,
        "reasoning_content_present": False,
        "completion_tokens": 0,
        "reasoning_tokens": 0,
        "unavailable_reason": "",
    }
    empty_bindings = {
        "schema": "generated_slot_bindings_v1",
        "generated_at": now_iso(),
        "slot_bindings_generated": False,
        "slot_bindings": {},
    }
    if require_glm and not key_present:
        log["unavailable_reason"] = "ZHIPUAI_API_KEY/GLM_API_KEY is not set in environment"
        return log, empty_bindings
    if require_glm and not model:
        log["unavailable_reason"] = "GLM_MODEL is not set in environment"
        return log, empty_bindings
    try:
        if not os.environ.get("ZHIPUAI_API_KEY") and os.environ.get("GLM_API_KEY"):
            os.environ["ZHIPUAI_API_KEY"] = os.environ["GLM_API_KEY"]
        prompt = {
            "task": "Generate slot_bindings only for object/container parsing baseline.",
            "instructions": [
                "Return only YAML.",
                "Do not use markdown fences.",
                "Do not include explanations.",
                "Do not generate C code.",
                "Do not generate adapter recipes, normalized templates, knowledge records, mutation code, or renderer code.",
                "Every allowed slot must have one concrete non-placeholder scalar value.",
            ],
            "slot_plan": slot_plan,
            "output_contract": {
                "slot_bindings": {
                    "parser_api": "one OpenSSL parser API or parser API family selected from mapping_gate_results",
                    "input_format": "DER or PEM",
                    "object_type": "OpenSSL object type such as EVP_PKEY, PKCS8_PRIV_KEY_INFO, CMS_ContentInfo, or X509_CRL",
                    "cleanup_api": "matching cleanup API such as EVP_PKEY_free, PKCS8_PRIV_KEY_INFO_free, CMS_ContentInfo_free, or X509_CRL_free",
                    "oracle_observable": "parser_accept_and_full_consumption",
                }
            },
        }
        messages = [
            {
                "role": "system",
                "content": "Return YAML only. Do not generate C code. Do not modify recipes or templates.",
            },
            {"role": "user", "content": yaml.safe_dump(prompt, sort_keys=False, allow_unicode=True)},
        ]
        response = call_glm_structured(
            messages,
            model=model,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        content = response.content
        log.update(
            {
                "glm_called": True,
                "glm_model": model,
                "glm_request_count": 1,
                "glm_response_count": 1,
                "thinking_disable_attempted": response.thinking_disable_attempted,
                "thinking_disable_supported": response.thinking_disable_supported,
                "finish_reason": response.finish_reason,
                "content_empty": not bool(content.strip()),
                "reasoning_content_present": bool(response.reasoning_content.strip()),
                "completion_tokens": response.completion_tokens,
                "reasoning_tokens": response.reasoning_tokens,
            }
        )
        if not content.strip():
            if response.finish_reason == "length":
                log["unavailable_reason"] = "content empty and finish_reason=length"
                return log, {**empty_bindings, "blocked_reason": "blocked_token_budget_exhausted"}
            if response.reasoning_content.strip():
                log["unavailable_reason"] = "content empty while reasoning_content is present"
                return log, {**empty_bindings, "blocked_reason": "blocked_reasoning_only_response"}
            log["unavailable_reason"] = "content empty in GLM response"
            return log, {**empty_bindings, "blocked_reason": "blocked_glm_unavailable"}
        forbidden = invalid_output_markers(content)
        if forbidden:
            log["invalid_output_markers"] = forbidden
            return (
                log,
                {
                    **empty_bindings,
                    "invalid_glm_output": True,
                    "invalid_output_markers": forbidden,
                },
            )
        bindings, parse_error = parse_slot_bindings_yaml(content)
        if parse_error:
            log["unavailable_reason"] = parse_error
            return (
                log,
                {
                    **empty_bindings,
                    "invalid_slot_bindings_yaml": True,
                    "parse_error": parse_error,
                },
            )
        return (
            log,
            {
                "schema": "generated_slot_bindings_v1",
                "generated_at": now_iso(),
                "slot_bindings_generated": bool(bindings),
                "slot_bindings": bindings,
            },
        )
    except Exception as exc:  # noqa: BLE001 - audit must record optional GLM failures.
        log["unavailable_reason"] = str(exc)
        return log, empty_bindings


def slot_schema_valid(bindings_doc: dict[str, Any]) -> bool:
    bindings = bindings_doc.get("slot_bindings")
    if not isinstance(bindings, dict) or not bindings:
        return False
    return set(bindings) == set(ALLOWED_SLOTS) and all(str(value).strip() for value in bindings.values())


def invalid_output_markers(text: str) -> list[str]:
    markers = []
    forbidden = {
        "#include": "C include",
        "int main": "C harness main",
        "adapter_recipe": "adapter recipe",
        "adapter_recipes": "adapter recipe",
        "normalized_template": "normalized template",
        "normalized_templates": "normalized template",
        "knowledge_raw": "knowledge main library write",
        "harness.c": "complete harness",
        "```c": "C code fence",
    }
    lower_text = text.lower()
    for token, label in forbidden.items():
        if token.lower() in lower_text:
            markers.append(label)
    return sorted(set(markers))


def adapter_validate_result(bindings_doc: dict[str, Any], mapping_results: dict[str, Any]) -> dict[str, Any]:
    valid = slot_schema_valid(bindings_doc) and bool(mapping_results.get("mapping_gate_passed"))
    return {
        "schema": "adapter_validate_results_v1",
        "generated_at": now_iso(),
        "adapter_validate_executed": bool(bindings_doc.get("slot_bindings_generated")),
        "slot_schema_valid": slot_schema_valid(bindings_doc),
        "mapping_gate_validate": bool(mapping_results.get("mapping_gate_passed")),
        "status": "pass" if valid else "blocked",
        "errors": [] if valid else ["slot_bindings missing/invalid or mapping gate not passed"],
    }
