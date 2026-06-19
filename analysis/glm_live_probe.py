#!/usr/bin/env python3
"""Run a minimal live GLM probe without logging secrets."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import yaml


TASK_NAME = "glm_live_probe_and_mainline_status_refresh_v1"
DEFAULT_MODEL = "glm-4-flash-250414"
PROMPT = "只回复 OK"
SECRET_FIELDS = ("ZHIPUAI_API_KEY", "GLM_API_KEY")


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def mask_key(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


def sanitize_error(message: str, api_key: str) -> str:
    sanitized = str(message or "")
    for value in [api_key, os.environ.get("ZHIPUAI_API_KEY", ""), os.environ.get("GLM_API_KEY", "")]:
        if value:
            sanitized = sanitized.replace(value, "[REDACTED_API_KEY]")
    return sanitized[:500]


def classify_error(exc: Exception) -> str:
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    combined = f"{name} {text}"
    if any(token in combined for token in ["unauthorized", "authentication", "auth", "api key", "apikey", "401"]):
        return "auth_failed"
    if any(token in combined for token in ["model not found", "model_not_found", "does not exist", "404"]):
        return "model_not_found"
    if any(
        token in combined
        for token in [
            "timeout",
            "timed out",
            "proxy",
            "tls",
            "ssl",
            "certificate",
            "connection",
            "network",
            "name resolution",
            "nodename",
            "gaierror",
        ]
    ):
        return "network_or_proxy_error"
    return "api_error"


def response_text(resp: Any) -> str:
    choices = getattr(resp, "choices", None) or []
    if not choices:
        return ""
    choice = choices[0]
    message = getattr(choice, "message", None)
    return str(getattr(message, "content", "") or "")


def run_probe(out_dir: Path) -> dict[str, Any]:
    api_key = (os.environ.get("ZHIPUAI_API_KEY") or os.environ.get("GLM_API_KEY") or "").strip()
    model = (os.environ.get("GLM_MODEL") or DEFAULT_MODEL).strip()
    base_url = (os.environ.get("GLM_BASE_URL") or "").strip()

    result: dict[str, Any] = {
        "key_present": bool(api_key),
        "key_masked": mask_key(api_key),
        "model": model,
        "base_url_present": bool(base_url),
        "sdk": "zhipuai.ZhipuAI",
        "request_attempted": False,
        "request_success": False,
        "response_preview": "",
        "response_is_ok": False,
        "error_type": "",
        "error_sanitized": "",
        "api_key_logged": False,
    }

    if not api_key:
        result["error_type"] = "auth_failed"
        result["error_sanitized"] = "ZHIPUAI_API_KEY/GLM_API_KEY is not set"
        return result

    try:
        from zhipuai import ZhipuAI
    except Exception as exc:  # noqa: BLE001 - import diagnostics must not crash the report.
        result["error_type"] = "sdk_import_failed"
        result["error_sanitized"] = sanitize_error(str(exc), api_key)
        return result

    try:
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        client = ZhipuAI(**kwargs)
        result["request_attempted"] = True
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": PROMPT}],
            max_tokens=16,
            temperature=0.1,
        )
        content = response_text(resp).strip()
        result["request_success"] = True
        result["response_preview"] = content[:80]
        result["response_is_ok"] = content.upper() == "OK"
    except Exception as exc:  # noqa: BLE001 - probe should classify and persist failures.
        result["error_type"] = classify_error(exc)
        result["error_sanitized"] = sanitize_error(str(exc), api_key)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    result = run_probe(out_dir)
    glm_available = bool(result["request_success"] and result["response_is_ok"])
    quality = {
        "task_name": TASK_NAME,
        "glm_available": glm_available,
        "request_success": bool(result["request_success"]),
        "response_is_ok": bool(result["response_is_ok"]),
        "api_key_logged": False,
        "quality_status": "pass_glm_live_probe" if glm_available else "fail_glm_live_probe",
    }
    write_yaml(out_dir / "live_probe_result.yaml", result)
    write_yaml(out_dir / "quality_report.yaml", quality)
    print(
        "glm live probe:",
        quality["quality_status"],
        "request_success=",
        quality["request_success"],
        "response_is_ok=",
        quality["response_is_ok"],
    )


if __name__ == "__main__":
    main()
