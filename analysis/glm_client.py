"""Small GLM client wrapper for structured analysis calls."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass
class GLMCallResult:
    content: str
    reasoning_content: str
    finish_reason: str
    completion_tokens: int
    reasoning_tokens: int
    thinking_disable_attempted: bool
    thinking_disable_supported: bool


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _extract_response(resp: Any, *, attempted: bool, supported: bool) -> GLMCallResult:
    choices = _get_attr(resp, "choices", []) or []
    choice = choices[0] if choices else None
    message = _get_attr(choice, "message", None)
    usage = _get_attr(resp, "usage", None)
    details = _get_attr(usage, "completion_tokens_details", None)
    return GLMCallResult(
        content=str(_get_attr(message, "content", "") or ""),
        reasoning_content=str(_get_attr(message, "reasoning_content", "") or ""),
        finish_reason=str(_get_attr(choice, "finish_reason", "") or ""),
        completion_tokens=int(_get_attr(usage, "completion_tokens", 0) or 0),
        reasoning_tokens=int(_get_attr(details, "reasoning_tokens", 0) or 0),
        thinking_disable_attempted=attempted,
        thinking_disable_supported=supported,
    )


def call_glm_structured(
    messages: list[dict[str, str]],
    *,
    model: str,
    max_tokens: int = 4096,
    temperature: float = 0.0,
) -> GLMCallResult:
    try:
        from zhipuai import ZhipuAI
    except ModuleNotFoundError as exc:
        raise RuntimeError("zhipuai package is not installed") from exc

    api_key = (os.environ.get("ZHIPUAI_API_KEY") or os.environ.get("GLM_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError("ZHIPUAI_API_KEY/GLM_API_KEY is not set in environment")

    kwargs: dict[str, Any] = {"api_key": api_key}
    base_url = (os.environ.get("GLM_BASE_URL") or "").strip()
    if base_url:
        kwargs["base_url"] = base_url
    client = ZhipuAI(**kwargs)

    params: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "extra_body": {"thinking": {"type": "disabled"}},
    }
    try:
        return _extract_response(
            client.chat.completions.create(**params),
            attempted=True,
            supported=True,
        )
    except TypeError:
        params.pop("extra_body", None)
        return _extract_response(
            client.chat.completions.create(**params),
            attempted=True,
            supported=False,
        )
    except Exception as exc:
        message = str(exc).lower()
        if "extra_body" not in message and "thinking" not in message:
            raise
        params.pop("extra_body", None)
        return _extract_response(
            client.chat.completions.create(**params),
            attempted=True,
            supported=False,
        )
