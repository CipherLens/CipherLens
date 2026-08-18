"""Strict provider configuration with explicit paid-fallback consent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from binding_proposal.model import FallbackPolicy, ProviderKind


@dataclass(frozen=True)
class CodexExecConfig:
    executable: str = "codex"
    working_root: str = "."
    sandbox: str = "READ_ONLY"
    ephemeral: bool = True
    ignore_user_config: bool = True
    ignore_rules: bool = True
    tool_network_policy: str = "DISABLED_REQUIRED"
    tool_network_isolation_proven: bool = False


@dataclass(frozen=True)
class GLMConfig:
    enabled: bool = False
    credential_env: str = "ZHIPUAI_API_KEY"
    model_ref: str = "glm-configured-model"


@dataclass(frozen=True)
class ProviderConfig:
    provider: ProviderKind = ProviderKind.CODEX_EXEC
    fallback_policy: FallbackPolicy = FallbackPolicy.DISABLED
    timeout_seconds: int = 60
    structured_output_schema_ref: str = "binding_proposal/payload.schema.yaml"
    codex_exec: CodexExecConfig = CodexExecConfig()
    glm: GLMConfig = GLMConfig()


def parse_provider_config(value: Mapping[str, Any]) -> ProviderConfig:
    expected = {"provider", "fallback_policy", "timeout_seconds", "structured_output_schema_ref", "codex_exec", "glm"}
    _exact(value, expected, "llm_role_proposal")
    codex_raw = _mapping(value["codex_exec"], "codex_exec")
    glm_raw = _mapping(value["glm"], "glm")
    _exact(codex_raw, {"executable", "working_root", "sandbox", "ephemeral", "ignore_user_config", "ignore_rules", "tool_network_policy", "tool_network_isolation_proven"}, "codex_exec")
    _exact(glm_raw, {"enabled", "credential_env", "model_ref"}, "glm")
    timeout = value["timeout_seconds"]
    if not isinstance(timeout, int) or timeout < 1:
        raise ValueError("timeout_seconds must be a positive integer")
    codex = CodexExecConfig(**codex_raw)
    if codex.sandbox != "READ_ONLY" or codex.tool_network_policy != "DISABLED_REQUIRED":
        raise ValueError("Codex provider requires READ_ONLY and DISABLED_REQUIRED policies")
    glm = GLMConfig(**glm_raw)
    return ProviderConfig(
        provider=ProviderKind(value["provider"]), fallback_policy=FallbackPolicy(value["fallback_policy"]),
        timeout_seconds=timeout, structured_output_schema_ref=str(value["structured_output_schema_ref"]),
        codex_exec=codex, glm=glm,
    )


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def _exact(value: Mapping[str, Any], expected: set[str], path: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        raise ValueError(f"{path}: missing={sorted(missing)!r}, unknown={sorted(unknown)!r}")
