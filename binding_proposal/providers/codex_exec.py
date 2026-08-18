"""Thin, policy-gated Codex CLI provider. No invocation occurs without proof."""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from binding_proposal.config import CodexExecConfig
from binding_proposal.model import AuthClass, InvocationStatus, PAYLOAD_SCHEMA_VERSION, PreparedRequest, ProviderInvocationResult, ProviderKind, UsagePlane
from binding_proposal.provider import LLMRoleProposalProvider
from binding_proposal.validate import validate_payload


class CodexJSONLError(ValueError):
    pass


def decode_codex_jsonl(raw: str) -> Mapping[str, Any]:
    messages: list[str] = []
    turn_completed = 0
    allowed = {"thread.started", "turn.started", "item.started", "item.completed", "turn.completed", "error"}
    lines = raw.splitlines()
    if not lines:
        raise CodexJSONLError("empty JSONL stream")
    for number, line in enumerate(lines, 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CodexJSONLError(f"malformed JSONL event at line {number}") from exc
        if not isinstance(event, dict) or event.get("type") not in allowed:
            raise CodexJSONLError(f"unexpected event at line {number}")
        if event["type"] == "item.completed":
            item = event.get("item")
            if isinstance(item, dict) and item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                messages.append(item["text"])
        elif event["type"] == "turn.completed":
            turn_completed += 1
    if turn_completed != 1:
        raise CodexJSONLError(f"expected one completed turn, found {turn_completed}")
    if len(messages) != 1:
        raise CodexJSONLError(f"expected one final agent payload, found {len(messages)}")
    try:
        payload = json.loads(messages[0])
    except json.JSONDecodeError as exc:
        raise CodexJSONLError("final agent payload is not one JSON document") from exc
    if not isinstance(payload, dict):
        raise CodexJSONLError("final agent payload must be an object")
    return payload


class CodexExecProvider(LLMRoleProposalProvider):
    def __init__(self, config: CodexExecConfig | None = None, *, transport: Callable[[list[str], str], tuple[int, str, str]] | None = None) -> None:
        self.config = config or CodexExecConfig()
        self.transport = transport

    def prepare_request(self, prompt: str, *, schema_path: str, invocation_ref: str) -> PreparedRequest:
        return PreparedRequest(invocation_ref, prompt, schema_path, {"transport": "codex-jsonl"})

    def build_command(self, request: PreparedRequest) -> list[str]:
        return [self.config.executable, "exec", "--sandbox", "read-only", "--cd", self.config.working_root,
                "--ephemeral", "--ignore-user-config", "--ignore-rules", "--output-schema", request.schema_path,
                "--json", "--color", "never", "-"]

    def invoke(self, request: PreparedRequest) -> ProviderInvocationResult:
        if not self.config.tool_network_isolation_proven:
            return ProviderInvocationResult(InvocationStatus.POLICY_REJECTED, ProviderKind.CODEX_EXEC, request.invocation_ref, "TOOL_NETWORK_ISOLATION_UNPROVEN")
        if self.transport is None:
            return ProviderInvocationResult(InvocationStatus.PROVIDER_UNAVAILABLE, ProviderKind.CODEX_EXEC, request.invocation_ref, "NO_CODEX_TRANSPORT")
        try:
            exit_code, stdout, _stderr = self.transport(self.build_command(request), request.prompt)
        except TimeoutError:
            return ProviderInvocationResult(InvocationStatus.TIMEOUT, ProviderKind.CODEX_EXEC, request.invocation_ref, "CODEX_TIMEOUT")
        except OSError:
            return ProviderInvocationResult(InvocationStatus.TRANSPORT_ERROR, ProviderKind.CODEX_EXEC, request.invocation_ref, "CODEX_TRANSPORT_ERROR")
        if exit_code != 0:
            return ProviderInvocationResult(InvocationStatus.EXECUTION_ERROR, ProviderKind.CODEX_EXEC, request.invocation_ref, "CODEX_NONZERO_EXIT", {"exit_code": exit_code})
        try:
            payload = decode_codex_jsonl(stdout)
        except CodexJSONLError:
            return ProviderInvocationResult(InvocationStatus.INVALID_OUTPUT, ProviderKind.CODEX_EXEC, request.invocation_ref, "CODEX_INVALID_JSONL")
        errors = validate_payload(payload)
        if errors:
            return ProviderInvocationResult(InvocationStatus.SCHEMA_REJECTED, ProviderKind.CODEX_EXEC, request.invocation_ref, "CODEX_SCHEMA_REJECTED", {"error_count": len(errors)})
        return ProviderInvocationResult(InvocationStatus.SUCCESS, ProviderKind.CODEX_EXEC, request.invocation_ref, "CODEX_SUCCESS", {"exit_code": 0}, payload)

    def parse_output(self, raw_output: str) -> Mapping[str, Any]:
        return decode_codex_jsonl(raw_output)

    def build_provenance(self, request: PreparedRequest, result: ProviderInvocationResult) -> Mapping[str, Any]:
        return {
            "provider_kind": ProviderKind.CODEX_EXEC.value, "usage_plane": UsagePlane.CHATGPT_AUTHENTICATED_LOCAL_CODEX.value,
            "auth_class": AuthClass.CHATGPT_AUTHENTICATED_SESSION.value, "model_ref": "codex-configured-model",
            "provider_instance_ref": "provider:codex-exec:v0.1", "invocation_ref": request.invocation_ref,
            "prompt_template_version": "v0.1", "structured_output_schema_version": PAYLOAD_SCHEMA_VERSION,
            "sandbox_profile": {"sandbox_mode": "READ_ONLY", "working_root": self.config.working_root, "tool_network_policy": "DISABLED_REQUIRED", "ephemeral": self.config.ephemeral, "ignore_user_config": self.config.ignore_user_config, "ignore_rules": self.config.ignore_rules},
            "generation_metadata": {"transport": "codex-jsonl", "exit_code": result.safe_metadata.get("exit_code")}, "credential_env": None,
        }
