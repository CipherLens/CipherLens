"""Optional strict GLM API provider with no permissive JSON recovery."""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Mapping

from binding_proposal.config import GLMConfig
from binding_proposal.model import AuthClass, InvocationStatus, PAYLOAD_SCHEMA_VERSION, PreparedRequest, ProviderInvocationResult, ProviderKind, UsagePlane
from binding_proposal.provider import LLMRoleProposalProvider
from binding_proposal.validate import validate_payload


class GLMProvider(LLMRoleProposalProvider):
    def __init__(self, config: GLMConfig | None = None, *, transport: Callable[[str, str, str], str] | None = None, environ: Mapping[str, str] | None = None) -> None:
        self.config = config or GLMConfig()
        self.transport = transport
        self.environ = environ if environ is not None else os.environ

    def prepare_request(self, prompt: str, *, schema_path: str, invocation_ref: str) -> PreparedRequest:
        return PreparedRequest(invocation_ref, prompt, schema_path, {"transport": "glm-api"})

    def invoke(self, request: PreparedRequest) -> ProviderInvocationResult:
        if not self.config.enabled:
            return ProviderInvocationResult(InvocationStatus.PROVIDER_UNAVAILABLE, ProviderKind.GLM_API, request.invocation_ref, "GLM_DISABLED")
        credential = self.environ.get(self.config.credential_env)
        if not credential:
            return ProviderInvocationResult(InvocationStatus.AUTH_FAILED, ProviderKind.GLM_API, request.invocation_ref, "GLM_CREDENTIAL_MISSING")
        if self.transport is None:
            return ProviderInvocationResult(InvocationStatus.PROVIDER_UNAVAILABLE, ProviderKind.GLM_API, request.invocation_ref, "NO_GLM_TRANSPORT")
        try:
            raw = self.transport(request.prompt, self.config.model_ref, credential)
        except TimeoutError:
            return ProviderInvocationResult(InvocationStatus.TIMEOUT, ProviderKind.GLM_API, request.invocation_ref, "GLM_TIMEOUT")
        except OSError:
            return ProviderInvocationResult(InvocationStatus.TRANSPORT_ERROR, ProviderKind.GLM_API, request.invocation_ref, "GLM_TRANSPORT_ERROR")
        try:
            payload = self.parse_output(raw)
        except (ValueError, json.JSONDecodeError):
            return ProviderInvocationResult(InvocationStatus.INVALID_OUTPUT, ProviderKind.GLM_API, request.invocation_ref, "GLM_INVALID_JSON")
        errors = validate_payload(payload)
        if errors:
            return ProviderInvocationResult(InvocationStatus.SCHEMA_REJECTED, ProviderKind.GLM_API, request.invocation_ref, "GLM_SCHEMA_REJECTED", {"error_count": len(errors)})
        return ProviderInvocationResult(InvocationStatus.SUCCESS, ProviderKind.GLM_API, request.invocation_ref, "GLM_SUCCESS", {}, payload)

    def parse_output(self, raw_output: str) -> Mapping[str, Any]:
        value = json.loads(raw_output)
        if not isinstance(value, dict):
            raise ValueError("GLM output must be one JSON object")
        return value

    def build_provenance(self, request: PreparedRequest, result: ProviderInvocationResult) -> Mapping[str, Any]:
        return {
            "provider_kind": ProviderKind.GLM_API.value, "usage_plane": UsagePlane.API_METERED.value,
            "auth_class": AuthClass.API_KEY_ENVIRONMENT.value, "model_ref": self.config.model_ref,
            "provider_instance_ref": "provider:glm-api:v0.1", "invocation_ref": request.invocation_ref,
            "prompt_template_version": "v0.1", "structured_output_schema_version": PAYLOAD_SCHEMA_VERSION,
            "sandbox_profile": {"sandbox_mode": "NONE", "working_root": ".", "tool_network_policy": "NOT_APPLICABLE", "ephemeral": True, "ignore_user_config": True, "ignore_rules": True},
            "generation_metadata": {"transport": "glm-api", "exit_code": None}, "credential_env": self.config.credential_env,
        }
