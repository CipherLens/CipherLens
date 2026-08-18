"""Deterministic no-network proposal replay provider."""

from __future__ import annotations

import json
from typing import Any, Mapping

from binding_proposal.model import AuthClass, InvocationStatus, PAYLOAD_SCHEMA_VERSION, PreparedRequest, ProviderInvocationResult, ProviderKind, UsagePlane
from binding_proposal.provider import LLMRoleProposalProvider
from binding_proposal.validate import validate_payload


class ReplayProposalProvider(LLMRoleProposalProvider):
    def __init__(self, fixture: Mapping[str, Any] | str) -> None:
        self.fixture = fixture
        self.invocation_count = 0

    def prepare_request(self, prompt: str, *, schema_path: str, invocation_ref: str) -> PreparedRequest:
        return PreparedRequest(invocation_ref, prompt, schema_path, {"transport": "replay"})

    def invoke(self, request: PreparedRequest) -> ProviderInvocationResult:
        self.invocation_count += 1
        try:
            payload = dict(self.fixture) if isinstance(self.fixture, Mapping) else dict(self.parse_output(self.fixture))
        except (ValueError, TypeError, json.JSONDecodeError):
            return ProviderInvocationResult(InvocationStatus.INVALID_OUTPUT, ProviderKind.TEST_REPLAY, request.invocation_ref, "REPLAY_INVALID_JSON")
        errors = validate_payload(payload)
        if errors:
            return ProviderInvocationResult(InvocationStatus.SCHEMA_REJECTED, ProviderKind.TEST_REPLAY, request.invocation_ref, "REPLAY_SCHEMA_REJECTED", {"error_count": len(errors)})
        return ProviderInvocationResult(InvocationStatus.SUCCESS, ProviderKind.TEST_REPLAY, request.invocation_ref, "REPLAY_SUCCESS", {"schema_version": PAYLOAD_SCHEMA_VERSION}, payload)

    def parse_output(self, raw_output: str) -> Mapping[str, Any]:
        value = json.loads(raw_output)
        if not isinstance(value, dict):
            raise ValueError("replay output must be one JSON object")
        return value

    def build_provenance(self, request: PreparedRequest, result: ProviderInvocationResult) -> Mapping[str, Any]:
        return {
            "provider_kind": ProviderKind.TEST_REPLAY.value, "usage_plane": UsagePlane.TEST_REPLAY.value,
            "auth_class": AuthClass.NONE.value, "model_ref": "replay-fixture",
            "provider_instance_ref": "provider:test-replay:v0.1", "invocation_ref": request.invocation_ref,
            "prompt_template_version": "v0.1", "structured_output_schema_version": PAYLOAD_SCHEMA_VERSION,
            "sandbox_profile": {"sandbox_mode": "NONE", "working_root": ".", "tool_network_policy": "NOT_APPLICABLE", "ephemeral": True, "ignore_user_config": True, "ignore_rules": True},
            "generation_metadata": {"transport": "replay", "exit_code": 0}, "credential_env": None,
        }
