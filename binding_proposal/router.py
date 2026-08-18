"""Minimal provider selection with no silent metered fallback."""

from __future__ import annotations

from binding_proposal.config import ProviderConfig
from binding_proposal.model import FallbackPolicy, PreparedRequest, ProviderInvocationResult
from binding_proposal.provider import LLMRoleProposalProvider


class ProviderRouter:
    def __init__(self, primary: LLMRoleProposalProvider, *, config: ProviderConfig, glm_provider: LLMRoleProposalProvider | None = None) -> None:
        self.primary = primary
        self.config = config
        self.glm_provider = glm_provider

    def invoke(self, request: PreparedRequest) -> ProviderInvocationResult:
        result = self.primary.invoke(request)
        if result.status.value == "SUCCESS":
            return result
        if self.config.fallback_policy is not FallbackPolicy.API_FALLBACK_EXPLICITLY_ALLOWED:
            return result
        if not self.config.glm.enabled or self.glm_provider is None:
            return result
        fallback_request = self.glm_provider.prepare_request(
            request.prompt, schema_path=request.schema_path, invocation_ref=request.invocation_ref + ":glm-fallback"
        )
        return self.glm_provider.invoke(fallback_request)
