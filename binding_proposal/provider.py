"""LLM role-proposal provider abstraction; providers never verify facts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from binding_proposal.canonical import build_binding_proposal
from binding_proposal.model import PreparedRequest, ProviderInvocationResult
from binding_proposal.validate import validate_payload


class LLMRoleProposalProvider(ABC):
    @abstractmethod
    def prepare_request(self, prompt: str, *, schema_path: str, invocation_ref: str) -> PreparedRequest:
        raise NotImplementedError

    @abstractmethod
    def invoke(self, request: PreparedRequest) -> ProviderInvocationResult:
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, raw_output: str) -> Mapping[str, Any]:
        raise NotImplementedError

    def validate_provider_output(self, payload: Mapping[str, Any]) -> list[str]:
        return validate_payload(payload)

    @abstractmethod
    def build_provenance(self, request: PreparedRequest, result: ProviderInvocationResult) -> Mapping[str, Any]:
        raise NotImplementedError

    def build_binding_proposal(self, payload: Mapping[str, Any], **trusted_envelope: Any) -> dict[str, Any]:
        return build_binding_proposal(payload, **trusted_envelope)
