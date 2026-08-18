"""Provider-neutral types for advisory binding proposals."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


PAYLOAD_SCHEMA_VERSION = "cipherlens.binding_proposal_payload.v0.1"
PROPOSAL_SCHEMA_VERSION = "cipherlens.binding_proposal.v0.1"


class ProviderKind(str, Enum):
    CODEX_EXEC = "CODEX_EXEC"
    GLM_API = "GLM_API"
    OTHER = "OTHER"
    TEST_REPLAY = "TEST_REPLAY"


class UsagePlane(str, Enum):
    CHATGPT_AUTHENTICATED_LOCAL_CODEX = "CHATGPT_AUTHENTICATED_LOCAL_CODEX"
    API_METERED = "API_METERED"
    TEST_REPLAY = "TEST_REPLAY"


class AuthClass(str, Enum):
    CHATGPT_AUTHENTICATED_SESSION = "CHATGPT_AUTHENTICATED_SESSION"
    API_KEY_ENVIRONMENT = "API_KEY_ENVIRONMENT"
    NONE = "NONE"


class InvocationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    AUTH_FAILED = "AUTH_FAILED"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    TIMEOUT = "TIMEOUT"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    SCHEMA_REJECTED = "SCHEMA_REJECTED"
    POLICY_REJECTED = "POLICY_REJECTED"
    EXECUTION_ERROR = "EXECUTION_ERROR"


class FallbackPolicy(str, Enum):
    DISABLED = "DISABLED"
    MANUAL = "MANUAL"
    API_FALLBACK_EXPLICITLY_ALLOWED = "API_FALLBACK_EXPLICITLY_ALLOWED"


@dataclass(frozen=True)
class PreparedRequest:
    invocation_ref: str
    prompt: str
    schema_path: str
    safe_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderInvocationResult:
    status: InvocationStatus
    provider_kind: ProviderKind
    invocation_ref: str
    reason_code: str
    safe_metadata: Mapping[str, Any] = field(default_factory=dict)
    payload: Mapping[str, Any] | None = None


class BindingProposalError(ValueError):
    def __init__(self, document_kind: str, errors: list[str] | tuple[str, ...]) -> None:
        self.document_kind = document_kind
        self.errors = tuple(sorted(dict.fromkeys(errors)))
        super().__init__(f"invalid {document_kind}:\n" + "\n".join(f"- {item}" for item in self.errors))
