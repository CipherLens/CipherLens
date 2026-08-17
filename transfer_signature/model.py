"""Closed semantic result types for Transfer Signature evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


TS_SCHEMA_VERSION = "cipherlens.transfer_signature.v0.1"
PROFILE_SCHEMA_VERSION = "cipherlens.target_semantic_profile.v0.1"
EVALUATION_SCHEMA_VERSION = "cipherlens.ts_evaluation.v0.1"


class ConstraintClass(str, Enum):
    REQUIRED_CAPABILITY = "required_capability"
    EXCLUDED_SEMANTIC = "excluded_semantic"
    REQUIRED_OBSERVABILITY = "required_observability"


class ConstraintResult(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNKNOWN = "UNKNOWN"


class Eligibility(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    INDETERMINATE = "INDETERMINATE"


class Assertion(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class EpistemicStatus(str, Enum):
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    PROPOSED = "PROPOSED"


class FactCoverage(str, Enum):
    SUBJECT = "SUBJECT"
    SURFACE = "SURFACE"


@dataclass(frozen=True)
class ConstraintEvaluation:
    constraint_id: str
    constraint_class: ConstraintClass
    result: ConstraintResult
    matched_fact_refs: tuple[str, ...]
    reason_code: str
    missing_fact_requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "constraint_class": self.constraint_class.value,
            "result": self.result.value,
            "matched_fact_refs": list(self.matched_fact_refs),
            "reason_code": self.reason_code,
            "missing_fact_requirements": list(self.missing_fact_requirements),
        }


@dataclass(frozen=True)
class SourceValidationArtifact:
    """One source-validation record paired with its declared artifact digest."""

    record: Mapping[str, Any]
    digest: str


class TransferSignatureError(ValueError):
    """Base error for deterministic TS foundation failures."""


class SchemaValidationError(TransferSignatureError):
    def __init__(self, document_kind: str, errors: list[str]) -> None:
        self.document_kind = document_kind
        self.errors = tuple(sorted(dict.fromkeys(errors)))
        super().__init__(
            f"invalid {document_kind}:\n"
            + "\n".join(f"- {error}" for error in self.errors)
        )


class DerivationError(TransferSignatureError):
    """Raised when the validated-Contract generation gate rejects input."""
