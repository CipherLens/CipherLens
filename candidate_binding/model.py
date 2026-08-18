"""Frozen vocabulary for CandidateBinding and validation artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


BINDING_SCHEMA_VERSION = "cipherlens.candidate_binding.v0.1"
VALIDATION_SCHEMA_VERSION = "cipherlens.candidate_binding_validation.v0.1"
VALIDATOR_REGISTRY_VERSION = "cipherlens.candidate_binding_validator_registry.v0.1"


class ValidationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"


class CheckResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


class ValidatorType(str, Enum):
    REFERENCE_INTEGRITY = "REFERENCE_INTEGRITY"
    TARGET_SCOPE = "TARGET_SCOPE"
    ELIGIBILITY_GATE = "ELIGIBILITY_GATE"
    SUBJECT_BINDING = "SUBJECT_BINDING"
    OPERATION_BINDING = "OPERATION_BINDING"
    INPUT_BINDING = "INPUT_BINDING"
    INTERVENTION_BINDING = "INTERVENTION_BINDING"
    CONTINUITY = "CONTINUITY"
    OBSERVABILITY = "OBSERVABILITY"
    COMPLETENESS = "COMPLETENESS"


class CandidateBindingError(ValueError):
    def __init__(self, errors: list[str] | tuple[str, ...]) -> None:
        self.errors = tuple(sorted(dict.fromkeys(errors)))
        super().__init__("invalid CandidateBinding:\n" + "\n".join(f"- {x}" for x in self.errors))


class ConstructionRejected(CandidateBindingError):
    pass


@dataclass(frozen=True)
class ValidationContext:
    contract: Mapping[str, Any]
    transfer_signature: Mapping[str, Any]
    template_manifest: Mapping[str, Any]
    target_profile: Mapping[str, Any]
    eligibility_evaluation: Mapping[str, Any]
