"""Frozen vocabulary for Template--CandidateBinding Merge v0.1."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


MERGE_SCHEMA_VERSION = "cipherlens.template_binding_merge.v0.1"
BOUND_SOURCE_SCHEMA_VERSION = "cipherlens.bound_template_source.v0.1"
SOURCE_MAP_SCHEMA_VERSION = "cipherlens.bound_source_map.v0.1"
ADAPTATION_SCHEMA_VERSION = "cipherlens.adaptation_proposal.v0.1"
VALIDATION_SCHEMA_VERSION = "cipherlens.template_binding_merge_validation.v0.1"
MERGE_REGISTRY_VERSION = "cipherlens.template_binding_merge_registry.v0.1"
VALIDATOR_REGISTRY_VERSION = "cipherlens.template_binding_merge_validator_registry.v0.1"
COMPLETION_REGISTRY_VERSION = "cipherlens.programmatic_completion_registry.v0.1"
RENDERER_ID = "cipherlens.template_binding_merge.bound_renderer"
RENDERER_VERSION = "v0.1"


class SlotKind(str, Enum):
    INPUT = "INPUT"
    OBJECT = "OBJECT"
    OPERATION = "OPERATION"
    INTERVENTION = "INTERVENTION"
    OBSERVATION = "OBSERVATION"
    ORDER_ANCHOR = "ORDER_ANCHOR"
    STATE_ANCHOR = "STATE_ANCHOR"


class CandidateElementKind(str, Enum):
    SUBJECT = "SUBJECT"
    OPERATION = "OPERATION"
    INPUT = "INPUT"
    INTERVENTION = "INTERVENTION"
    OBSERVATION = "OBSERVATION"
    CONTINUITY = "CONTINUITY"
    CORRELATION = "CORRELATION"


class RenderDisposition(str, Enum):
    DIRECT_SUBSTITUTION = "DIRECT_SUBSTITUTION"
    DECLARED_ADAPTATION_HOLE = "DECLARED_ADAPTATION_HOLE"
    STRUCTURAL_ANCHOR = "STRUCTURAL_ANCHOR"


class StructuralObligationType(str, Enum):
    REQUIRED_SLOT_COVERAGE = "REQUIRED_SLOT_COVERAGE"
    OPERATION_SEQUENCE_PRESERVED = "OPERATION_SEQUENCE_PRESERVED"
    INTERVENTION_PHASE_PRESERVED = "INTERVENTION_PHASE_PRESERVED"
    OBSERVATION_PHASE_PRESERVED = "OBSERVATION_PHASE_PRESERVED"
    INPUT_DATA_DEPENDENCY_PRESERVED = "INPUT_DATA_DEPENDENCY_PRESERVED"
    SUBJECT_IDENTITY_PRESERVED = "SUBJECT_IDENTITY_PRESERVED"
    SAME_IDENTITY_ACROSS_OPERATIONS = "SAME_IDENTITY_ACROSS_OPERATIONS"
    FOLLOWUP_SEQUENCE_PRESERVED = "FOLLOWUP_SEQUENCE_PRESERVED"
    CORRELATION_RELATION_PRESERVED = "CORRELATION_RELATION_PRESERVED"
    CONTROL_FLOW_ANCHOR_PRESERVED = "CONTROL_FLOW_ANCHOR_PRESERVED"


class AdaptationHoleType(str, Enum):
    INCLUDE_IMPORT = "INCLUDE_IMPORT"
    NAMESPACE_QUALIFICATION = "NAMESPACE_QUALIFICATION"
    DECLARATION_SYNTAX = "DECLARATION_SYNTAX"
    TYPE_COMPATIBLE_CONVERSION = "TYPE_COMPATIBLE_CONVERSION"
    ALLOCATION_GLUE = "ALLOCATION_GLUE"
    DEALLOCATION_GLUE = "DEALLOCATION_GLUE"
    ERROR_VARIABLE_DECLARATION = "ERROR_VARIABLE_DECLARATION"
    WRAPPER_GLUE = "WRAPPER_GLUE"
    CONSTANT_SPELLING = "CONSTANT_SPELLING"
    ENUM_SPELLING = "ENUM_SPELLING"
    ACCESSOR_SYNTAX = "ACCESSOR_SYNTAX"
    SAFE_CAST = "SAFE_CAST"
    CONTROL_FLOW_GLUE = "CONTROL_FLOW_GLUE"
    OBSERVATION_CAPTURE_GLUE = "OBSERVATION_CAPTURE_GLUE"
    BUILD_METADATA = "BUILD_METADATA"


class HoleResolver(str, Enum):
    DETERMINISTIC_ONLY = "DETERMINISTIC_ONLY"
    PROPOSAL_ALLOWED = "PROPOSAL_ALLOWED"


class RestrictedEditType(str, Enum):
    FILL_HOLE = "FILL_HOLE"
    ADD_DECLARED_INCLUDE = "ADD_DECLARED_INCLUDE"
    INSERT_DECLARED_BOILERPLATE = "INSERT_DECLARED_BOILERPLATE"
    REPLACE_DECLARED_EXPRESSION = "REPLACE_DECLARED_EXPRESSION"


class RegionKind(str, Enum):
    TEMPLATE_PROTECTED = "TEMPLATE_PROTECTED"
    MAPPING_PROTECTED = "MAPPING_PROTECTED"
    ADAPTATION_HOLE = "ADAPTATION_HOLE"


class ValidationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"


class CheckResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


class ValidationRouting(str, Enum):
    EXECUTION_HANDOFF = "EXECUTION_HANDOFF"
    CONSTRAINED_ADAPTATION = "CONSTRAINED_ADAPTATION"
    PROGRAMMATIC_COMPLETION = "PROGRAMMATIC_COMPLETION"
    WHOLE_BINDING_SWITCH = "WHOLE_BINDING_SWITCH"


class ValidatorType(str, Enum):
    REFERENCE_INTEGRITY = "REFERENCE_INTEGRITY"
    VALID_BINDING_GATE = "VALID_BINDING_GATE"
    TARGET_SCOPE_CONSISTENCY = "TARGET_SCOPE_CONSISTENCY"
    SLOT_COVERAGE = "SLOT_COVERAGE"
    SLOT_MULTIPLICITY = "SLOT_MULTIPLICITY"
    SUBJECT_PRESERVATION = "SUBJECT_PRESERVATION"
    OPERATION_PRESERVATION = "OPERATION_PRESERVATION"
    INPUT_PRESERVATION = "INPUT_PRESERVATION"
    INTERVENTION_PRESERVATION = "INTERVENTION_PRESERVATION"
    ORDER_PRESERVATION = "ORDER_PRESERVATION"
    STATE_CONTINUITY_PRESERVATION = "STATE_CONTINUITY_PRESERVATION"
    OBSERVATION_PRESERVATION = "OBSERVATION_PRESERVATION"
    CORRELATION_PRESERVATION = "CORRELATION_PRESERVATION"
    STRUCTURAL_OBLIGATION = "STRUCTURAL_OBLIGATION"
    ADAPTATION_BOUNDARY = "ADAPTATION_BOUNDARY"
    FORBIDDEN_SEMANTIC_DRIFT = "FORBIDDEN_SEMANTIC_DRIFT"
    SOURCE_BINDING_CONSISTENCY = "SOURCE_BINDING_CONSISTENCY"
    COMPLETENESS = "COMPLETENESS"


class MergeError(ValueError):
    def __init__(self, document_kind: str, errors: list[str] | tuple[str, ...]) -> None:
        self.document_kind = document_kind
        self.errors = tuple(sorted(dict.fromkeys(errors)))
        super().__init__(f"invalid {document_kind}:\n" + "\n".join(f"- {x}" for x in self.errors))


class MergeGateError(MergeError):
    pass


class AdaptationRejected(MergeError):
    pass


@dataclass(frozen=True)
class TemplateBundle:
    trigger_template_ref: str
    trigger_template_digest: str
    source_artifact_ref: str
    source_artifact_digest: str
    language: str = "c"

    def to_dict(self) -> dict[str, str]:
        return {
            "trigger_template_ref": self.trigger_template_ref,
            "trigger_template_digest": self.trigger_template_digest,
            "source_artifact_ref": self.source_artifact_ref,
            "source_artifact_digest": self.source_artifact_digest,
            "language": self.language,
        }


@dataclass(frozen=True)
class MergeGateResult:
    template_bundle: TemplateBundle
    template_manifest: Mapping[str, Any]
    candidate_binding: Mapping[str, Any]
    candidate_binding_validation: Mapping[str, Any]
    template_interface_digest: str
    candidate_binding_digest: str
    candidate_binding_validation_digest: str


@dataclass(frozen=True)
class RenderResult:
    source_bytes: bytes
    source_map: Mapping[str, Any]
    bound_source: Mapping[str, Any]


@dataclass(frozen=True)
class ValidationContext:
    gate: MergeGateResult
    merge: Mapping[str, Any]
    source_bytes: bytes
    source_map: Mapping[str, Any]
    bound_source: Mapping[str, Any]
