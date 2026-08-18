"""Frozen vocabulary for CipherLens evaluation evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


SCHEMA_VERSIONS = {
    "ledger": "cipherlens.evaluation_evidence_ledger.v0.1",
    "artifact_record": "cipherlens.artifact_record.v0.1",
    "test_run_record": "cipherlens.test_run_record.v0.1",
    "experiment_unit": "cipherlens.experiment_unit.v0.1",
    "metric_definition": "cipherlens.metric_definition.v0.1",
    "metric_population_manifest": "cipherlens.metric_population_manifest.v0.1",
    "metric_record": "cipherlens.metric_record.v0.1",
    "claim_record": "cipherlens.claim_record.v0.1",
    "claim_gate_report": "cipherlens.claim_gate_report.v0.1",
    "finding_ledger": "cipherlens.security_finding_ledger.v0.1",
}

REGISTRY_VERSION = "cipherlens.evaluation_evidence_registry.v0.1"
METRIC_REGISTRY_VERSION = "cipherlens.metric_registry.v0.1"


class EvidenceOrigin(str, Enum):
    CURRENT_V2 = "CURRENT_V2"
    CURRENT_NON_V2 = "CURRENT_NON_V2"
    LEGACY = "LEGACY"
    SYNTHETIC = "SYNTHETIC"
    EXTERNAL_UPSTREAM = "EXTERNAL_UPSTREAM"


class ValidationMaturity(str, Enum):
    SOURCE_PRESENT = "SOURCE_PRESENT"
    DIGEST_VERIFIED = "DIGEST_VERIFIED"
    SCHEMA_VALIDATED = "SCHEMA_VALIDATED"
    TEST_DEFINED = "TEST_DEFINED"
    TEST_RUN_RECORDED = "TEST_RUN_RECORDED"
    UNIT_VALIDATED = "UNIT_VALIDATED"
    GOLDEN_VALIDATED = "GOLDEN_VALIDATED"
    SYNTHETIC_E2E_VALIDATED = "SYNTHETIC_E2E_VALIDATED"
    REAL_EXECUTION_REPRODUCED = "REAL_EXECUTION_REPRODUCED"


class FindingStatus(str, Enum):
    NOT_A_FINDING = "NOT_A_FINDING"
    HYPOTHESIS = "HYPOTHESIS"
    REPRODUCED_RELATION_BEHAVIOR = "REPRODUCED_RELATION_BEHAVIOR"
    V2_VIOLATED_WITNESS = "V2_VIOLATED_WITNESS"
    IMPACT_ANALYZED = "IMPACT_ANALYZED"
    REPORTED_UPSTREAM = "REPORTED_UPSTREAM"
    UPSTREAM_ACKNOWLEDGED = "UPSTREAM_ACKNOWLEDGED"
    FIX_CONFIRMED = "FIX_CONFIRMED"
    CVE_OR_ADVISORY_CONFIRMED = "CVE_OR_ADVISORY_CONFIRMED"
    HARDENING_ONLY = "HARDENING_ONLY"
    SAFE_NEGATIVE = "SAFE_NEGATIVE"


class InventoryState(str, Enum):
    VERIFIED_PRESENT = "VERIFIED_PRESENT"
    PRESENT_UNVERIFIED = "PRESENT_UNVERIFIED"
    REFERENCE_ONLY = "REFERENCE_ONLY"
    LEGACY_ONLY = "LEGACY_ONLY"
    SYNTHETIC_ONLY = "SYNTHETIC_ONLY"
    NOT_FOUND = "NOT_FOUND"


class ClaimTaxonomy(str, Enum):
    DESIGN_CLAIM = "DESIGN_CLAIM"
    IMPLEMENTATION_CLAIM = "IMPLEMENTATION_CLAIM"
    ENGINEERING_VALIDATION_CLAIM = "ENGINEERING_VALIDATION_CLAIM"
    PIPELINE_VALIDATION_CLAIM = "PIPELINE_VALIDATION_CLAIM"
    LEGACY_BASELINE_CLAIM = "LEGACY_BASELINE_CLAIM"
    CURRENT_CAMPAIGN_RESULT_CLAIM = "CURRENT_CAMPAIGN_RESULT_CLAIM"
    SECURITY_FINDING_CLAIM = "SECURITY_FINDING_CLAIM"
    UPSTREAM_CONFIRMED_CLAIM = "UPSTREAM_CONFIRMED_CLAIM"


class ClaimGateResult(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_CAVEAT = "ALLOW_WITH_CAVEAT"
    BLOCK = "BLOCK"
    NEEDS_RERUN = "NEEDS_RERUN"
    NEEDS_RECOMPUTATION = "NEEDS_RECOMPUTATION"
    NEEDS_EXTERNAL_CONFIRMATION = "NEEDS_EXTERNAL_CONFIRMATION"
    LEGACY_ONLY = "LEGACY_ONLY"


class RecomputeStatus(str, Enum):
    RECOMPUTABLE = "RECOMPUTABLE"
    PARTIALLY_RECOMPUTABLE = "PARTIALLY_RECOMPUTABLE"
    NOT_RECOMPUTABLE = "NOT_RECOMPUTABLE"


class LegacyReusePolicy(str, Enum):
    REFERENCE_ONLY = "REFERENCE_ONLY"
    LEGACY_BASELINE = "LEGACY_BASELINE"
    RECOMPUTABLE_FROM_RAW_ARTIFACT = "RECOMPUTABLE_FROM_RAW_ARTIFACT"
    MUST_RERUN_V2 = "MUST_RERUN_V2"
    DISCARD = "DISCARD"


class EvaluationEvidenceError(ValueError):
    """Raised when a closed evidence artifact violates its contract."""

    def __init__(self, kind: str, errors: list[str] | tuple[str, ...]) -> None:
        self.kind = kind
        self.errors = tuple(sorted(dict.fromkeys(errors)))
        super().__init__(f"invalid {kind}:\n" + "\n".join(f"- {item}" for item in self.errors))


@dataclass(frozen=True)
class ArtifactLink:
    ref: str
    digest: str

    def to_dict(self) -> dict[str, str]:
        return {"ref": self.ref, "digest": self.digest}


@dataclass(frozen=True)
class ExternalEvidenceRecord:
    url: str
    publisher_identity: str
    evidence_type: str
    authority_classification: str
    record: dict[str, Any]
    telemetry: dict[str, Any]


ExternalAdapterResult = ExternalEvidenceRecord
