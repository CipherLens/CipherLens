from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from evaluation_evidence.inventory import build_artifact_record
from evaluation_evidence.model import EvidenceOrigin, InventoryState, ValidationMaturity


ROOT = Path(__file__).resolve().parents[2]
HEAD = "ba71d8f3f3a26349de9283cbf515778c43cd7638"


def raw_link(ref: str, payload: bytes) -> dict[str, str]:
    return {"ref": ref, "digest": hashlib.sha256(payload).hexdigest()}


def resolver_for(links: Iterable[Mapping[str, str]]):
    allowed = {(item["ref"], item["digest"]) for item in links}
    return lambda ref, digest: (ref, digest) in allowed


def artifact_record(
    ref: str, payload: bytes, *, artifact_type: str = "source",
    origin: EvidenceOrigin = EvidenceOrigin.CURRENT_V2, synthetic: bool = False,
    maturity: tuple[ValidationMaturity, ...] = (ValidationMaturity.SOURCE_PRESENT, ValidationMaturity.DIGEST_VERIFIED),
    public: str = "LOCAL_ONLY",
) -> dict[str, Any]:
    return build_artifact_record(
        artifact_ref=ref, artifact_digest=hashlib.sha256(payload).hexdigest(),
        artifact_type=artifact_type, artifact_schema_version="fixture.v0.1",
        media_type="application/json", producer_id="test-fixture", producer_version="0.1",
        git_revision=HEAD, origin=origin, inventory_state=InventoryState.VERIFIED_PRESENT,
        validation_maturity=maturity, execution_scope="unit-test",
        synthetic_or_real="SYNTHETIC" if synthetic else "REAL",
        public_disclosure_state=public, source_location="tests/evaluation_evidence/fixture",
    )


def scope(**changes: bool) -> dict[str, bool]:
    value = {
        "current_v2": False, "real_campaign": False, "global_security": False,
        "confirmed_vulnerability": False, "upstream_acknowledged": False,
    }
    value.update(changes)
    return value
