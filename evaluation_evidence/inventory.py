"""Read-only repository evidence observation and deterministic legacy recounts."""

from __future__ import annotations

from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

import yaml

from evaluation_evidence.canonical import identify, raw_digest, validate_relative_location
from evaluation_evidence.model import EvidenceOrigin, InventoryState, SCHEMA_VERSIONS, ValidationMaturity
from evaluation_evidence.registry import validate_document_or_raise


def build_artifact_record(
    *, artifact_ref: str, artifact_digest: str | None, artifact_type: str,
    artifact_schema_version: str, media_type: str, producer_id: str,
    producer_version: str, git_revision: str, origin: EvidenceOrigin | str,
    inventory_state: InventoryState | str,
    validation_maturity: Iterable[ValidationMaturity | str], execution_scope: str,
    synthetic_or_real: str, public_disclosure_state: str, source_location: str,
    parent_refs: Iterable[Mapping[str, str]] = (),
    validation_evidence_refs: Iterable[Mapping[str, str]] = (), notes: Iterable[str] = (),
) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSIONS["artifact_record"],
        "artifact_record_id": "pending",
        "artifact_ref": artifact_ref,
        "artifact_digest": artifact_digest,
        "artifact_type": artifact_type,
        "artifact_schema_version": artifact_schema_version,
        "media_type": media_type,
        "producer": {"producer_id": producer_id, "producer_version": producer_version},
        "git_revision": git_revision,
        "origin": origin.value if isinstance(origin, EvidenceOrigin) else origin,
        "inventory_state": inventory_state.value if isinstance(inventory_state, InventoryState) else inventory_state,
        "validation_maturity": [item.value if isinstance(item, ValidationMaturity) else item for item in validation_maturity],
        "execution_scope": execution_scope,
        "synthetic_or_real": synthetic_or_real,
        "public_disclosure_state": public_disclosure_state,
        "parent_refs": [dict(item) for item in parent_refs],
        "source_location": source_location,
        "validation_evidence_refs": [dict(item) for item in validation_evidence_refs],
        "notes": list(notes),
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result


def observe_repository_file(
    repo_root: str | Path, relative_location: str, *, artifact_type: str,
    git_revision: str, origin: EvidenceOrigin, producer_id: str = "repository-inventory",
    producer_version: str = "0.1", artifact_schema_version: str = "",
    media_type: str = "application/octet-stream", execution_scope: str = "repository",
    synthetic_or_real: str = "REAL", public_disclosure_state: str = "LOCAL_ONLY",
) -> dict[str, Any]:
    if not validate_relative_location(relative_location):
        raise ValueError("relative_location must be repository-relative")
    root = Path(repo_root).resolve()
    path = root.joinpath(*PurePosixPath(relative_location).parts)
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ValueError("repository location escapes root") from exc
    artifact_ref = f"repo:{relative_location}"
    if not path.is_file() or path.is_symlink():
        return build_artifact_record(
            artifact_ref=artifact_ref, artifact_digest=None, artifact_type=artifact_type,
            artifact_schema_version=artifact_schema_version, media_type=media_type,
            producer_id=producer_id, producer_version=producer_version, git_revision=git_revision,
            origin=origin, inventory_state=InventoryState.NOT_FOUND, validation_maturity=(),
            execution_scope=execution_scope, synthetic_or_real=synthetic_or_real,
            public_disclosure_state=public_disclosure_state, source_location=relative_location,
            notes=("Expected artifact was not present at inventory time",),
        )
    payload = path.read_bytes()
    return build_artifact_record(
        artifact_ref=artifact_ref, artifact_digest=raw_digest(payload), artifact_type=artifact_type,
        artifact_schema_version=artifact_schema_version, media_type=media_type,
        producer_id=producer_id, producer_version=producer_version, git_revision=git_revision,
        origin=origin, inventory_state=InventoryState.VERIFIED_PRESENT,
        validation_maturity=(ValidationMaturity.SOURCE_PRESENT, ValidationMaturity.DIGEST_VERIFIED),
        execution_scope=execution_scope, synthetic_or_real=synthetic_or_real,
        public_disclosure_state=public_disclosure_state, source_location=relative_location,
    )


def recount_legacy_candidate_population(
    repo_root: str | Path,
    queue_location: str = "artifacts/candidate_queue/candidate_queue.yaml",
) -> dict[str, Any]:
    """Recount a unique-ID population without trusting summary count fields."""
    root = Path(repo_root).resolve()
    queue_payload = (root / queue_location).read_bytes()
    queue = yaml.safe_load(queue_payload)
    if not isinstance(queue, Mapping) or not isinstance(queue.get("candidates"), list):
        raise ValueError("candidate queue must contain candidates[]")
    upstream_location = str((queue.get("sources") or {}).get("pattern_bank") or "")
    if not validate_relative_location(upstream_location):
        raise ValueError("candidate queue pattern_bank source is not repository-relative")
    upstream_payload = (root / upstream_location).read_bytes()
    upstream = yaml.safe_load(upstream_payload)
    if not isinstance(upstream, Mapping) or not isinstance(upstream.get("patterns"), list):
        raise ValueError("pattern bank must contain patterns[]")

    def identities(items: list[Any], label: str) -> list[str]:
        result: list[str] = []
        for index, item in enumerate(items):
            if not isinstance(item, Mapping) or not isinstance(item.get("pattern_id"), str) or not item["pattern_id"]:
                raise ValueError(f"{label}[{index}] lacks a non-empty pattern_id")
            result.append(item["pattern_id"])
        duplicates = sorted(item for item, count in Counter(result).items() if count > 1)
        if duplicates:
            raise ValueError(f"{label} contains duplicate pattern_id values: {duplicates}")
        return sorted(result)

    queue_ids = identities(queue["candidates"], "candidates")
    upstream_ids = identities(upstream["patterns"], "patterns")
    if queue_ids != upstream_ids:
        raise ValueError("candidate queue population differs from its upstream pattern bank")
    source_types = Counter(str(item.get("source_type") or "UNDECLARED") for item in upstream["patterns"])
    declared = (queue.get("summary") or {}).get("total_candidates")
    return {
        "schema_version": "cipherlens.legacy_population_recount.v0.1",
        "population_unit": "unique pattern_id in candidate_queue.candidates",
        "selection_rule": "include every candidates[] item with one non-empty pattern_id",
        "duplicate_policy": "REJECT_DUPLICATE_PATTERN_ID",
        "exclusion_rule": "no valid candidate item is excluded",
        "queue_ref": f"repo:{queue_location}", "queue_digest": raw_digest(queue_payload),
        "upstream_ref": f"repo:{upstream_location}", "upstream_digest": raw_digest(upstream_payload),
        "identity_set_equal": True, "item_identities": queue_ids,
        "source_type_counts": {key: source_types[key] for key in sorted(source_types)},
        "actual_count": len(queue_ids), "declared_count": declared,
        "declared_count_matches": declared == len(queue_ids),
    }
