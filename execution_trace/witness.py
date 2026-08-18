"""Execution witness formation and no-witness enforcement."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from execution_model.canonical import artifact_digest, identify
from execution_model.model import ExecutionAttemptOutcome, REGISTRY_VERSION, SCHEMA_VERSIONS, WitnessStatus
from execution_model.registry import validate_artifact_or_raise
from execution_pipeline.runner_adapter import attempt_outcome


def form_execution_witness(
    *, contract_ref: str, contract_digest: str,
    candidate_binding_ref: str, candidate_binding_digest: str,
    merge_ref: str, merge_digest: str, merge_validation_ref: str, merge_validation_digest: str,
    bound_source_ref: str, bound_source_digest: str, source_map_ref: str, source_map_digest: str,
    build_spec: Mapping[str, Any] | None, build_record: Mapping[str, Any] | None,
    run_spec: Mapping[str, Any] | None, run_record: Mapping[str, Any] | None,
    source_artifact_digest: str, input_artifact_digests: Sequence[str] = (),
    acquisition_integrity: Mapping[str, Any] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    outcome = attempt_outcome(build_record, run_record)
    if outcome != ExecutionAttemptOutcome.WITNESS_FORMED.value:
        return outcome, None
    assert build_spec is not None and build_record is not None and run_spec is not None and run_record is not None
    errors: list[str] = []
    pairs = (
        (build_record.get("build_spec_ref"), build_spec.get("build_spec_id"), "BuildRecord/BuildSpec ref"),
        (build_record.get("build_spec_digest"), artifact_digest(build_spec), "BuildRecord/BuildSpec digest"),
        (run_spec.get("build_record_ref"), build_record.get("build_record_id"), "RunSpec/BuildRecord ref"),
        (run_spec.get("build_record_digest"), artifact_digest(build_record), "RunSpec/BuildRecord digest"),
        (run_record.get("run_spec_ref"), run_spec.get("run_spec_id"), "RunRecord/RunSpec ref"),
        (run_record.get("run_spec_digest"), artifact_digest(run_spec), "RunRecord/RunSpec digest"),
        (run_record.get("binary_digest"), build_record.get("binary_digest"), "binary digest"),
    )
    errors.extend(f"{label} mismatch" for actual, expected, label in pairs if actual != expected)
    integrity = dict(acquisition_integrity or {
        "framework_complete": run_record.get("collection") == "COMPLETE",
        "artifact_integrity": True,
        "lineage_integrity": not errors,
        "required_channels_complete": run_record.get("collection") == "COMPLETE",
    })
    if errors or not integrity.get("lineage_integrity") or not integrity.get("artifact_integrity"):
        status = WitnessStatus.INVALID_WITNESS.value
    elif all(integrity.get(key) for key in ("framework_complete", "required_channels_complete")):
        status = WitnessStatus.VALID_WITNESS.value
    else:
        status = WitnessStatus.PARTIAL_WITNESS.value
    witness_outcome = ExecutionAttemptOutcome.LINEAGE_INTEGRITY_FAILED.value if status == WitnessStatus.INVALID_WITNESS.value else outcome
    witness = identify({
        "schema_version": SCHEMA_VERSIONS["witness"], "witness_id": "pending",
        "status": status, "attempt_outcome": witness_outcome,
        "contract_ref": contract_ref, "contract_digest": contract_digest,
        "candidate_binding_ref": candidate_binding_ref, "candidate_binding_digest": candidate_binding_digest,
        "merge_ref": merge_ref, "merge_digest": merge_digest,
        "merge_validation_ref": merge_validation_ref, "merge_validation_digest": merge_validation_digest,
        "bound_source_ref": bound_source_ref, "bound_source_digest": bound_source_digest,
        "source_map_ref": source_map_ref, "source_map_digest": source_map_digest,
        "build_spec_ref": build_spec["build_spec_id"], "build_spec_digest": artifact_digest(build_spec),
        "build_record_ref": build_record["build_record_id"], "build_record_digest": artifact_digest(build_record),
        "run_spec_ref": run_spec["run_spec_id"], "run_spec_digest": artifact_digest(run_spec),
        "run_record_ref": run_record["run_record_id"], "run_record_digest": artifact_digest(run_record),
        "source_artifact_digest": source_artifact_digest, "binary_digest": run_record["binary_digest"],
        "input_artifact_digests": list(input_artifact_digests),
        "raw_artifact_manifest": [{"artifact_ref": x["artifact_ref"], "artifact_digest": x["artifact_digest"]} for x in run_record.get("raw_artifacts", [])],
        "acquisition_integrity": integrity, "reason_codes": errors or [status],
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(witness)
    return witness_outcome, witness
