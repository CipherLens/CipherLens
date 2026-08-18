"""Digest-complete package for an execution-level Contract violation."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from execution_model.canonical import artifact_digest, identify
from execution_model.model import REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact_or_raise
from template_binding_merge.canonical import bound_source_digest, merge_validation_digest, source_map_digest


def build_violation_evidence_package(
    *, contract: Mapping[str, Any], candidate_binding: Mapping[str, Any], merge: Mapping[str, Any],
    merge_validation: Mapping[str, Any], bound_source: Mapping[str, Any], source_map: Mapping[str, Any],
    build_spec: Mapping[str, Any], build_record: Mapping[str, Any], run_spec: Mapping[str, Any],
    run_record: Mapping[str, Any], witness: Mapping[str, Any], trace: Mapping[str, Any],
    evaluations: Sequence[Mapping[str, Any]], verdict: Mapping[str, Any],
    supporting_raw_artifacts: Sequence[Mapping[str, Any]] = (), reproduction_metadata_refs: Sequence[str] = (),
) -> dict[str, Any]:
    if verdict.get("verdict") != "VIOLATED": raise ValueError("ViolationEvidencePackage requires VIOLATED Verdict")
    broken = [x for x in evaluations if x.get("result") == "BROKEN" and (x.get("admissibility") or {}).get("broken_admissible") is True]
    if not broken: raise ValueError("VIOLATED package requires admissible BROKEN evaluation")
    lineage = (
        (witness.get("contract_ref"), f"contract:{contract.get('contract_id')}"),
        (witness.get("candidate_binding_ref"), candidate_binding.get("binding_id")),
        (witness.get("merge_ref"), merge.get("merge_id")),
        (witness.get("merge_validation_ref"), merge_validation.get("validation_id")),
        (witness.get("merge_validation_digest"), merge_validation_digest(merge_validation)),
        (witness.get("bound_source_ref"), bound_source.get("bound_source_id")),
        (witness.get("bound_source_digest"), bound_source_digest(bound_source)),
        (witness.get("source_map_ref"), source_map.get("source_map_id")),
        (witness.get("source_map_digest"), source_map_digest(source_map)),
        (witness.get("build_spec_ref"), build_spec.get("build_spec_id")),
        (witness.get("build_spec_digest"), artifact_digest(build_spec)),
        (witness.get("build_record_ref"), build_record.get("build_record_id")),
        (witness.get("build_record_digest"), artifact_digest(build_record)),
        (witness.get("run_spec_ref"), run_spec.get("run_spec_id")),
        (witness.get("run_spec_digest"), artifact_digest(run_spec)),
        (witness.get("run_record_ref"), run_record.get("run_record_id")),
        (witness.get("run_record_digest"), artifact_digest(run_record)),
        (verdict.get("witness_ref"), witness.get("witness_id")),
        (verdict.get("trace_ref"), trace.get("trace_id")),
    )
    if any(actual != expected for actual, expected in lineage):
        raise ValueError("ViolationEvidencePackage lineage mismatch")
    document = identify({
        "schema_version": SCHEMA_VERSIONS["violation_package"], "package_id": "pending",
        "contract_ref": witness["contract_ref"], "contract_digest": witness["contract_digest"],
        "candidate_binding_ref": candidate_binding["binding_id"], "candidate_binding_digest": witness["candidate_binding_digest"],
        "merge_ref": merge["merge_id"], "merge_digest": witness["merge_digest"],
        "merge_validation_ref": merge_validation["validation_id"], "merge_validation_digest": witness["merge_validation_digest"],
        "bound_source_ref": bound_source["bound_source_id"], "bound_source_digest": witness["bound_source_digest"],
        "source_map_ref": source_map["source_map_id"], "source_map_digest": witness["source_map_digest"],
        "build_spec_ref": build_spec["build_spec_id"], "build_spec_digest": artifact_digest(build_spec),
        "build_record_ref": build_record["build_record_id"], "build_record_digest": artifact_digest(build_record),
        "run_spec_ref": run_spec["run_spec_id"], "run_spec_digest": artifact_digest(run_spec),
        "run_record_ref": run_record["run_record_id"], "run_record_digest": artifact_digest(run_record),
        "witness_ref": witness["witness_id"], "witness_digest": artifact_digest(witness),
        "trace_ref": trace["trace_id"], "trace_digest": artifact_digest(trace),
        "broken_relation_evaluations": [{"ref": x["evaluation_id"], "digest": artifact_digest(x)} for x in broken],
        "execution_verdict_ref": verdict["verdict_id"], "execution_verdict_digest": artifact_digest(verdict),
        "supporting_raw_artifacts": [dict(x) for x in supporting_raw_artifacts],
        "reproduction_metadata_refs": list(reproduction_metadata_refs),
        "claim_policy": {"execution_relation_violation": True, "confirmed_vulnerability": False, "cve": False, "exploitability": "not_assessed"},
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document); return document
