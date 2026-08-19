"""Create-only C1 pre-run repair records for the approved 0020 fixed unit.

The helpers in this module inspect and materialize preparation metadata only.
They never resolve an unrecorded source path, invoke a compiler, or launch a
target process.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from execution_model.canonical import artifact_digest
from execution_pipeline.build_adapter import build_spec_from_handoff
from target_knowledge.canonical import canonical_json_bytes, identified, semantic_safety_errors

from .c1_gate import APPROVED_UNIT_ID


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
CAMPAIGN_SCOPE = "NOT_FULL_CAMPAIGN"
_SHA_CHARS = set("0123456789abcdef")
_LINEAGE_REQUIREMENTS = (
    "candidate_binding",
    "candidate_binding_validation",
    "merge",
    "bound_source",
    "source_map",
    "execution_handoff",
)


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _SHA_CHARS for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _edge(value: Mapping[str, Any], label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not isinstance(value.get("ref"), str) or not value["ref"]:
        raise ValueError(f"{label} requires ref + digest")
    if value["ref"].startswith("/"):
        raise ValueError(f"{label} ref must be logical, not an absolute path")
    return {"ref": value["ref"], "digest": _sha(value.get("digest"), f"{label} digest")}


def _common() -> dict[str, Any]:
    return {
        "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE,
        "campaign_scope": CAMPAIGN_SCOPE,
        "report_real_number_allowed": False,
        "execution_status": "NOT_EXECUTED",
    }


def inspect_fixed_library(
    artifact_path: Path | None,
    *,
    artifact_ref: str | None = None,
    library_kind: str = "static",
    producer_evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Digest an existing library or explicitly record all missing evidence."""

    common = _common()
    if artifact_path is None or not artifact_path.is_file():
        return identified({
            "schema_version": "cipherlens.c1_fixed_library_readiness.v0.1",
            **common,
            "status": "MISSING",
            "library_artifact": None,
            "producer_evidence": [],
            "missing_artifacts": [
                "fixed-side library artifact",
                "library build provenance",
                "link input digest",
            ],
            "authority": "C1_PRE_RUN_LIBRARY_INVENTORY_ONLY",
        }, "c1-fixed-library-readiness", "readiness_id")
    if not artifact_ref:
        raise ValueError("an existing library requires a logical artifact ref")
    library = _edge({"ref": artifact_ref, "digest": hashlib.sha256(artifact_path.read_bytes()).hexdigest()}, "library artifact")
    producers = [_edge(item, f"producer evidence {index}") for index, item in enumerate(producer_evidence)]
    result = identified({
        "schema_version": "cipherlens.c1_fixed_library_readiness.v0.1",
        **common,
        "status": "AVAILABLE",
        "library_artifact": {**library, "kind": library_kind},
        "producer_evidence": producers,
        "missing_artifacts": [] if producers else ["library build provenance"],
        "authority": "C1_PRE_RUN_LIBRARY_INVENTORY_ONLY",
        "telemetry": {"local_path": str(artifact_path.resolve())},
    }, "c1-fixed-library-readiness", "readiness_id")
    if semantic_safety_errors(result):
        raise ValueError("unsafe fixed library readiness document")
    return result


def fixed_include_readiness(
    *,
    fixed_source_identity: Mapping[str, Any],
    buggy_source_identity: Mapping[str, Any],
    rejected_include_evidence: Mapping[str, Any],
    fixed_include_roots: Sequence[Mapping[str, Any]] = (),
    fixed_headers: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Reject a buggy-side include edge and require byte-addressed fixed headers."""

    fixed = _edge(fixed_source_identity, "fixed source identity")
    buggy = _edge(buggy_source_identity, "buggy source identity")
    rejected = _edge(rejected_include_evidence, "rejected include evidence")
    if fixed == buggy:
        raise ValueError("fixed and buggy source identities must differ")
    roots = [_edge(item, f"fixed include root {index}") for index, item in enumerate(fixed_include_roots)]
    headers = [_edge(item, f"fixed header {index}") for index, item in enumerate(fixed_headers)]
    complete = bool(roots) and bool(headers)
    return identified({
        "schema_version": "cipherlens.c1_fixed_include_readiness.v0.1",
        **_common(),
        "status": "VERIFIED" if complete else "MISSING",
        "fixed_source_identity": fixed,
        "buggy_source_identity": buggy,
        "rejected_buggy_include_evidence": rejected,
        "fixed_include_roots": roots,
        "fixed_headers": headers,
        "missing_artifacts": ([] if complete else [
            "fixed include root evidence",
            "fixed selected header evidence",
        ]),
        "reason_code": "FIXED_INCLUDE_EVIDENCE_VERIFIED" if complete else "BUGGY_INCLUDE_EDGE_REJECTED_FIXED_EVIDENCE_MISSING",
        "authority": "C1_FIXED_SIDE_INCLUDE_EVIDENCE_ONLY",
    }, "c1-fixed-include-readiness", "readiness_id")


def validate_fixed_profile_include(
    *,
    profile: Mapping[str, Any],
    profile_edge: Mapping[str, Any],
    pair: Mapping[str, Any],
    fixed_source_identity: Mapping[str, Any],
    include_evidence: Mapping[str, Any],
) -> None:
    """Reject swapped or buggy-side include evidence for a fixed profile."""

    fixed = _edge(fixed_source_identity, "fixed source identity")
    current_profile = _edge(profile_edge, "fixed build profile")
    if profile.get("source_root") != fixed:
        raise ValueError("fixed profile source identity mismatch")
    if pair.get("fixed_profile_digest") != current_profile["digest"]:
        raise ValueError("differential pair fixed profile digest mismatch")
    if include_evidence.get("source_identity_ref") != fixed["ref"]:
        raise ValueError("fixed include evidence points to a non-fixed source identity")
    if include_evidence.get("source_identity_digest") != fixed["digest"]:
        raise ValueError("fixed include evidence source digest mismatch")
    tree_digests = {item.get("tree_digest") for item in include_evidence.get("header_roots", [])}
    fixed_tree = (profile.get("source_tree_digest") or {}).get("fixed")
    if fixed_tree not in tree_digests:
        raise ValueError("fixed include evidence has no fixed-side header tree digest")


def make_local_execution_mapping(
    *,
    source_identity_document: Mapping[str, Any],
    source_identity: Mapping[str, Any],
    source_root_ref: str,
    build_profile: Mapping[str, Any],
    compile_units: Sequence[Mapping[str, Any]] = (),
    include_roots: Sequence[Mapping[str, Any]] = (),
    library_inputs: Sequence[Mapping[str, Any]] = (),
    local_source_root: Path | None = None,
) -> dict[str, Any]:
    """Bind logical fixed-side inputs while keeping local paths as telemetry."""

    source = _edge(source_identity, "source identity")
    if hashlib.sha256(canonical_json_bytes(source_identity_document)).hexdigest() != source["digest"]:
        raise ValueError("source identity digest mismatch")
    profile = _edge(build_profile, "build profile")
    if not source_root_ref or source_root_ref.startswith("/"):
        raise ValueError("source root must be a logical reference")
    units = [_edge(item, f"compile unit {index}") for index, item in enumerate(compile_units)]
    includes = [_edge(item, f"include root {index}") for index, item in enumerate(include_roots)]
    libraries = [_edge(item, f"library input {index}") for index, item in enumerate(library_inputs)]
    missing = []
    if local_source_root is None:
        missing.append("verified local fixed source root")
    if not units:
        missing.append("fixed compile unit refs")
    if not includes:
        missing.append("fixed include root refs")
    if not libraries:
        missing.append("fixed library input refs")
    document = {
        "schema_version": "cipherlens.c1_local_execution_mapping.v0.1",
        **_common(),
        "status": "COMPLETE" if not missing else "INCOMPLETE",
        "source_identity": source,
        "source_root_logical_ref": source_root_ref,
        "build_profile": profile,
        "compile_units": units,
        "include_roots": includes,
        "library_inputs": libraries,
        "missing_artifacts": missing,
        "validation_status": "VALID" if not missing else "INCOMPLETE",
        "authority": "C1_LOCAL_MAPPING_NO_RAW_PATH_EXECUTION",
        "telemetry": {"local_mapping": str(local_source_root.resolve()) if local_source_root else None},
    }
    errors = semantic_safety_errors(document)
    if errors:
        raise ValueError("; ".join(errors))
    return identified(document, "c1-local-execution-mapping", "mapping_id")


def make_c1_lineage_readiness(artifacts: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Require canonical C1 lineage and explicitly reject C0 replay artifacts."""

    unexpected = sorted(set(artifacts) - set(_LINEAGE_REQUIREMENTS))
    if unexpected:
        raise ValueError(f"unexpected C1 lineage artifacts: {', '.join(unexpected)}")
    accepted: dict[str, dict[str, str]] = {}
    for name, value in artifacts.items():
        classification = str(value.get("classification", ""))
        authority = str(value.get("authority", ""))
        if "C0_REPLAY" in classification or "C0_REPLAY" in authority:
            raise ValueError("C0 replay fixture cannot satisfy C1 canonical lineage")
        accepted[name] = _edge(value, f"C1 {name}")
    missing = [f"C1 {name.replace('_', ' ')}" for name in _LINEAGE_REQUIREMENTS if name not in accepted]
    return identified({
        "schema_version": "cipherlens.c1_canonical_lineage_readiness.v0.1",
        **_common(),
        "status": "COMPLETE_NOT_EXECUTED" if not missing else "INCOMPLETE",
        "lineage_artifacts": accepted,
        "missing_artifacts": missing,
        "c0_replay_accepted": False,
        "authority": "C1_CANONICAL_LINEAGE_REQUIREMENTS_ONLY",
    }, "c1-canonical-lineage-readiness", "readiness_id")


def check_build_run_materialization(
    *,
    execution_handoff: Mapping[str, Any] | None,
    build_profile_document: Mapping[str, Any],
    build_profile: Mapping[str, Any],
    local_mapping: Mapping[str, Any],
    compile_units: Sequence[Mapping[str, Any]] = (),
    expected_output: Mapping[str, Any] | None = None,
    instrumentation_profile: Mapping[str, Any] | None = None,
    environment_profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Materialize only a BuildSpec when all semantic pre-run inputs exist."""

    profile = _edge(build_profile, "build profile")
    if hashlib.sha256(canonical_json_bytes(build_profile_document)).hexdigest() != profile["digest"]:
        raise ValueError("build profile digest mismatch")
    if any(key in local_mapping for key in ("raw_source_path", "source_path", "compiler_path")):
        raise ValueError("raw path shortcut is forbidden")
    if local_mapping.get("unit_id") != APPROVED_UNIT_ID:
        raise ValueError("local execution mapping unit mismatch")
    if local_mapping.get("build_profile") != profile:
        raise ValueError("local execution mapping build profile mismatch")

    missing: list[str] = []
    if execution_handoff is None:
        missing.append("C1 execution handoff")
    if local_mapping.get("status") != "COMPLETE":
        missing.extend(str(item) for item in local_mapping.get("missing_artifacts", []))
    if not local_mapping.get("library_inputs"):
        missing.append("fixed library input refs")
    if not compile_units:
        missing.append("fixed compile unit refs")
    missing = list(dict.fromkeys(missing))
    build_spec = None
    if not missing:
        build_spec = build_spec_from_handoff(
            execution_handoff,
            toolchain={"compiler": build_profile_document["compiler_identity"]["logical_name"], "version_profile_digest": build_profile_document["compiler_version_evidence"]["digest"]},
            compile_units=compile_units,
            include_configs=[{"artifact_ref": item["ref"], "artifact_digest": item["digest"]} for item in local_mapping["include_roots"]],
            compile_flags=build_profile_document.get("compile_flags", []),
            library_inputs=[{"artifact_ref": item["ref"], "artifact_digest": item["digest"]} for item in local_mapping["library_inputs"]],
            link_flags=build_profile_document.get("link_flags", []),
            expected_output=expected_output or {"artifact_ref": "c1:synthetic:binary", "kind": "EXECUTABLE"},
            instrumentation_profile=instrumentation_profile or {"profile_ref": "c1:instrumentation:none", "profile_digest": "1" * 64},
            environment_profile=environment_profile or {"profile_ref": "c1:environment:controlled", "profile_digest": "2" * 64},
        )
    status = "BUILDSPEC_MATERIALIZED_NOT_EXECUTED" if build_spec else "BLOCKED"
    return identified({
        "schema_version": "cipherlens.c1_build_run_materialization_readiness.v0.1",
        **_common(),
        "status": status,
        "build_profile": profile,
        "local_execution_mapping_ref": local_mapping.get("mapping_id"),
        "local_execution_mapping_digest": hashlib.sha256(canonical_json_bytes(local_mapping)).hexdigest(),
        "execution_handoff_ref": execution_handoff.get("handoff_id") if execution_handoff else None,
        "execution_handoff_digest": artifact_digest(execution_handoff) if execution_handoff else None,
        "build_spec": build_spec,
        "run_spec": None,
        "missing_artifacts": missing + ([] if build_spec else ["canonical BuildSpec"]),
        "run_spec_requirement": "BUILT_BUILD_RECORD_REQUIRED_AFTER_SEPARATELY_AUTHORIZED_BUILD",
        "build_attempted": False,
        "run_attempted": False,
        "authority": "C1_MATERIALIZATION_CHECK_ONLY_NO_EXECUTION",
    }, "c1-build-run-readiness", "readiness_id")


def make_repair_claim_gate(
    *,
    repair_documents: Mapping[str, Mapping[str, Any]],
    repair_artifacts: Mapping[str, Mapping[str, Any]],
    parent_gate: Mapping[str, Any],
) -> dict[str, Any]:
    required = {"library", "fixed_include", "local_mapping", "canonical_lineage", "build_run"}
    if set(repair_artifacts) != required or set(repair_documents) != required:
        raise ValueError("repair claim gate requires the complete repair artifact set")
    artifacts = {name: _edge(value, f"repair artifact {name}") for name, value in repair_artifacts.items()}
    parent = _edge(parent_gate, "parent blocked gate")
    blockers: list[str] = []
    for document in repair_documents.values():
        blockers.extend([item.upper().replace(" ", "_").replace("-", "_") + "_MISSING" for item in document.get("missing_artifacts", [])])
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers
    return identified({
        "schema_version": "cipherlens.c1_pre_run_repair_claim_gate.v0.1",
        **_common(),
        "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if ready else "C1_PRE_RUN_GATE_STILL_BLOCKED",
        "parent_blocked_gate": parent,
        "repair_artifacts": artifacts,
        "blocking_reasons": blockers,
        "allowed_next_stage": "C1_RETRY_ONLY" if ready else "C1_FIX_CONTINUE",
        "full_campaign_allowed": False,
        "current_campaign_result": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED",
        "witness_generated": False,
        "structured_trace_generated": False,
        "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
        "authority": "C1_FIX_ROUND_CLAIM_GATE_ONLY",
    }, "c1-repair-claim-gate", "decision_id")


def make_repair_artifact_index(
    *,
    parent_index: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    parent = _edge(parent_index, "parent artifact index")
    entries = []
    for name in sorted(artifacts):
        edge = _edge(artifacts[name], f"repair index artifact {name}")
        entries.append({"artifact_type": name, **edge})
    return identified({
        "schema_version": "cipherlens.c1_repair_artifact_index.v0.1",
        **_common(),
        "status": "C1_PRE_RUN_GATE_STILL_BLOCKED",
        "parent_artifact_index": parent,
        "repair_lineage": "CREATE_ONLY_SUCCESSOR_DO_NOT_REWRITE_PARENT",
        "artifacts": entries,
        "authority": "C1_CREATE_ONLY_REPAIR_ARTIFACT_INDEX",
    }, "c1-repair-artifact-index", "index_id")
