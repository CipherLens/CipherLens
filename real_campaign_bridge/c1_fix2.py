"""Fixed-side discovery and create-only C1 preparation records.

This module performs byte inspection and canonical materialization only.  It
does not invoke Git, a compiler, a target binary, a provider, or a network.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from candidate_binding.canonical import candidate_binding_digest, validation_digest
from candidate_binding.validate import validate_candidate_binding_or_raise, validate_validation_artifact_or_raise
from execution_model.canonical import artifact_digest
from execution_model.registry import validate_artifact_or_raise
from target_knowledge.canonical import canonical_json_bytes, identified, semantic_safety_errors
from target_knowledge.source_index import file_digest, tree_digest
from template_binding_merge.canonical import bound_source_digest, merge_digest, merge_validation_digest, source_map_digest
from template_binding_merge.validate import (
    validate_bound_source_or_raise,
    validate_merge_or_raise,
    validate_merge_validation_or_raise,
    validate_source_map_or_raise,
)

from .c1_gate import APPROVED_UNIT_ID


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
CAMPAIGN_SCOPE = "NOT_FULL_CAMPAIGN"
_SHA_CHARS = set("0123456789abcdef")
_LINEAGE_NAMES = (
    "candidate_binding",
    "candidate_binding_validation",
    "merge",
    "merge_validation",
    "bound_source",
    "source_map",
    "execution_handoff",
    "bound_source_artifact",
)


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _SHA_CHARS for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 40 or any(char not in _SHA_CHARS for char in value):
        raise ValueError(f"{label} must be a lowercase Git SHA-1")
    return value


def _edge(value: Mapping[str, Any], label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not isinstance(value.get("ref"), str) or not value["ref"]:
        raise ValueError(f"{label} requires ref + digest")
    if value["ref"].startswith("/"):
        raise ValueError(f"{label} ref must be logical, not absolute")
    return {"ref": value["ref"], "digest": _sha(value.get("digest"), f"{label} digest")}


def _common() -> dict[str, Any]:
    return {
        "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE,
        "campaign_scope": CAMPAIGN_SCOPE,
        "execution_status": "NOT_EXECUTED",
        "report_real_number_allowed": False,
    }


def _identified(document: Mapping[str, Any], prefix: str, field: str) -> dict[str, Any]:
    errors = semantic_safety_errors(document)
    if errors:
        raise ValueError("; ".join(errors))
    return identified(document, prefix, field)


def read_worktree_head(root: Path) -> str:
    """Read a linked-worktree detached HEAD without invoking Git."""

    marker = root / ".git"
    if not marker.is_file():
        raise ValueError("candidate source root is not a linked Git worktree")
    line = marker.read_text(encoding="utf-8").strip()
    if not line.startswith("gitdir: "):
        raise ValueError("unsupported linked-worktree metadata")
    gitdir = Path(line.removeprefix("gitdir: "))
    head = (gitdir / "HEAD").read_text(encoding="ascii").strip()
    return _git_sha(head, "worktree HEAD")


def discover_fixed_source(
    *,
    fixed_root: Path,
    buggy_root: Path,
    fixed_source_identity_document: Mapping[str, Any],
    fixed_source_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a fixed worktree against its frozen source identity."""

    source_edge = _edge(fixed_source_identity, "fixed source identity")
    if hashlib.sha256(canonical_json_bytes(fixed_source_identity_document)).hexdigest() != source_edge["digest"]:
        raise ValueError("fixed SourceIdentity digest mismatch")
    fixed_head = read_worktree_head(fixed_root)
    buggy_head = read_worktree_head(buggy_root)
    fixed_tree, fixed_count = tree_digest(fixed_root)
    buggy_tree, _ = tree_digest(buggy_root)
    expected_revision = (fixed_source_identity_document.get("identity") or {}).get("revision")
    expected_tree = fixed_source_identity_document.get("source_tree_digest")
    expected_count = fixed_source_identity_document.get("file_count")
    verified = (
        fixed_head == expected_revision
        and fixed_tree == expected_tree
        and fixed_count == expected_count
        and fixed_head != buggy_head
        and fixed_tree != buggy_tree
    )
    missing = [] if verified else ["fixed source identity verification"]
    return _identified({
        "schema_version": "cipherlens.c1_fixed_source_discovery.v0.1",
        **_common(),
        "status": "VERIFIED" if verified else "CANDIDATE",
        "fixed_source_identity": source_edge,
        "source_root_logical_ref": fixed_source_identity_document.get("source_root_ref"),
        "observed_revision": fixed_head,
        "observed_source_tree_digest": fixed_tree,
        "observed_file_count": fixed_count,
        "buggy_revision": buggy_head,
        "buggy_source_tree_digest": buggy_tree,
        "fixed_distinct_from_buggy": fixed_head != buggy_head and fixed_tree != buggy_tree,
        "missing_artifacts": missing,
        "authority": "C1_LOCAL_FIXED_SOURCE_DISCOVERY_ONLY",
        "telemetry": {"fixed_source_root": str(fixed_root.resolve()), "buggy_source_root": str(buggy_root.resolve())},
    }, "c1-fixed-source-discovery", "discovery_id")


def make_fixed_include_readiness(
    *,
    fixed_root: Path,
    source_discovery: Mapping[str, Any],
    selected_headers: Sequence[str],
) -> dict[str, Any]:
    if source_discovery.get("status") != "VERIFIED":
        raise ValueError("fixed include evidence requires VERIFIED source discovery")
    include_root = fixed_root / "include"
    include_digest, file_count = tree_digest(include_root)
    headers = []
    for relative in selected_headers:
        if relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError("selected header ref must be source-root relative")
        path = fixed_root / relative
        if not path.is_file() or not path.resolve().is_relative_to(include_root.resolve()):
            raise ValueError(f"selected fixed header is missing or outside include root: {relative}")
        headers.append({"ref": f"source:mbedtls:0020:fixed/{relative}", "digest": file_digest(path)})
    complete = bool(headers)
    return _identified({
        "schema_version": "cipherlens.c1_fixed_include_readiness.v0.2",
        **_common(),
        "status": "VERIFIED" if complete else "MISSING",
        "fixed_source_identity": dict(source_discovery["fixed_source_identity"]),
        "source_discovery_ref": source_discovery["discovery_id"],
        "source_discovery_digest": hashlib.sha256(canonical_json_bytes(source_discovery)).hexdigest(),
        "include_root": {"ref": "source:mbedtls:0020:fixed/include", "digest": include_digest, "file_count": file_count},
        "selected_headers": headers,
        "missing_artifacts": [] if complete else ["fixed selected header evidence"],
        "buggy_include_edge_accepted": False,
        "authority": "C1_FIXED_INCLUDE_BYTES_ONLY",
        "telemetry": {"include_root": str(include_root.resolve())},
    }, "c1-fixed-include-readiness", "readiness_id")


def make_fixed_library_readiness(
    *,
    fixed_root: Path,
    source_discovery: Mapping[str, Any],
    libraries: Sequence[tuple[str, str]],
    build_provenance: Sequence[Mapping[str, Any]] = (),
    build_provenance_complete: bool = False,
) -> dict[str, Any]:
    if source_discovery.get("status") != "VERIFIED":
        raise ValueError("fixed library evidence requires VERIFIED source discovery")
    artifacts = []
    telemetry_paths: dict[str, str] = {}
    for relative, kind in libraries:
        if relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError("library ref must be source-root relative")
        path = fixed_root / relative
        if not path.is_file():
            continue
        ref = f"library:mbedtls:0020:fixed:{Path(relative).name}"
        artifacts.append({"ref": ref, "digest": file_digest(path), "kind": kind})
        telemetry_paths[ref] = str(path.resolve())
    producers = [_edge(item, f"build provenance {index}") for index, item in enumerate(build_provenance)]
    reproducible = bool(artifacts) and bool(producers) and build_provenance_complete
    missing = []
    if not artifacts:
        missing.extend(["fixed-side library artifact", "link input digest"])
    if not producers or not build_provenance_complete:
        missing.append("library build provenance")
    status = "REPRODUCIBLE" if reproducible else ("ARTIFACT_PRESENT_PROVENANCE_INCOMPLETE" if artifacts else "MISSING")
    return _identified({
        "schema_version": "cipherlens.c1_fixed_library_readiness.v0.2",
        **_common(),
        "status": status,
        "reproducible_target_library": reproducible,
        "fixed_source_identity": dict(source_discovery["fixed_source_identity"]),
        "source_discovery_ref": source_discovery["discovery_id"],
        "source_discovery_digest": hashlib.sha256(canonical_json_bytes(source_discovery)).hexdigest(),
        "library_artifacts": artifacts,
        "build_provenance": producers,
        "build_provenance_complete": build_provenance_complete,
        "missing_artifacts": missing,
        "authority": "C1_FIXED_LIBRARY_BYTE_INVENTORY_ONLY",
        "telemetry": {"library_paths": telemetry_paths},
    }, "c1-fixed-library-readiness", "readiness_id")


def make_fix2_local_execution_mapping(
    *,
    source_discovery: Mapping[str, Any],
    include_readiness: Mapping[str, Any],
    library_readiness: Mapping[str, Any],
    build_profile: Mapping[str, Any],
    differential_pair: Mapping[str, Any],
    compile_units: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    source = _edge(source_discovery["fixed_source_identity"], "fixed source identity")
    profile = _edge(build_profile, "BuildEnvironmentProfile")
    pair = _edge(differential_pair, "DifferentialPairManifest")
    units = [_edge(item, f"compile unit {index}") for index, item in enumerate(compile_units)]
    include = include_readiness.get("include_root") or {}
    include_edge = _edge(include, "fixed include root") if include else None
    libraries = [_edge(item, f"library input {index}") for index, item in enumerate(library_readiness.get("library_artifacts", []))]
    missing = []
    if source_discovery.get("status") != "VERIFIED": missing.append("verified fixed source root")
    if not units: missing.append("fixed compile unit refs")
    if include_readiness.get("status") != "VERIFIED" or include_edge is None: missing.append("fixed include root refs")
    if not libraries: missing.append("fixed library input refs")
    status = "COMPLETE" if not missing else "INCOMPLETE"
    document = {
        "schema_version": "cipherlens.c1_local_execution_mapping.v0.2",
        **_common(),
        "status": status,
        "validation_status": status,
        "target_unit_linkage": APPROVED_UNIT_ID,
        "source_identity": source,
        "source_root_logical_ref": source_discovery["source_root_logical_ref"],
        "source_tree_digest": source_discovery["observed_source_tree_digest"],
        "compile_units": units,
        "include_roots": [include_edge] if include_edge else [],
        "library_inputs": libraries,
        "build_profile": profile,
        "differential_pair": pair,
        "missing_artifacts": missing,
        "authority": "C1_LOCAL_MAPPING_NO_RAW_PATH_EXECUTION",
        "telemetry": {
            "source_root": (source_discovery.get("telemetry") or {}).get("fixed_source_root"),
            "include_root": (include_readiness.get("telemetry") or {}).get("include_root"),
            "library_paths": (library_readiness.get("telemetry") or {}).get("library_paths", {}),
        },
    }
    return _identified(document, "c1-local-execution-mapping", "mapping_id")


def make_c1_prep_lineage(
    *,
    documents: Mapping[str, Mapping[str, Any]],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if set(artifacts) != set(_LINEAGE_NAMES) or set(documents) != set(_LINEAGE_NAMES) - {"bound_source_artifact"}:
        raise ValueError("C1 prep lineage requires the complete deterministic artifact chain")
    for document in documents.values():
        if "C0_REPLAY" in str(document.get("classification", "")) or "C0_REPLAY" in str(document.get("authority", "")):
            raise ValueError("C0 replay fixture cannot satisfy C1 prep lineage")
    validate_candidate_binding_or_raise(documents["candidate_binding"])
    validate_validation_artifact_or_raise(documents["candidate_binding_validation"])
    validate_merge_or_raise(documents["merge"])
    validate_merge_validation_or_raise(documents["merge_validation"])
    validate_bound_source_or_raise(documents["bound_source"])
    validate_source_map_or_raise(documents["source_map"])
    validate_artifact_or_raise(documents["execution_handoff"])
    semantic_digests = {
        "candidate_binding": candidate_binding_digest(documents["candidate_binding"]),
        "candidate_binding_validation": validation_digest(documents["candidate_binding_validation"]),
        "merge": merge_digest(documents["merge"]),
        "merge_validation": merge_validation_digest(documents["merge_validation"]),
        "bound_source": bound_source_digest(documents["bound_source"]),
        "source_map": source_map_digest(documents["source_map"]),
        "execution_handoff": artifact_digest(documents["execution_handoff"]),
    }
    edges = {name: _edge(value, f"C1 prep {name}") for name, value in artifacts.items()}
    return _identified({
        "schema_version": "cipherlens.c1_canonical_lineage_readiness.v0.2",
        **_common(),
        "status": "COMPLETE_NOT_EXECUTED",
        "classification": "C1_DETERMINISTIC_SOURCE_SIDE_PREP_NOT_EXECUTED",
        "lineage_artifacts": edges,
        "semantic_digests": semantic_digests,
        "missing_artifacts": [],
        "c0_replay_accepted": False,
        "witness_generated": False,
        "structured_trace_generated": False,
        "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
        "authority": "C1_PREP_LINEAGE_ONLY_NOT_REAL_EXECUTION",
    }, "c1-canonical-lineage-readiness", "readiness_id")


def make_fix2_build_run_readiness(
    *,
    build_spec_document: Mapping[str, Any],
    build_spec: Mapping[str, Any],
    build_profile: Mapping[str, Any],
    local_mapping: Mapping[str, Any],
    lineage: Mapping[str, Any],
) -> dict[str, Any]:
    validate_artifact_or_raise(build_spec_document)
    spec_edge = _edge(build_spec, "BuildSpec artifact")
    if local_mapping.get("status") != "COMPLETE":
        raise ValueError("BuildSpec readiness requires a complete local mapping")
    if lineage.get("status") != "COMPLETE_NOT_EXECUTED":
        raise ValueError("BuildSpec readiness requires complete C1 prep lineage")
    return _identified({
        "schema_version": "cipherlens.c1_build_run_materialization_readiness.v0.2",
        **_common(),
        "status": "BUILDSPEC_MATERIALIZED_NOT_EXECUTED",
        "build_spec": spec_edge,
        "build_profile": _edge(build_profile, "BuildEnvironmentProfile"),
        "local_execution_mapping_ref": local_mapping["mapping_id"],
        "local_execution_mapping_digest": hashlib.sha256(canonical_json_bytes(local_mapping)).hexdigest(),
        "c1_lineage_ref": lineage["readiness_id"],
        "c1_lineage_digest": hashlib.sha256(canonical_json_bytes(lineage)).hexdigest(),
        "run_spec": None,
        "build_attempted": False,
        "run_attempted": False,
        "missing_future_outputs": ["built binary", "BUILT BuildRecord", "RunSpec"],
        "missing_artifacts": [],
        "authority": "C1_BUILDSPEC_MATERIALIZATION_ONLY_NO_EXECUTION",
    }, "c1-build-run-readiness", "readiness_id")


def make_fix2_claim_gate(
    *,
    documents: Mapping[str, Mapping[str, Any]],
    artifacts: Mapping[str, Mapping[str, Any]],
    parent_claim_gate: Mapping[str, Any],
) -> dict[str, Any]:
    required = {"source", "include", "library", "local_mapping", "lineage", "build_run"}
    if set(documents) != required or set(artifacts) != required:
        raise ValueError("fix2 claim gate requires the complete readiness set")
    edges = {name: _edge(value, f"fix2 {name}") for name, value in artifacts.items()}
    blockers = []
    if documents["source"].get("status") != "VERIFIED": blockers.extend(documents["source"].get("missing_artifacts", []))
    if documents["include"].get("status") != "VERIFIED": blockers.extend(documents["include"].get("missing_artifacts", []))
    if not documents["library"].get("reproducible_target_library"):
        blockers.extend(documents["library"].get("missing_artifacts", []))
    if documents["local_mapping"].get("status") != "COMPLETE": blockers.extend(documents["local_mapping"].get("missing_artifacts", []))
    if documents["lineage"].get("status") != "COMPLETE_NOT_EXECUTED": blockers.extend(documents["lineage"].get("missing_artifacts", []))
    if documents["build_run"].get("status") != "BUILDSPEC_MATERIALIZED_NOT_EXECUTED": blockers.extend(documents["build_run"].get("missing_artifacts", []))
    blockers = [str(item).upper().replace(" ", "_").replace("-", "_") + "_MISSING" for item in dict.fromkeys(blockers)]
    ready = not blockers
    return _identified({
        "schema_version": "cipherlens.c1_pre_run_repair_claim_gate.v0.2",
        **_common(),
        "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if ready else "C1_PRE_RUN_GATE_STILL_BLOCKED",
        "parent_claim_gate": _edge(parent_claim_gate, "previous C1-fix claim gate"),
        "repair_artifacts": edges,
        "blocking_reasons": blockers,
        "allowed_next_stage": "C1_RETRY_ONLY" if ready else "C1_FIX_CONTINUE",
        "full_campaign_allowed": False,
        "current_campaign_result": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED",
        "witness_generated": False,
        "structured_trace_generated": False,
        "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
        "authority": "C1_FIX2_CLAIM_GATE_ONLY",
    }, "c1-fix2-claim-gate", "decision_id")


def make_fix2_artifact_index(
    *,
    parent_index: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    status: str,
) -> dict[str, Any]:
    entries = [{"artifact_type": name, **_edge(edge, f"fix2 index {name}")} for name, edge in sorted(artifacts.items())]
    return _identified({
        "schema_version": "cipherlens.c1_repair_artifact_index.v0.2",
        **_common(),
        "status": status,
        "parent_artifact_index": _edge(parent_index, "previous C1-fix artifact index"),
        "repair_lineage": "CREATE_ONLY_FIX2_SUCCESSOR_DO_NOT_REWRITE_PARENT",
        "artifacts": entries,
        "authority": "C1_CREATE_ONLY_FIX2_ARTIFACT_INDEX",
    }, "c1-fix2-artifact-index", "index_id")
