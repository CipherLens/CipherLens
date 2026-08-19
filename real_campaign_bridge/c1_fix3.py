"""Read-only fixed-library provenance discovery for the C1 approved unit.

This module only digests existing evidence and materializes fail-closed
records.  It never invokes a compiler, archive tool, target process, provider,
or network transport.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from target_knowledge.canonical import canonical_json_bytes, identified, semantic_safety_errors
from target_knowledge.source_index import file_digest

from .c1_gate import APPROVED_UNIT_ID


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
CAMPAIGN_SCOPE = "NOT_FULL_CAMPAIGN"
_SHA_CHARS = set("0123456789abcdef")


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _SHA_CHARS for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
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


def fixed_object_inventory(*, fixed_root: Path) -> dict[str, Any]:
    """Digest existing fixed-tree objects without running archive tooling."""

    library = fixed_root / "library"
    objects = []
    for path in sorted(library.glob("*.o")):
        objects.append({
            "ref": f"object:mbedtls:0020:fixed:{path.name}",
            "digest": file_digest(path),
        })
    return _identified({
        "schema_version": "cipherlens.library_object_inventory.v0.1",
        **_common(),
        "status": "AVAILABLE" if objects else "MISSING",
        "object_inputs": objects,
        "missing_provenance": [] if objects else ["OBJECT_INPUT_PROVENANCE_MISSING"],
        "authority": "C1_READ_ONLY_OBJECT_BYTE_INVENTORY",
        "telemetry": {"fixed_library_directory": str(library.resolve())},
    }, "c1-fixed-object-inventory", "inventory_id")


def make_provenance_discovery(
    *,
    source_identity: Mapping[str, Any],
    source_tree_digest: str,
    build_profile: Mapping[str, Any],
    libraries: Sequence[Mapping[str, Any]],
    compiler_identity: Mapping[str, Any],
    compiler_version: Mapping[str, Any],
    makefile_evidence: Sequence[Mapping[str, Any]],
    include_evidence: Sequence[Mapping[str, Any]],
    object_inventory: Mapping[str, Any],
    actual_compiler_invocation: Mapping[str, Any] | None = None,
    actual_build_log: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify only byte-addressed evidence already available locally.

    Makefile recipes and a current inventory compiler profile are not treated as
    proof that a particular archive was built by those inputs.
    """

    source = _edge(source_identity, "fixed SourceIdentity")
    profile = _edge(build_profile, "BuildEnvironmentProfile")
    library_edges = [_edge(item, f"library {index}") for index, item in enumerate(libraries)]
    identity = _edge(compiler_identity, "compiler identity evidence")
    version = _edge(compiler_version, "compiler version evidence")
    makefiles = [_edge(item, f"Makefile evidence {index}") for index, item in enumerate(makefile_evidence)]
    includes = [_edge(item, f"include evidence {index}") for index, item in enumerate(include_evidence)]
    inventory = _edge(object_inventory, "object inventory")
    invocation = _edge(actual_compiler_invocation, "actual compiler invocation") if actual_compiler_invocation else None
    build_log = _edge(actual_build_log, "actual build log") if actual_build_log else None

    missing: list[str] = []
    if not library_edges:
        missing.append("LIBRARY_ARTIFACT_PROVENANCE_MISSING")
    if not makefiles:
        missing.append("BUILD_CONFIG_PROVENANCE_MISSING")
    if not includes:
        missing.append("BUILD_CONFIG_PROVENANCE_MISSING")
    if not inventory or object_inventory.get("status") != "AVAILABLE":
        missing.append("OBJECT_INPUT_PROVENANCE_MISSING")
    if invocation is None:
        missing.extend(["COMPILER_PROVENANCE_MISSING", "LINK_COMMAND_PROVENANCE_MISSING"])
    if build_log is None:
        missing.append("BUILD_LOG_MISSING")
    if missing:
        missing.append("REBUILD_REQUIRED_FOR_PROVENANCE")
    missing = list(dict.fromkeys(missing))
    return _identified({
        "schema_version": "cipherlens.library_build_provenance_discovery.v0.1",
        **_common(),
        "status": "SUFFICIENT" if not missing else "PARTIAL",
        "source_identity": source,
        "fixed_source_tree_digest": _sha(source_tree_digest, "fixed source tree digest"),
        "build_profile": profile,
        "library_artifacts": library_edges,
        "compiler_identity_evidence": identity,
        "compiler_version_evidence": version,
        "build_recipe_evidence": makefiles,
        "include_config_evidence": includes,
        "object_inventory": inventory,
        "actual_compiler_invocation": invocation,
        "actual_build_log": build_log,
        "missing_provenance": missing,
        "authority": "C1_READ_ONLY_LIBRARY_PROVENANCE_DISCOVERY",
    }, "c1-library-provenance-discovery", "discovery_id")


def make_library_build_provenance_record(discovery: Mapping[str, Any]) -> dict[str, Any]:
    """Turn discovery into an explicit reproducibility decision, never a guess."""

    required = (
        "source_identity", "build_profile", "library_artifacts",
        "compiler_identity_evidence", "compiler_version_evidence",
        "build_recipe_evidence", "include_config_evidence", "object_inventory",
    )
    if any(key not in discovery for key in required):
        raise ValueError("library provenance discovery is incomplete")
    missing = [str(item) for item in discovery.get("missing_provenance", [])]
    complete = discovery.get("status") == "SUFFICIENT" and not missing
    status = "COMPLETE" if complete else "PARTIAL"
    validation = "REPRODUCIBLE_PROVENANCE_READY" if complete else "PROVENANCE_PARTIAL"
    return _identified({
        "schema_version": "cipherlens.library_build_provenance_record.v0.1",
        **_common(),
        "provenance_completeness_status": status,
        "validation_status": validation,
        "source_identity_ref": _edge(discovery["source_identity"], "source identity")["ref"],
        "source_identity_digest": _edge(discovery["source_identity"], "source identity")["digest"],
        "fixed_source_tree_digest": _sha(discovery["fixed_source_tree_digest"], "fixed source tree digest"),
        "build_profile": _edge(discovery["build_profile"], "build profile"),
        "library_artifact_refs": [_edge(item, f"library artifact {index}") for index, item in enumerate(discovery["library_artifacts"])],
        "compiler_identity_evidence": _edge(discovery["compiler_identity_evidence"], "compiler identity"),
        "compiler_version_evidence": _edge(discovery["compiler_version_evidence"], "compiler version"),
        "build_system_config_evidence": [_edge(item, f"build recipe {index}") for index, item in enumerate(discovery["build_recipe_evidence"])],
        "compile_flag_evidence": [_edge(item, f"build recipe {index}") for index, item in enumerate(discovery["build_recipe_evidence"])],
        "link_archive_command_evidence": [_edge(item, f"build recipe {index}") for index, item in enumerate(discovery["build_recipe_evidence"])],
        "object_input_evidence": _edge(discovery["object_inventory"], "object inventory"),
        "include_evidence": [_edge(item, f"include evidence {index}") for index, item in enumerate(discovery["include_config_evidence"])],
        "actual_compiler_invocation": discovery.get("actual_compiler_invocation"),
        "actual_build_log": discovery.get("actual_build_log"),
        "missing_provenance": missing,
        "authority": "C1_LIBRARY_PROVENANCE_RECORD_FAIL_CLOSED",
    }, "c1-library-build-provenance", "provenance_id")


def make_build_profile_alignment(*, build_profile: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    profile = _edge(build_profile, "BuildEnvironmentProfile")
    aligned = provenance.get("build_profile") == profile
    profile_is_preparation_only = bool(provenance.get("missing_provenance"))
    return _identified({
        "schema_version": "cipherlens.library_build_profile_alignment.v0.1",
        **_common(),
        "status": "ALIGNED_FOR_REPRODUCIBILITY" if aligned and not profile_is_preparation_only else "PREPARATION_PROFILE_ONLY",
        "build_profile": profile,
        "provenance_record": _edge({"ref": provenance["provenance_id"], "digest": hashlib.sha256(canonical_json_bytes(provenance)).hexdigest()}, "provenance record"),
        "profile_matches_provenance": aligned,
        "profile_proves_actual_library_build": False,
        "missing_provenance": list(provenance.get("missing_provenance", [])),
        "authority": "C1_BUILD_PROFILE_ALIGNMENT_NOT_BUILD_PROOF",
    }, "c1-build-profile-alignment", "alignment_id")


def make_fix3_claim_gate(
    *,
    provenance: Mapping[str, Any],
    alignment: Mapping[str, Any],
    parent_claim_gate: Mapping[str, Any],
) -> dict[str, Any]:
    parent = _edge(parent_claim_gate, "C1-fix2 claim gate")
    provenance_edge = _edge({"ref": provenance["provenance_id"], "digest": hashlib.sha256(canonical_json_bytes(provenance)).hexdigest()}, "provenance")
    alignment_edge = _edge({"ref": alignment["alignment_id"], "digest": hashlib.sha256(canonical_json_bytes(alignment)).hexdigest()}, "alignment")
    blockers = list(dict.fromkeys([str(item) for item in provenance.get("missing_provenance", [])]))
    ready = provenance.get("validation_status") == "REPRODUCIBLE_PROVENANCE_READY" and not blockers and alignment.get("status") == "ALIGNED_FOR_REPRODUCIBILITY"
    controlled_rebuild = bool(blockers) and "REBUILD_REQUIRED_FOR_PROVENANCE" in blockers
    return _identified({
        "schema_version": "cipherlens.c1_pre_run_repair_claim_gate.v0.3",
        **_common(),
        "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if ready else ("C1_REQUIRES_CONTROLLED_LIBRARY_REBUILD_PROVENANCE" if controlled_rebuild else "C1_PRE_RUN_GATE_STILL_BLOCKED"),
        "parent_claim_gate": parent,
        "provenance_record": provenance_edge,
        "build_profile_alignment": alignment_edge,
        "blocking_reasons": blockers,
        "allowed_next_stage": "C1_RETRY_ONLY" if ready else ("C1_FIX4_CONTROLLED_REBUILD_PROVENANCE" if controlled_rebuild else "C1_FIX_CONTINUE"),
        "full_campaign_allowed": False,
        "current_campaign_result": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED",
        "witness_generated": False,
        "structured_trace_generated": False,
        "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
        "authority": "C1_FIX3_PROVENANCE_CLAIM_GATE_ONLY",
    }, "c1-fix3-claim-gate", "decision_id")


def make_fix3_artifact_index(*, parent_index: Mapping[str, Any], artifacts: Mapping[str, Mapping[str, Any]], status: str) -> dict[str, Any]:
    entries = [{"artifact_type": name, **_edge(edge, f"fix3 index {name}")} for name, edge in sorted(artifacts.items())]
    return _identified({
        "schema_version": "cipherlens.c1_repair_artifact_index.v0.3",
        **_common(),
        "status": status,
        "parent_artifact_index": _edge(parent_index, "C1-fix2 artifact index"),
        "repair_lineage": "CREATE_ONLY_FIX3_SUCCESSOR_DO_NOT_REWRITE_PARENT",
        "artifacts": entries,
        "authority": "C1_FIX3_CREATE_ONLY_ARTIFACT_INDEX",
    }, "c1-fix3-artifact-index", "index_id")
