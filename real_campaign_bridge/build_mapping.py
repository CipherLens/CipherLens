"""Map frozen build-inventory evidence into canonical BuildSpec inputs.

This module deliberately prepares only semantic inputs.  It neither resolves a
local path nor launches a compiler; path resolution belongs to a later,
explicitly approved execution environment.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from execution_pipeline.build_adapter import build_spec_from_handoff
from target_knowledge.canonical import semantic_digest, semantic_safety_errors


_SHA = set("0123456789abcdef")


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _SHA for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _edge(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not isinstance(value.get("ref"), str):
        raise ValueError(f"{label} requires ref + digest")
    return {"artifact_ref": value["ref"], "artifact_digest": _sha(value.get("digest"), f"{label} digest")}


def map_build_environment_profile(
    profile: Mapping[str, Any], *, profile_ref: str, profile_digest: str,
) -> dict[str, Any]:
    """Create a path-free C0 mapping from a frozen profile edge.

    A missing future library stays explicitly missing.  The adapter never
    manufactures a digest or upgrades preparation evidence to runtime-ready.
    """

    _sha(profile_digest, "profile digest")
    if not isinstance(profile_ref, str) or not profile_ref or profile_ref.startswith("/"):
        raise ValueError("profile ref must be a non-absolute reference")
    if profile.get("schema_version") != "cipherlens.build_environment_profile.v0.1":
        raise ValueError("unsupported build environment profile")
    compiler = profile.get("compiler_identity") or {}
    compiler_name = compiler.get("logical_name", compiler.get("name"))
    if not isinstance(compiler_name, str) or not compiler_name or compiler_name.startswith("/"):
        raise ValueError("profile compiler identity must be a logical compiler name")
    compiler_evidence = _edge(profile.get("compiler_version_evidence"), "compiler version evidence")
    includes = [_edge(item, "include path evidence") for item in profile.get("include_path_evidence", [])]
    libraries = [_edge(item, "library input") for item in profile.get("library_inputs", [])]
    missing_artifacts = [dict(item) for item in profile.get("missing_artifacts", [])]
    missing_requirements = list(profile.get("missing_requirements", []))
    if not libraries and any("library" in str(item).lower() for item in missing_artifacts + missing_requirements):
        missing_artifacts.append({"expected_future_artifact_type": "resolved_library_input", "preparation_status": "MISSING_ARTIFACT"})
    status = "READY_FOR_BUILDSPEC_FIXTURE" if not missing_artifacts else "MISSING_EXECUTION_INPUTS"
    document = {
        "schema_version": "cipherlens.real_campaign_build_profile_mapping.v0.1",
        "profile_ref": profile_ref,
        "profile_digest": profile_digest,
        "profile_id": str(profile.get("profile_id", "")),
        "status": status,
        "toolchain": {"compiler": compiler_name, "version_profile_digest": compiler_evidence["artifact_digest"]},
        "include_configs": includes,
        "library_inputs": libraries,
        "compile_flags": list(profile.get("compile_flags", [])),
        "link_flags": list(profile.get("link_flags", [])),
        "missing_artifacts": missing_artifacts,
        "missing_requirements": missing_requirements,
        "authority": "C0_PREPARATION_ONLY_NO_BUILD_EXECUTION",
        "telemetry": {"local_execution_plan": "UNRESOLVED_BY_C0"},
    }
    errors = semantic_safety_errors(document)
    if errors:
        raise ValueError("; ".join(errors))
    document["mapping_id"] = "build-profile-mapping:" + mapping_semantic_digest(document)
    return document


def build_spec_from_profile_mapping(
    handoff: Mapping[str, Any], mapping: Mapping[str, Any], *,
    compile_units: Sequence[Mapping[str, Any]], expected_output: Mapping[str, Any],
    instrumentation_profile: Mapping[str, Any], environment_profile: Mapping[str, Any],
) -> dict[str, Any]:
    """Materialize a canonical BuildSpec from a complete C0 profile mapping.

    This only allocates a semantic BuildSpec; it does not resolve paths or run
    a compiler.  The frozen BuildSpec schema remains unchanged.
    """

    if mapping.get("status") != "READY_FOR_BUILDSPEC_FIXTURE":
        raise ValueError("BuildSpec blocked: profile mapping has missing execution inputs")
    if mapping.get("authority") != "C0_PREPARATION_ONLY_NO_BUILD_EXECUTION":
        raise ValueError("untrusted build profile mapping authority")
    return build_spec_from_handoff(
        handoff,
        toolchain=mapping["toolchain"],
        compile_units=compile_units,
        include_configs=mapping["include_configs"],
        compile_flags=mapping["compile_flags"],
        library_inputs=mapping["library_inputs"],
        link_flags=mapping["link_flags"],
        expected_output=expected_output,
        instrumentation_profile=instrumentation_profile,
        environment_profile=environment_profile,
    )


def mapping_semantic_digest(mapping: Mapping[str, Any]) -> str:
    """Expose the path-free semantic identity for focused C0 assertions."""

    semantic = dict(mapping)
    # Profile bytes and local telemetry are provenance only: neither may change
    # the prepared BuildSpec semantics.  The ref+digest edge remains present in
    # the document for auditability.
    semantic.pop("mapping_id", None)
    semantic.pop("profile_digest", None)
    return semantic_digest(semantic)
