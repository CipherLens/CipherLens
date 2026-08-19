"""Build-environment profile contracts; collection is inventory, never execution."""

from __future__ import annotations

from typing import Any, Mapping

from target_knowledge.canonical import identified, semantic_safety_errors
from target_knowledge.model import BUILD_ENVIRONMENT_PROFILE_SCHEMA


_REQUIRED = {
    "source_root", "source_identity", "source_tree_digest", "compiler_identity", "architecture",
    "build_system_config", "compile_flags", "link_flags", "include_roots", "library_inputs",
    "artifact_outputs", "sanitizer_profile", "dependencies", "controlled_environment", "timeout_seconds",
    "target_options", "input_artifact_digests", "reproducibility_status",
    "compiler_version_evidence", "include_path_evidence", "missing_artifacts", "missing_requirements",
}


def _require_edge(item: Mapping[str, Any], label: str) -> None:
    if not isinstance(item.get("ref"), str) or not isinstance(item.get("digest"), str):
        raise ValueError(f"{label} requires a ref and SHA-256 digest")
    digest = item["digest"]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{label} digest must be lowercase SHA-256")


def _require_tree_digest(value: Any) -> None:
    values = value.values() if isinstance(value, Mapping) else (value,)
    if not all(isinstance(item, str) and len(item) == 64 and all(char in "0123456789abcdef" for char in item) for item in values):
        raise ValueError("source tree digest must be a SHA-256 or a mapping of SHA-256 values")


def make_build_environment_profile(**fields: Any) -> dict[str, Any]:
    missing = sorted(_REQUIRED - set(fields))
    if missing:
        raise ValueError(f"build environment profile missing fields: {', '.join(missing)}")
    _require_edge(fields["source_root"], "source root")
    _require_tree_digest(fields["source_tree_digest"])
    _require_edge(fields["compiler_version_evidence"], "compiler version evidence")
    for item in fields["library_inputs"]:
        _require_edge(item, "library input")
    for item in fields["include_path_evidence"]:
        _require_edge(item, "include path evidence")
    result = {"schema_version": BUILD_ENVIRONMENT_PROFILE_SCHEMA, **fields}
    errors = semantic_safety_errors(result)
    if errors:
        raise ValueError("; ".join(errors))
    return identified(result, "build-profile", "profile_id")


def same_source_root(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return left.get("source_identity") == right.get("source_identity")
