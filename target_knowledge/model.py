"""Typed validation helpers for v0.1 target-knowledge materialization."""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from .canonical import identified, semantic_safety_errors


TARGET_KNOWLEDGE_PROFILE_SCHEMA = "cipherlens.target_knowledge_profile.v0.1"
BUILD_ENVIRONMENT_PROFILE_SCHEMA = "cipherlens.build_environment_profile.v0.1"
DIFFERENTIAL_PAIR_MANIFEST_SCHEMA = "cipherlens.differential_pair_manifest.v0.1"
CAMPAIGN_POPULATION_MANIFEST_SCHEMA = "cipherlens.campaign_population_manifest.v0.1"


class ValidationStatus(str, Enum):
    READY = "READY"
    PREPARED = "PREPARED"
    NOT_READY = "NOT_READY"


_PROFILE_REQUIRED = {
    "schema_version", "target_scope", "source_roots", "header_roots", "library_artifacts",
    "config_artifacts", "symbol_records", "type_records", "surface_records", "evidence_records",
    "producer", "git_or_release_identity", "tree_digest", "validation_status",
}


def finalize_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(profile)
    result.setdefault("schema_version", TARGET_KNOWLEDGE_PROFILE_SCHEMA)
    missing = sorted(_PROFILE_REQUIRED - set(result))
    if missing:
        raise ValueError(f"target profile missing fields: {', '.join(missing)}")
    if result["schema_version"] != TARGET_KNOWLEDGE_PROFILE_SCHEMA:
        raise ValueError("unsupported target profile schema")
    errors = semantic_safety_errors(result)
    if errors:
        raise ValueError("; ".join(errors))
    return identified(result, "target-profile", "profile_id")


def profile_is_usable(profile: Mapping[str, Any]) -> bool:
    return profile.get("validation_status") == ValidationStatus.READY.value
