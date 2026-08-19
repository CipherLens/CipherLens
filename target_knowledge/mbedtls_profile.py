"""Mbed TLS historical-pair profile materialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import ValidationStatus, finalize_profile
from .source_index import file_digest, source_root_record


def materialize_mbedtls_pair_profile(
    buggy_root: Path,
    fixed_root: Path,
    case_id: str,
    buggy_revision: str,
    fixed_revision: str,
) -> dict[str, Any]:
    """Create a portable, pair-scoped profile; paths remain local telemetry only."""
    buggy_record = source_root_record(buggy_root, f"source:mbedtls:{case_id}:buggy")
    fixed_record = source_root_record(fixed_root, f"source:mbedtls:{case_id}:fixed")
    return finalize_profile({
        "target_scope": {
            "library": "Mbed TLS", "version": f"historical-pair:{case_id}",
            "source_identity": f"git-pair:{buggy_revision[:12]}..{fixed_revision[:12]}",
            "surface_ref": f"surface:mbedtls:{case_id}",
        },
        "source_roots": [buggy_record, fixed_record],
        "header_roots": [{"root_ref": f"header:mbedtls:{case_id}", "tree_digest": buggy_record["tree_digest"]}],
        "library_artifacts": [
            {"artifact_ref": f"library:mbedtls:{case_id}:buggy:libmbedcrypto.a", "digest": file_digest(buggy_root / "library/libmbedcrypto.a"), "kind": "static_library"},
            {"artifact_ref": f"library:mbedtls:{case_id}:fixed:libmbedcrypto.a", "digest": file_digest(fixed_root / "library/libmbedcrypto.a"), "kind": "static_library"},
        ],
        "config_artifacts": [],
        "symbol_records": [], "type_records": [], "surface_records": [], "evidence_records": [],
        "producer": "cipherlens.local_target_knowledge.v0.1",
        "git_or_release_identity": {"kind": "git_pair", "buggy": buggy_revision, "fixed": fixed_revision},
        "tree_digest": {"buggy": buggy_record["tree_digest"], "fixed": fixed_record["tree_digest"]},
        "validation_status": ValidationStatus.PREPARED.value,
        "telemetry": {"buggy_root": str(buggy_root), "fixed_root": str(fixed_root)},
    })


def materialize_mbedtls_410_profile(root: Path, revision: str) -> dict[str, Any]:
    """Materialize the standalone Mbed TLS 4.1 source identity for target scope."""
    source = source_root_record(root, "source:mbedtls:4.1.0")
    return finalize_profile({
        "target_scope": {"library": "Mbed TLS", "version": "4.1.0", "source_identity": f"git:{revision}", "surface_ref": "surface:mbedtls:4.1.0"},
        "source_roots": [source], "header_roots": [{"root_ref": "header:mbedtls:4.1.0", "tree_digest": source["tree_digest"]}],
        "library_artifacts": [], "config_artifacts": [], "symbol_records": [], "type_records": [], "surface_records": [], "evidence_records": [],
        "producer": "cipherlens.local_target_knowledge.v0.1", "git_or_release_identity": {"kind": "git", "revision": revision},
        "tree_digest": source["tree_digest"], "validation_status": ValidationStatus.PREPARED.value,
        "telemetry": {"source_root": str(root)},
    })
