"""A deliberately blocked wolfSSL profile: partial cards never become facts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import ValidationStatus, finalize_profile
from .source_index import source_root_record


def materialize_wolfssl_591_blocked_profile(root: Path, revision: str) -> dict[str, Any]:
    source = source_root_record(root, "source:wolfssl:5.9.1:stable")
    return finalize_profile({
        "target_scope": {"library": "wolfSSL", "version": "5.9.1", "source_identity": f"git:{revision}", "surface_ref": "surface:wolfssl:5.9.1"},
        "source_roots": [source], "header_roots": [{"root_ref": "header:wolfssl:5.9.1", "tree_digest": source["tree_digest"]}],
        "library_artifacts": [], "config_artifacts": [], "symbol_records": [], "type_records": [], "surface_records": [],
        "evidence_records": [
            {"evidence_type": "API_CARD", "card_ref": "knowledge_raw/api_cards/wolfssl/rsa_der_trailing_garbage.yaml", "lifecycle": "draft", "runtime_status": "blocked", "verification_status": "CANDIDATE"},
            {"evidence_type": "API_CARD", "card_ref": "knowledge_raw/api_cards/wolfssl/cipher_pkcs_padding_outlen_underflow.yaml", "lifecycle": "partial", "runtime_status": "blocked", "verification_status": "CANDIDATE"},
            {"evidence_type": "API_CARD", "card_ref": "knowledge_raw/api_cards/wolfssl/asn1_store_named_data_zero_len_stale_state.yaml", "lifecycle": "needs_review", "runtime_status": "blocked", "verification_status": "CANDIDATE"},
        ],
        "producer": "cipherlens.local_target_knowledge.v0.1",
        "git_or_release_identity": {"kind": "git", "revision": revision}, "tree_digest": source["tree_digest"],
        "validation_status": ValidationStatus.NOT_READY.value,
        "telemetry": {"source_root": str(root)},
    })
