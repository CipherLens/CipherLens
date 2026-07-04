"""Minimal cryptographic semantic model for fault-surface validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SEMANTIC_DIMENSIONS = (
    "key_lifecycle",
    "sign_verify_consistency",
    "encryption_correctness",
    "key_usage_semantics",
)

OPERATION_TOKENS = {
    "key_lifecycle": ("key", "pkey", "ctx", "init", "load", "free", "destroy", "cleanup"),
    "sign_verify_consistency": ("sign", "verify", "signature"),
    "encryption_correctness": ("encrypt", "decrypt", "cipher", "aead", "final", "finish"),
    "key_usage_semantics": ("usage", "purpose", "private", "public", "import", "parse"),
}


def build_crypto_semantic_model(seed_context: Mapping[str, Any], oracle_output: Mapping[str, Any]) -> dict[str, Any]:
    """Build a small semantic model from seed context and oracle signals."""

    text = _context_text(seed_context, oracle_output)
    dimensions = []
    for dimension, tokens in OPERATION_TOKENS.items():
        matched = sorted({token for token in tokens if token in text})
        dimensions.append(
            {
                "dimension": dimension,
                "matched_tokens": matched,
                "active": bool(matched),
                "security_invariant": _invariant(dimension),
            }
        )
    active = [item["dimension"] for item in dimensions if item["active"]]
    return {
        "schema": "crypto_semantic_model_v1",
        "semantic_dimensions": list(SEMANTIC_DIMENSIONS),
        "active_dimensions": active,
        "dimension_models": dimensions,
        "model_status": "ok" if active else "no_crypto_semantic_dimension_detected",
    }


def _context_text(seed_context: Mapping[str, Any], oracle_output: Mapping[str, Any]) -> str:
    return f"{seed_context} {oracle_output}".lower()


def _invariant(dimension: str) -> str:
    invariants = {
        "key_lifecycle": "key_or_context_state_must_not_be_reused_after_terminal_or_error_state",
        "sign_verify_consistency": "valid_signature_result_must_be_equivalent_across_libraries",
        "encryption_correctness": "encrypt_decrypt_or_finalization_result_must_preserve_plaintext_auth_semantics",
        "key_usage_semantics": "key_usage_and_object_type_constraints_must_be_consistent",
    }
    return invariants.get(dimension, "crypto_semantic_consistency_required")
