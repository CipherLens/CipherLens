"""OpenSSL 3.5.5 release-profile materialization backed by local source."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import ValidationStatus, finalize_profile
from .source_index import file_digest, find_symbol, source_root_record
from .verifier import verify_evidence_record


def materialize_openssl_355_profile(root: Path) -> dict[str, Any]:
    source = source_root_record(root, "source:openssl:3.5.5:release")
    config_path = root / "configdata.pm"
    config = []
    if config_path.exists():
        config.append({"artifact_ref": "config:openssl:3.5.5:configdata.pm", "digest": file_digest(config_path)})
    evidence: list[dict[str, Any]] = []
    symbols = []
    for symbol, role in (("d2i_RSAPrivateKey", "rsa_private_key_decode"), ("EVP_DecryptFinal_ex", "cipher_final")):
        header = find_symbol(root, symbol, suffixes=(".h",))
        source_evidence = find_symbol(root, symbol, suffixes=(".c", ".cc", ".cpp"))
        records = [item for item in (header, source_evidence) if item is not None]
        for record in records:
            record["verification_status"] = verify_evidence_record(record).value
            record["semantic_role"] = role
            evidence.append(record)
        verifier_status = "VERIFIED" if records and all(item["verification_status"] == "VERIFIED" for item in records) else "CANDIDATE"
        symbols.append({
            "target_symbol_ref": f"symbol:openssl:3.5.5:{symbol}", "symbol": symbol, "role": role,
            "header_evidence_ref": f"evidence:openssl-3.5.5:{symbol}:header" if header else None,
            "source_evidence_ref": f"evidence:openssl-3.5.5:{symbol}:source" if source_evidence else None,
            "config_evidence_ref": config[0]["artifact_ref"] if config else None,
            "verification_status": verifier_status,
        })
    # The legacy cards may inform recall, but no card grants verified target facts.
    evidence.extend([
        {"evidence_type": "API_CARD", "card_ref": "knowledge_raw/api_cards/openssl/rsa_der_trailing_garbage.yaml", "lifecycle": "draft", "verification_status": "CANDIDATE"},
        {"evidence_type": "API_CARD", "card_ref": "knowledge_raw/api_cards/openssl/cipher_pkcs_padding_outlen_underflow.yaml", "lifecycle": "partial", "verification_status": "CANDIDATE"},
    ])
    return finalize_profile({
        "target_scope": {"library": "OpenSSL", "version": "3.5.5", "source_identity": "release:openssl-3.5.5", "surface_ref": "surface:openssl:3.5.5"},
        "source_roots": [source],
        "header_roots": [{"root_ref": "header:openssl:3.5.5", "tree_digest": source["tree_digest"]}],
        "library_artifacts": [{"artifact_ref": "library:openssl:3.5.5:libcrypto.a", "digest": file_digest(root / "libcrypto.a"), "kind": "static_library"}],
        "config_artifacts": config,
        "symbol_records": symbols, "type_records": [],
        "surface_records": [{"surface_ref": "surface:openssl:3.5.5", "verification_policy": "source_header_only", "facts": []}],
        "evidence_records": evidence,
        "producer": "cipherlens.local_target_knowledge.v0.1",
        "git_or_release_identity": {"kind": "release", "release": "openssl-3.5.5", "tree_digest": source["tree_digest"], "configdata_digest": config[0]["digest"] if config else None},
        "tree_digest": source["tree_digest"],
        "validation_status": ValidationStatus.PREPARED.value,
        "telemetry": {"source_root": str(root)},
    })
