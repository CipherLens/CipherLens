"""Bootstrap scoped family/API cards for RAG baseline audits."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso


FAMILY_SPECS: dict[str, dict[str, Any]] = {
    "pkey_parsing": {
        "apps": ["openssl pkey"],
        "apis": [
            "PEM_read_bio_PrivateKey",
            "PEM_read_bio_PUBKEY",
            "d2i_AutoPrivateKey",
            "d2i_PUBKEY",
            "d2i_PrivateKey_bio",
            "d2i_PUBKEY_bio",
            "EVP_PKEY",
        ],
        "formats": ["PEM private key", "PEM public key", "DER private key", "DER public key"],
        "oracle_goals": [
            "parser_accept",
            "full_consumption_gap",
            "malformed_only_reject",
            "app_level_replay",
        ],
    },
    "pkcs8_parsing": {
        "apps": ["openssl pkcs8"],
        "apis": ["d2i_PKCS8_PRIV_KEY_INFO", "d2i_AutoPrivateKey", "PEM_read_bio_PrivateKey", "EVP_PKEY"],
        "formats": ["PKCS#8 PEM", "PKCS#8 DER", "encrypted PKCS#8", "unencrypted PKCS#8"],
        "oracle_goals": [
            "parser_accept",
            "full_consumption_gap",
            "encrypted_or_unencrypted_boundary",
            "malformed_only_reject",
        ],
    },
    "cms_container_parsing": {
        "apps": ["openssl cms"],
        "apis": ["CMS_ContentInfo", "d2i_CMS_bio", "PEM_read_bio_CMS"],
        "formats": ["CMS DER", "CMS PEM", "SignedData", "EnvelopedData"],
        "oracle_goals": [
            "parser_accept",
            "full_consumption_gap",
            "container_boundary",
            "malformed_only_reject",
        ],
    },
    "x509_crl_parsing": {
        "apps": ["openssl crl"],
        "apis": ["X509_CRL", "d2i_X509_CRL_bio", "PEM_read_bio_X509_CRL"],
        "formats": ["CRL DER", "CRL PEM"],
        "oracle_goals": ["parser_accept", "full_consumption_gap", "malformed_only_reject"],
    },
}


def api_card(family: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "api_card_v1",
        "family": family,
        "library": "openssl",
        "apps": spec["apps"],
        "apis": spec["apis"],
        "formats": spec["formats"],
        "observables": ["return_code", "accepted", "consumed_len", "input_len", "full_consumption"],
        "oracle_goals": spec["oracle_goals"],
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def family_card(family: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "family_card_v1",
        "family": family,
        "harness_family": "object_or_container_parsing",
        "operation_family": family.replace("_", " "),
        "apps": spec["apps"],
        "target_api_features": [
            "parser API",
            "DER or PEM input",
            "accepted/rejected observability",
            "full-consumption observability",
        ],
        "common_mutation_points": [
            "valid DER single object plus trailing garbage",
            "malformed-only control",
            "near-valid length delta",
            "DER/PEM format toggle",
        ],
        "oracle_goals": spec["oracle_goals"],
        "known_pattern_refs": ["der_single_object_trailing_garbage_full_consumption"],
        "safe_behavior": "reject malformed-only controls and avoid claiming accepted-prefix behavior as confirmed vulnerability",
        "triage_behavior": "deduplicate known full-consumption gaps unless a new semantic class or crash/sanitizer appears",
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def bootstrap_knowledge(repo_root: Path, families: list[str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    api_root = repo_root / "knowledge/api_cards"
    family_root = repo_root / "knowledge/family_cards"
    api_added = {}
    family_added = {}
    for family in families:
        spec = FAMILY_SPECS[family]
        api_doc = api_card(family, spec)
        family_doc = family_card(family, spec)
        dump_yaml(api_root / f"{family}.yaml", api_doc)
        dump_yaml(family_root / f"{family}.yaml", family_doc)
        api_added[family] = (api_root / f"{family}.yaml").as_posix()
        family_added[family] = (family_root / f"{family}.yaml").as_posix()

    profiles_path = repo_root / "config/family_profiles.yaml"
    profiles = load_yaml(profiles_path)
    for family in families:
        profile = (profiles.setdefault("families", {})).setdefault(family, {})
        profile.setdefault("family", family)
        profile["api_card_refs"] = [api_added[family]]
        profile["rag_refs"] = [family_added[family], api_added[family]]
        profile["known_pattern_refs"] = ["der_single_object_trailing_garbage_full_consumption"]
    dump_yaml(profiles_path, profiles)

    return (
        {
            "schema": "family_knowledge_added_v1",
            "generated_at": now_iso(),
            "families": family_added,
        },
        {
            "schema": "api_cards_added_v1",
            "generated_at": now_iso(),
            "api_cards": api_added,
        },
        profiles,
    )
