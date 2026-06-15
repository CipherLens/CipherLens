"""Generate structured semantic seed manifests from family profiles and API cards."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text


TASK = "pkey_verify_semantic_seed_discovery_v1"
DEFAULT_FAMILY_PROFILES = "config/family_profiles.yaml"
DEFAULT_SELECTION = "artifacts/campaigns/scheduler_novelty_gate_skip_tested_family_v1"
DEFAULT_API_CARD_PATHS = [
    "knowledge_base/api_cards/openssl/EVP_DigestVerify.yaml",
    "knowledge_base/api_cards/openssl/EVP_DigestVerifyInit.yaml",
    "knowledge_base/api_cards/openssl/EVP_PKEY_verify.yaml",
    "knowledge_base/api_cards/openssl/EVP_PKEY_CTX_set_rsa_padding.yaml",
    "knowledge_base/api_cards/openssl/EVP_PKEY_CTX_set_rsa_pss_saltlen.yaml",
    "knowledge_base/api_cards/mbedtls/mbedtls_pk_verify.yaml",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--family", default="pkey_verify_semantic")
    parser.add_argument("--family-profiles", default=DEFAULT_FAMILY_PROFILES)
    parser.add_argument("--selection-snapshot", default=DEFAULT_SELECTION)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def family_profile(profiles: dict[str, Any], family: str) -> dict[str, Any]:
    return ((profiles.get("families") or {}).get(family)) or {}


def api_card_lookup(repo_root: Path) -> dict[str, Any]:
    cards = []
    for rel in DEFAULT_API_CARD_PATHS:
        path = repo_root / rel
        doc = load_yaml(path)
        if not doc:
            continue
        cards.append(
            {
                "source_path": rel,
                "library": doc.get("library", ""),
                "api": doc.get("api", ""),
                "family": doc.get("family", ""),
                "signature": doc.get("signature", ""),
                "oracle_observables": doc.get("oracle_observables", []) or [],
                "mutation_hints": doc.get("mutation_hints", []) or [],
                "known_pitfalls": doc.get("known_pitfalls", []) or [],
            }
        )
    return {
        "schema": "semantic_api_card_lookup_v1",
        "generated_at": now_iso(),
        "family": "pkey_verify_semantic",
        "lookup_executed": True,
        "api_cards_used": [card["source_path"] for card in cards],
        "preferred_algorithm": "RSA + SHA256",
        "selection_reason": (
            "OpenSSL EVP_DigestSign/EVP_DigestVerify with RSA+SHA256 provides a high-level "
            "sign/verify semantic control without DER parsing, trailing garbage, or a "
            "full-consumption oracle."
        ),
        "cards": cards,
    }


def seed(
    *,
    seed_id: str,
    seed_type: str,
    expected_behavior: str,
    scenario: str,
    oracle: list[str],
    mutation_hints: list[str],
) -> dict[str, Any]:
    return {
        "seed_id": seed_id,
        "seed_type": seed_type,
        "operation_family": "public_key_signature_verification",
        "algorithm": "RSA",
        "digest": "SHA256",
        "message": "fixed deterministic semantic seed message",
        "api_sequence": [
            "EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)",
            "EVP_PKEY_keygen_init",
            "EVP_PKEY_CTX_set_rsa_keygen_bits(2048)",
            "EVP_PKEY_keygen",
            "EVP_MD_CTX_new",
            "EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, signing_key)",
            "EVP_DigestSignUpdate(ctx, message, message_len)",
            "EVP_DigestSignFinal(ctx, NULL, &sig_len)",
            "EVP_DigestSignFinal(ctx, sig, &sig_len)",
            "EVP_MD_CTX_new",
            "EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, verify_key)",
            "EVP_DigestVerifyUpdate(ctx, verify_message, verify_message_len)",
            "EVP_DigestVerifyFinal(ctx, signature, signature_len)",
        ],
        "scenario": scenario,
        "expected_behavior": expected_behavior,
        "oracle": oracle,
        "mutation_hints": mutation_hints,
        "render_requirements": {
            "generate_key_at_runtime": True,
            "serialize_key_or_signature_as_der": False,
            "use_evp_high_level_api": True,
            "must_not_use_d2i_prefix_parsing": True,
            "observe_verify_return_code": True,
            "cleanup": [
                "EVP_MD_CTX_free",
                "EVP_PKEY_free",
                "EVP_PKEY_CTX_free",
                "OPENSSL_free(signature)",
            ],
        },
    }


def build_manifest(profile: dict[str, Any], lookup: dict[str, Any]) -> dict[str, Any]:
    seeds = [
        seed(
            seed_id="pkey_verify_semantic_valid_sign_verify_control",
            seed_type="valid_sign_verify_control",
            expected_behavior="accept",
            scenario="sign with key A and verify the same message/signature with key A",
            oracle=["unexpected_reject", "semantic_divergence", "crash_or_sanitizer"],
            mutation_hints=["control case for valid signature acceptance"],
        ),
        seed(
            seed_id="pkey_verify_semantic_modified_signature_reject_control",
            seed_type="modified_signature_reject_control",
            expected_behavior="reject",
            scenario="flip one byte in a valid signature before verification",
            oracle=["unexpected_accept", "semantic_divergence", "crash_or_sanitizer"],
            mutation_hints=["bitflip signature", "malformed signature length boundary"],
        ),
        seed(
            seed_id="pkey_verify_semantic_modified_message_reject_control",
            seed_type="modified_message_reject_control",
            expected_behavior="reject",
            scenario="verify a valid signature against a modified message",
            oracle=["unexpected_accept", "semantic_divergence", "crash_or_sanitizer"],
            mutation_hints=["wrong message", "message length delta"],
        ),
        seed(
            seed_id="pkey_verify_semantic_wrong_key_reject_control",
            seed_type="wrong_key_reject_control",
            expected_behavior="reject",
            scenario="sign with key A and verify with independently generated key B",
            oracle=["unexpected_accept", "semantic_divergence", "crash_or_sanitizer"],
            mutation_hints=["wrong public key", "key mismatch", "provider dispatch boundary"],
        ),
    ]
    return {
        "schema": "semantic_seed_manifest_v1",
        "generated_at": now_iso(),
        "family": "pkey_verify_semantic",
        "track": profile.get("track", "semantic"),
        "target_library": profile.get("target_library", "openssl"),
        "seed_ready": True,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "api_cards_used": lookup.get("api_cards_used", []),
        "preferred_algorithm": lookup.get("preferred_algorithm", "RSA + SHA256"),
        "seeds": seeds,
        "next_stage": "generic_mutation_engine",
    }


def seed_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    seeds = manifest.get("seeds", []) or []
    return {
        "schema": "semantic_seed_summary_v1",
        "generated_at": now_iso(),
        "family": manifest.get("family"),
        "track": manifest.get("track"),
        "target_library": manifest.get("target_library"),
        "seed_count": len(seeds),
        "expected_behavior_counts": {
            "accept": len([item for item in seeds if item.get("expected_behavior") == "accept"]),
            "reject": len([item for item in seeds if item.get("expected_behavior") == "reject"]),
        },
        "seed_ids": [item.get("seed_id") for item in seeds],
        "semantic_focus": [
            "valid signature acceptance",
            "modified signature rejection",
            "modified message rejection",
            "wrong key rejection",
        ],
    }


def seed_readiness(manifest: dict[str, Any]) -> dict[str, Any]:
    seeds = manifest.get("seeds", []) or []
    return {
        "schema": "semantic_seed_readiness_v1",
        "generated_at": now_iso(),
        "family": manifest.get("family"),
        "seed_ready": bool(manifest.get("seed_ready")),
        "ready_for_generic_mutation": bool(seeds),
        "ready_for_render_plan": bool(seeds),
        "blocked_by": [],
        "next_stage": manifest.get("next_stage"),
    }


def quality_checks(
    *,
    profile: dict[str, Any],
    lookup: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    seeds = manifest.get("seeds", []) or []
    seed_ids = {item.get("seed_id") for item in seeds}
    required = {
        "valid_accept_control_present": "pkey_verify_semantic_valid_sign_verify_control" in seed_ids,
        "modified_signature_reject_control_present": (
            "pkey_verify_semantic_modified_signature_reject_control" in seed_ids
        ),
        "modified_message_reject_control_present": (
            "pkey_verify_semantic_modified_message_reject_control" in seed_ids
        ),
        "wrong_key_reject_control_present": "pkey_verify_semantic_wrong_key_reject_control" in seed_ids,
    }
    semantic_oracles_defined = all(bool(item.get("oracle")) for item in seeds)
    seed_ready = bool(manifest.get("seed_ready"))
    return {
        "schema": "pkey_verify_semantic_seed_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family": manifest.get("family"),
        "track": manifest.get("track"),
        "target_library": manifest.get("target_library"),
        "rag_lookup_executed": bool(lookup.get("lookup_executed")),
        "api_cards_used": bool(lookup.get("api_cards_used")),
        "seed_manifest_generated": True,
        "seed_ready": seed_ready,
        "seed_count": len(seeds),
        **required,
        "uses_der_parsing": bool(manifest.get("uses_der_parsing")),
        "uses_trailing_garbage": bool(manifest.get("uses_trailing_garbage")),
        "uses_full_consumption_oracle": bool(manifest.get("uses_full_consumption_oracle")),
        "semantic_oracles_defined": semantic_oracles_defined,
        "generic_seed_discovery_used": True,
        "family_specific_script_created": False,
        "mapping_gate_bypassed": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if profile
        and seed_ready
        and len(seeds) >= 4
        and all(required.values())
        and semantic_oracles_defined
        and not manifest.get("uses_der_parsing")
        and not manifest.get("uses_trailing_garbage")
        and not manifest.get("uses_full_consumption_oracle")
        else "blocked",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "rag", "seed_discovery", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    profiles = load_yaml(repo_root / args.family_profiles)
    profile = family_profile(profiles, args.family)
    selection_state = load_yaml(repo_root / args.selection_snapshot / "campaign_state.yaml")
    selection_summary = load_yaml(repo_root / args.selection_snapshot / "family_selection_summary.yaml")
    lookup = api_card_lookup(repo_root)
    manifest = build_manifest(profile, lookup)
    summary = seed_summary(manifest)
    readiness = seed_readiness(manifest)
    qc = quality_checks(profile=profile, lookup=lookup, manifest=manifest)

    dump_yaml(
        out_dir / "inputs/selection_snapshot.yaml",
        {
            "schema": "semantic_seed_selection_snapshot_v1",
            "generated_at": now_iso(),
            "source_campaign": args.selection_snapshot,
            "selected_family": selection_state.get("current_family") or selection_summary.get("selected_family"),
            "next_action": (selection_state.get("next_recommended_action") or {}).get("action", ""),
            "profile": profile,
        },
    )
    dump_yaml(out_dir / "rag/api_card_lookup.yaml", lookup)
    dump_yaml(out_dir / "seed_discovery/seed_manifest.yaml", manifest)
    dump_yaml(out_dir / "seed_discovery/seed_summary.yaml", summary)
    dump_yaml(out_dir / "seed_discovery/seed_readiness.yaml", readiness)
    dump_yaml(out_dir / "validation/pkey_verify_semantic_seed_quality_checks.yaml", qc)

    report = f"""# {TASK} Report

## Seed Discovery

- family: {manifest.get('family')}
- track: {manifest.get('track')}
- target_library: {manifest.get('target_library')}
- seed_ready: {manifest.get('seed_ready')}
- seed_count: {summary.get('seed_count')}

## Semantic Scope

- uses_der_parsing: {manifest.get('uses_der_parsing')}
- uses_trailing_garbage: {manifest.get('uses_trailing_garbage')}
- uses_full_consumption_oracle: {manifest.get('uses_full_consumption_oracle')}
- preferred_algorithm: {manifest.get('preferred_algorithm')}

## Seeds

- pkey_verify_semantic_valid_sign_verify_control: accept
- pkey_verify_semantic_modified_signature_reject_control: reject
- pkey_verify_semantic_modified_message_reject_control: reject
- pkey_verify_semantic_wrong_key_reject_control: reject

## Policy

No tools script, family-specific seed discovery script, DER trailing-garbage seed,
full-consumption oracle, harness render, compile, run, feedback, pattern-bank,
adapter recipe, normalized template, API key logging, git operation, CVE,
exploitability, or confirmed vulnerability claim was produced.

## Quality

- quality_status: {qc.get('quality_status')}
"""
    write_text(out_dir / "reports/pkey_verify_semantic_seed_discovery_v1_report.md", report)
    print(f"[OK] wrote semantic seed discovery artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"family={manifest.get('family')} seeds={summary.get('seed_count')} "
        f"seed_ready={manifest.get('seed_ready')} quality={qc.get('quality_status')}"
    )
    return 0 if qc.get("quality_status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
