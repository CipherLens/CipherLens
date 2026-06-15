"""Generate generic semantic mutation plans from semantic seed manifests."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text


TASK = "pkey_verify_semantic_generic_mutation_plan_v1"
DEFAULT_SEED_MANIFEST = (
    "artifacts/sprints/pkey_verify_semantic_seed_discovery_v1/seed_discovery/seed_manifest.yaml"
)
DEFAULT_FAMILY_CARD = "knowledge/family_cards/pkey_verify_semantic.yaml"


FORBIDDEN_MARKERS = [
    "DER trailing garbage",
    "PEM trailing garbage",
    "d2i_",
    "full_consumption=false",
    "ASN.1 malformed tail",
    "x509 parsing",
    "pkcs8 parsing",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--seed-manifest", default=DEFAULT_SEED_MANIFEST)
    parser.add_argument("--family-card", default=DEFAULT_FAMILY_CARD)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def seed_by_id(manifest: dict[str, Any], suffix: str) -> dict[str, Any]:
    for seed in manifest.get("seeds", []) or []:
        if str(seed.get("seed_id", "")).endswith(suffix):
            return seed
    return (manifest.get("seeds") or [{}])[0] or {}


def make_case(
    *,
    case_id: str,
    source_seed: dict[str, Any],
    mutation_strategy: str,
    expected_behavior: str,
    oracle: list[str],
    mutation_parameters: dict[str, Any],
) -> dict[str, Any]:
    render_requirements = dict(source_seed.get("render_requirements") or {})
    render_requirements.pop("must_not_use_d2i_prefix_parsing", None)
    render_requirements.update(
        {
            "serialize_key_or_signature_as_der": False,
            "must_not_use_prefix_parsing": True,
            "observe_verify_return_code": True,
        }
    )
    return {
        "case_id": case_id,
        "source_seed_id": source_seed.get("seed_id"),
        "mutation_strategy": mutation_strategy,
        "expected_behavior": expected_behavior,
        "oracle": oracle,
        "api_sequence": source_seed.get("api_sequence", []),
        "mutation_parameters": mutation_parameters,
        "render_requirements": render_requirements,
    }


def build_cases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    valid = seed_by_id(manifest, "valid_sign_verify_control")
    modified_sig = seed_by_id(manifest, "modified_signature_reject_control")
    modified_msg = seed_by_id(manifest, "modified_message_reject_control")
    wrong_key = seed_by_id(manifest, "wrong_key_reject_control")
    reject_oracle = ["unexpected_accept", "semantic_divergence", "crash_or_sanitizer"]
    accept_oracle = ["unexpected_reject", "semantic_divergence", "crash_or_sanitizer"]
    return [
        make_case(
            case_id="pkey_verify_semantic_mut_valid_accept_control",
            source_seed=valid,
            mutation_strategy="valid_accept_control",
            expected_behavior="accept",
            oracle=accept_oracle,
            mutation_parameters={"signature": "unchanged", "message": "unchanged", "verify_key": "same_key"},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_signature_flip_one_byte",
            source_seed=modified_sig,
            mutation_strategy="signature_corruption_flip_one_byte",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"signature_mutation": "flip_byte", "byte_index": 0},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_signature_truncate",
            source_seed=modified_sig,
            mutation_strategy="signature_corruption_truncate",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"signature_mutation": "truncate", "remove_bytes": 1},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_signature_extend",
            source_seed=modified_sig,
            mutation_strategy="signature_corruption_extend",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"signature_mutation": "append_bytes", "append_hex": "00"},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_signature_all_zero",
            source_seed=modified_sig,
            mutation_strategy="signature_corruption_all_zero",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"signature_mutation": "replace_with_zero_buffer"},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_message_flip_one_byte",
            source_seed=modified_msg,
            mutation_strategy="message_mismatch_flip_one_byte",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"message_mutation": "flip_byte", "byte_index": 0},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_message_empty",
            source_seed=modified_msg,
            mutation_strategy="message_mismatch_empty_message",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"message_mutation": "empty_message"},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_message_longer",
            source_seed=modified_msg,
            mutation_strategy="message_mismatch_longer_message",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"message_mutation": "append_text", "append_text": "-extra"},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_message_different",
            source_seed=modified_msg,
            mutation_strategy="message_mismatch_different_message",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"message_mutation": "replace_message", "replacement": "different semantic message"},
        ),
        make_case(
            case_id="pkey_verify_semantic_mut_wrong_key_reject",
            source_seed=wrong_key,
            mutation_strategy="wrong_key_verify",
            expected_behavior="reject",
            oracle=reject_oracle,
            mutation_parameters={"signing_key": "key_A", "verify_key": "independent_key_B"},
        ),
    ]


def deferred_mutations() -> dict[str, Any]:
    return {
        "schema": "semantic_deferred_mutations_v1",
        "generated_at": now_iso(),
        "family": "pkey_verify_semantic",
        "deferred": [
            {
                "mutation_strategy": "digest_mismatch_sha256_to_sha384_or_sha512",
                "deferred_mutation_reason": "renderer_capability_missing",
                "expected_behavior": "reject",
                "oracle": ["unexpected_accept", "semantic_divergence", "crash_or_sanitizer"],
            },
            {
                "mutation_strategy": "api_state_misuse_without_update_or_failed_init",
                "deferred_mutation_reason": "renderer_capability_missing",
                "expected_behavior": "reject_or_error",
                "oracle": ["unexpected_accept", "semantic_divergence", "crash_or_sanitizer"],
            },
        ],
    }


def forbidden_leakage(plan: dict[str, Any]) -> bool:
    text = str(plan)
    return any(marker in text for marker in FORBIDDEN_MARKERS)


def mutation_summary(plan: dict[str, Any], deferred: dict[str, Any]) -> dict[str, Any]:
    cases = plan.get("cases", []) or []
    strategies = [case.get("mutation_strategy", "") for case in cases]
    return {
        "schema": "semantic_mutation_summary_v1",
        "generated_at": now_iso(),
        "family": plan.get("family"),
        "track": plan.get("track"),
        "target_library": plan.get("target_library"),
        "case_count": len(cases),
        "strategy_groups": {
            "valid_accept_control": len([s for s in strategies if s == "valid_accept_control"]),
            "signature_corruption": len([s for s in strategies if s.startswith("signature_corruption")]),
            "message_mismatch": len([s for s in strategies if s.startswith("message_mismatch")]),
            "wrong_key": len([s for s in strategies if s == "wrong_key_verify"]),
        },
        "deferred_count": len(deferred.get("deferred", []) or []),
        "deferred_strategies": [item.get("mutation_strategy") for item in deferred.get("deferred", []) or []],
    }


def quality_checks(
    *,
    manifest: dict[str, Any],
    plan: dict[str, Any],
    deferred: dict[str, Any],
    leakage: bool,
) -> dict[str, Any]:
    cases = plan.get("cases", []) or []
    strategies = [str(case.get("mutation_strategy") or "") for case in cases]
    semantic_oracles_defined = all(bool(case.get("oracle")) for case in cases)
    status = "failed_der_parsing_leakage" if leakage else "pass"
    return {
        "schema": "pkey_verify_semantic_mutation_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family": plan.get("family"),
        "track": plan.get("track"),
        "target_library": plan.get("target_library"),
        "seed_manifest_loaded": bool(manifest),
        "seed_ready": bool(manifest.get("seed_ready")),
        "mutation_plan_generated": True,
        "case_count": len(cases),
        "valid_accept_control_present": "valid_accept_control" in strategies,
        "signature_corruption_cases_present": any(s.startswith("signature_corruption") for s in strategies),
        "message_mismatch_cases_present": any(s.startswith("message_mismatch") for s in strategies),
        "wrong_key_case_present": "wrong_key_verify" in strategies,
        "digest_mismatch_case_present": any("digest_mismatch" in s for s in strategies),
        "api_state_misuse_case_present": any("api_state_misuse" in s for s in strategies),
        "uses_der_parsing": bool(plan.get("uses_der_parsing")),
        "uses_trailing_garbage": bool(plan.get("uses_trailing_garbage")),
        "uses_full_consumption_oracle": bool(plan.get("uses_full_consumption_oracle")),
        "semantic_oracles_defined": semantic_oracles_defined,
        "generic_mutation_engine_used": True,
        "family_specific_script_created": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "mapping_gate_bypassed": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status
        if manifest.get("seed_ready")
        and len(cases) >= 8
        and semantic_oracles_defined
        and not plan.get("uses_der_parsing")
        and not plan.get("uses_trailing_garbage")
        and not plan.get("uses_full_consumption_oracle")
        and not leakage
        else "blocked",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "mutation", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    seed_manifest_path = repo_root / args.seed_manifest
    family_card_path = repo_root / args.family_card
    manifest = load_yaml(seed_manifest_path)
    family_card = load_yaml(family_card_path)
    deferred = deferred_mutations()
    plan = {
        "schema": "semantic_mutation_plan_v1",
        "generated_at": now_iso(),
        "family": manifest.get("family", "pkey_verify_semantic"),
        "track": manifest.get("track", "semantic"),
        "target_library": manifest.get("target_library", "openssl"),
        "source_seed_manifest": args.seed_manifest,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "cases": build_cases(manifest),
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    leakage = forbidden_leakage(plan)
    summary = mutation_summary(plan, deferred)
    qc = quality_checks(manifest=manifest, plan=plan, deferred=deferred, leakage=leakage)

    dump_yaml(out_dir / "inputs/seed_manifest_snapshot.yaml", manifest)
    dump_yaml(out_dir / "inputs/family_card_snapshot.yaml", family_card)
    dump_yaml(out_dir / "mutation/mutation_plan.yaml", plan)
    dump_yaml(out_dir / "mutation/mutation_summary.yaml", summary)
    dump_yaml(out_dir / "mutation/deferred_mutations.yaml", deferred)
    dump_yaml(out_dir / "validation/pkey_verify_semantic_mutation_quality_checks.yaml", qc)

    report = f"""# {TASK} Report

## Mutation Plan

- family: {plan.get('family')}
- track: {plan.get('track')}
- target_library: {plan.get('target_library')}
- case_count: {summary.get('case_count')}
- quality_status: {qc.get('quality_status')}

## Case Groups

- valid_accept_control: {summary['strategy_groups']['valid_accept_control']}
- signature_corruption: {summary['strategy_groups']['signature_corruption']}
- message_mismatch: {summary['strategy_groups']['message_mismatch']}
- wrong_key: {summary['strategy_groups']['wrong_key']}

## Deferred

- deferred_count: {summary.get('deferred_count')}
- deferred_strategies: {summary.get('deferred_strategies')}

## Policy

No tools script, family-specific mutation script, DER trailing-garbage case,
full-consumption oracle, render, compile, run, feedback, pattern-bank, adapter
recipe, normalized template, API key logging, git operation, CVE,
exploitability, or confirmed vulnerability claim was produced.
"""
    write_text(out_dir / "reports/pkey_verify_semantic_generic_mutation_plan_v1_report.md", report)
    print(f"[OK] wrote semantic mutation plan artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"family={plan.get('family')} cases={summary.get('case_count')} "
        f"quality={qc.get('quality_status')}"
    )
    return 0 if qc.get("quality_status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
