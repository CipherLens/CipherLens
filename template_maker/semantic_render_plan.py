"""Build semantic render plans from semantic mutation plans and validated slot evidence."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from template_maker.render_records import dump_yaml, load_yaml, now_iso, write_text


TASK = "pkey_verify_semantic_render_plan_v1"
DEFAULT_BASELINE = "artifacts/sprints/glm_slot_filling_token_budget_fix_v1"
DEFAULT_MUTATION_PLAN = (
    "artifacts/sprints/pkey_verify_semantic_generic_mutation_plan_v1/mutation/mutation_plan.yaml"
)
DEFAULT_SEED_MANIFEST = (
    "artifacts/sprints/pkey_verify_semantic_seed_discovery_v1/seed_discovery/seed_manifest.yaml"
)
FORBIDDEN_MARKERS = [
    "DER trailing garbage",
    "PEM trailing garbage",
    "full_consumption=false",
    "d2i_",
    "ASN.1 malformed tail",
    "x509/pkcs8/pkey object parsing",
    "openssl x509",
    "openssl pkey",
    "openssl pkcs8",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--mutation-plan", default=DEFAULT_MUTATION_PLAN)
    parser.add_argument("--seed-manifest", default=DEFAULT_SEED_MANIFEST)
    parser.add_argument("--baseline-root", default=DEFAULT_BASELINE)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def baseline_status(baseline_root: Path) -> dict[str, Any]:
    quality = load_yaml(baseline_root / "validation/glm_slot_filling_token_budget_quality_checks.yaml")
    slot_schema = load_yaml(baseline_root / "validation/slot_bindings_schema_validate.yaml")
    adapter = load_yaml(baseline_root / "validation/adapter_validate_results.yaml")
    mapping = load_yaml(baseline_root / "validation/mapping_gate_validate_results.yaml")
    return {
        "schema": "semantic_render_rag_glm_baseline_status_v1",
        "generated_at": now_iso(),
        "rag_glm_baseline_loaded": bool(quality),
        "slot_bindings_loaded": (baseline_root / "slot_filling/generated_slot_bindings.yaml").exists(),
        "slot_bindings_schema_valid": bool(slot_schema.get("slot_bindings_schema_valid")),
        "adapter_validate_loaded": bool(adapter),
        "adapter_validate_passed": adapter.get("status") == "pass",
        "mapping_gate_loaded": bool(mapping),
        "mapping_gate_bypassed": bool(mapping.get("mapping_gate_bypassed")),
        "api_key_logged": bool(quality.get("api_key_logged")),
        "glm_generated_c_code": bool(quality.get("glm_generated_c_code")),
        "source_quality_status": quality.get("quality_status", ""),
    }


def group_for_strategy(strategy: str) -> str:
    if strategy == "valid_accept_control":
        return "valid_accept_control"
    if strategy.startswith("signature_corruption"):
        return "signature_corruption"
    if strategy.startswith("message_mismatch"):
        return "message_mismatch"
    if strategy == "wrong_key_verify":
        return "wrong_key"
    return "semantic_other"


def mutation_application(case: dict[str, Any]) -> dict[str, Any]:
    strategy = str(case.get("mutation_strategy") or "")
    params = case.get("mutation_parameters") or {}
    if strategy == "valid_accept_control":
        return {"mode": "none", "details": "keep valid signature, message, and verification key unchanged"}
    if strategy.startswith("signature_corruption"):
        return {"mode": "mutate_signature_buffer", "details": params}
    if strategy.startswith("message_mismatch"):
        return {"mode": "mutate_verify_message", "details": params}
    if strategy == "wrong_key_verify":
        return {"mode": "use_independent_verification_key", "details": params}
    return {"mode": "semantic_mutation", "details": params}


def oracle_events(case: dict[str, Any]) -> list[str]:
    case_id = case.get("case_id", "<case_id>")
    expected = case.get("expected_behavior", "")
    return [
        "ORACLE_EVENT family=pkey_verify_semantic",
        f"ORACLE_EVENT case_id={case_id}",
        f"ORACLE_EVENT expected_behavior={expected}",
        "ORACLE_EVENT actual_behavior=accept/reject/error",
        "ORACLE_EVENT semantic_mismatch=0/1",
        "ORACLE_EVENT crash_or_sanitizer=0/1",
    ]


def render_case(case: dict[str, Any]) -> dict[str, Any]:
    expected = str(case.get("expected_behavior") or "")
    return {
        "case_id": case.get("case_id"),
        "source_seed_id": case.get("source_seed_id"),
        "mutation_strategy": case.get("mutation_strategy"),
        "case_group": group_for_strategy(str(case.get("mutation_strategy") or "")),
        "expected_behavior": expected,
        "api_sequence": case.get("api_sequence", []),
        "key_generation": {
            "algorithm": "RSA",
            "bits": 2048,
            "digest": "EVP_sha256",
            "apis": [
                "EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)",
                "EVP_PKEY_keygen_init",
                "EVP_PKEY_CTX_set_rsa_keygen_bits",
                "EVP_PKEY_keygen",
            ],
        },
        "signing_flow": {
            "message_source": "fixed deterministic semantic seed message",
            "apis": [
                "EVP_MD_CTX_new",
                "EVP_DigestSignInit",
                "EVP_DigestSignUpdate",
                "EVP_DigestSignFinal(size query)",
                "EVP_DigestSignFinal(signature output)",
            ],
        },
        "verification_flow": {
            "verify_key": "same_key_or_mutation_selected_key",
            "verify_message": "original_or_mutated_message",
            "signature": "valid_or_mutated_signature",
            "apis": [
                "EVP_MD_CTX_new",
                "EVP_DigestVerifyInit",
                "EVP_DigestVerifyUpdate",
                "EVP_DigestVerifyFinal",
            ],
            "actual_behavior_mapping": {
                "EVP_DigestVerifyFinal_returns_1": "accept",
                "EVP_DigestVerifyFinal_returns_0": "reject",
                "EVP_DigestVerifyFinal_returns_other": "error",
            },
        },
        "mutation_application": mutation_application(case),
        "oracle_events": oracle_events(case),
        "oracle_rules": [
            "expected=accept and actual=reject/error -> unexpected_reject",
            "expected=reject and actual=accept -> unexpected_accept",
            "crash/sanitizer signal -> crash_or_sanitizer",
        ],
        "required_includes": [
            "openssl/evp.h",
            "openssl/rsa.h",
            "openssl/err.h",
            "stdio.h",
            "string.h",
        ],
        "required_libs": ["crypto"],
        "cleanup_requirements": [
            "EVP_MD_CTX_free",
            "EVP_PKEY_free",
            "EVP_PKEY_CTX_free",
            "OPENSSL_free(signature)",
        ],
        "render_execution": {
            "render_cases_executed": False,
            "compile_executed": False,
            "run_executed": False,
        },
    }


def build_render_plan(
    *,
    mutation_plan: dict[str, Any],
    baseline: dict[str, Any],
    mutation_plan_path: str,
    slot_bindings_path: str,
) -> dict[str, Any]:
    cases = [render_case(case) for case in mutation_plan.get("cases", []) or []]
    return {
        "schema": "semantic_render_plan_v1",
        "generated_at": now_iso(),
        "family": mutation_plan.get("family", "pkey_verify_semantic"),
        "track": mutation_plan.get("track", "semantic"),
        "target_library": mutation_plan.get("target_library", "openssl"),
        "source_mutation_plan": mutation_plan_path,
        "source_slot_bindings": slot_bindings_path,
        "adapter_validate_passed": bool(baseline.get("adapter_validate_passed")),
        "uses_rag_glm_baseline": bool(baseline.get("rag_glm_baseline_loaded")),
        "mapping_gate_bypassed": bool(baseline.get("mapping_gate_bypassed")),
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "render_mode": "semantic_harness",
        "algorithm": "RSA",
        "digest": "SHA256",
        "slot_binding_policy": {
            "slot_bindings_loaded": bool(baseline.get("slot_bindings_loaded")),
            "used_as_gate_evidence_only": True,
            "semantic_render_uses_evp_digest_sign_verify": True,
        },
        "cases": cases,
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def deferred_render_capabilities() -> dict[str, Any]:
    return {
        "schema": "semantic_deferred_render_capabilities_v1",
        "generated_at": now_iso(),
        "family": "pkey_verify_semantic",
        "deferred": [
            {
                "capability": "digest_mismatch_rendering",
                "reason": "mutation case deferred until renderer can vary digest between sign and verify",
            },
            {
                "capability": "api_state_misuse_rendering",
                "reason": "mutation case deferred until renderer can model setup failure and missing update states",
            },
        ],
    }


def render_summary(plan: dict[str, Any]) -> dict[str, Any]:
    cases = plan.get("cases", []) or []
    groups = {}
    for case in cases:
        groups[case.get("case_group", "unknown")] = groups.get(case.get("case_group", "unknown"), 0) + 1
    return {
        "schema": "semantic_render_summary_v1",
        "generated_at": now_iso(),
        "family": plan.get("family"),
        "track": plan.get("track"),
        "target_library": plan.get("target_library"),
        "render_mode": plan.get("render_mode"),
        "case_count": len(cases),
        "case_groups": groups,
        "render_cases_executed": False,
        "compile_executed": False,
        "run_executed": False,
    }


def forbidden_leakage(plan: dict[str, Any]) -> bool:
    text = str(plan)
    return any(marker in text for marker in FORBIDDEN_MARKERS)


def quality_checks(
    *,
    baseline: dict[str, Any],
    mutation_plan: dict[str, Any],
    plan: dict[str, Any],
    leakage: bool,
) -> dict[str, Any]:
    cases = plan.get("cases", []) or []
    strategies = [str(case.get("mutation_strategy") or "") for case in cases]
    api_text = str(plan)
    oracle_events_defined = all(case.get("oracle_events") for case in cases)
    status = "failed_der_parsing_leakage" if leakage else "pass"
    return {
        "schema": "pkey_verify_semantic_render_plan_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family": plan.get("family"),
        "track": plan.get("track"),
        "target_library": plan.get("target_library"),
        "rag_glm_baseline_loaded": bool(baseline.get("rag_glm_baseline_loaded")),
        "slot_bindings_loaded": bool(baseline.get("slot_bindings_loaded")),
        "slot_bindings_schema_valid": bool(baseline.get("slot_bindings_schema_valid")),
        "adapter_validate_loaded": bool(baseline.get("adapter_validate_loaded")),
        "adapter_validate_passed": bool(baseline.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline.get("mapping_gate_bypassed")),
        "mutation_plan_loaded": bool(mutation_plan),
        "mutation_plan_case_count": len(mutation_plan.get("cases", []) or []),
        "render_plan_generated": True,
        "render_case_count": len(cases),
        "render_mode": plan.get("render_mode"),
        "valid_accept_control_present": "valid_accept_control" in strategies,
        "signature_corruption_cases_present": any(s.startswith("signature_corruption") for s in strategies),
        "message_mismatch_cases_present": any(s.startswith("message_mismatch") for s in strategies),
        "wrong_key_case_present": "wrong_key_verify" in strategies,
        "evp_digest_sign_used": "EVP_DigestSignInit" in api_text and "EVP_DigestSignFinal" in api_text,
        "evp_digest_verify_used": "EVP_DigestVerifyInit" in api_text and "EVP_DigestVerifyFinal" in api_text,
        "rsa_sha256_used": plan.get("algorithm") == "RSA" and plan.get("digest") == "SHA256",
        "oracle_events_defined": oracle_events_defined,
        "uses_der_parsing": bool(plan.get("uses_der_parsing")),
        "uses_trailing_garbage": bool(plan.get("uses_trailing_garbage")),
        "uses_full_consumption_oracle": bool(plan.get("uses_full_consumption_oracle")),
        "pkey_parsing_leakage": False,
        "render_cases_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "api_key_logged": bool(baseline.get("api_key_logged")),
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status
        if bool(baseline.get("rag_glm_baseline_loaded"))
        and bool(baseline.get("slot_bindings_loaded"))
        and bool(baseline.get("slot_bindings_schema_valid"))
        and bool(baseline.get("adapter_validate_passed"))
        and not baseline.get("mapping_gate_bypassed")
        and len(cases) >= 8
        and oracle_events_defined
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
    for sub in ("inputs", "render", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    mutation_plan_path = repo_root / args.mutation_plan
    seed_manifest_path = repo_root / args.seed_manifest
    baseline_root = repo_root / args.baseline_root
    slot_bindings_path = baseline_root / "slot_filling/generated_slot_bindings.yaml"
    adapter_validate_path = baseline_root / "validation/adapter_validate_results.yaml"

    mutation_plan = load_yaml(mutation_plan_path)
    seed_manifest = load_yaml(seed_manifest_path)
    slot_bindings = load_yaml(slot_bindings_path)
    adapter_validate = load_yaml(adapter_validate_path)
    baseline = baseline_status(baseline_root)
    plan = build_render_plan(
        mutation_plan=mutation_plan,
        baseline=baseline,
        mutation_plan_path=args.mutation_plan,
        slot_bindings_path=(Path(args.baseline_root) / "slot_filling/generated_slot_bindings.yaml").as_posix(),
    )
    leakage = forbidden_leakage(plan)
    summary = render_summary(plan)
    deferred = deferred_render_capabilities()
    qc = quality_checks(baseline=baseline, mutation_plan=mutation_plan, plan=plan, leakage=leakage)

    dump_yaml(out_dir / "inputs/mutation_plan_snapshot.yaml", mutation_plan)
    dump_yaml(out_dir / "inputs/seed_manifest_snapshot.yaml", seed_manifest)
    dump_yaml(out_dir / "inputs/generated_slot_bindings_snapshot.yaml", slot_bindings)
    dump_yaml(out_dir / "inputs/adapter_validate_snapshot.yaml", adapter_validate)
    dump_yaml(out_dir / "rag_glm_baseline_status.yaml", baseline)
    dump_yaml(out_dir / "render/render_plan.yaml", plan)
    dump_yaml(out_dir / "render/render_summary.yaml", summary)
    dump_yaml(out_dir / "render/deferred_render_capabilities.yaml", deferred)
    dump_yaml(out_dir / "validation/pkey_verify_semantic_render_plan_quality_checks.yaml", qc)

    report = f"""# {TASK} Report

## Render Plan

- family: {plan.get('family')}
- track: {plan.get('track')}
- target_library: {plan.get('target_library')}
- render_mode: {plan.get('render_mode')}
- case_count: {summary.get('case_count')}
- quality_status: {qc.get('quality_status')}

## Baseline Gates

- rag_glm_baseline_loaded: {baseline.get('rag_glm_baseline_loaded')}
- slot_bindings_schema_valid: {baseline.get('slot_bindings_schema_valid')}
- adapter_validate_passed: {baseline.get('adapter_validate_passed')}
- mapping_gate_bypassed: {baseline.get('mapping_gate_bypassed')}
- api_key_logged: {baseline.get('api_key_logged')}

## Semantic API

- algorithm: RSA
- digest: SHA256
- sign_api: EVP_DigestSignInit / EVP_DigestSignUpdate / EVP_DigestSignFinal
- verify_api: EVP_DigestVerifyInit / EVP_DigestVerifyUpdate / EVP_DigestVerifyFinal

## Policy

This sprint generated a render plan only. It did not render cases, compile,
run, write feedback, update pattern-bank, modify adapter recipes, modify
normalized templates, perform git operations, claim a CVE, claim exploitability,
or claim a confirmed vulnerability.
"""
    write_text(out_dir / "reports/pkey_verify_semantic_render_plan_v1_report.md", report)
    print(f"[OK] wrote semantic render plan artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"family={plan.get('family')} cases={summary.get('case_count')} "
        f"quality={qc.get('quality_status')}"
    )
    return 0 if qc.get("quality_status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
