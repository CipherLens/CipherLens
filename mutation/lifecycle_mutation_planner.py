"""Build lifecycle mutation plans from lifecycle seed manifests."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


DISABLED_UNSAFE_SEED = "evp_digest_ctx_lifecycle_use_after_free_negative_control"


def case_record(
    *,
    case_id: str,
    source_seed_id: str,
    mutation_strategy: str,
    case_group: str,
    expected_behavior: str,
    oracle_rule: str,
    enabled: bool = True,
    notes: str = "",
) -> dict[str, Any]:
    record = {
        "case_id": case_id,
        "source_seed_id": source_seed_id,
        "mutation_strategy": mutation_strategy,
        "case_group": case_group,
        "expected_behavior": expected_behavior,
        "oracle_rule": oracle_rule,
        "enabled": enabled,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
    }
    if notes:
        record["notes"] = notes
    return record


def build_lifecycle_mutation_plan(seed_manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    family = str(seed_manifest.get("family") or "evp_digest_ctx_lifecycle")
    if family == "mac_lifecycle":
        return build_mac_lifecycle_mutation_plan(seed_manifest)
    valid_seed = (
        "evp_cipher_ctx_lifecycle_valid_encrypt_init_update_final_control"
        if family == "evp_cipher_ctx_lifecycle"
        else "evp_digest_ctx_lifecycle_valid_init_update_final_control"
    )
    update_seed = f"{family}_update_before_init_control"
    final_seed = f"{family}_final_without_update_control"
    update_after_seed = f"{family}_update_after_final_control"
    reset_seed = f"{family}_reset_reuse_control"
    unsafe_seed = f"{family}_use_after_free_negative_control"
    cases = [
        case_record(
            case_id=f"{family}_mut_valid_init_update_final_control",
            source_seed_id=valid_seed,
            mutation_strategy="valid_init_update_final_control",
            case_group="valid_lifecycle_control",
            expected_behavior="success",
            oracle_rule="unexpected_failure_on_valid_sequence",
        ),
        case_record(
            case_id=f"{family}_mut_update_before_init",
            source_seed_id=update_seed,
            mutation_strategy="update_before_init",
            case_group="invalid_state_control",
            expected_behavior="error_or_documented",
            oracle_rule="unexpected_success_after_invalid_state",
        ),
        case_record(
            case_id=f"{family}_mut_final_without_update",
            source_seed_id=final_seed,
            mutation_strategy="final_without_update",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
            notes="Empty-message digest may be documented success; observe only.",
        ),
        case_record(
            case_id=f"{family}_mut_update_after_final",
            source_seed_id=update_after_seed,
            mutation_strategy="update_after_final",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
            notes="Post-final update is API-contract boundary; observe only.",
        ),
        case_record(
            case_id=f"{family}_mut_reset_reuse",
            source_seed_id=reset_seed,
            mutation_strategy="reset_reuse",
            case_group="valid_lifecycle_control",
            expected_behavior="success",
            oracle_rule="unexpected_failure_on_valid_sequence",
        ),
        case_record(
            case_id=f"{family}_mut_reinit_without_reset",
            source_seed_id=valid_seed,
            mutation_strategy="reinit_without_reset",
            case_group="valid_lifecycle_control",
            expected_behavior="success",
            oracle_rule="unexpected_failure_on_valid_sequence",
        ),
        case_record(
            case_id=f"{family}_mut_double_final_observation",
            source_seed_id=final_seed,
            mutation_strategy="double_final",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
        ),
        case_record(
            case_id=f"{family}_mut_reset_before_init_observation",
            source_seed_id=reset_seed,
            mutation_strategy="reset_before_init",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
        ),
    ]
    deferred = [
        {
            "seed_id": unsafe_seed,
            "mutation_strategy": "use_after_free",
            "enabled": False,
            "reason": "unsafe use-after-free negative control must not run by default",
        }
    ]
    plan = {
        "schema": "lifecycle_mutation_plan_v1",
        "generated_at": now_iso(),
        "family": family,
        "track": seed_manifest.get("track", "lifecycle"),
        "archetype": seed_manifest.get("archetype", "evp_context_lifecycle"),
        "target_library": seed_manifest.get("target_library", "openssl"),
        "seed_manifest_schema": seed_manifest.get("schema", ""),
        "mutation_case_count": len(cases),
        "enabled_case_count": len([item for item in cases if item.get("enabled") is True]),
        "unsafe_use_after_free_executed": False,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "cases": cases,
    }
    summary = {
        "schema": "lifecycle_mutation_summary_v1",
        "generated_at": now_iso(),
        "family": family,
        "mutation_plan_generated": True,
        "mutation_case_count": len(cases),
        "enabled_case_count": len([item for item in cases if item.get("enabled") is True]),
        "deferred_mutation_count": len(deferred),
        "case_groups": sorted(set(str(item.get("case_group")) for item in cases)),
    }
    deferred_doc = {
        "schema": "lifecycle_deferred_mutations_v1",
        "generated_at": now_iso(),
        "family": family,
        "deferred_mutations": deferred,
    }
    return plan, summary, deferred_doc


def build_mac_lifecycle_mutation_plan(seed_manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    family = "mac_lifecycle"
    cases = [
        case_record(
            case_id="valid_hmac_init_update_final_control",
            source_seed_id="mac_lifecycle_valid_hmac_init_update_final_control",
            mutation_strategy="valid_hmac_init_update_final_control",
            case_group="valid_lifecycle_control",
            expected_behavior="success",
            oracle_rule="unexpected_failure_on_valid_sequence",
        ),
        case_record(
            case_id="update_before_init",
            source_seed_id="mac_lifecycle_update_before_init_control",
            mutation_strategy="update_before_init",
            case_group="invalid_state_control",
            expected_behavior="error_or_documented",
            oracle_rule="unexpected_success_after_invalid_state",
        ),
        case_record(
            case_id="final_without_update_after_init",
            source_seed_id="mac_lifecycle_final_without_update_after_init_control",
            mutation_strategy="final_without_update_after_init",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
            notes="HMAC final after init with no update may be documented success; observe only.",
        ),
        case_record(
            case_id="repeated_final",
            source_seed_id="mac_lifecycle_repeated_final_observation_control",
            mutation_strategy="repeated_final",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
            notes="Repeated final is observed only; success alone is not a candidate.",
        ),
        case_record(
            case_id="update_after_final",
            source_seed_id="mac_lifecycle_update_after_final_observation_control",
            mutation_strategy="update_after_final",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
            notes="Post-final update is observed only; success alone is not a candidate.",
        ),
        case_record(
            case_id="reinit_reuse",
            source_seed_id="mac_lifecycle_reinit_reuse_control",
            mutation_strategy="reinit_reuse",
            case_group="valid_lifecycle_control",
            expected_behavior="success",
            oracle_rule="unexpected_failure_on_valid_sequence",
        ),
        case_record(
            case_id="wrong_key_length_observation",
            source_seed_id="mac_lifecycle_valid_hmac_init_update_final_control",
            mutation_strategy="wrong_key_length_observation",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
            notes="Wrong key length for HMAC is an observation boundary, not a candidate by itself.",
        ),
        case_record(
            case_id="empty_message_observation",
            source_seed_id="mac_lifecycle_final_without_update_after_init_control",
            mutation_strategy="empty_message_observation",
            case_group="observation",
            expected_behavior="observation",
            oracle_rule="state_transition_observation",
            notes="Empty-message HMAC is observed only.",
        ),
    ]
    deferred = [
        {
            "seed_id": "mac_lifecycle_use_after_free_negative_control",
            "mutation_strategy": "use_after_free",
            "enabled": False,
            "reason": "unsafe use-after-free negative control must not run by default",
        }
    ]
    plan = {
        "schema": "lifecycle_mutation_plan_v1",
        "generated_at": now_iso(),
        "family": family,
        "track": seed_manifest.get("track", "lifecycle"),
        "archetype": seed_manifest.get("archetype", "mac_context_lifecycle"),
        "target_library": seed_manifest.get("target_library", "openssl"),
        "seed_manifest_schema": seed_manifest.get("schema", ""),
        "mutation_case_count": len(cases),
        "enabled_case_count": len([item for item in cases if item.get("enabled") is True]),
        "unsafe_use_after_free_executed": False,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "cases": cases,
    }
    summary = {
        "schema": "lifecycle_mutation_summary_v1",
        "generated_at": now_iso(),
        "family": family,
        "mutation_plan_generated": True,
        "mutation_case_count": len(cases),
        "enabled_case_count": len([item for item in cases if item.get("enabled") is True]),
        "deferred_mutation_count": len(deferred),
        "case_groups": sorted(set(str(item.get("case_group")) for item in cases)),
    }
    deferred_doc = {
        "schema": "lifecycle_deferred_mutations_v1",
        "generated_at": now_iso(),
        "family": family,
        "deferred_mutations": deferred,
    }
    return plan, summary, deferred_doc
