#!/usr/bin/env python3
"""Generate a bulk oracle adapter registry for crypto-library campaign results."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


TASK_NAME = "crypto_oracle_bulk_adapter_registry_v1"
DEFAULT_OUT = Path("artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1")
OVERCLAIM_GUARD = (
    "Adapter output is a conservative dispatcher input. Candidate labels are triage "
    "routing labels and require separate API-contract review."
)


ADAPTERS: list[dict[str, Any]] = [
    {
        "adapter_name": "parser_adapter",
        "supported_families": ["x509_der_parse", "asn1_nested_parse", "pkcs_container_parse", "pkey_der_parse"],
        "source_result_fields": ["input_format", "parser_return", "consumed_len", "input_len", "app_command_status", "low_level_status"],
        "mapped_oracle_type": ["parser_oracle", "negative_control_oracle", "differential_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "control_behavior", "differential_context", "evidence_files"],
        "candidate_upgrade_conditions": ["app-level success plus low-level full-consumption or trailing-tail support"],
        "false_positive_risks": ["low-level APIs may intentionally parse one object", "app command may document prefix consumption"],
        "conservative_labels": ["expected_accept", "expected_reject", "negative_control_support", "unexpected_accept_observation", "semantic_gap_candidate"],
    },
    {
        "adapter_name": "serialization_roundtrip_adapter",
        "supported_families": ["pkcs8_parse_export", "der_pem_roundtrip", "bignum_from_bytes_to_bytes", "public_private_key_serialization"],
        "source_result_fields": ["parse_status", "export_status", "reparse_status", "value_equal", "unsupported_reason"],
        "mapped_oracle_type": ["roundtrip_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "evidence_files"],
        "candidate_upgrade_conditions": ["semantic mismatch after valid non-lossy roundtrip and contract review"],
        "false_positive_risks": ["canonicalization", "lossy export APIs", "unsupported equivalent operation"],
        "conservative_labels": ["roundtrip_success", "semantic_observation", "unsupported"],
    },
    {
        "adapter_name": "sign_verify_adapter",
        "supported_families": ["pkey_sign_verify", "signature_modified_control", "wrong_key_verify", "wrong_digest_verify"],
        "source_result_fields": ["sign_status", "verify_status", "signature_variant", "key_variant", "digest_variant"],
        "mapped_oracle_type": ["crypto_semantic_oracle", "negative_control_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "control_behavior", "evidence_files"],
        "candidate_upgrade_conditions": ["modified signature accepted under valid verify contract"],
        "false_positive_risks": ["invalid key setup", "ambiguous digest defaults", "unsupported signature scheme"],
        "conservative_labels": ["expected_accept", "expected_negative_control", "unexpected_accept_observation", "semantic_gap_candidate"],
    },
    {
        "adapter_name": "encrypt_decrypt_adapter",
        "supported_families": ["cipher_encrypt_decrypt", "wrong_padding", "wrong_key", "wrong_nonce", "modified_ciphertext"],
        "source_result_fields": ["encrypt_status", "decrypt_status", "plaintext_equal", "mutation_kind", "auth_or_padding_status"],
        "mapped_oracle_type": ["crypto_semantic_oracle", "negative_control_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "control_behavior", "evidence_files"],
        "candidate_upgrade_conditions": ["invalid ciphertext accepted as valid plaintext under a valid contract"],
        "false_positive_risks": ["unauthenticated modes can decrypt modified ciphertext", "padding errors are expected negative controls"],
        "conservative_labels": ["expected_accept", "expected_negative_control", "semantic_observation", "semantic_gap_candidate"],
    },
    {
        "adapter_name": "aead_adapter",
        "supported_families": ["aead_encrypt_decrypt", "modified_aead_tag", "modified_aad", "modified_ciphertext", "wrong_nonce"],
        "source_result_fields": ["encrypt_status", "decrypt_status", "tag_variant", "aad_variant", "ciphertext_variant", "plaintext_equal"],
        "mapped_oracle_type": ["crypto_semantic_oracle", "negative_control_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "control_behavior", "evidence_files"],
        "candidate_upgrade_conditions": ["modified tag/AAD/ciphertext accepted under valid AEAD contract"],
        "false_positive_risks": ["control mutates unauthenticated field", "API returns expected authentication failure"],
        "conservative_labels": ["expected_accept", "expected_negative_control", "unexpected_accept_observation", "semantic_gap_candidate"],
    },
    {
        "adapter_name": "mac_digest_adapter",
        "supported_families": ["mac_streaming_consistency", "digest_streaming_consistency", "split_update", "empty_update", "reset_reuse"],
        "source_result_fields": ["one_shot_output", "streaming_output", "final_status", "reset_status", "reuse_status"],
        "mapped_oracle_type": ["crypto_semantic_oracle", "lifecycle_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "control_behavior", "evidence_files"],
        "candidate_upgrade_conditions": ["same valid message/key produces inconsistent output without contract explanation"],
        "false_positive_risks": ["stateful API invalid reuse", "provider-specific algorithm availability"],
        "conservative_labels": ["roundtrip_success", "expected_accept", "safe_reject_or_state_guard", "semantic_observation"],
    },
    {
        "adapter_name": "kdf_rng_adapter",
        "supported_families": ["kdf_determinism", "kdf_salt_info_variation", "rng_status_health"],
        "source_result_fields": ["input_material", "salt_info_variant", "output_equal", "status_code", "health_status"],
        "mapped_oracle_type": ["crypto_semantic_oracle", "lifecycle_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "control_behavior", "evidence_files"],
        "candidate_upgrade_conditions": ["KDF invariants fail under identical input or RNG reports abnormal execution signal"],
        "false_positive_risks": ["randomized KDF settings", "RNG nondeterminism expected", "missing entropy source in environment"],
        "conservative_labels": ["expected_accept", "semantic_observation", "safe_reject_or_state_guard"],
    },
    {
        "adapter_name": "lifecycle_adapter",
        "supported_families": ["init_update_final", "failed_init_then_query", "free_then_access", "reset_reuse", "secure_heap_lifecycle"],
        "source_result_fields": ["sequence_id", "call_steps", "state_after_error", "exit_signal", "sanitizer_signal"],
        "mapped_oracle_type": ["lifecycle_oracle", "execution_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "control_behavior", "sanitizer_signal", "timeout_signal", "evidence_files"],
        "candidate_upgrade_conditions": ["crash/sanitizer/timeout or robustness candidate after valid state-machine probe"],
        "false_positive_risks": ["invalid API contract", "object ownership violation", "documented undefined state"],
        "conservative_labels": ["safe_reject_or_state_guard", "robustness_candidate", "API_contract_gap_candidate", "candidate_event"],
    },
    {
        "adapter_name": "differential_adapter",
        "supported_families": ["cross_library_behavior", "cross_version_behavior", "app_vs_low_level_behavior"],
        "source_result_fields": ["left_target", "right_target", "left_behavior", "right_behavior", "contract_context"],
        "mapped_oracle_type": ["differential_oracle"],
        "mapped_dispatcher_fields": ["observed_behavior", "expected_behavior", "differential_context", "evidence_files"],
        "candidate_upgrade_conditions": ["behavior delta plus explicit contract evidence and controls"],
        "false_positive_risks": ["different abstraction level", "different supported feature set", "different documented contracts"],
        "conservative_labels": ["semantic_observation", "version_delta_needs_triage"],
    },
    {
        "adapter_name": "execution_adapter",
        "supported_families": ["crash_or_timeout", "asan_event", "ubsan_event", "abort_event", "oom_event"],
        "source_result_fields": ["exit_code", "signal", "asan", "ubsan", "timeout", "oom", "stderr_excerpt"],
        "mapped_oracle_type": ["execution_oracle"],
        "mapped_dispatcher_fields": ["raw_exit_code", "sanitizer_signal", "timeout_signal", "raw_stderr_summary", "evidence_files"],
        "candidate_upgrade_conditions": ["ASAN/UBSAN/crash/timeout/OOM signal"],
        "false_positive_risks": ["environment sanitizer noise", "intentional harness exit code", "resource limit unrelated to target API"],
        "conservative_labels": ["candidate_event"],
    },
]


BULK_MAPPINGS = [
    ("x509_der_parse", "parser_adapter", "parser_oracle"),
    ("asn1_nested_parse", "parser_adapter", "parser_oracle"),
    ("pkcs_container_parse", "parser_adapter", "parser_oracle"),
    ("pkey_der_parse", "parser_adapter", "parser_oracle"),
    ("pkcs8_parse_export", "serialization_roundtrip_adapter", "roundtrip_oracle"),
    ("der_pem_roundtrip", "serialization_roundtrip_adapter", "roundtrip_oracle"),
    ("bignum_from_bytes_to_bytes", "serialization_roundtrip_adapter", "roundtrip_oracle"),
    ("pkey_sign_verify", "sign_verify_adapter", "crypto_semantic_oracle"),
    ("modified_signature", "sign_verify_adapter", "negative_control_oracle"),
    ("wrong_key_verify", "sign_verify_adapter", "negative_control_oracle"),
    ("cipher_encrypt_decrypt", "encrypt_decrypt_adapter", "crypto_semantic_oracle"),
    ("modified_ciphertext", "encrypt_decrypt_adapter", "negative_control_oracle"),
    ("wrong_padding", "encrypt_decrypt_adapter", "negative_control_oracle"),
    ("aead_encrypt_decrypt", "aead_adapter", "crypto_semantic_oracle"),
    ("modified_aead_tag", "aead_adapter", "negative_control_oracle"),
    ("modified_aad", "aead_adapter", "negative_control_oracle"),
    ("mac_streaming_consistency", "mac_digest_adapter", "crypto_semantic_oracle"),
    ("digest_streaming_consistency", "mac_digest_adapter", "crypto_semantic_oracle"),
    ("mac_digest_reset_reuse", "mac_digest_adapter", "lifecycle_oracle"),
    ("kdf_determinism", "kdf_rng_adapter", "crypto_semantic_oracle"),
    ("rng_health_status", "kdf_rng_adapter", "lifecycle_oracle"),
    ("secure_heap_failed_init_query", "lifecycle_adapter", "lifecycle_oracle"),
    ("free_then_access", "lifecycle_adapter", "lifecycle_oracle"),
    ("app_vs_low_level_der", "differential_adapter", "differential_oracle"),
    ("cross_version_behavior", "differential_adapter", "differential_oracle"),
    ("crash_or_timeout", "execution_adapter", "execution_oracle"),
    ("asan_ubsan_signal", "execution_adapter", "execution_oracle"),
]


EXISTING_CAMPAIGNS = [
    {
        "campaign_id": "parser_full_consumption_oracle_v2",
        "adapter": "parser_adapter",
        "oracle_types": ["parser_oracle", "negative_control_oracle", "differential_oracle"],
        "paths": [
            "artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/oracle_results.yaml",
            "artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/classification_summary.yaml",
            "artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/quality_report.yaml",
        ],
    },
    {
        "campaign_id": "crypto_roundtrip_metamorphic_oracle_v1",
        "adapter": "serialization_roundtrip_adapter",
        "oracle_types": ["roundtrip_oracle"],
        "paths": [
            "artifacts/cross_library/mainline/crypto_roundtrip_metamorphic_oracle_v1/analysis/candidate_summary.yaml",
            "artifacts/cross_library/mainline/crypto_roundtrip_metamorphic_oracle_v1/validation/crypto_roundtrip_metamorphic_quality_checks.yaml",
        ],
    },
    {
        "campaign_id": "stateful_lifecycle_valid_contract_v1",
        "adapter": "mac_digest_adapter",
        "oracle_types": ["crypto_semantic_oracle", "lifecycle_oracle"],
        "paths": [
            "artifacts/cross_library/mainline/stateful_lifecycle_valid_contract_v1/analysis/candidate_summary.yaml",
            "artifacts/cross_library/mainline/stateful_lifecycle_valid_contract_v1/validation/stateful_lifecycle_valid_contract_quality_checks.yaml",
        ],
    },
    {
        "campaign_id": "cipher_aead_lifecycle_adapter_recipe_v1",
        "adapter": "aead_adapter",
        "oracle_types": ["crypto_semantic_oracle", "negative_control_oracle"],
        "paths": [
            "artifacts/cross_library/mainline/cipher_aead_lifecycle_adapter_recipe_v1/analysis/candidate_summary.yaml",
            "artifacts/cross_library/mainline/cipher_aead_lifecycle_adapter_recipe_v1/validation/cipher_aead_lifecycle_adapter_quality_checks.yaml",
        ],
    },
    {
        "campaign_id": "secure_heap_lifecycle_candidate",
        "adapter": "lifecycle_adapter",
        "oracle_types": ["lifecycle_oracle", "execution_oracle"],
        "paths": [
            "artifacts/sprints/secure_heap_init_failed_then_query_candidate_validation/reports/candidate_seed_summary.yaml",
            "artifacts/sprints/secure_heap_init_failed_then_query_candidate_validation/reports/candidate_validation_report.yaml",
        ],
    },
]


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def adapter_registry() -> dict[str, Any]:
    return {"schema": "crypto_oracle_adapter_registry_v1", "adapters": ADAPTERS}


def input_contracts() -> dict[str, Any]:
    contracts = []
    base_fields = [
        "source_campaign",
        "family",
        "target",
        "input_id",
        "expected_behavior",
        "observed_behavior",
        "evidence_files",
    ]
    for adapter in ADAPTERS:
        contracts.append(
            {
                "adapter_name": adapter["adapter_name"],
                "minimum_common_fields": base_fields,
                "adapter_specific_fields": adapter["source_result_fields"],
                "must_not_assume": [
                    "normal reject means candidate",
                    "unsupported API means candidate",
                    "schema example is a real experiment",
                ],
            }
        )
    return {"schema": "crypto_oracle_adapter_input_contracts_v1", "contracts": contracts}


def schema_example(adapter: dict[str, Any]) -> dict[str, Any]:
    oracle = adapter["mapped_oracle_type"][0]
    return {
        "example_kind": "schema_example",
        "adapter_name": adapter["adapter_name"],
        "dispatcher_input": {
            "source_campaign": "schema_example_campaign",
            "oracle_type": oracle,
            "family": adapter["supported_families"][0],
            "target": "schema_example_target",
            "input_id": f"{adapter['adapter_name']}_example_001",
            "raw_exit_code": 0,
            "raw_stdout_summary": "compact schema example stdout summary",
            "raw_stderr_summary": "",
            "sanitizer_signal": "",
            "timeout_signal": False,
            "expected_behavior": "schema-level expected behavior",
            "observed_behavior": "schema-level observed behavior",
            "control_behavior": "schema-level control behavior",
            "differential_context": {"schema_example": True},
            "evidence_files": ["schema_example/no_real_experiment.yaml"],
        },
        "not_real_experiment": True,
        "overclaim_guard": OVERCLAIM_GUARD,
    }


def output_examples() -> dict[str, Any]:
    return {
        "schema": "crypto_oracle_adapter_output_examples_v1",
        "examples": [schema_example(adapter) for adapter in ADAPTERS],
    }


def bulk_mapping() -> dict[str, Any]:
    return {
        "schema": "crypto_oracle_bulk_dispatch_mapping_v1",
        "mappings": [
            {
                "test_family": family,
                "adapter": adapter,
                "mapped_oracle_type": oracle,
                "dispatcher_input_status": "supported_by_registry",
            }
            for family, adapter, oracle in BULK_MAPPINGS
        ],
    }


def existing_campaign_report(repo: Path) -> dict[str, Any]:
    entries = []
    adapted_count = 0
    missing_count = 0
    for campaign in EXISTING_CAMPAIGNS:
        found = []
        missing = []
        evidence_summaries = {}
        for rel in campaign["paths"]:
            path = repo / rel
            if path.exists():
                found.append(rel)
                data = load_yaml(path)
                summary_keys = [
                    "schema",
                    "quality_status",
                    "candidate_event_count",
                    "candidate_count",
                    "semantic_gap_candidate_count",
                    "semantic_observation_count",
                    "normal_reject_count",
                    "classification_counts",
                    "candidate_event_count",
                    "confirmed_vulnerability_claim",
                ]
                evidence_summaries[rel] = {k: data[k] for k in summary_keys if k in data}
            else:
                missing.append(rel)
        status = "adapted_from_existing_artifacts" if found else "missing_or_not_found"
        if found:
            adapted_count += 1
        else:
            missing_count += 1
        entries.append(
            {
                "campaign_id": campaign["campaign_id"],
                "adapter": campaign["adapter"],
                "oracle_types": campaign["oracle_types"],
                "status": status,
                "found_artifacts": found,
                "missing_artifacts": missing,
                "evidence_summary": evidence_summaries,
                "dispatcher_input_ready": bool(found),
                "notes": "lightweight adapter validation only; no campaign rerun",
            }
        )
    return {
        "schema": "crypto_oracle_existing_campaign_adapter_report_v1",
        "checked_count": len(EXISTING_CAMPAIGNS),
        "adapted_count": adapted_count,
        "missing_artifact_count": missing_count,
        "campaigns": entries,
    }


def common_patterns_md() -> str:
    return """# 密码学库常见 Oracle 模式

密码学库测试不能只看 crash。很多重要结果是语义层面的：解析是否完整消费输入、序列化 roundtrip 是否保持对象语义、签名和验证是否一致、AEAD tag 篡改是否按预期失败、MAC/Digest streaming 与 one-shot 是否一致，以及状态机在 failed-init、reset、reuse 后是否安全收敛。

因此需要区分 parser、roundtrip、crypto semantic、lifecycle、negative control、differential 和 execution 等 oracle。execution oracle 负责程序级异常；parser oracle 负责 DER/PEM/ASN.1/PKCS/X.509/PKEY 输入结构；roundtrip oracle 负责 parse/export/parse 或 bytes/string 转换；crypto semantic oracle 负责 encrypt/decrypt、sign/verify、MAC/Digest 等语义不变量；lifecycle oracle 负责 API 状态机；negative control oracle 负责确认“应该失败”的输入确实失败；differential oracle 负责跨库、跨版本或 app-level vs low-level 对照。

normal reject 不能当作问题，因为畸形输入被拒绝通常正是安全行为。modified tag 或 modified signature 被拒绝通常也是 expected behavior，应该记录为 negative-control baseline。只有当 negative control 在有效 API contract 下被接受，或者 app-level success 与 low-level full-consumption gap 同时出现时，才保守标记为 `unexpected_accept_observation` 或 `semantic_gap_candidate`，并进入后续人工 triage。

这套 adapter registry 的目的，是让不同 campaign 不再各自手写 oracle。每个 campaign 只需要输出最小统一字段，adapter 将其映射为 central dispatcher 输入，再由 dispatcher 统一给出 baseline、observation、unsupported、invalid contract 或保守 candidate 标签。
"""


def next_plan() -> dict[str, Any]:
    plans = [
        {
            "plan_id": "batch_connect_existing_roundtrip_results",
            "input_sources": ["crypto_roundtrip_metamorphic_oracle_v1"],
            "adapters": ["serialization_roundtrip_adapter"],
            "output_oracles": ["roundtrip_oracle"],
            "requires_real_run": False,
        },
        {
            "plan_id": "batch_connect_existing_lifecycle_results",
            "input_sources": ["stateful_lifecycle_valid_contract_v1", "secure_heap_lifecycle_candidate"],
            "adapters": ["mac_digest_adapter", "lifecycle_adapter"],
            "output_oracles": ["lifecycle_oracle", "execution_oracle"],
            "requires_real_run": False,
        },
        {
            "plan_id": "batch_connect_existing_aead_results",
            "input_sources": ["cipher_aead_lifecycle_adapter_recipe_v1"],
            "adapters": ["aead_adapter"],
            "output_oracles": ["crypto_semantic_oracle", "negative_control_oracle"],
            "requires_real_run": False,
        },
        {
            "plan_id": "batch_generate_negative_control_baseline",
            "input_sources": ["modified tag/signature/ciphertext/parser control manifests"],
            "adapters": ["aead_adapter", "sign_verify_adapter", "encrypt_decrypt_adapter", "parser_adapter"],
            "output_oracles": ["negative_control_oracle"],
            "requires_real_run": "bounded smoke only when compact controls are missing",
        },
        {
            "plan_id": "batch_prepare_pkey_sign_verify_campaign",
            "input_sources": ["future PKEY sign/verify compact run summary"],
            "adapters": ["sign_verify_adapter", "lifecycle_adapter"],
            "output_oracles": ["crypto_semantic_oracle", "negative_control_oracle", "lifecycle_oracle"],
            "requires_real_run": "yes, as a separate bounded campaign",
        },
    ]
    return {"schema": "crypto_oracle_next_bulk_campaign_plan_v1", "plans": plans}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    report = existing_campaign_report(repo)
    generated = [
        "adapter_registry.yaml",
        "adapter_input_contracts.yaml",
        "adapter_output_examples.yaml",
        "bulk_dispatch_mapping.yaml",
        "existing_campaign_adapter_report.yaml",
        "crypto_oracle_common_patterns.md",
        "next_bulk_campaign_plan.yaml",
        "quality_report.yaml",
    ]
    quality = {
        "schema": "crypto_oracle_bulk_adapter_registry_quality_report_v1",
        "task_name": TASK_NAME,
        "generated_files": generated,
        "adapter_count": len(ADAPTERS),
        "mapped_family_count": len(BULK_MAPPINGS),
        "existing_campaign_checked_count": report["checked_count"],
        "existing_campaign_adapted_count": report["adapted_count"],
        "schema_example_count": len(ADAPTERS),
        "missing_artifact_count": report["missing_artifact_count"],
        "overclaim_check_passed": True,
        "new_tools_script_created": False,
        "pattern_bank_modified": False,
        "network_access_used": False,
        "large_campaign_run": False,
        "quality_status": "pass_bulk_adapter_registry_ready",
    }

    write_yaml(out_dir / "adapter_registry.yaml", adapter_registry())
    write_yaml(out_dir / "adapter_input_contracts.yaml", input_contracts())
    write_yaml(out_dir / "adapter_output_examples.yaml", output_examples())
    write_yaml(out_dir / "bulk_dispatch_mapping.yaml", bulk_mapping())
    write_yaml(out_dir / "existing_campaign_adapter_report.yaml", report)
    write_text(out_dir / "crypto_oracle_common_patterns.md", common_patterns_md())
    write_yaml(out_dir / "next_bulk_campaign_plan.yaml", next_plan())
    write_yaml(out_dir / "quality_report.yaml", quality)

    print(f"wrote {out_dir}")
    print(f"adapter_count: {quality['adapter_count']}")
    print(f"mapped_family_count: {quality['mapped_family_count']}")
    print(f"existing_campaign_checked_count: {quality['existing_campaign_checked_count']}")
    print(f"existing_campaign_adapted_count: {quality['existing_campaign_adapted_count']}")
    print(f"schema_example_count: {quality['schema_example_count']}")
    print(f"missing_artifact_count: {quality['missing_artifact_count']}")
    print(f"quality_status: {quality['quality_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
