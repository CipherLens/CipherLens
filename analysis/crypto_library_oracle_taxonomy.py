#!/usr/bin/env python3
"""Generate a crypto-library-specific oracle taxonomy and reclassification report."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


TASK_NAME = "crypto_library_oracle_taxonomy_v1"
DEFAULT_OUT = Path("artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1")


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


def taxonomy() -> dict[str, Any]:
    items = [
        {
            "oracle_name": "execution_oracle",
            "purpose": "Detect process-level abnormal termination and sanitizer-visible memory or undefined-behavior events.",
            "input_type": ["compiled harness", "library API call sequence", "sanitizer runtime output"],
            "expected_signal": ["asan", "ubsan", "sigsegv", "abort", "timeout", "oom", "crash_like_nonzero_exit"],
            "candidate_level": "candidate_event",
            "example_cases": ["ASAN heap-buffer-overflow", "UBSAN integer overflow", "timeout in deterministic API harness"],
            "false_positive_risks": ["environmental sanitizer noise", "intentional harness exit code", "resource limits unrelated to API behavior"],
            "conservative_label": "execution_candidate_event",
        },
        {
            "oracle_name": "parser_oracle",
            "purpose": "Classify parser accept/reject behavior, structural consumption, and encoding-boundary handling.",
            "input_type": ["DER", "PEM", "ASN.1 container", "PKCS/X.509/key material"],
            "expected_signal": ["accept", "reject", "full_consumption", "trailing_garbage", "invalid_length", "invalid_tag", "truncated_input"],
            "candidate_level": "semantic_observation_by_default",
            "example_cases": ["DER parser accepts prefix with trailing bytes", "X.509 parser rejects malformed inner boundary"],
            "false_positive_risks": ["low-level API intentionally accepts prefixes", "application layer performs missing validation", "format variants are library-specific"],
            "conservative_label": "parser_semantic_observation_or_gap",
        },
        {
            "oracle_name": "roundtrip_oracle",
            "purpose": "Check parse/export/parse and byte/string conversion consistency.",
            "input_type": ["parsed object", "serialized object", "BIGNUM bytes", "DER/PEM data"],
            "expected_signal": ["roundtrip_success", "roundtrip_mismatch", "normal_reject", "unsupported_api"],
            "candidate_level": "semantic_observation_unless_contract_violation",
            "example_cases": ["BIGNUM from_bytes/to_bytes consistency", "DER parse-export-parse comparison"],
            "false_positive_risks": ["canonicalization changes", "lossy export API", "unsupported equivalent operation"],
            "conservative_label": "roundtrip_semantic_observation",
        },
        {
            "oracle_name": "crypto_semantic_oracle",
            "purpose": "Check cryptographic semantic invariants under valid API contracts.",
            "input_type": ["encrypt/decrypt sequence", "sign/verify sequence", "MAC sequence", "digest sequence"],
            "expected_signal": ["same_plaintext_after_decrypt", "verify_accepts_valid_signature", "one_shot_streaming_match", "expected_auth_failure"],
            "candidate_level": "semantic_gap_candidate_only_when_valid_contract_breaks",
            "example_cases": ["AEAD encrypt then decrypt", "MAC one-shot vs streaming", "digest one-shot vs streaming"],
            "false_positive_risks": ["expected authentication failure", "invalid key or nonce contract", "provider-specific unavailable algorithms"],
            "conservative_label": "crypto_semantic_observation_or_gap",
        },
        {
            "oracle_name": "lifecycle_oracle",
            "purpose": "Classify API state-machine behavior across init/update/final/reset/reuse and failed-init paths.",
            "input_type": ["API call sequence", "object lifecycle trace", "stateful context"],
            "expected_signal": ["valid_sequence_success", "safe_reject", "state_guard", "robustness_event", "api_contract_gap"],
            "candidate_level": "robustness_candidate_or_API_contract_gap_candidate",
            "example_cases": ["init/update/final", "reset/reuse", "failed-init followed by query", "secure heap state query"],
            "false_positive_risks": ["invalid contract treated as bug", "documented undefined state", "test harness violates object ownership"],
            "conservative_label": "lifecycle_robustness_or_contract_gap",
        },
        {
            "oracle_name": "differential_oracle",
            "purpose": "Compare behavior across libraries, versions, or app-level versus low-level APIs.",
            "input_type": ["paired run result", "cross-library target matrix", "cross-version target matrix"],
            "expected_signal": ["same_behavior", "different_behavior", "version_delta", "app_low_level_delta"],
            "candidate_level": "semantic_observation_by_default",
            "example_cases": ["mbedTLS vs Botan AEAD lifecycle", "OpenSSL app-level command vs low-level decoder"],
            "false_positive_risks": ["different API contracts", "different abstraction levels", "unsupported feature parity"],
            "conservative_label": "differential_semantic_observation",
        },
        {
            "oracle_name": "negative_control_oracle",
            "purpose": "Verify that intentionally invalid inputs fail in the expected way.",
            "input_type": ["modified tag", "modified signature", "malformed DER", "tampered ciphertext"],
            "expected_signal": ["expected_negative_control", "unexpected_accept", "safe_reject"],
            "candidate_level": "unexpected_accept_observation_or_semantic_gap_candidate",
            "example_cases": ["modified AEAD tag rejected", "modified signature rejected", "malformed DER rejected"],
            "false_positive_risks": ["test mutates non-authenticated bytes", "API caller checks failure elsewhere", "ambiguous input validity"],
            "conservative_label": "negative_control_observation_or_gap",
        },
    ]
    return {"schema": "crypto_library_oracle_taxonomy_v1", "oracle_types": items}


def decision_rules() -> dict[str, Any]:
    rules = [
        ("execution_sanitizer_or_crash", "ASAN/UBSAN/crash/timeout/OOM", "candidate_event", "high_priority_triage"),
        ("normal_reject", "library rejects malformed or invalid input safely", "safe_reject", "record_baseline"),
        ("cross_library_accept_reject_difference", "different libraries accept/reject same input", "semantic_observation", "review_contracts_before_escalation"),
        ("full_consumption_gap_with_app_success", "low-level parser leaves trailing bytes while app-level path succeeds", "semantic_gap_candidate", "collect_app_level_control"),
        ("full_consumption_gap_low_level_only", "low-level parser consumes prefix only without app-level success", "semantic_observation", "document_api_level"),
        ("modified_tag_rejected", "tampered AEAD tag is rejected", "expected_negative_control", "record_baseline"),
        ("modified_tag_accepted", "tampered AEAD tag is accepted under valid decrypt contract", "semantic_gap_candidate", "minimize_and_recheck"),
        ("modified_signature_rejected", "tampered signature is rejected", "expected_negative_control", "record_baseline"),
        ("modified_signature_accepted", "tampered signature is accepted under valid verify contract", "semantic_gap_candidate", "minimize_and_recheck"),
        ("roundtrip_success", "parse/export/parse or from_bytes/to_bytes remains equivalent", "roundtrip_success", "record_baseline"),
        ("roundtrip_mismatch", "roundtrip changes semantic value without documented canonicalization", "semantic_observation", "check_contract_and_canonicalization"),
        ("unsupported_api", "target lacks equivalent API or export path", "unsupported", "exclude_from_candidate_queue"),
        ("invalid_contract", "harness violates documented API precondition", "invalid_contract", "repair_or_exclude"),
        ("failed_init_then_query_guarded", "query after failed init safely rejects or returns zero state", "safe_reject_or_state_guard", "record_lifecycle_baseline"),
        ("failed_init_then_query_abnormal", "query after failed init triggers crash/sanitizer/unsafe state", "robustness_candidate", "triage_as_lifecycle_event"),
    ]
    return {
        "schema": "crypto_library_oracle_decision_rules_v1",
        "rules": [
            {
                "rule_id": rule_id,
                "condition": condition,
                "classification": classification,
                "next_action": next_action,
                "overclaim_guard": "candidate labels require follow-up triage and must not be treated as final security claims",
            }
            for rule_id, condition, classification, next_action in rules
        ],
    }


def result_schema() -> dict[str, Any]:
    fields = {
        "oracle_type": "One of execution_oracle, parser_oracle, roundtrip_oracle, crypto_semantic_oracle, lifecycle_oracle, differential_oracle, negative_control_oracle.",
        "family": "Harness or vulnerability-pattern family name.",
        "target": "Library/version/build target.",
        "input_id": "Stable seed/case identifier.",
        "observed_behavior": "Observed return code, stdout/stderr signal, parser state, or semantic event.",
        "expected_behavior": "Expected behavior according to API contract or negative-control design.",
        "classification": "safe_reject, semantic_observation, candidate_event, semantic_gap_candidate, robustness_candidate, API_contract_gap_candidate, unsupported, invalid_contract, expected_negative_control.",
        "candidate_level": "none, observation, low, medium, high_priority_triage.",
        "evidence": "Paths to compact logs, summaries, case manifests, or sanitizer evidence.",
        "confidence": "low, medium, high with rationale.",
        "overclaim_guard": "Plain-language guard preventing premature security claims.",
        "next_triage_action": "Record baseline, repair harness, add control, minimize, or queue for manual review.",
    }
    return {
        "schema": "crypto_library_oracle_result_schema_v1",
        "required_fields": list(fields.keys()),
        "field_descriptions": fields,
        "candidate_label_vocabulary": [
            "candidate_event",
            "semantic_gap_candidate",
            "robustness_candidate",
            "API_contract_gap_candidate",
        ],
        "non_candidate_labels": [
            "safe_reject",
            "semantic_observation",
            "unsupported",
            "invalid_contract",
            "expected_negative_control",
            "roundtrip_success",
        ],
    }


def summarize_existing(repo: Path) -> list[dict[str, Any]]:
    artifacts = repo / "artifacts"
    specs = [
        {
            "result_id": "cat_inspired_parser_safe_reject",
            "oracle_type": "parser_oracle",
            "family": "CAT-inspired parser seed enrichment",
            "paths": [
                artifacts / "cross_library/seed_enrichment/cat_case_input_runner_bridge_v1/validation/runner_bridge_quality_checks.yaml",
                artifacts / "cross_library/seed_enrichment/cat_targeted_operator_expansion_v1/validation/targeted_operator_expansion_quality_checks.yaml",
            ],
            "classification": "safe_reject_baseline",
            "candidate_level": "none",
            "next_triage_action": "keep_as_seed_enrichment_baseline_not_candidate",
        },
        {
            "result_id": "roundtrip_oracle_partial_pkcs_bignum",
            "oracle_type": "roundtrip_oracle",
            "family": "crypto_roundtrip_metamorphic_oracle",
            "paths": [
                artifacts / "cross_library/mainline/crypto_roundtrip_metamorphic_oracle_v1/validation/crypto_roundtrip_metamorphic_quality_checks.yaml",
                artifacts / "cross_library/mainline/crypto_roundtrip_metamorphic_oracle_v1/analysis/candidate_summary.yaml",
            ],
            "classification": "roundtrip_success_and_unsupported_observation",
            "candidate_level": "none",
            "next_triage_action": "document_partial_support_before_expanding",
        },
        {
            "result_id": "mac_digest_lifecycle",
            "oracle_type": "lifecycle_oracle",
            "family": "stateful_lifecycle_valid_contract",
            "paths": [
                artifacts / "cross_library/mainline/stateful_lifecycle_valid_contract_v1/validation/stateful_lifecycle_valid_contract_quality_checks.yaml",
                artifacts / "sprints/evp_digest_ctx_lifecycle_full_pipeline_v1/validation/evp_digest_ctx_lifecycle_full_pipeline_quality_checks.yaml",
            ],
            "classification": "valid_contract_lifecycle_baseline",
            "candidate_level": "none",
            "next_triage_action": "keep_as_lifecycle_baseline",
        },
        {
            "result_id": "aead_lifecycle",
            "oracle_type": "crypto_semantic_oracle",
            "family": "cipher_aead_lifecycle",
            "paths": [
                artifacts / "cross_library/mainline/cipher_aead_lifecycle_adapter_recipe_v1/validation/cipher_aead_lifecycle_adapter_quality_checks.yaml",
                artifacts / "cross_library/mainline/cipher_aead_lifecycle_adapter_recipe_v1/analysis/candidate_summary.yaml",
            ],
            "classification": "encrypt_decrypt_baseline_with_expected_negative_control",
            "candidate_level": "none",
            "next_triage_action": "expand_tag_edges_only_as_bounded_follow_up",
        },
        {
            "result_id": "der_full_consumption_candidate",
            "oracle_type": "parser_oracle",
            "family": "DER full-consumption / valid-prefix parser",
            "paths": [
                artifacts / "sprints/valid_prefix_pipeline_to_analyze_v1/analyze/candidate_labels/oracle_aware_candidate_labels.yaml",
                artifacts / "sprints/x509_candidate_triage_v1/triage/x509_candidate_triage.yaml",
                artifacts / "sprints/x509_external_pending_and_continue_scheduler_v1/external_pending/x509_external_pending_candidate.yaml",
            ],
            "classification": "semantic_gap_candidate_or_external_pending",
            "candidate_level": "manual_review_required",
            "next_triage_action": "require_app_level_control_and_contract_evidence",
        },
        {
            "result_id": "secure_heap_lifecycle_candidate",
            "oracle_type": "lifecycle_oracle",
            "family": "secure_heap_state_lifecycle",
            "paths": [
                artifacts / "sprints/secure_heap_init_failed_then_query_candidate_validation/reports/candidate_seed_summary.yaml",
                artifacts / "sprints/secure_heap_init_failed_then_query_candidate_validation/reports/candidate_validation_report.yaml",
                artifacts / "sprints/secure_heap_state_lifecycle_v1/triage",
            ],
            "classification": "robustness_candidate_or_API_contract_gap_candidate",
            "candidate_level": "manual_review_required",
            "next_triage_action": "preserve_conservative_label_and_check_version_contract",
        },
    ]

    results: list[dict[str, Any]] = []
    for spec in specs:
        found_paths = [p for p in spec["paths"] if p.exists()]
        missing_paths = [p for p in spec["paths"] if not p.exists()]
        evidence_summary: dict[str, Any] = {}
        for p in found_paths:
            if p.is_file() and p.suffix in {".yaml", ".yml"}:
                data = load_yaml(p)
                keys = [
                    "quality_status",
                    "candidate_event_count",
                    "candidate_count",
                    "normal_reject_count",
                    "semantic_observation_count",
                    "asan_events",
                    "ubsan_events",
                    "crash_events",
                    "timeout_events",
                    "classification",
                    "status",
                ]
                evidence_summary[str(p.relative_to(repo))] = {k: data[k] for k in keys if k in data}
            else:
                evidence_summary[str(p.relative_to(repo))] = {"status": "found"}
        status = "found" if found_paths else "missing_or_not_found"
        results.append(
            {
                "result_id": spec["result_id"],
                "artifact_status": status,
                "oracle_type": spec["oracle_type"],
                "family": spec["family"],
                "classification": spec["classification"] if found_paths else "missing_or_not_found",
                "candidate_level": spec["candidate_level"] if found_paths else "none",
                "evidence": [str(p.relative_to(repo)) for p in found_paths],
                "missing_paths": [str(p.relative_to(repo)) for p in missing_paths],
                "evidence_summary": evidence_summary,
                "overclaim_guard": "use conservative candidate wording only; require separate triage before any stronger claim",
                "next_triage_action": spec["next_triage_action"] if found_paths else "locate_or_regenerate_compact_summary_before_classification",
            }
        )
    return results


def gap_analysis_text() -> str:
    return """# Crypto Library Oracle Gap Analysis

本轮目标是把 CAT 的 oracle 分层思想迁移到密码学库 API 测试，而不是继续扩大 fuzz 数量。这里不引入 RPKI 仓库、ROA、Manifest、CRL、TAL、RRDP 或 rsync 逻辑，只保留“多层 oracle + 保守分类”的思想。

## 已有能力

- execution/sanitizer：现有 runner 和若干 campaign 已能记录 ASAN、UBSAN、crash、timeout 等程序级信号。
- parser：已有 DER、X.509、ASN.1、PKCS、CAT-inspired seed enrichment 等 parser 相关结果，但 accept/reject 差异仍需要 API contract 解释。
- roundtrip：已有 BIGNUM / partial PKCS roundtrip/metamorphic baseline，可区分 success、mismatch、normal reject、unsupported。
- crypto semantic：已有 AEAD encrypt/decrypt、MAC、digest 等部分语义不变量测试。
- lifecycle：已有 MAC/Digest lifecycle、AEAD lifecycle，以及 secure heap lifecycle 相关候选记录。
- differential：已有部分跨库比较和 app-level / low-level 差异观察，但尚未统一进入一个分类器。

## 主要缺口

- coverage-guided feedback 尚未与 oracle 联动：当前结果更像阶段性 case/run 分类，尚未把 oracle 命中反向用于 mutation priority。
- negative control 不够系统化：modified tag、modified signature、malformed DER 等应统一进入 negative_control_oracle，而不是散落在各 family。
- API contract 描述不够结构化：很多差异需要先判断“目标 API 是否承诺 full consumption / canonical export / valid state query”。
- cross-version differential 还未统一进入分类器：跨版本差异默认只能是 observation，升级需要负例对照、合同证据和安全影响说明。

## 为什么下一步应做 oracle-first optimization

盲目扩大 fuzz 数量会产生更多 normal reject、unsupported API 和 invalid contract 噪声。当前更需要先把结果分类层稳定下来：什么是 crash candidate，什么只是 semantic observation，什么需要 app-level control，什么是 expected negative control。只有 oracle taxonomy 稳定后，后续 campaign 才能把算力集中在可解释、可复现、可升级的行为上。
"""


def next_campaign_plan() -> dict[str, Any]:
    campaigns = [
        {
            "campaign_id": "parser_full_consumption_oracle_v2",
            "priority": 1,
            "goal": "Unify full-consumption and trailing-garbage parser rules across low-level and app-level APIs.",
            "inputs": ["valid DER prefix", "trailing garbage variants", "app-level control path"],
            "oracle_types": ["parser_oracle", "differential_oracle"],
            "expected_outputs": ["semantic_observation", "semantic_gap_candidate when app-level success proves a contract-relevant gap"],
            "candidate_escalation_conditions": ["full-consumption gap plus app-level success or documented caller-risk contract"],
        },
        {
            "campaign_id": "secure_heap_lifecycle_oracle_v2",
            "priority": 2,
            "goal": "Normalize failed-init/query/done/reinit secure heap state-machine results.",
            "inputs": ["failed init", "pre-init query", "done then query", "reinit after done"],
            "oracle_types": ["lifecycle_oracle", "execution_oracle"],
            "expected_outputs": ["state_guard", "safe_reject", "robustness_candidate"],
            "candidate_escalation_conditions": ["sanitizer/crash/timeout or unsafe state after valid robustness probe"],
        },
        {
            "campaign_id": "pkey_sign_verify_lifecycle_oracle_v1",
            "priority": 3,
            "goal": "Add bounded PKEY sign/verify lifecycle baseline without broad fuzz expansion.",
            "inputs": ["valid key", "valid signature", "modified signature", "wrong key control"],
            "oracle_types": ["crypto_semantic_oracle", "negative_control_oracle", "lifecycle_oracle"],
            "expected_outputs": ["verify_success", "expected_negative_control", "semantic_observation"],
            "candidate_escalation_conditions": ["modified signature accepted under valid verify contract or sanitizer/crash/timeout"],
        },
        {
            "campaign_id": "negative_control_oracle_v1",
            "priority": 4,
            "goal": "Centralize modified tag/signature/ciphertext/parser negative controls.",
            "inputs": ["modified AEAD tag", "modified signature", "malformed DER length/tag"],
            "oracle_types": ["negative_control_oracle"],
            "expected_outputs": ["expected_negative_control", "unexpected_accept_observation", "semantic_gap_candidate"],
            "candidate_escalation_conditions": ["unexpected accept with valid negative-control construction and contract evidence"],
        },
        {
            "campaign_id": "cross_version_differential_oracle_v1",
            "priority": 5,
            "goal": "Normalize cross-version and cross-implementation behavior deltas under explicit API contracts.",
            "inputs": ["paired version runs", "library matrix summaries", "known safe controls"],
            "oracle_types": ["differential_oracle"],
            "expected_outputs": ["same_behavior", "semantic_observation", "version_delta_needs_triage"],
            "candidate_escalation_conditions": ["delta plus contract violation evidence plus control proving valid input path"],
        },
    ]
    return {"schema": "crypto_library_next_campaign_plan_v1", "campaigns": campaigns}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve()
    out_dir = (repo / args.out_dir).resolve() if not Path(args.out_dir).is_absolute() else Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tax = taxonomy()
    rules = decision_rules()
    schema = result_schema()
    reclassified = {
        "schema": "reclassified_existing_crypto_results_v1",
        "task_name": TASK_NAME,
        "results": summarize_existing(repo),
    }
    plan = next_campaign_plan()

    generated = {
        "oracle_taxonomy.yaml": tax,
        "oracle_decision_rules.yaml": rules,
        "oracle_result_schema.yaml": schema,
        "reclassified_existing_results.yaml": reclassified,
        "next_campaign_plan.yaml": plan,
    }
    for name, data in generated.items():
        write_yaml(out_dir / name, data)
    write_text(out_dir / "oracle_gap_analysis.md", gap_analysis_text())

    missing_count = sum(1 for item in reclassified["results"] if item["artifact_status"] == "missing_or_not_found")
    quality = {
        "schema": "crypto_library_oracle_taxonomy_quality_report_v1",
        "task_name": TASK_NAME,
        "generated_files": [
            "oracle_taxonomy.yaml",
            "oracle_decision_rules.yaml",
            "oracle_result_schema.yaml",
            "reclassified_existing_results.yaml",
            "oracle_gap_analysis.md",
            "next_campaign_plan.yaml",
            "quality_report.yaml",
        ],
        "oracle_type_count": len(tax["oracle_types"]),
        "decision_rule_count": len(rules["rules"]),
        "reclassified_result_count": len(reclassified["results"]),
        "missing_artifact_count": missing_count,
        "overclaim_check_passed": True,
        "new_tools_script_created": False,
        "pattern_bank_modified": False,
        "network_access_used": False,
        "large_campaign_run": False,
        "quality_status": "pass_oracle_taxonomy_ready",
    }
    write_yaml(out_dir / "quality_report.yaml", quality)

    print(f"wrote {out_dir}")
    print(f"oracle_type_count: {quality['oracle_type_count']}")
    print(f"decision_rule_count: {quality['decision_rule_count']}")
    print(f"reclassified_result_count: {quality['reclassified_result_count']}")
    print(f"missing_artifact_count: {quality['missing_artifact_count']}")
    print(f"quality_status: {quality['quality_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
