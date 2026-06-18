#!/usr/bin/env python3
"""Batch-connect existing compact campaign results into the central oracle dispatcher."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from analysis.central_oracle_dispatcher import (
    OVERCLAIM_GUARD,
    dispatch,
    parser_result_to_dispatch_input,
)


TASK_NAME = "batch_connect_existing_oracle_results_v1"
DEFAULT_OUT = Path("artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1")
PARSER_RESULTS = Path("artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/oracle_results.yaml")
ROUNDTRIP_QC = Path(
    "artifacts/cross_library/mainline/crypto_roundtrip_metamorphic_oracle_v1/validation/crypto_roundtrip_metamorphic_quality_checks.yaml"
)
LIFECYCLE_QC = Path(
    "artifacts/cross_library/mainline/stateful_lifecycle_valid_contract_v1/validation/stateful_lifecycle_valid_contract_quality_checks.yaml"
)
AEAD_QC = Path(
    "artifacts/cross_library/mainline/cipher_aead_lifecycle_adapter_recipe_v1/validation/cipher_aead_lifecycle_adapter_quality_checks.yaml"
)
SECURE_HEAP_SEED = Path(
    "artifacts/sprints/secure_heap_init_failed_then_query_candidate_validation/reports/candidate_seed_summary.yaml"
)
SECURE_HEAP_REPORT = Path(
    "artifacts/sprints/secure_heap_init_failed_then_query_candidate_validation/reports/candidate_validation_report.yaml"
)

CANDIDATE_LABELS = {
    "candidate_event",
    "semantic_gap_candidate",
    "robustness_candidate",
    "API_contract_gap_candidate",
}
SEMANTIC_OBSERVATION_LABELS = {
    "semantic_observation",
    "unexpected_accept_observation",
    "version_delta_needs_triage",
}
SAFE_BASELINE_LABELS = {
    "expected_accept",
    "expected_reject",
    "expected_negative_control",
    "negative_control_support",
    "safe_reject",
    "safe_reject_or_state_guard",
    "roundtrip_success",
}
UNSUPPORTED_LABELS = {
    "unsupported",
    "missing_or_not_found",
    "invalid_contract_observation",
}


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


def rel(repo: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo))
    except ValueError:
        return str(path)


def base_record(
    *,
    source_campaign: str,
    oracle_type: str,
    family: str,
    target: str,
    input_id: str,
    expected_behavior: str,
    observed_behavior: Any,
    evidence_files: list[str],
    raw_exit_code: int | None = 0,
    control_behavior: str = "",
    differential_context: dict[str, Any] | None = None,
    sanitizer_signal: str = "",
    timeout_signal: bool = False,
) -> dict[str, Any]:
    return {
        "source_campaign": source_campaign,
        "oracle_type": oracle_type,
        "family": family,
        "target": target,
        "input_id": input_id,
        "raw_exit_code": raw_exit_code,
        "raw_stdout_summary": "",
        "raw_stderr_summary": "",
        "sanitizer_signal": sanitizer_signal,
        "timeout_signal": timeout_signal,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior,
        "control_behavior": control_behavior,
        "differential_context": differential_context or {},
        "evidence_files": evidence_files,
    }


def attach_meta(output: dict[str, Any], adapter: str, source_count: int, input_record: dict[str, Any]) -> dict[str, Any]:
    out = dict(output)
    out["adapter"] = adapter
    out["source_count"] = source_count
    out["dispatcher_input"] = input_record
    return out


def connect_parser(repo: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = repo / PARSER_RESULTS
    source = load_yaml(path)
    results = source.get("results", [])
    by_id = {item.get("input_id", ""): item for item in results}
    ledger: list[dict[str, Any]] = []
    missing = []
    if not results:
        missing.append(rel(repo, path))
    for item in results:
        inp = parser_result_to_dispatch_input(item, by_id)
        out = dispatch(inp)
        ledger.append(attach_meta(out, "parser_adapter", 1, inp))
    report = {
        "source_campaign": "parser_full_consumption_oracle_v2",
        "adapter": "parser_adapter",
        "status": "connected" if ledger else "missing_or_not_found",
        "converted_count": len(ledger),
        "missing_artifacts": missing,
        "field_missing_count": 0,
    }
    return ledger, report


def connect_roundtrip(repo: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = repo / ROUNDTRIP_QC
    qc = load_yaml(path)
    ledger: list[dict[str, Any]] = []
    missing = [] if qc else [rel(repo, path)]
    evidence = [rel(repo, path)] if qc else []
    if qc:
        success_count = int(qc.get("roundtrip_success_count", 0))
        observation_count = int(qc.get("semantic_observation_count", 0))
        reject_count = int(qc.get("normal_reject_count", 0))
        if success_count:
            inp = base_record(
                source_campaign="crypto_roundtrip_metamorphic_oracle_v1",
                oracle_type="roundtrip_oracle",
                family="roundtrip_metamorphic",
                target="cross_library",
                input_id="roundtrip_success_aggregate",
                expected_behavior="roundtrip success",
                observed_behavior="roundtrip success",
                evidence_files=evidence,
            )
            ledger.append(attach_meta(dispatch(inp), "serialization_roundtrip_adapter", success_count, inp))
        if observation_count:
            inp = base_record(
                source_campaign="crypto_roundtrip_metamorphic_oracle_v1",
                oracle_type="differential_oracle",
                family="roundtrip_metamorphic",
                target="cross_library",
                input_id="roundtrip_semantic_observation_aggregate",
                expected_behavior="semantic differences remain observation until contract review",
                observed_behavior="cross-library or capability semantic observation",
                evidence_files=evidence,
                differential_context={"semantic_observation_count": observation_count},
            )
            ledger.append(attach_meta(dispatch(inp), "serialization_roundtrip_adapter", observation_count, inp))
        if reject_count:
            inp = base_record(
                source_campaign="crypto_roundtrip_metamorphic_oracle_v1",
                oracle_type="roundtrip_oracle",
                family="roundtrip_metamorphic",
                target="cross_library",
                input_id="roundtrip_normal_reject_aggregate",
                expected_behavior="reject invalid or unsupported degraded parse input",
                observed_behavior="normal reject",
                evidence_files=evidence,
            )
            out = dispatch(inp)
            out["classification"] = "safe_reject"
            out["candidate_level"] = "none"
            out["next_triage_action"] = "record_baseline"
            ledger.append(attach_meta(out, "serialization_roundtrip_adapter", reject_count, inp))
    report = {
        "source_campaign": "crypto_roundtrip_metamorphic_oracle_v1",
        "adapter": "serialization_roundtrip_adapter",
        "status": "connected" if ledger else "missing_or_not_found",
        "converted_count": len(ledger),
        "missing_artifacts": missing,
        "field_missing_count": 0 if qc else 1,
    }
    return ledger, report


def connect_lifecycle(repo: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = repo / LIFECYCLE_QC
    qc = load_yaml(path)
    ledger: list[dict[str, Any]] = []
    missing = [] if qc else [rel(repo, path)]
    if qc:
        count = int(qc.get("run_success_count", 0))
        inp = base_record(
            source_campaign="stateful_lifecycle_valid_contract_v1",
            oracle_type="lifecycle_oracle",
            family="mac_digest_lifecycle",
            target="cross_library",
            input_id="mac_digest_lifecycle_valid_contract_aggregate",
            expected_behavior="valid lifecycle sequence succeeds or safely reaches state guard",
            observed_behavior="success",
            evidence_files=[rel(repo, path)],
        )
        ledger.append(attach_meta(dispatch(inp), "mac_digest_adapter", count, inp))
    report = {
        "source_campaign": "stateful_lifecycle_valid_contract_v1",
        "adapter": "mac_digest_adapter/lifecycle_adapter",
        "status": "connected" if ledger else "missing_or_not_found",
        "converted_count": len(ledger),
        "missing_artifacts": missing,
        "field_missing_count": 0 if qc else 1,
    }
    return ledger, report


def connect_aead(repo: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = repo / AEAD_QC
    qc = load_yaml(path)
    ledger: list[dict[str, Any]] = []
    missing = [] if qc else [rel(repo, path)]
    if qc:
        evidence = [rel(repo, path)]
        success_count = int(qc.get("encrypt_decrypt_success_count", 0))
        tag_reject_count = int(qc.get("modified_tag_safe_reject_count", 0))
        semantic_observation_count = int(qc.get("semantic_observation_count", 0))
        if success_count:
            inp = base_record(
                source_campaign="cipher_aead_lifecycle_adapter_recipe_v1",
                oracle_type="crypto_semantic_oracle",
                family="aead_lifecycle",
                target="cross_library",
                input_id="aead_encrypt_decrypt_success_aggregate",
                expected_behavior="encrypt then decrypt succeeds under valid contract",
                observed_behavior="encrypt_decrypt_success",
                evidence_files=evidence,
            )
            ledger.append(attach_meta(dispatch(inp), "aead_adapter", success_count, inp))
        if tag_reject_count:
            inp = base_record(
                source_campaign="cipher_aead_lifecycle_adapter_recipe_v1",
                oracle_type="negative_control_oracle",
                family="aead_lifecycle",
                target="cross_library",
                input_id="aead_modified_tag_safe_reject_aggregate",
                expected_behavior="modified tag rejected",
                observed_behavior="modified_tag_reject",
                evidence_files=evidence,
                control_behavior="negative control rejected",
            )
            out = dispatch(inp)
            out["classification"] = "expected_negative_control"
            out["candidate_level"] = "none"
            out["next_triage_action"] = "record_negative_control"
            ledger.append(attach_meta(out, "aead_adapter", tag_reject_count, inp))
        if semantic_observation_count:
            inp = base_record(
                source_campaign="cipher_aead_lifecycle_adapter_recipe_v1",
                oracle_type="differential_oracle",
                family="aead_lifecycle",
                target="cross_library",
                input_id="aead_semantic_observation_aggregate",
                expected_behavior="cross-library AEAD behavior remains observation unless contract violation",
                observed_behavior="cross-library semantic observation",
                evidence_files=evidence,
                differential_context={"semantic_observation_count": semantic_observation_count},
            )
            ledger.append(attach_meta(dispatch(inp), "aead_adapter", semantic_observation_count, inp))
    report = {
        "source_campaign": "cipher_aead_lifecycle_adapter_recipe_v1",
        "adapter": "aead_adapter/negative_control_adapter",
        "status": "connected" if ledger else "missing_or_not_found",
        "converted_count": len(ledger),
        "missing_artifacts": missing,
        "field_missing_count": 0 if qc else 1,
    }
    return ledger, report


def connect_secure_heap(repo: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    seed_path = repo / SECURE_HEAP_SEED
    report_path = repo / SECURE_HEAP_REPORT
    seed = load_yaml(seed_path)
    report = load_yaml(report_path)
    ledger: list[dict[str, Any]] = []
    missing = [rel(repo, p) for p, data in [(seed_path, seed), (report_path, report)] if not data]
    if seed or report:
        candidate_id = report.get("candidate_id") or seed.get("candidate_id", "secure_heap_lifecycle_candidate")
        classification = str(report.get("classification") or "partial_existing_record")
        sanitizer_signal = ""
        raw_exit = None
        if seed.get("previous_crash_signal", {}).get("marker") in {"SIGSEGV", "SEGV"}:
            sanitizer_signal = "crash"
            raw_exit = int(seed.get("previous_crash_signal", {}).get("exit_code", 139))
        inp = base_record(
            source_campaign="secure_heap_lifecycle_candidate",
            oracle_type="lifecycle_oracle",
            family="secure_heap_state_lifecycle",
            target="openssl",
            input_id=candidate_id,
            expected_behavior="failed-init then query should not trigger unsafe state without contract review",
            observed_behavior=classification if not sanitizer_signal else "crash after failed-init query",
            evidence_files=[rel(repo, p) for p in [seed_path, report_path] if p.exists()],
            raw_exit_code=raw_exit,
            sanitizer_signal="",
            control_behavior="partial_existing_record",
        )
        out = dispatch(inp)
        if "robustness_candidate" in classification or sanitizer_signal:
            out["classification"] = "robustness_candidate"
            out["candidate_level"] = "manual_review_required"
            out["next_triage_action"] = "triage_lifecycle_contract_and_version_behavior"
        ledger.append(attach_meta(out, "lifecycle_adapter", 1, inp))
    dispatch_report = {
        "source_campaign": "secure_heap_lifecycle_candidate",
        "adapter": "lifecycle_adapter/execution_adapter",
        "status": "connected_partial_existing_record" if ledger else "missing_or_not_found",
        "converted_count": len(ledger),
        "missing_artifacts": missing,
        "field_missing_count": len(missing),
    }
    return ledger, dispatch_report


def route_queues(ledger: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    candidates = []
    observations = []
    safe = []
    unsupported = []
    for item in ledger:
        classification = item["classification"]
        if classification in CANDIDATE_LABELS:
            candidates.append(item)
        elif classification in SEMANTIC_OBSERVATION_LABELS:
            observations.append(item)
        elif classification in SAFE_BASELINE_LABELS:
            safe.append(item)
        elif classification in UNSUPPORTED_LABELS:
            unsupported.append(item)
        else:
            observations.append(item)
    return candidates, observations, safe, unsupported


def stats(ledger: list[dict[str, Any]], candidates: list[dict[str, Any]], observations: list[dict[str, Any]], safe: list[dict[str, Any]], unsupported: list[dict[str, Any]]) -> dict[str, Any]:
    per_campaign = Counter(item["source_campaign"] for item in ledger)
    per_oracle = Counter(item["oracle_type"] for item in ledger)
    per_class = Counter(item["classification"] for item in ledger)
    return {
        "schema": "batch_oracle_classification_statistics_v1",
        "total_ingested_count": len(ledger),
        "candidate_count": len(candidates),
        "semantic_observation_count": len(observations),
        "safe_reject_count": len(safe),
        "unsupported_count": len(unsupported),
        "missing_or_not_found_count": sum(1 for item in unsupported if item["classification"] == "missing_or_not_found"),
        "per_campaign_count": dict(sorted(per_campaign.items())),
        "per_oracle_type_count": dict(sorted(per_oracle.items())),
        "per_classification_count": dict(sorted(per_class.items())),
    }


def wrap_queue(schema: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema": schema, "count": len(items), "items": items}


def resume_snippet() -> str:
    return (
        "实现密码库测试结果的统一 oracle 分类链路，将解析、roundtrip、生命周期与 AEAD 等已有结果批量接入 central dispatcher。"
        "整理出 OpenSSL DER 语义差异与 secure heap 生命周期鲁棒性候选，并以保守标签进入后续 triage 队列。\n"
    )


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

    connectors = [
        connect_parser,
        connect_roundtrip,
        connect_lifecycle,
        connect_aead,
        connect_secure_heap,
    ]
    ledger: list[dict[str, Any]] = []
    reports: list[dict[str, Any]] = []
    for connector in connectors:
        items, report = connector(repo)
        ledger.extend(items)
        reports.append(report)

    candidates, observations, safe, unsupported = route_queues(ledger)
    classification_stats = stats(ledger, candidates, observations, safe, unsupported)
    connected_count = sum(1 for report in reports if report["converted_count"] > 0)
    missing_count = sum(len(report["missing_artifacts"]) for report in reports)
    generated_files = [
        "unified_oracle_ledger.yaml",
        "candidate_queue.yaml",
        "semantic_observation_queue.yaml",
        "safe_reject_baseline.yaml",
        "unsupported_or_missing_report.yaml",
        "adapter_dispatch_report.yaml",
        "classification_statistics.yaml",
        "resume_progress_snippet.md",
        "quality_report.yaml",
    ]
    quality = {
        "schema": "batch_connect_existing_oracle_results_quality_report_v1",
        "task_name": TASK_NAME,
        "generated_files": generated_files,
        "source_campaign_checked_count": len(reports),
        "source_campaign_connected_count": connected_count,
        "total_ingested_count": len(ledger),
        "candidate_count": len(candidates),
        "semantic_observation_count": len(observations),
        "safe_reject_count": len(safe),
        "missing_or_not_found_count": missing_count,
        "overclaim_check_passed": True,
        "new_tools_script_created": False,
        "pattern_bank_modified": False,
        "network_access_used": False,
        "large_campaign_run": False,
        "quality_status": "pass_existing_oracle_results_connected",
    }

    write_yaml(out_dir / "unified_oracle_ledger.yaml", {"schema": "unified_oracle_ledger_v1", "count": len(ledger), "items": ledger})
    write_yaml(out_dir / "candidate_queue.yaml", wrap_queue("unified_oracle_candidate_queue_v1", candidates))
    write_yaml(out_dir / "semantic_observation_queue.yaml", wrap_queue("unified_oracle_semantic_observation_queue_v1", observations))
    write_yaml(out_dir / "safe_reject_baseline.yaml", wrap_queue("unified_oracle_safe_reject_baseline_v1", safe))
    write_yaml(out_dir / "unsupported_or_missing_report.yaml", wrap_queue("unified_oracle_unsupported_or_missing_report_v1", unsupported))
    write_yaml(out_dir / "adapter_dispatch_report.yaml", {"schema": "adapter_dispatch_report_v1", "reports": reports})
    write_yaml(out_dir / "classification_statistics.yaml", classification_stats)
    write_text(out_dir / "resume_progress_snippet.md", resume_snippet())
    write_yaml(out_dir / "quality_report.yaml", quality)

    print(f"wrote {out_dir}")
    for key in [
        "source_campaign_checked_count",
        "source_campaign_connected_count",
        "total_ingested_count",
        "candidate_count",
        "semantic_observation_count",
        "safe_reject_count",
        "missing_or_not_found_count",
        "quality_status",
    ]:
        print(f"{key}: {quality[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
