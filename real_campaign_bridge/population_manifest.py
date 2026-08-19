"""The fixed 11-unit RQ4 pilot denominator for B0 preflight."""

from __future__ import annotations

from typing import Any, Mapping

from target_knowledge.canonical import identified
from target_knowledge.model import CAMPAIGN_POPULATION_MANIFEST_SCHEMA


def _edge(edge: Mapping[str, str], name: str) -> tuple[str, str]:
    ref, digest = edge.get("ref"), edge.get("digest")
    if not isinstance(ref, str) or not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{name} must be an existing ref plus lowercase SHA-256 digest")
    return ref, digest


def _missing(*types: str) -> list[dict[str, str]]:
    return [{"expected_future_artifact_type": item, "preparation_status": "MISSING_ARTIFACT"} for item in types]


def _unit(unit_id: str, track: str, source_case: str, target: str, expected_terminal_states: list[str], forbidden: list[str], contract: Mapping[str, str], pair: Mapping[str, str] | None = None, target_profile: Mapping[str, str] | None = None) -> dict[str, Any]:
    contract_ref, contract_digest = _edge(contract, "source contract")
    pair_ref, pair_digest = _edge(pair, "source pair") if pair is not None else (None, None)
    target_profile_ref, target_profile_digest = _edge(target_profile, "target profile") if target_profile is not None else (None, None)
    missing = _missing("candidate_binding", "template_binding_merge", "real_execution_trace", "claim_gate_decision")
    return {
        "unit_id": unit_id, "track": track, "family": source_case.rsplit(":", 1)[-1],
        "source_contract_ref": contract_ref, "source_contract_digest": contract_digest,
        "source_pair_ref": pair_ref, "source_pair_digest": pair_digest,
        "target_profile_ref": target_profile_ref, "target_profile_digest": target_profile_digest,
        "target_scope": target if track in {"B", "C"} else None, "target_surface_ref": target if track in {"B", "C"} else None,
        "expected_pipeline_entry": "contract_guided_matcher", "expected_non_result_state": expected_terminal_states if track == "C" else [],
        "inclusion_reason": "frozen RQ4 pilot denominator", "exclusion_constraints": forbidden,
        "automation_classification": "ASSISTED", "denominator_policy": "RETAIN_ALL_TERMINAL_STATES",
        "allowed_report_usage": ["population_accounting_after_claim_gate"], "forbidden_report_usage": ["CURRENT_V2_RESULT_WITHOUT_REAL_TRACE", *forbidden],
        "binding_mode": "CONTRACT_GUIDED", "expected_terminal_states": expected_terminal_states,
        "missing_artifacts": missing, "missing_requirements": ["verified target knowledge", "deterministic build and capture evidence"],
        "blocking_reasons": ["B0_PREPARATION_ONLY"], "execution_route": "REAL_TARGET_PREPARATION_ONLY",
    }


def make_population_manifest(case_evidence: Mapping[str, Mapping[str, Mapping[str, str]]]) -> dict[str, Any]:
    forbidden = ["synthetic_only_claim", "llm_security_verdict", "legacy_adapter_filler"]
    units = [
        _unit(f"unit:track-a:{case}:{side}", "A", f"case:mbedtls:{case}", f"Mbed TLS historical pair {case}", ["SATISFIED", "VIOLATED", "UNKNOWN", "BUILD_FAILED"], forbidden, case_evidence[case]["contract"], case_evidence[case]["pair"])
        for case in ("0020", "0004", "0005") for side in ("buggy", "fixed")
    ]
    units += [
        _unit("unit:track-b:0020:openssl-3.5.5:d2i-rsa-private-key", "B", "case:mbedtls:0020", "OpenSSL 3.5.5:d2i_RSAPrivateKey", ["SATISFIED", "VIOLATED", "UNKNOWN"], forbidden, case_evidence["0020"]["contract"], target_profile=case_evidence["0020"]["openssl_profile"]),
        _unit("unit:track-b:0004:openssl-3.5.5:evp-decrypt-final-ex", "B", "case:mbedtls:0004", "OpenSSL 3.5.5:EVP_DecryptFinal_ex", ["SATISFIED", "VIOLATED", "UNKNOWN"], forbidden, case_evidence["0004"]["contract"], target_profile=case_evidence["0004"]["openssl_profile"]),
        _unit("unit:track-c:0005:openssl-3.5.5:no-direct-equivalent", "C", "case:mbedtls:0005", "OpenSSL 3.5.5", ["TS_INDETERMINATE", "MATCHER_NO_MATCH", "UNKNOWN"], forbidden, case_evidence["0005"]["contract"], target_profile=case_evidence["0005"]["openssl_profile"]),
        _unit("unit:track-c:0020:wolfssl-5.9.1:blocked", "C", "case:mbedtls:0020", "wolfSSL 5.9.1", ["BLOCKED_TARGET_KNOWLEDGE", "UNKNOWN"], forbidden, case_evidence["0020"]["contract"], target_profile=case_evidence["0020"]["wolfssl_profile"]),
        _unit("unit:track-c:0004:wolfssl-5.9.1:blocked", "C", "case:mbedtls:0004", "wolfSSL 5.9.1", ["BLOCKED_TARGET_KNOWLEDGE", "UNKNOWN"], forbidden, case_evidence["0004"]["contract"], target_profile=case_evidence["0004"]["wolfssl_profile"]),
    ]
    if len(units) != 11 or len({item["unit_id"] for item in units}) != 11:
        raise AssertionError("B0 population must retain exactly eleven distinct units")
    return identified({"schema_version": CAMPAIGN_POPULATION_MANIFEST_SCHEMA, "campaign_id": "CLV2-RQ4-PILOT-001", "denominator_policy": "RETAIN_ALL_TERMINAL_STATES", "units": units}, "campaign-population", "manifest_id")
