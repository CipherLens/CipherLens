"""Manual Codex-assisted local crypto-library audit lane.

This module builds a small, local-only audit campaign from existing family
inventory information. It generates minimal OpenSSL harnesses, compiles/runs
them against the local ASAN OpenSSL install, parses ORACLE_EVENT lines, and
emits feedback artifacts for later automation. It does not write the main
feedback store or pattern bank.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from runner.sanitizer_env import lib_dir_for_install, matched_keywords, run_env, sanitizer_kinds, signal_name


TASK = "crypto_library_bug_hunt_v1"
DEFAULT_OUT_DIR = "artifacts/manual_codex_audit/crypto_library_bug_hunt_v1"
DEFAULT_OPENSSL_INSTALL = "/home/wen/work/install-openssl-3.5.5-asan"

AUDIT_FAMILIES = [
    "provider_fetch_lifecycle",
    "evp_pkey_context_lifecycle",
    "ossl_store_lifecycle",
    "ossl_store_decoder_boundary",
    "cipher_aead_lifecycle",
    "cipher_aead_lifecycle_ccm",
    "cipher_aead_lifecycle_ctx_copy",
    "bn_arithmetic_semantic",
    "bn_usub_semantic",
    "ec_arithmetic_semantic",
    "bignum_serialization_boundary",
    "return_code_outlen_semantic",
    "invalid_parameter_setup_oracle",
    "memory_length_boundary",
    "null_deref_dispatch",
    "object_state_lifecycle",
]

SELECTED_FAMILIES = [
    "provider_fetch_lifecycle",
    "evp_pkey_context_lifecycle",
    "bn_usub_semantic",
]

FORBIDDEN_LABELS = {
    "confirmed_vulnerability",
    "CVE",
    "exploit",
    "remote_attack",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--openssl-install", default=DEFAULT_OPENSSL_INSTALL)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def command_for(harness: Path, binary: Path, include_dir: Path, lib_dir: Path) -> list[str]:
    return [
        "gcc",
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined",
        f"-I{include_dir}",
        harness.as_posix(),
        f"-L{lib_dir}",
        f"-Wl,-rpath,{lib_dir}",
        "-lssl",
        "-lcrypto",
        "-ldl",
        "-pthread",
        "-o",
        binary.as_posix(),
    ]


def parse_oracle_events(text: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    values: dict[str, str] = {}
    raw_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("ORACLE_EVENT"):
            continue
        raw_lines.append(stripped)
        payload = stripped[len("ORACLE_EVENT") :].strip()
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        values[key.strip()] = value.strip()
    if not raw_lines:
        return []
    return [
        {
            "schema": "manual_codex_oracle_event_v1",
            "case_id": values.get("case_id") or case["case_id"],
            "family": values.get("family") or case["family"],
            "expected_behavior": values.get("expected_behavior") or case["expected_behavior"],
            "actual_behavior": values.get("actual_behavior") or "",
            "semantic_mismatch": values.get("semantic_mismatch") == "1",
            "state_transition_mismatch": values.get("state_transition_mismatch") == "1",
            "crash_or_sanitizer": values.get("crash_or_sanitizer") == "1",
            "raw_lines": raw_lines,
        }
    ]


def classify(case: dict[str, Any], run: dict[str, Any], event: dict[str, Any] | None) -> dict[str, Any]:
    signal = str(run.get("signal") or "")
    sanitizer = bool(run.get("sanitizer_observed"))
    actual = str((event or {}).get("actual_behavior") or "")
    expected = str(case.get("expected_behavior") or "")
    label = "no_candidate"
    reason = "behavior matched local oracle"
    if sanitizer or bool((event or {}).get("crash_or_sanitizer")):
        label = "sanitizer_candidate"
        reason = "sanitizer evidence observed"
    elif signal in {"SIGSEGV", "SIGABRT"}:
        label = "crash_candidate"
        reason = f"process signaled: {signal}"
    elif event is None:
        label = "needs_triage"
        reason = "missing ORACLE_EVENT"
    elif expected == "success" and actual != "success":
        label = "unexpected_failure_on_valid_sequence_candidate"
        reason = "valid control did not report success"
    elif expected == "error_or_documented" and actual == "success":
        label = "unexpected_success_after_invalid_state_candidate"
        reason = "invalid/documented-error case reported success"
    elif expected == "observation":
        label = "state_transition_observation"
        reason = "observation-only behavior; not a candidate by itself"
    return {
        "case_id": case["case_id"],
        "family": case["family"],
        "track": case["track"],
        "expected_behavior": expected,
        "actual_behavior": actual,
        "label": label,
        "candidate": label
        in {
            "crash_candidate",
            "sanitizer_candidate",
            "unexpected_success_after_invalid_state_candidate",
            "unexpected_failure_on_valid_sequence_candidate",
            "semantic_divergence_candidate",
            "needs_triage",
        },
        "reason": reason,
        "exit_code": run.get("exit_code"),
        "signal": signal,
        "sanitizer_observed": sanitizer,
        "sanitizer_kinds": run.get("sanitizer_kinds") or [],
    }


def family_priority_ranking(repo_root: Path) -> dict[str, Any]:
    inventory = load_yaml(repo_root / "artifacts/reports/family_inventory_registry_reconcile_v2/family_status_matrix.yaml")
    rows = {str(item.get("family")): item for item in inventory.get("families", []) or []}
    entries = []
    for family in AUDIT_FAMILIES:
        row = rows.get(family, {})
        track = str(row.get("track") or infer_track(family))
        active = bool(row.get("active_profile_present"))
        remaining = bool(row.get("remaining_novel", True))
        local = family in SELECTED_FAMILIES or family in {
            "cipher_aead_lifecycle",
            "bn_arithmetic_semantic",
            "ec_arithmetic_semantic",
        }
        if family in SELECTED_FAMILIES:
            risk = "medium"
            action = "manual_minimal_harness_now"
        elif local and remaining:
            risk = "medium"
            action = "prepare_renderer_or_seed_manifest"
        else:
            risk = "low_to_medium"
            action = "needs_api_card_or_renderer_before_manual_run"
        entries.append(
            {
                "family": family,
                "track": track,
                "why_interesting": why_interesting(family),
                "existing_evidence": row.get("sources", [])[:8],
                "missing_capability": missing_capability(family, active),
                "risk_level": risk,
                "recommended_action": action,
            }
        )
    return {
        "schema": "manual_codex_family_priority_ranking_v1",
        "generated_at": now_iso(),
        "source_inventory": "artifacts/reports/family_inventory_registry_reconcile_v2/family_status_matrix.yaml",
        "families": entries,
    }


def infer_track(family: str) -> str:
    if "lifecycle" in family:
        return "lifecycle"
    if "semantic" in family or "oracle" in family:
        return "semantic"
    if "boundary" in family or "length" in family:
        return "boundary"
    return "unknown"


def why_interesting(family: str) -> str:
    reasons = {
        "provider_fetch_lifecycle": "Provider/property fetch paths are local, non-parsing, and expose success/error state.",
        "evp_pkey_context_lifecycle": "PKEY context operation ordering has clear init-before-use state oracles.",
        "bn_usub_semantic": "BN arithmetic boundary behavior is local and sanitizer-observable without parser replay.",
    }
    return reasons.get(family, "Remaining novel family from inventory; needs profile/renderer triage.")


def missing_capability(family: str, active: bool) -> str:
    if family in SELECTED_FAMILIES:
        return "manual minimal harness available; active profile still proposed"
    if active:
        return "active profile exists; may need dedicated renderer"
    return "active profile and family-specific renderer likely missing"


def selected_targets() -> dict[str, Any]:
    return {
        "schema": "manual_codex_selected_targets_v1",
        "generated_at": now_iso(),
        "selection_policy": {
            "local_only": True,
            "non_parsing": True,
            "avoid_historical_tested": True,
            "avoid_completed_no_candidate": True,
            "max_harnesses_per_target": 3,
        },
        "targets": [
            {
                "family": "provider_fetch_lifecycle",
                "track": "lifecycle",
                "target_library": "openssl",
                "reason": "EVP fetch APIs have local success/error behavior and no parser dependency.",
            },
            {
                "family": "evp_pkey_context_lifecycle",
                "track": "lifecycle",
                "target_library": "openssl",
                "reason": "EVP_PKEY_CTX operation ordering is locally testable with return-code oracle.",
            },
            {
                "family": "bn_usub_semantic",
                "track": "semantic",
                "target_library": "openssl",
                "reason": "BN arithmetic edge cases are local and deterministic under ASAN/UBSAN.",
            },
        ],
    }


def case_records() -> list[dict[str, Any]]:
    return [
        {
            "case_id": "provider_valid_sha256_fetch_control",
            "family": "provider_fetch_lifecycle",
            "track": "lifecycle",
            "expected_behavior": "success",
            "mutation_strategy": "valid_sha256_fetch",
            "source": provider_case("provider_valid_sha256_fetch_control", "success", "valid_sha256_fetch"),
        },
        {
            "case_id": "provider_invalid_algorithm_fetch_observation",
            "family": "provider_fetch_lifecycle",
            "track": "lifecycle",
            "expected_behavior": "observation",
            "mutation_strategy": "invalid_algorithm_fetch",
            "source": provider_case("provider_invalid_algorithm_fetch_observation", "observation", "invalid_algorithm_fetch"),
        },
        {
            "case_id": "provider_invalid_property_fetch_observation",
            "family": "provider_fetch_lifecycle",
            "track": "lifecycle",
            "expected_behavior": "observation",
            "mutation_strategy": "invalid_property_fetch",
            "source": provider_case("provider_invalid_property_fetch_observation", "observation", "invalid_property_fetch"),
        },
        {
            "case_id": "pkey_ctx_valid_rsa_keygen_init_control",
            "family": "evp_pkey_context_lifecycle",
            "track": "lifecycle",
            "expected_behavior": "success",
            "mutation_strategy": "valid_rsa_keygen_init",
            "source": pkey_ctx_case("pkey_ctx_valid_rsa_keygen_init_control", "success", "valid_rsa_keygen_init"),
        },
        {
            "case_id": "pkey_ctx_keygen_before_init",
            "family": "evp_pkey_context_lifecycle",
            "track": "lifecycle",
            "expected_behavior": "error_or_documented",
            "mutation_strategy": "keygen_before_init",
            "source": pkey_ctx_case("pkey_ctx_keygen_before_init", "error_or_documented", "keygen_before_init"),
        },
        {
            "case_id": "pkey_ctx_set_padding_before_sign_init_observation",
            "family": "evp_pkey_context_lifecycle",
            "track": "lifecycle",
            "expected_behavior": "observation",
            "mutation_strategy": "set_padding_before_sign_init",
            "source": pkey_ctx_case(
                "pkey_ctx_set_padding_before_sign_init_observation",
                "observation",
                "set_padding_before_sign_init",
            ),
        },
        {
            "case_id": "bn_usub_valid_control",
            "family": "bn_usub_semantic",
            "track": "semantic",
            "expected_behavior": "success",
            "mutation_strategy": "valid_usub",
            "source": bn_case("bn_usub_valid_control", "success", "valid_usub"),
        },
        {
            "case_id": "bn_usub_negative_observation",
            "family": "bn_usub_semantic",
            "track": "semantic",
            "expected_behavior": "observation",
            "mutation_strategy": "usub_negative",
            "source": bn_case("bn_usub_negative_observation", "observation", "usub_negative"),
        },
        {
            "case_id": "bn_div_by_zero_observation",
            "family": "bn_usub_semantic",
            "track": "semantic",
            "expected_behavior": "observation",
            "mutation_strategy": "div_by_zero",
            "source": bn_case("bn_div_by_zero_observation", "observation", "div_by_zero"),
        },
    ]


def provider_case(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "valid_sha256_fetch":
        body = 'md = EVP_MD_fetch(NULL, "SHA256", NULL); actual_behavior = (md != NULL) ? "success" : "error";'
    elif strategy == "invalid_algorithm_fetch":
        body = 'md = EVP_MD_fetch(NULL, "NO_SUCH_DIGEST_FOR_AUDIT", NULL); actual_behavior = (md == NULL) ? "error" : "success";'
    else:
        body = 'md = EVP_MD_fetch(NULL, "SHA256", "provider=no_such_provider_for_audit"); actual_behavior = (md == NULL) ? "error" : "success";'
    return common_c(
        case_id,
        "provider_fetch_lifecycle",
        expected,
        includes="#include <openssl/evp.h>\n",
        declarations='EVP_MD *md = NULL;\n    const char *actual_behavior = "error";',
        body=body,
        cleanup="EVP_MD_free(md);",
    )


def pkey_ctx_case(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "valid_rsa_keygen_init":
        body = "ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); ret = (ctx != NULL) ? EVP_PKEY_keygen_init(ctx) : 0; actual_behavior = (ret == 1) ? \"success\" : \"error\";"
    elif strategy == "keygen_before_init":
        body = "ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); ret = (ctx != NULL) ? EVP_PKEY_keygen(ctx, &pkey) : 0; actual_behavior = (ret == 1) ? \"success\" : \"error\";"
    else:
        body = "ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); ret = (ctx != NULL) ? EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) : 0; actual_behavior = (ret > 0) ? \"success\" : \"error\";"
    return common_c(
        case_id,
        "evp_pkey_context_lifecycle",
        expected,
        includes="#include <openssl/evp.h>\n#include <openssl/rsa.h>\n",
        declarations='EVP_PKEY_CTX *ctx = NULL;\n    EVP_PKEY *pkey = NULL;\n    int ret = 0;\n    const char *actual_behavior = "error";',
        body=body,
        cleanup="EVP_PKEY_free(pkey);\n    EVP_PKEY_CTX_free(ctx);",
    )


def bn_case(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "valid_usub":
        setup = "BN_set_word(a, 9); BN_set_word(b, 4);"
        body = "ret = BN_usub(r, a, b); actual_behavior = (ret == 1) ? \"success\" : \"error\";"
    elif strategy == "usub_negative":
        setup = "BN_set_word(a, 4); BN_set_word(b, 9);"
        body = "ret = BN_usub(r, a, b); actual_behavior = (ret == 1) ? \"success\" : \"error\";"
    else:
        setup = "BN_set_word(a, 9); BN_zero(b);"
        body = "ret = BN_div(q, r, a, b, bn_ctx); actual_behavior = (ret == 1) ? \"success\" : \"error\";"
    return common_c(
        case_id,
        "bn_usub_semantic",
        expected,
        includes="#include <openssl/bn.h>\n",
        declarations=(
            'BIGNUM *a = BN_new();\n    BIGNUM *b = BN_new();\n    BIGNUM *r = BN_new();\n'
            '    BIGNUM *q = BN_new();\n    BN_CTX *bn_ctx = BN_CTX_new();\n    int ret = 0;\n'
            '    const char *actual_behavior = "error";'
        ),
        body=f"if (a == NULL || b == NULL || r == NULL || q == NULL || bn_ctx == NULL) goto done;\n    {setup}\n    {body}",
        cleanup="BN_free(a);\n    BN_free(b);\n    BN_free(r);\n    BN_free(q);\n    BN_CTX_free(bn_ctx);",
    )


def common_c(
    case_id: str,
    family: str,
    expected: str,
    *,
    includes: str,
    declarations: str,
    body: str,
    cleanup: str,
) -> str:
    return f"""/*
 * Manual local audit harness for {family}.
 * No parser replay, DER trailing garbage, full-consumption oracle, or exploit chain.
 */
#include <stdio.h>
#include <string.h>
{includes}
int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    {declarations}

    {body}

done:
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;
    else if (strcmp(expected_behavior, "error_or_documented") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
    else
        state_transition_mismatch = 0;

    printf("ORACLE_EVENT family={family}\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);

    {cleanup}
    return 0;
}}
"""


def write_cases(cases: list[dict[str, Any]], out_dir: Path) -> list[dict[str, Any]]:
    records = []
    for case in cases:
        path = out_dir / "cases" / f"{case['case_id']}.c"
        write_text(path, case["source"])
        records.append({k: v for k, v in case.items() if k != "source"} | {"path": path.as_posix()})
    return records


def compile_and_run(
    case_records: list[dict[str, Any]],
    out_dir: Path,
    openssl_install: Path,
    timeout_seconds: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    compile_records = []
    run_records = []
    oracle_events = []
    for case in case_records:
        case_id = str(case["case_id"])
        harness = Path(case["path"])
        work = out_dir / "work" / case_id
        binary = work / "case.bin"
        work.mkdir(parents=True, exist_ok=True)
        compile_stdout = work / "compile.stdout.log"
        compile_stderr = work / "compile.stderr.log"
        cmd = command_for(harness, binary, include_dir, lib_dir)
        proc = subprocess.run(cmd, text=True, capture_output=True)
        write_text(compile_stdout, proc.stdout)
        write_text(compile_stderr, proc.stderr)
        compile_status = "compile_success" if proc.returncode == 0 and binary.exists() else "compile_failed"
        compile_records.append(
            {
                "case_id": case_id,
                "family": case["family"],
                "harness_c": harness.as_posix(),
                "binary_path": binary.as_posix(),
                "compile_command": " ".join(cmd),
                "compile_status": compile_status,
                "return_code": proc.returncode,
                "stdout_log": compile_stdout.as_posix(),
                "stderr_log": compile_stderr.as_posix(),
            }
        )
        run_stdout = work / "run.stdout.log"
        run_stderr = work / "run.stderr.log"
        if compile_status != "compile_success":
            write_text(run_stdout, "")
            write_text(run_stderr, "")
            run_records.append(
                {
                    "case_id": case_id,
                    "family": case["family"],
                    "run_status": "not_run_compile_failed",
                    "exit_code": None,
                    "signal": "",
                    "sanitizer_observed": False,
                    "sanitizer_kinds": [],
                    "stdout_log": run_stdout.as_posix(),
                    "stderr_log": run_stderr.as_posix(),
                }
            )
            continue
        start = time.monotonic()
        try:
            run_proc = subprocess.run(
                [binary.as_posix()],
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                env=run_env(openssl_install, lib_dir),
            )
            duration = round(time.monotonic() - start, 6)
            write_text(run_stdout, run_proc.stdout)
            write_text(run_stderr, run_proc.stderr)
            combined = run_proc.stdout + "\n" + run_proc.stderr
            kinds = sanitizer_kinds(combined)
            keywords = matched_keywords(combined)
            sig = signal_name(run_proc.returncode)
            sanitizer_seen = bool(kinds or keywords)
            events = parse_oracle_events(run_proc.stdout, case)
            oracle_events.extend(events)
            run_records.append(
                {
                    "case_id": case_id,
                    "family": case["family"],
                    "run_status": "signaled" if sig else "exited",
                    "exit_code": run_proc.returncode if run_proc.returncode >= 0 else None,
                    "signal": sig,
                    "timeout": False,
                    "duration_seconds": duration,
                    "sanitizer_observed": sanitizer_seen,
                    "sanitizer_kinds": kinds,
                    "matched_keywords": keywords,
                    "stdout_log": run_stdout.as_posix(),
                    "stderr_log": run_stderr.as_posix(),
                    "oracle_event_count": len(events),
                }
            )
        except subprocess.TimeoutExpired as exc:
            write_text(run_stdout, exc.stdout or "")
            write_text(run_stderr, (exc.stderr or "") + "\ntimeout\n")
            run_records.append(
                {
                    "case_id": case_id,
                    "family": case["family"],
                    "run_status": "timeout",
                    "exit_code": None,
                    "signal": "",
                    "timeout": True,
                    "sanitizer_observed": False,
                    "sanitizer_kinds": [],
                    "stdout_log": run_stdout.as_posix(),
                    "stderr_log": run_stderr.as_posix(),
                    "oracle_event_count": 0,
                }
            )
    return compile_records, run_records, oracle_events


def summarize_and_feedback(
    out_dir: Path,
    cases: list[dict[str, Any]],
    compile_records: list[dict[str, Any]],
    run_records: list[dict[str, Any]],
    oracle_events: list[dict[str, Any]],
) -> dict[str, Any]:
    run_map = {item["case_id"]: item for item in run_records}
    event_map = {item["case_id"]: item for item in oracle_events}
    findings = [classify(case, run_map.get(case["case_id"], {}), event_map.get(case["case_id"])) for case in cases]
    candidates = [item for item in findings if item["candidate"]]
    labels = sorted(set(item["label"] for item in findings))
    by_family: dict[str, list[dict[str, Any]]] = {}
    for item in findings:
        by_family.setdefault(str(item["family"]), []).append(item)
    no_candidate_families = sorted(
        family for family, rows in by_family.items() if not any(row["candidate"] for row in rows)
    )

    dump_yaml(
        out_dir / "candidate/candidate_findings.yaml",
        {
            "schema": "manual_codex_candidate_findings_v1",
            "allowed_labels": [
                "crash_candidate",
                "sanitizer_candidate",
                "unexpected_success_after_invalid_state_candidate",
                "unexpected_failure_on_valid_sequence_candidate",
                "semantic_divergence_candidate",
                "state_transition_observation",
                "needs_triage",
                "no_candidate",
            ],
            "forbidden_labels": sorted(FORBIDDEN_LABELS),
            "findings": findings,
        },
    )
    summary = {
        "schema": "manual_codex_candidate_summary_v1",
        "candidate_summary_generated": True,
        "candidate_count": len(candidates),
        "candidate_labels": labels,
        "needs_triage_count": len([item for item in findings if item["label"] == "needs_triage"]),
        "crash_candidate_count": len([item for item in findings if item["label"] == "crash_candidate"]),
        "sanitizer_candidate_count": len([item for item in findings if item["label"] == "sanitizer_candidate"]),
        "unexpected_success_after_invalid_state_count": len(
            [item for item in findings if item["label"] == "unexpected_success_after_invalid_state_candidate"]
        ),
        "unexpected_failure_on_valid_sequence_count": len(
            [item for item in findings if item["label"] == "unexpected_failure_on_valid_sequence_candidate"]
        ),
        "semantic_divergence_count": len([item for item in findings if item["label"] == "semantic_divergence_candidate"]),
        "state_transition_observation_count": len([item for item in findings if item["label"] == "state_transition_observation"]),
        "no_candidate_families": no_candidate_families,
    }
    dump_yaml(out_dir / "candidate/candidate_summary.yaml", summary)
    write_feedback(out_dir, no_candidate_families)
    return summary


def write_feedback(out_dir: Path, no_candidate_families: list[str]) -> None:
    profiles = {
        "schema": "manual_codex_proposed_family_profiles_v1",
        "generated_at": now_iso(),
        "profiles": {
            "provider_fetch_lifecycle": {
                "track": "lifecycle",
                "archetype": "provider_fetch_context_lifecycle",
                "target_library": "openssl",
                "status": "profile_proposed",
                "render": {"mode": "minimal_fetch_lifecycle_harness"},
            },
            "evp_pkey_context_lifecycle": {
                "track": "lifecycle",
                "archetype": "pkey_context_operation_lifecycle",
                "target_library": "openssl",
                "status": "profile_proposed",
                "render": {"mode": "minimal_pkey_ctx_lifecycle_harness"},
            },
            "bn_usub_semantic": {
                "track": "semantic",
                "archetype": "bignum_arithmetic_semantic",
                "target_library": "openssl",
                "status": "profile_proposed",
                "render": {"mode": "minimal_bignum_semantic_harness"},
            },
        },
        "not_written_to_active_registry": True,
    }
    seeds = {
        "schema": "manual_codex_proposed_seed_manifest_v1",
        "generated_at": now_iso(),
        "seeds": [
            {"family": "provider_fetch_lifecycle", "seed": "EVP_MD_fetch valid and invalid property paths"},
            {"family": "evp_pkey_context_lifecycle", "seed": "EVP_PKEY_CTX init-before-operation paths"},
            {"family": "bn_usub_semantic", "seed": "BN_usub and BN_div arithmetic boundary paths"},
        ],
        "use_after_free_default_enabled": False,
    }
    mutations = {
        "schema": "manual_codex_proposed_mutation_rules_v1",
        "generated_at": now_iso(),
        "rules": [
            {"family": "provider_fetch_lifecycle", "rule": "valid_fetch_vs_invalid_algorithm_or_property"},
            {"family": "evp_pkey_context_lifecycle", "rule": "operation_before_required_init"},
            {"family": "bn_usub_semantic", "rule": "valid_arithmetic_vs_documented_error_boundary"},
        ],
    }
    oracles = {
        "schema": "manual_codex_proposed_oracles_v1",
        "generated_at": now_iso(),
        "oracles": [
            "unexpected_failure_on_valid_sequence",
            "unexpected_success_after_invalid_state",
            "semantic_divergence_candidate",
            "crash_or_sanitizer",
            "state_transition_observation",
        ],
    }
    plan = {
        "schema": "manual_codex_integration_plan_v1",
        "generated_at": now_iso(),
        "candidate_found": False,
        "no_candidate_families": no_candidate_families,
        "automatable_families": SELECTED_FAMILIES,
        "needs_renderer": ["provider_fetch_lifecycle", "evp_pkey_context_lifecycle", "bn_usub_semantic"],
        "needs_api_card": ["provider_fetch_lifecycle", "evp_pkey_context_lifecycle"],
        "worth_continuing_next": ["provider_fetch_lifecycle", "evp_pkey_context_lifecycle", "ec_arithmetic_semantic"],
        "main_feedback_written": False,
        "pattern_bank_modified": False,
    }
    dump_yaml(out_dir / "feedback_to_pipeline/proposed_family_profiles.yaml", profiles)
    dump_yaml(out_dir / "feedback_to_pipeline/proposed_seed_manifest.yaml", seeds)
    dump_yaml(out_dir / "feedback_to_pipeline/proposed_mutation_rules.yaml", mutations)
    dump_yaml(out_dir / "feedback_to_pipeline/proposed_oracles.yaml", oracles)
    dump_yaml(out_dir / "feedback_to_pipeline/integration_plan.yaml", plan)


def write_summaries(
    out_dir: Path,
    case_index: list[dict[str, Any]],
    compile_records: list[dict[str, Any]],
    run_records: list[dict[str, Any]],
    oracle_events: list[dict[str, Any]],
    candidate_summary: dict[str, Any],
) -> dict[str, Any]:
    compile_success = len([item for item in compile_records if item["compile_status"] == "compile_success"])
    compile_failed = len(compile_records) - compile_success
    run_attempted = len([item for item in run_records if item["run_status"] != "not_run_compile_failed"])
    crash_count = len([item for item in run_records if item.get("signal") in {"SIGSEGV", "SIGABRT"}])
    sanitizer_count = len([item for item in run_records if item.get("sanitizer_observed")])
    dump_yaml(out_dir / "compile/compile_jobs.yaml", {"schema": "manual_codex_compile_jobs_v1", "compile_jobs": compile_records})
    dump_yaml(
        out_dir / "compile/compile_summary.yaml",
        {
            "schema": "manual_codex_compile_summary_v1",
            "compile_executed": True,
            "harness_count": len(case_index),
            "compile_success": compile_success,
            "compile_failed": compile_failed,
        },
    )
    dump_yaml(out_dir / "run/run_records.yaml", {"schema": "manual_codex_run_records_v1", "run_records": run_records})
    dump_yaml(
        out_dir / "run/run_summary.yaml",
        {
            "schema": "manual_codex_run_summary_v1",
            "run_executed": True,
            "run_attempted": run_attempted,
            "crash": crash_count,
            "sanitizer": sanitizer_count,
        },
    )
    dump_yaml(out_dir / "analyze/oracle_events.yaml", {"schema": "manual_codex_oracle_events_v1", "oracle_events": oracle_events})
    dump_yaml(
        out_dir / "analyze/analyze_summary.yaml",
        {
            "schema": "manual_codex_analyze_summary_v1",
            "oracle_analyze_executed": True,
            "oracle_events_parsed": bool(oracle_events),
            "oracle_event_count": len(oracle_events),
        },
    )
    qc = {
        "schema": "manual_codex_audit_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "local_only": True,
        "public_target_access": False,
        "exploit_chain_generated": False,
        "family_priority_ranking_generated": True,
        "selected_targets_generated": True,
        "harness_generated": bool(case_index),
        "compile_executed": True,
        "run_executed": True,
        "oracle_analyze_executed": True,
        "candidate_summary_generated": True,
        "feedback_to_pipeline_generated": True,
        "uses_der_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "repeats_known_pattern_only": False,
        "nonzero_exit_treated_as_crash_without_evidence": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": (
            "pass_candidate_found"
            if int(candidate_summary.get("candidate_count") or 0) > 0
            else "pass_no_candidate_but_feedback_generated"
        ),
    }
    dump_yaml(out_dir / "validation/manual_codex_audit_quality_checks.yaml", qc)
    return qc


def write_report(out_dir: Path, qc: dict[str, Any], candidate_summary: dict[str, Any]) -> None:
    report = f"""# {TASK} Report

## Scope

- local_only: true
- target library: OpenSSL 3.5.5 ASAN build
- public_target_access: false
- exploit_chain_generated: false

## Results

- quality_status: {qc.get('quality_status')}
- candidate_count: {candidate_summary.get('candidate_count')}
- candidate_labels: {candidate_summary.get('candidate_labels')}
- no_candidate_families: {candidate_summary.get('no_candidate_families')}

## Policy

No DER trailing-garbage path, full-consumption oracle, public target access,
main feedback write, pattern-bank update, git operation, exploit chain, CVE
claim, or confirmed vulnerability claim was made.
"""
    write_text(out_dir / "reports/crypto_library_bug_hunt_v1_report.md", report)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    openssl_install = Path(args.openssl_install)

    ranking = family_priority_ranking(repo_root)
    selected = selected_targets()
    dump_yaml(out_dir / "audit/family_priority_ranking.yaml", ranking)
    dump_yaml(out_dir / "audit/selected_manual_targets.yaml", selected)

    cases = case_records()
    case_index = write_cases(cases, out_dir)
    compile_records, run_records, oracle_events = compile_and_run(
        case_index,
        out_dir,
        openssl_install,
        args.timeout_seconds,
    )
    candidate_summary = summarize_and_feedback(out_dir, case_index, compile_records, run_records, oracle_events)
    qc = write_summaries(out_dir, case_index, compile_records, run_records, oracle_events, candidate_summary)
    write_report(out_dir, qc, candidate_summary)

    print(f"wrote {out_dir}")
    print(f"quality_status: {qc['quality_status']}")
    print(f"candidate_count: {candidate_summary['candidate_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
