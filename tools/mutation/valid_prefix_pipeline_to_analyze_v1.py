#!/usr/bin/env python3
"""Run the valid-prefix supplemental pipeline through oracle-aware analysis.

Stages:
1. render_plan_valid_prefix
2. render_cases_valid_prefix
3. compile_run_valid_prefix_oracle_instrumented
4. analyze_results_valid_prefix_oracle_aware

The pipeline is scoped to render_allowed ASN.1 OpenSSL supplemental cases only.
It does not process PKCS pending-seed cases, mbedTLS cases, feedback, GLM, or
validated issue claims.
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from tools.compile_run_oracle_instrumented_v1 import execute_case
from tools.compile_run_v1 import dump_yaml, lib_dir_for_install, load_yaml, now_iso, rel, write_text


def md_dump(title: str, data: dict[str, Any]) -> str:
    return f"# {title}\n\n```yaml\n{yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)}```\n"


def write_md(path: Path, title: str, data: dict[str, Any]) -> None:
    write_text(path, md_dump(title, data))


def parse_pem_or_der(path: Path) -> bytes:
    data = path.read_bytes()
    if b"-----BEGIN" not in data:
        return data
    text = data.decode("ascii", errors="ignore")
    lines = [
        line.strip()
        for line in text.splitlines()
        if line and not line.startswith("-----BEGIN") and not line.startswith("-----END")
    ]
    return base64.b64decode("".join(lines))


def find_asn1_seed() -> tuple[Path, bytes]:
    candidates = [
        Path("data/wolfssl_collect/WOLFSSL-POC-0002/inputs/reconstructed/cve-2017-2800-cert1.der"),
        Path("datasets/openssl/poc_artifacts/issue_13860/inputs/cert.crt"),
        Path("datasets/openssl/poc_artifacts/issue_6788/inputs/ca.crt"),
        Path("datasets/openssl/poc_artifacts/issue_15899/inputs/httpd.crt"),
    ]
    for path in candidates:
        if path.exists():
            data = parse_pem_or_der(path)
            if data:
                return path, data
    raise FileNotFoundError("no ASN.1/X509 seed candidate found")


def bytes_literal(data: bytes, width: int = 12) -> str:
    chunks = []
    for idx in range(0, len(data), width):
        row = ", ".join(f"0x{b:02x}" for b in data[idx : idx + width])
        chunks.append("    " + row)
    return ",\n".join(chunks)


def mutate_seed(strategy: str, seed: bytes) -> bytes:
    if strategy == "valid_object_plus_trailing_garbage":
        return seed + b"\x00"
    if strategy == "valid_prefix_trailing_only":
        return seed + b"\xff\x00"
    if strategy == "near_valid_small_length_delta":
        return seed[:-1] if len(seed) > 1 else seed
    if strategy == "preserve_outer_container_mutate_inner":
        return seed
    return seed


def render_harness(case_id: str, mutation_strategy: str, der_bytes: bytes) -> str:
    byte_rows = bytes_literal(der_bytes)
    return f"""/*
 * Rendered by valid_prefix_pipeline_to_analyze_v1 from supplemental mutation plan.
 * Candidate mapping only. This harness must not be interpreted as a confirmed
 * vulnerability, CVE, exploit, or confirmed API equivalence.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/err.h>

static const unsigned char der_bytes[] = {{
{byte_rows}
}};

int main(void)
{{
    const unsigned char *p = der_bytes;
    long der_len = (long)sizeof(der_bytes);
    long consumed_len = 0;
    int ret = 0;
    X509 *x509 = NULL;

    x509 = (X509 *)ASN1_item_d2i(NULL, &p, der_len, ASN1_ITEM_rptr(X509));
    consumed_len = (long)(p - der_bytes);

    unsigned long openssl_error = ERR_peek_last_error();
    char openssl_error_reason[256];
    ERR_error_string_n(openssl_error, openssl_error_reason, sizeof(openssl_error_reason));
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case_id} family=asn1_nested_boundary mutation_strategy={mutation_strategy} target_library=openssl phase=parse api=ASN1_item_d2i ret=%d accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d openssl_error_code=%lu openssl_error_reason=\\"%s\\"\\n",
           x509 != NULL ? 1 : 0, x509 != NULL ? 1 : 0, der_len, consumed_len,
           consumed_len == der_len ? 1 : 0, openssl_error, openssl_error_reason);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case_id} family=asn1_nested_boundary mutation_strategy={mutation_strategy} target_library=openssl phase=full_consumption_check api=ASN1_item_d2i input_len=%ld consumed_len=%ld full_consumption=%d notes=consumption_observed_from_ASN1_item_d2i\\n",
           der_len, consumed_len, consumed_len == der_len ? 1 : 0);

    if (x509 != NULL && consumed_len < der_len) {{
        ret = 10;
    }} else if (x509 != NULL) {{
        ret = 0;
    }} else {{
        ret = 0;
    }}

    if (x509 != NULL)
        X509_free(x509);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case_id} family=asn1_nested_boundary mutation_strategy={mutation_strategy} target_library=openssl phase=cleanup api=ASN1_item_d2i cleanup_executed=1\\n");

    return ret;
}}
"""


def as_bool_true(value: Any) -> bool:
    return value is True or value == 1 or str(value).lower() == "true"


def as_bool_false(value: Any) -> bool:
    return value is False or value == 0 or str(value).lower() == "false"


def count_event_values(events: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts = {"true": 0, "false": 0, "unknown": 0}
    for event in events:
        value = event.get(key, "unknown")
        if as_bool_true(value):
            counts["true"] += 1
        elif as_bool_false(value):
            counts["false"] += 1
        else:
            counts["unknown"] += 1
    return counts


def phase_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    c = Counter(str(event.get("phase") or "unknown") for event in events)
    return {
        "parse": c.get("parse", 0),
        "full_consumption_check": c.get("full_consumption_check", 0),
        "cleanup": c.get("cleanup", 0),
    }


def select_render_candidates(plan: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates = [
        item
        for item in plan.get("render_candidates", [])
        if item.get("render_allowed") is True
        and item.get("family") == "asn1_nested_boundary"
        and item.get("target_library") == "openssl"
    ]
    blocked = list(plan.get("blocked_cases", []))
    return candidates, blocked


def build_render_plan_stage(
    out_dir: Path,
    supplemental_matrix: dict[str, Any],
    candidate_plan: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    root = out_dir / "render_plan"
    candidates, blocked = select_render_candidates(candidate_plan)
    jobs = []
    matrix_by_id = {
        c.get("supplemental_case_id"): c for c in supplemental_matrix.get("cases", [])
    }
    for idx, item in enumerate(candidates, 1):
        case = matrix_by_id.get(item["supplemental_case_id"], {})
        jobs.append(
            {
                "render_job_id": f"render_valid_prefix__asn1_nested_boundary__openssl__{idx:03d}",
                "supplemental_case_id": item["supplemental_case_id"],
                "family": item["family"],
                "target_library": "openssl",
                "refinement_strategy": item["refinement_strategy"],
                "mutation_assignments": case.get("mutation_assignments", []),
                "render_allowed": True,
            }
        )
    render_plan = {
        "schema": "render_plan_valid_prefix_v1",
        "generated_at": now_iso(),
        "render_jobs": jobs,
        "summary": {
            "total_render_jobs": len(jobs),
            "family": "asn1_nested_boundary" if jobs else "",
            "target_library": "openssl" if jobs else "",
            "pkcs_jobs": 0,
            "mbedtls_jobs": 0,
            "harness_generated": False,
        },
    }
    case_manifest = {
        "schema": "valid_prefix_case_manifest_v1",
        "generated_at": now_iso(),
        "cases": jobs,
        "summary": {"total_cases": len(jobs)},
    }
    naming = {
        "schema": "valid_prefix_case_naming_plan_v1",
        "generated_at": now_iso(),
        "case_naming": [
            {
                "supplemental_case_id": job["supplemental_case_id"],
                "render_job_id": job["render_job_id"],
                "case_dir_name": job["render_job_id"],
            }
            for job in jobs
        ],
    }
    preflight = {
        "schema": "render_preflight_plan_v1",
        "generated_at": now_iso(),
        "checks": {
            "openssl_only": all(job["target_library"] == "openssl" for job in jobs),
            "asn1_only": all(job["family"] == "asn1_nested_boundary" for job in jobs),
            "pkcs_excluded": True,
            "mbedtls_excluded": True,
            "render_job_count": len(jobs),
        },
    }
    blocked_doc = {
        "schema": "valid_prefix_render_plan_blocked_cases_v1",
        "generated_at": now_iso(),
        "blocked_cases": blocked,
        "summary": {
            "pkcs_pending_seed_cases": len([b for b in blocked if b.get("family") == "pkcs_container_parsing"]),
            "mbedtls_cases": 0,
        },
    }
    quality = {
        "schema": "render_plan_valid_prefix_quality_checks_v1",
        "generated_at": now_iso(),
        "total_render_jobs": len(jobs),
        "family": "asn1_nested_boundary",
        "target_library": "openssl",
        "pkcs_jobs": 0,
        "mbedtls_jobs": 0,
        "harness_generated": False,
        "quality_status": "pass" if len(jobs) == 6 else "fail",
    }
    dump_yaml(root / "render_plan" / "render_plan.yaml", render_plan)
    dump_yaml(root / "case_manifest" / "case_manifest.yaml", case_manifest)
    dump_yaml(root / "case_naming" / "case_naming_plan.yaml", naming)
    dump_yaml(root / "preflight" / "render_preflight_plan.yaml", preflight)
    dump_yaml(root / "blocked_cases" / "blocked_cases.yaml", blocked_doc)
    dump_yaml(root / "validation" / "render_plan_valid_prefix_quality_checks.yaml", quality)
    write_md(root / "render_plan" / "render_plan.md", "Render Plan Valid Prefix", render_plan)
    return quality["quality_status"], jobs, blocked


def build_render_cases_stage(out_dir: Path, jobs: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    root = out_dir / "render_cases"
    seed_path, seed = find_asn1_seed()
    rendered: list[dict[str, Any]] = []
    for job in jobs:
        case_id = job["supplemental_case_id"]
        strategy = job["refinement_strategy"]
        mutation_strategy = "valid_prefix_" + strategy
        der = mutate_seed(strategy, seed)
        case_dir = root / "rendered_cases" / job["render_job_id"]
        input_dir = case_dir / "input_corpus"
        input_dir.mkdir(parents=True, exist_ok=True)
        harness = case_dir / "harness.c"
        der_path = input_dir / "input.der"
        der_path.write_bytes(der)
        write_text(harness, render_harness(case_id, mutation_strategy, der))
        common_meta = {
            "supplemental_case_id": case_id,
            "case_id": case_id,
            "render_job_id": job["render_job_id"],
            "family": "asn1_nested_boundary",
            "target_library": "openssl",
            "refinement_strategy": strategy,
            "mutation_strategy": mutation_strategy,
            "seed_source": rel(seed_path),
            "input_der": rel(der_path),
            "harness_c": rel(harness),
        }
        build_meta = {
            "schema": "valid_prefix_build_metadata_v1",
            **common_meta,
            "include_headers": ["openssl/asn1.h", "openssl/asn1t.h", "openssl/x509.h", "openssl/err.h"],
        }
        oracle_meta = {
            "schema": "valid_prefix_oracle_metadata_v1",
            **common_meta,
            "oracle_event_profile": "oracle_event_v1",
            "oracle_focus": ["accepted", "full_consumption", "consumed_len", "openssl_error"],
            "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitability_claimed": False},
        }
        case_meta = {"schema": "valid_prefix_case_metadata_v1", **common_meta}
        trace = {
            "schema": "valid_prefix_render_trace_v1",
            **common_meta,
            "rendered_by": "tools/mutation/valid_prefix_pipeline_to_analyze_v1.py",
            "render_stage": "render_cases_valid_prefix_v1",
        }
        dump_yaml(case_dir / "build_metadata.yaml", build_meta)
        dump_yaml(case_dir / "oracle_metadata.yaml", oracle_meta)
        dump_yaml(case_dir / "case_metadata.yaml", case_meta)
        dump_yaml(case_dir / "render_trace.yaml", trace)
        write_text(
            case_dir / "README.md",
            f"# {case_id}\n\nValid-prefix supplemental ASN.1 OpenSSL harness with ORACLE_EVENT instrumentation.\n",
        )
        rendered.append(
            {
                **common_meta,
                "case_dir": rel(case_dir),
                "oracle_instrumentation": {
                    "enabled": True,
                    "profile": "oracle_event_v1",
                    "expected_event_prefix": "ORACLE_EVENT",
                },
                "render_status": "rendered",
            }
        )
    index = {
        "schema": "valid_prefix_rendered_case_index_v1",
        "generated_at": now_iso(),
        "cases": rendered,
        "summary": {
            "rendered_cases": len(rendered),
            "family": "asn1_nested_boundary",
            "target_library": "openssl",
            "pkcs_cases": 0,
            "mbedtls_cases": 0,
        },
    }
    dump_yaml(root / "case_index" / "rendered_case_index.yaml", index)
    write_md(root / "case_index" / "rendered_case_index.md", "Rendered Case Index", index)
    return ("pass" if len(rendered) == len(jobs) == 6 else "partial"), rendered


def build_compile_run_stage(
    out_dir: Path,
    rendered_cases: list[dict[str, Any]],
    openssl_install: Path,
    timeout_seconds: int,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = out_dir / "compile_run"
    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    compile_results = []
    run_results = []
    all_events = []
    sanitizer_observations = []
    for case in rendered_cases:
        compile_result, run_result, events, sanitizer_observation = execute_case(
            case=case,
            out_dir=root,
            include_dir=include_dir,
            lib_dir=lib_dir,
            openssl_install=openssl_install,
            timeout_seconds=timeout_seconds,
        )
        compile_results.append(compile_result)
        run_results.append(run_result)
        all_events.extend(events)
        sanitizer_observations.append(sanitizer_observation)
    compile_counts = Counter(c["compile_status"] for c in compile_results)
    raw_counts = Counter(r["raw_observation_label"] for r in run_results)
    phase = Counter(str(e.get("phase") or "") for e in all_events)
    accepted = Counter(e.get("accepted", "unknown") for e in all_events)
    full = Counter(e.get("full_consumption", "unknown") for e in all_events)
    compile_doc = {
        "schema": "compile_results_valid_prefix_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "compile_results": compile_results,
        "summary": {
            "total_jobs": len(compile_results),
            "compile_success": compile_counts.get("compile_success", 0),
            "compile_failed": compile_counts.get("compile_failed", 0),
            "compile_skipped": 0,
        },
    }
    run_doc = {
        "schema": "run_results_valid_prefix_oracle_instrumented_v1",
        "generated_at": now_iso(),
        "run_results": run_results,
        "summary": {
            "total_jobs": len(run_results),
            "run_attempted": len([r for r in run_results if r["run_status"] != "not_run_compile_failed"]),
            "normal_exit": raw_counts.get("normal_exit", 0),
            "nonzero_exit": raw_counts.get("nonzero_exit", 0),
            "signaled": len([r for r in run_results if r["run_status"] == "signaled"]),
            "timeout": raw_counts.get("timeout_observed", 0),
            "not_run_compile_failed": raw_counts.get("compile_failed_not_run", 0),
        },
    }
    oracle_doc = {
        "schema": "oracle_events_valid_prefix_results_v1",
        "generated_at": now_iso(),
        "events": all_events,
        "summary": {
            "total_events": len(all_events),
            "cases_with_events": len({e.get("case_id") for e in all_events}),
            "parse_events": phase.get("parse", 0),
            "full_consumption_events": phase.get("full_consumption_check", 0),
            "cleanup_events": phase.get("cleanup", 0),
            "accepted_true": accepted.get(1, 0),
            "accepted_false": accepted.get(0, 0),
            "full_consumption_true": full.get(1, 0),
            "full_consumption_false": full.get(0, 0),
            "full_consumption_unknown": full.get("unknown", 0),
        },
    }
    sanitizer_doc = {
        "schema": "sanitizer_observations_valid_prefix_v1",
        "generated_at": now_iso(),
        "observations": sanitizer_observations,
        "summary": {
            "total_observations": len(sanitizer_observations),
            "sanitizer_observed_count": len([o for o in sanitizer_observations if o["sanitizer_observed"]]),
            "asan_observed": len([o for o in sanitizer_observations if "ASAN" in o.get("sanitizer_kinds", [])]),
            "ubsan_observed": len([o for o in sanitizer_observations if "UBSAN" in o.get("sanitizer_kinds", [])]),
            "crash_signal_count": len([r for r in run_results if r["run_status"] == "signaled"]),
            "timeout_count": len([r for r in run_results if r["timeout"]]),
        },
    }
    blocked_doc = {
        "schema": "compile_run_valid_prefix_blocked_cases_v1",
        "generated_at": now_iso(),
        "blocked_cases": [],
        "summary": {"pkcs_pending_seed_cases": 4, "mbedtls_cases": 0},
    }
    quality = {
        "schema": "compile_run_valid_prefix_quality_checks_v1",
        "generated_at": now_iso(),
        "compile_jobs_seen": len(compile_results),
        "compile_success": compile_doc["summary"]["compile_success"],
        "compile_failed": compile_doc["summary"]["compile_failed"],
        "run_attempted": run_doc["summary"]["run_attempted"],
        "oracle_events": oracle_doc["summary"]["total_events"],
        "openssl_only": all(c.get("target_library") == "openssl" for c in compile_results + run_results),
        "mbedtls_attempted": False,
        "analyze_performed": False,
        "feedback_written": False,
        "quality_status": "pass"
        if len(compile_results) == 6 and run_doc["summary"]["run_attempted"] == 6
        else "partial",
    }
    dump_yaml(root / "compile_results" / "compile_results.yaml", compile_doc)
    dump_yaml(root / "run_results" / "run_results.yaml", run_doc)
    dump_yaml(root / "oracle_events" / "oracle_events.yaml", oracle_doc)
    dump_yaml(root / "sanitizer_observations" / "sanitizer_observations.yaml", sanitizer_doc)
    dump_yaml(root / "blocked_cases" / "blocked_cases.yaml", blocked_doc)
    dump_yaml(root / "validation" / "compile_run_valid_prefix_quality_checks.yaml", quality)
    write_md(root / "validation" / "compile_run_valid_prefix_quality_checks.md", "Compile Run Quality", quality)
    return quality["quality_status"], compile_doc, run_doc, oracle_doc, sanitizer_doc, blocked_doc


def build_analyze_stage(
    out_dir: Path,
    rendered_cases: list[dict[str, Any]],
    run_doc: dict[str, Any],
    oracle_doc: dict[str, Any],
    sanitizer_doc: dict[str, Any],
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = out_dir / "analyze"
    events_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in oracle_doc.get("events", []):
        events_by_case[str(event.get("case_id"))].append(event)
    sanitizer_by_case = {o.get("case_id"): o for o in sanitizer_doc.get("observations", [])}
    rendered_by_case = {c.get("case_id"): c for c in rendered_cases}
    case_rows = []
    labels = []
    for run in run_doc.get("run_results", []):
        case_id = str(run.get("case_id"))
        events = events_by_case.get(case_id, [])
        accepted = count_event_values(events, "accepted")
        full = count_event_values(events, "full_consumption")
        sanitizer_seen = bool(run.get("sanitizer_observed") or sanitizer_by_case.get(case_id, {}).get("sanitizer_observed"))
        if sanitizer_seen:
            semantic = "sanitizer_crash_candidate"
            label = "needs_triage"
        elif run.get("timeout"):
            semantic = "timeout_candidate"
            label = "needs_triage"
        elif run.get("signal"):
            semantic = "crash_signal_candidate"
            label = "needs_triage"
        elif accepted["true"] > 0 and full["false"] > 0:
            semantic = "full_consumption_gap_candidate"
            label = "full_consumption_gap_candidate"
        elif accepted["true"] > 0 and full["true"] > 0:
            semantic = "successful_accept_path_observed"
            label = "normal_accept"
        elif accepted["false"] > 0:
            semantic = "normal_reject_observed"
            label = "normal_reject"
        else:
            semantic = "oracle_event_incomplete"
            label = "oracle_incomplete"
        phases = phase_counts(events)
        row = {
            "case_id": case_id,
            "family": run.get("family"),
            "mutation_strategy": run.get("mutation_strategy"),
            "target_library": "openssl",
            "run_status": run.get("run_status"),
            "exit_code": run.get("exit_code"),
            "signal": run.get("signal", ""),
            "timeout": run.get("timeout", False),
            "sanitizer_observed": sanitizer_seen,
            "oracle_events": {
                "total": len(events),
                "phases": phases,
                "accepted_values": accepted,
                "full_consumption_values": full,
            },
            "semantic_observation": semantic,
            "candidate_label": label,
            "source_render_case": rendered_by_case.get(case_id, {}).get("case_dir", ""),
            "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitability_claimed": False},
        }
        case_rows.append(row)
        labels.append(
            {
                "case_id": case_id,
                "family": row["family"],
                "mutation_strategy": row["mutation_strategy"],
                "oracle_semantic_label": semantic,
                "candidate_label": label,
                "confidence": "medium" if label == "full_consumption_gap_candidate" else "high",
                "reason": "accepted=true with full_consumption=false requires semantic triage"
                if label == "full_consumption_gap_candidate"
                else "oracle-aware valid-prefix execution result",
            }
        )
    semantic_counts = Counter(c["semantic_observation"] for c in case_rows)
    label_counts = Counter(l["candidate_label"] for l in labels)
    raw = oracle_doc["summary"]
    case_doc = {
        "schema": "valid_prefix_oracle_aware_case_analysis_v1",
        "generated_at": now_iso(),
        "cases": case_rows,
        "summary": {
            "total_cases": len(case_rows),
            "successful_accept_path_observed": semantic_counts.get("successful_accept_path_observed", 0),
            "normal_reject_observed": semantic_counts.get("normal_reject_observed", 0),
            "full_consumption_gap_candidate": semantic_counts.get("full_consumption_gap_candidate", 0),
            "oracle_event_incomplete": semantic_counts.get("oracle_event_incomplete", 0),
            "sanitizer_crash_candidate": semantic_counts.get("sanitizer_crash_candidate", 0),
            "valid_prefix_refinement_insufficient": raw.get("accepted_true", 0) == 0,
        },
    }
    family_doc = {
        "schema": "valid_prefix_oracle_aware_family_analysis_v1",
        "generated_at": now_iso(),
        "families": [
            {
                "family": "asn1_nested_boundary",
                "target_library": "openssl",
                "total_cases": len(case_rows),
                "accepted_true": raw.get("accepted_true", 0),
                "accepted_false": raw.get("accepted_false", 0),
                "full_consumption_true": raw.get("full_consumption_true", 0),
                "full_consumption_false": raw.get("full_consumption_false", 0),
                "full_consumption_unknown": raw.get("full_consumption_unknown", 0),
                "preliminary_interpretation": "accepted-path full-consumption candidates observed"
                if raw.get("accepted_true", 0) > 0
                else "valid-prefix refinement insufficient; still no accepted path",
            }
        ],
        "summary": {"families_seen": 1, "total_cases": len(case_rows)},
    }
    semantics_doc = {
        "schema": "valid_prefix_oracle_semantics_summary_v1",
        "generated_at": now_iso(),
        "raw_observations": raw,
        "semantic_outcome": {
            "any_success_accept": raw.get("accepted_true", 0) > 0,
            "full_consumption_gap_candidates": [
                c["case_id"] for c in case_rows if c["semantic_observation"] == "full_consumption_gap_candidate"
            ],
            "valid_prefix_refinement_insufficient": raw.get("accepted_true", 0) == 0,
        },
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitability_claimed": False},
    }
    mutation_doc = {
        "schema": "valid_prefix_mutation_effectiveness_v1",
        "generated_at": now_iso(),
        "summary": {
            "useful_accept_path": len([c for c in case_rows if c["oracle_events"]["accepted_values"]["true"] > 0]),
            "too_strong_all_reject": len([c for c in case_rows if c["oracle_events"]["accepted_values"]["true"] == 0]),
            "recommended_next_mutation_focus": "triage accepted-path consumption" if raw.get("accepted_true", 0) else "fix valid seed or mutation rendering",
        },
    }
    labels_doc = {
        "schema": "valid_prefix_oracle_aware_candidate_labels_v1",
        "generated_at": now_iso(),
        "labels": labels,
        "summary": {
            "normal_reject": label_counts.get("normal_reject", 0),
            "normal_accept": label_counts.get("normal_accept", 0),
            "full_consumption_gap_candidate": label_counts.get("full_consumption_gap_candidate", 0),
            "needs_triage": label_counts.get("needs_triage", 0),
            "oracle_incomplete": label_counts.get("oracle_incomplete", 0),
        },
    }
    limitations_doc = {
        "schema": "valid_prefix_oracle_aware_limitations_v1",
        "generated_at": now_iso(),
        "limitations": [
            "bounded supplemental matrix only",
            "accepted=true/full_consumption=false is a semantic candidate, not a validated issue",
            "no runtime feedback was written",
            "PKCS pending-seed cases were not processed",
            "mbedTLS was not processed",
        ],
    }
    quality = {
        "schema": "analyze_valid_prefix_quality_checks_v1",
        "generated_at": now_iso(),
        "cases_analyzed": len(case_rows),
        "cases_with_events": raw.get("cases_with_events", 0),
        "openssl_only": all(c["target_library"] == "openssl" for c in case_rows),
        "no_rerun": True,
        "no_compile": True,
        "no_feedback_written": True,
        "no_confirmed_vulnerability_claim": True,
        "quality_status": "pass" if len(case_rows) == 6 and raw.get("cases_with_events", 0) == 6 else "partial",
    }
    dump_yaml(root / "case_analysis" / "oracle_aware_case_analysis.yaml", case_doc)
    dump_yaml(root / "family_analysis" / "oracle_aware_family_analysis.yaml", family_doc)
    dump_yaml(root / "oracle_semantics" / "oracle_semantics_summary.yaml", semantics_doc)
    dump_yaml(root / "mutation_effectiveness" / "mutation_effectiveness.yaml", mutation_doc)
    dump_yaml(root / "candidate_labels" / "oracle_aware_candidate_labels.yaml", labels_doc)
    dump_yaml(root / "limitations" / "oracle_aware_limitations.yaml", limitations_doc)
    dump_yaml(root / "validation" / "analyze_valid_prefix_quality_checks.yaml", quality)
    for sub, title, doc in [
        ("case_analysis/oracle_aware_case_analysis.md", "Case Analysis", case_doc),
        ("family_analysis/oracle_aware_family_analysis.md", "Family Analysis", family_doc),
        ("oracle_semantics/oracle_semantics_summary.md", "Oracle Semantics", semantics_doc),
        ("candidate_labels/oracle_aware_candidate_labels.md", "Candidate Labels", labels_doc),
        ("validation/analyze_valid_prefix_quality_checks.md", "Analyze Quality", quality),
    ]:
        write_md(root / sub, title, doc)
    return quality["quality_status"], case_doc, semantics_doc, labels_doc, quality


def build_next_action(
    semantics_doc: dict[str, Any],
    sanitizer_doc: dict[str, Any],
    pkcs_pending: int,
) -> dict[str, Any]:
    raw = semantics_doc["raw_observations"]
    gap_count = len(semantics_doc["semantic_outcome"]["full_consumption_gap_candidates"])
    crashish = (
        sanitizer_doc["summary"]["sanitizer_observed_count"]
        + sanitizer_doc["summary"]["crash_signal_count"]
        + sanitizer_doc["summary"]["timeout_count"]
    )
    if gap_count:
        task = "oracle_semantic_triage_v1"
        reason = "accepted=true with full_consumption=false was observed in valid-prefix supplemental cases."
    elif crashish:
        task = "triage_crash_candidates_v1"
        reason = "sanitizer/crash/timeout evidence was observed."
    elif raw.get("accepted_true", 0) > 0:
        task = "runtime_feedback_integration_v1"
        reason = "accepted paths were observed with no suspicious full-consumption gap."
    else:
        task = "valid_seed_or_mutation_fixup_v1"
        reason = "accepted_true remained zero after valid-prefix supplemental rendering."
    return {
        "schema": "next_action_after_valid_prefix_pipeline_v1",
        "generated_at": now_iso(),
        "next_task_name": task,
        "secondary_next_task": "valid_seed_discovery_pkcs_v1" if pkcs_pending else "",
        "reason": reason,
    }


def build_reports(
    out_dir: Path,
    stage_status: dict[str, dict[str, Any]],
    blocked: dict[str, int],
    sanitizer_doc: dict[str, Any] | None,
    semantics_doc: dict[str, Any] | None,
    next_doc: dict[str, Any],
) -> None:
    compile_summary = stage_status.get("compile_run", {})
    analyze_summary = stage_status.get("analyze", {})
    pipeline = {
        "schema": "valid_prefix_pipeline_status_v1",
        "generated_at": now_iso(),
        "stages": stage_status,
        "blocked": blocked,
        "safety": {
            "no_glm_called": True,
            "no_feedback_written": True,
            "no_confirmed_vulnerability_claim": True,
        },
        "next_task": next_doc.get("next_task_name", ""),
    }
    report = {
        "schema": "valid_prefix_pipeline_to_analyze_v1_report",
        "task": "valid_prefix_pipeline_to_analyze_v1",
        "generated_at": now_iso(),
        "render_plan_completed": stage_status["render_plan"]["status"] in {"pass", "partial"},
        "render_cases_completed": stage_status["render_cases"]["status"] in {"pass", "partial"},
        "compile_run_completed": stage_status["compile_run"]["status"] in {"pass", "partial"},
        "analyze_completed": stage_status["analyze"]["status"] in {"pass", "partial"},
        "render_jobs": stage_status["render_plan"].get("render_jobs", 0),
        "rendered_cases": stage_status["render_cases"].get("rendered_cases", 0),
        "compile_success": stage_status["compile_run"].get("compile_success", 0),
        "run_attempted": stage_status["compile_run"].get("run_attempted", 0),
        "oracle_events": stage_status["compile_run"].get("oracle_events", 0),
        "accepted_true": stage_status["analyze"].get("accepted_true", 0),
        "accepted_false": stage_status["analyze"].get("accepted_false", 0),
        "full_consumption_gap_candidate": stage_status["analyze"].get("full_consumption_gap_candidates", 0),
        "sanitizer_crash_timeout_observed": 0 if sanitizer_doc is None else (
            sanitizer_doc["summary"]["sanitizer_observed_count"]
            + sanitizer_doc["summary"]["crash_signal_count"]
            + sanitizer_doc["summary"]["timeout_count"]
        ),
        "pkcs_pending_seed_processed": False,
        "mbedtls_processed": False,
        "feedback_written": False,
        "next_task_name": next_doc.get("next_task_name", ""),
        "secondary_next_task": next_doc.get("secondary_next_task", ""),
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitability_claimed": False},
    }
    dump_yaml(out_dir / "reports" / "pipeline_status.yaml", pipeline)
    write_md(out_dir / "reports" / "pipeline_status.md", "Pipeline Status", pipeline)
    dump_yaml(out_dir / "reports" / "next_action_after_valid_prefix_pipeline.yaml", next_doc)
    write_md(out_dir / "reports" / "next_action_after_valid_prefix_pipeline.md", "Next Action", next_doc)
    dump_yaml(out_dir / "reports" / "valid_prefix_pipeline_to_analyze_v1_report.yaml", report)
    write_md(out_dir / "reports" / "valid_prefix_pipeline_to_analyze_v1_report.md", "Valid Prefix Pipeline Report", report)
    write_text(
        out_dir / "README.md",
        "\n".join(
            [
                "# valid_prefix_pipeline_to_analyze_v1",
                "",
                f"- render_jobs: {report['render_jobs']}",
                f"- rendered_cases: {report['rendered_cases']}",
                f"- compile_success: {report['compile_success']}",
                f"- run_attempted: {report['run_attempted']}",
                f"- oracle_events: {report['oracle_events']}",
                f"- accepted_true: {report['accepted_true']}",
                f"- accepted_false: {report['accepted_false']}",
                f"- full_consumption_gap_candidate: {report['full_consumption_gap_candidate']}",
                f"- next_task_name: {report['next_task_name']}",
                "",
                "No PKCS pending seed cases, mbedTLS cases, GLM calls, feedback, or vulnerability claims were processed.",
                "",
            ]
        ),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--supplemental-mutation-case-matrix", required=True)
    parser.add_argument("--supplemental-render-candidate-plan", required=True)
    parser.add_argument("--family-template-root", required=True)
    parser.add_argument("--adapter-root", required=True)
    parser.add_argument("--openssl-install", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    input_summary = {
        "schema": "valid_prefix_pipeline_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": {
            "supplemental_mutation_case_matrix": args.supplemental_mutation_case_matrix,
            "supplemental_render_candidate_plan": args.supplemental_render_candidate_plan,
            "family_template_root": args.family_template_root,
            "adapter_root": args.adapter_root,
            "openssl_install": args.openssl_install,
        },
        "scope": {"openssl_only": True, "asn1_only": True, "pkcs_pending_seed_processed": False, "mbedtls_processed": False},
    }
    dump_yaml(out_dir / "input" / "input_summary.yaml", input_summary)

    stage_status: dict[str, dict[str, Any]] = {}
    supplemental_matrix = load_yaml(Path(args.supplemental_mutation_case_matrix))
    candidate_plan = load_yaml(Path(args.supplemental_render_candidate_plan))
    render_plan_status, jobs, blocked_cases = build_render_plan_stage(out_dir, supplemental_matrix, candidate_plan)
    stage_status["render_plan"] = {"executed": True, "status": render_plan_status, "render_jobs": len(jobs)}
    if render_plan_status not in {"pass", "partial"} or not jobs:
        next_doc = {"schema": "next_action_after_valid_prefix_pipeline_v1", "next_task_name": "render_plan_fixup_v1", "secondary_next_task": "valid_seed_discovery_pkcs_v1", "reason": "render_plan failed"}
        build_reports(out_dir, stage_status, {"pkcs_pending_seed_cases": len(blocked_cases), "mbedtls_cases": 0}, None, None, next_doc)
        return 1

    render_cases_status, rendered_cases = build_render_cases_stage(out_dir, jobs)
    stage_status["render_cases"] = {
        "executed": True,
        "status": render_cases_status,
        "rendered_cases": len(rendered_cases),
    }
    if render_cases_status not in {"pass", "partial"} or not rendered_cases:
        next_doc = {"schema": "next_action_after_valid_prefix_pipeline_v1", "next_task_name": "render_cases_fixup_v1", "secondary_next_task": "valid_seed_discovery_pkcs_v1", "reason": "render_cases failed"}
        build_reports(out_dir, stage_status, {"pkcs_pending_seed_cases": len(blocked_cases), "mbedtls_cases": 0}, None, None, next_doc)
        return 1

    compile_status, compile_doc, run_doc, oracle_doc, sanitizer_doc, blocked_doc = build_compile_run_stage(
        out_dir,
        rendered_cases,
        Path(args.openssl_install),
        args.timeout_seconds,
    )
    stage_status["compile_run"] = {
        "executed": True,
        "status": compile_status,
        "compile_success": compile_doc["summary"]["compile_success"],
        "compile_failed": compile_doc["summary"]["compile_failed"],
        "run_attempted": run_doc["summary"]["run_attempted"],
        "oracle_events": oracle_doc["summary"]["total_events"],
    }

    if not oracle_doc.get("events"):
        next_doc = {"schema": "next_action_after_valid_prefix_pipeline_v1", "next_task_name": "compile_run_oracle_output_fixup_v1", "secondary_next_task": "valid_seed_discovery_pkcs_v1", "reason": "compile_run produced no ORACLE_EVENT records"}
        stage_status["analyze"] = {"executed": False, "status": "blocked", "cases_analyzed": 0, "accepted_true": 0, "accepted_false": 0, "full_consumption_gap_candidates": 0}
        build_reports(out_dir, stage_status, {"pkcs_pending_seed_cases": len(blocked_cases), "mbedtls_cases": 0}, sanitizer_doc, None, next_doc)
        return 1

    analyze_status, case_doc, semantics_doc, labels_doc, analyze_quality = build_analyze_stage(
        out_dir, rendered_cases, run_doc, oracle_doc, sanitizer_doc
    )
    stage_status["analyze"] = {
        "executed": True,
        "status": analyze_status,
        "cases_analyzed": case_doc["summary"]["total_cases"],
        "accepted_true": semantics_doc["raw_observations"]["accepted_true"],
        "accepted_false": semantics_doc["raw_observations"]["accepted_false"],
        "full_consumption_gap_candidates": len(
            semantics_doc["semantic_outcome"]["full_consumption_gap_candidates"]
        ),
    }
    next_doc = build_next_action(semantics_doc, sanitizer_doc, len(blocked_cases))
    blocked = {"pkcs_pending_seed_cases": len(blocked_cases), "mbedtls_cases": 0}
    build_reports(out_dir, stage_status, blocked, sanitizer_doc, semantics_doc, next_doc)
    print(f"[OK] wrote valid-prefix pipeline artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"rendered={len(rendered_cases)} "
        f"compile_success={compile_doc['summary']['compile_success']} "
        f"run_attempted={run_doc['summary']['run_attempted']} "
        f"oracle_events={oracle_doc['summary']['total_events']} "
        f"accepted_true={semantics_doc['raw_observations']['accepted_true']} "
        f"gap_candidates={stage_status['analyze']['full_consumption_gap_candidates']}"
    )
    print(f"[NEXT] {next_doc['next_task_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
