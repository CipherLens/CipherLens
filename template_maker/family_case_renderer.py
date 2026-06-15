#!/usr/bin/env python3
"""Render OpenSSL family mutation cases from render_plan_v1.

This wrapper consumes the render-only plan and writes concrete C harnesses plus
metadata. It intentionally does not compile, run, analyze, rebuild RAG, or call
an LLM.
"""

from __future__ import annotations

import argparse
import datetime as _dt
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from template_maker.object_family_renderer import render_object_family
from template_maker.oracle_instrumentation import oracle_event_enabled, oracle_instrumentation_meta


SPRINT_NAME = "render_cases_v1"
ALLOWED_FAMILIES = {"pkcs_container_parsing", "asn1_nested_boundary"}
ALLOWED_TARGET_LIBRARY = "openssl"
BLOCKED_ADAPTERS = {"asn1_nested_boundary_mbedtls"}
FORBIDDEN_HARNESS_TERMS = ["d2i_PKCS7", "mbedtls_", "#include <mbedtls/", "wolfSSL_", "wc_"]


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=100)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rel(path: Path) -> str:
    return path.as_posix()


def c_bytes(values: list[int], width: int = 12) -> str:
    chunks: list[str] = []
    for i in range(0, len(values), width):
        part = ", ".join(f"0x{b:02x}" for b in values[i : i + width])
        chunks.append(f"    {part}")
    return ",\n".join(chunks)


def corpus_for_case(family: str, mutation_strategy: str) -> tuple[list[int], list[dict[str, Any]]]:
    if family == "pkcs_container_parsing":
        base = [0x30, 0x06, 0x06, 0x01, 0x2A, 0x04, 0x01, 0x00]
        variants = {
            "seed_preserving_baseline": base,
            "trailing_garbage": base + [0xFF, 0x00],
            "malformed_length": [0x30, 0x08, 0x06, 0x01, 0x2A, 0x04, 0x01, 0x00],
            "nested_length_mismatch": [0x30, 0x07, 0x06, 0x01, 0x2A, 0x04, 0x01, 0x00],
            "invalid_container_structure": [0x30, 0x03, 0x06, 0x01],
            "pem_der_format_toggle": list(b"-----BEGIN PKCS7-----\nAA==\n-----END PKCS7-----\n"),
            "expected_return_flip": base,
        }
        replacements = [
            {
                "slot_name": "CONTAINER_BYTES",
                "source": "mutation_case_matrix",
                "replacement_summary": f"{len(variants.get(mutation_strategy, base))} input bytes",
                "status": "applied",
            }
        ]
        if mutation_strategy == "trailing_garbage":
            replacements.append(
                {
                    "slot_name": "TRAILING_BYTES",
                    "source": "mutation_case_matrix",
                    "replacement_summary": "added ff00 tail",
                    "status": "applied",
                }
            )
        return variants.get(mutation_strategy, base), replacements

    base = [0x30, 0x03, 0x02, 0x01, 0x00]
    variants = {
        "seed_preserving_baseline": base,
        "trailing_garbage": base + [0xFF, 0x00],
        "short_length": [0x30, 0x02, 0x02, 0x01, 0x00],
        "long_length": [0x30, 0x08, 0x02, 0x01, 0x00],
        "nested_length_mismatch": [0x30, 0x04, 0x30, 0x03, 0x02, 0x01, 0x00],
        "nested_depth_variation": [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00],
        "expected_return_flip": base,
    }
    replacements = [
        {
            "slot_name": "DER_BYTES",
            "source": "mutation_case_matrix",
            "replacement_summary": f"{len(variants.get(mutation_strategy, base))} DER bytes",
            "status": "applied",
        }
    ]
    if mutation_strategy == "trailing_garbage":
        replacements.append(
            {
                "slot_name": "TRAILING_GARBAGE",
                "source": "mutation_case_matrix",
                "replacement_summary": "added ff00 tail",
                "status": "applied",
            }
        )
    return variants.get(mutation_strategy, base), replacements


def pkcs_harness(job: dict[str, Any], bytes_: list[int], instrumentation_profile: str = "") -> str:
    instrumentation = ""
    if oracle_event_enabled(instrumentation_profile):
        instrumentation = f"""
    unsigned long openssl_error = ERR_peek_last_error();
    char openssl_error_reason[256];
    ERR_error_string_n(openssl_error, openssl_error_reason, sizeof(openssl_error_reason));
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job['case_id']} family={job['family']} mutation_strategy={job['mutation_strategy']} target_library=openssl phase=parse api=d2i_PKCS12 ret=%d accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d openssl_error_code=%lu openssl_error_reason=\\\"%s\\\"\\n",
           p12 != NULL ? 1 : 0, p12 != NULL ? 1 : 0, input_len, consumed_len,
           consumed_len == input_len ? 1 : 0, openssl_error, openssl_error_reason);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job['case_id']} family={job['family']} mutation_strategy={job['mutation_strategy']} target_library=openssl phase=verify api=PKCS12_parse ret=%d accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d openssl_error_code=%lu openssl_error_reason=\\\"%s\\\"\\n",
           parse_ret, parse_ret == 1 ? 1 : 0, input_len, consumed_len,
           consumed_len == input_len ? 1 : 0, openssl_error, openssl_error_reason);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job['case_id']} family={job['family']} mutation_strategy={job['mutation_strategy']} target_library=openssl phase=full_consumption_check api=d2i_PKCS12 input_len=%ld consumed_len=%ld full_consumption=%d notes=consumption_observed_from_d2i_PKCS12\\n",
           input_len, consumed_len, consumed_len == input_len ? 1 : 0);
"""
    return f"""/*
 * Rendered by render_cases_v1 from family template:
 * {job['inputs']['canonical_template']}
 *
 * Candidate mapping only. This harness must not be interpreted as a confirmed
 * vulnerability, CVE, exploit, or confirmed API equivalence.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static const unsigned char input_bytes[] = {{
{c_bytes(bytes_)}
}};

int main(void)
{{
    const unsigned char *p = input_bytes;
    long input_len = (long)sizeof(input_bytes);
    long consumed_len = 0;
    int ret = 0;
    int parse_ret = 0;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    /* input loading: bytes are rendered from mutation_case_matrix. */
    p12 = d2i_PKCS12(NULL, &p, input_len);
    consumed_len = (long)(p - input_bytes);

    /* trigger_call: OpenSSL PKCS parser candidate selected by slot_bindings. */
    if (p12 != NULL) {{
        parse_ret = PKCS12_parse(p12, "", &pkey, &cert, &ca);
    }}
{instrumentation}

    /*
     * oracle / return check: parser accept/reject plus consumption signal.
     * A nonzero return here is an oracle classification signal only.
     */
    if (p12 != NULL && parse_ret == 1 && consumed_len < input_len) {{
        ret = 10;
    }} else if (p12 != NULL && parse_ret == 1) {{
        ret = 0;
    }} else {{
        ret = 0;
    }}

    /* cleanup_call: preserve target cleanup obligations. */
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (cert != NULL)
        X509_free(cert);
    if (ca != NULL)
        sk_X509_pop_free(ca, X509_free);
    if (p12 != NULL)
        PKCS12_free(p12);
{f'''    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job['case_id']} family={job['family']} mutation_strategy={job['mutation_strategy']} target_library=openssl phase=cleanup api=PKCS12_parse cleanup_executed=1\\n");
''' if oracle_event_enabled(instrumentation_profile) else ''}

    return ret;
}}
"""


def asn1_harness(job: dict[str, Any], bytes_: list[int], instrumentation_profile: str = "") -> str:
    instrumentation = ""
    if oracle_event_enabled(instrumentation_profile):
        instrumentation = f"""
    unsigned long openssl_error = ERR_peek_last_error();
    char openssl_error_reason[256];
    ERR_error_string_n(openssl_error, openssl_error_reason, sizeof(openssl_error_reason));
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job['case_id']} family={job['family']} mutation_strategy={job['mutation_strategy']} target_library=openssl phase=parse api=ASN1_item_d2i ret=%d accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d openssl_error_code=%lu openssl_error_reason=\\\"%s\\\"\\n",
           x509 != NULL ? 1 : 0, x509 != NULL ? 1 : 0, der_len, consumed_len,
           consumed_len == der_len ? 1 : 0, openssl_error, openssl_error_reason);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job['case_id']} family={job['family']} mutation_strategy={job['mutation_strategy']} target_library=openssl phase=full_consumption_check api=ASN1_item_d2i input_len=%ld consumed_len=%ld full_consumption=%d notes=consumption_observed_from_ASN1_item_d2i\\n",
           der_len, consumed_len, consumed_len == der_len ? 1 : 0);
"""
    return f"""/*
 * Rendered by render_cases_v1 from family template:
 * {job['inputs']['canonical_template']}
 *
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
{c_bytes(bytes_)}
}};

int main(void)
{{
    const unsigned char *p = der_bytes;
    long der_len = (long)sizeof(der_bytes);
    long consumed_len = 0;
    int ret = 0;
    X509 *x509 = NULL;

    /* trigger_call: OpenSSL ASN.1 parser candidate selected by slot_bindings. */
    x509 = (X509 *)ASN1_item_d2i(NULL, &p, der_len, ASN1_ITEM_rptr(X509));
    consumed_len = (long)(p - der_bytes);
{instrumentation}

    /*
     * oracle / return check: parser accept/reject plus consumption signal.
     * A nonzero return here is an oracle classification signal only.
     */
    if (x509 != NULL && consumed_len < der_len) {{
        ret = 10;
    }} else if (x509 != NULL) {{
        ret = 0;
    }} else {{
        ret = 0;
    }}

    /* cleanup_call: preserve target cleanup obligations. */
    if (x509 != NULL)
        X509_free(x509);
{f'''    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job['case_id']} family={job['family']} mutation_strategy={job['mutation_strategy']} target_library=openssl phase=cleanup api=ASN1_item_d2i cleanup_executed=1\\n");
''' if oracle_event_enabled(instrumentation_profile) else ''}

    return ret;
}}
"""


def render_harness(job: dict[str, Any], bytes_: list[int], instrumentation_profile: str = "") -> str:
    if job["family"] == "pkcs_container_parsing":
        return pkcs_harness(job, bytes_, instrumentation_profile)
    if job["family"] == "asn1_nested_boundary":
        return asn1_harness(job, bytes_, instrumentation_profile)
    raise ValueError(f"unsupported family {job['family']}")


def x509_harness(job: dict[str, Any], input_name: str, input_len: int) -> str:
    case_id = job.get("case_id", "")
    strategy = job.get("mutation_strategy", "")
    parser_accept = 1 if (job.get("expected_oracle") or {}).get("parser_accept_expected") else 0
    full_consumption_required = 1 if (job.get("expected_oracle") or {}).get("full_consumption_check_required") else 0
    if job.get("seed_format") == "pem":
        parse_block = f"""
    BIO *bio = BIO_new_mem_buf(input_bytes, (int)input_len);
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    consumed_len = input_len;
    if (bio != NULL)
        BIO_free(bio);
"""
        includes = "#include <openssl/bio.h>\n#include <openssl/pem.h>"
        api = "PEM_read_bio_X509"
    else:
        parse_block = """
    const unsigned char *p = input_bytes;
    X509 *x509 = d2i_X509(NULL, &p, input_len);
    consumed_len = (long)(p - input_bytes);
"""
        includes = ""
        api = "d2i_X509"
    return f"""/*
 * Rendered by orchestrator_execute_x509_render_cases_v1.
 *
 * This is a generated migration harness candidate. It is not a confirmed
 * vulnerability, CVE, exploit, or confirmed API equivalence.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/err.h>
{includes}

static const char *case_id = "{case_id}";
static const char *mutation_strategy = "{strategy}";
static const int parser_accept_expected = {parser_accept};
static const int full_consumption_check_required = {full_consumption_required};
static const unsigned char input_bytes[] = {{
#include "{input_name}.inc"
}};

int main(void)
{{
    long input_len = (long)sizeof(input_bytes);
    long consumed_len = 0;
    int accepted = 0;
    int full_consumption = 0;
    int ret = 0;
{parse_block}
    accepted = x509 != NULL ? 1 : 0;
    full_consumption = consumed_len == input_len ? 1 : 0;

    printf("ORACLE_EVENT schema=oracle_event_v1 case_id=%s family=x509_parsing mutation_strategy=%s target_library=openssl phase=parse api={api} accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d parser_accept_expected=%d full_consumption_check_required=%d\\n",
           case_id, mutation_strategy, accepted, input_len, consumed_len, full_consumption,
           parser_accept_expected, full_consumption_check_required);

    if (x509 != NULL)
        X509_free(x509);

    if (accepted && full_consumption_check_required && !full_consumption)
        ret = 10;
    else
        ret = 0;

    return ret;
}}
"""


def _byte_include(data: bytes, width: int = 12) -> str:
    values = list(data)
    chunks: list[str] = []
    for i in range(0, len(values), width):
        chunks.append(", ".join(f"0x{b:02x}" for b in values[i : i + width]))
    return ",\n".join(chunks) + ("\n" if chunks else "")


def render_x509_case_from_plan(job: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    case_id = str(job.get("case_id") or job.get("render_job_id"))
    render_job_id = str(job.get("render_job_id") or case_id)
    case_dir = out_dir / "rendered_cases" / render_job_id
    input_dir = case_dir / "input_corpus"
    input_path = Path(str(job.get("input_path") or ""))
    data = input_path.read_bytes() if input_path.exists() else b""
    input_name = "input.pem" if job.get("seed_format") == "pem" else "input.der"
    case_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)
    (input_dir / input_name).write_bytes(data)
    write_text(case_dir / f"{input_name}.inc", _byte_include(data))
    write_text(case_dir / "harness.c", x509_harness(job, input_name, len(data)))

    build_metadata = {
        "schema": "render_build_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": "x509_parsing",
        "target_library": "openssl",
        "harness_c": "harness.c",
        "compile_policy": {"compile_now": False, "compile_allowed_next_stage": True},
        "expected_includes": ["openssl/x509.h", "openssl/err.h"]
        + (["openssl/bio.h", "openssl/pem.h"] if job.get("seed_format") == "pem" else []),
        "expected_libraries": ["crypto", "ssl"],
        "notes": [
            "Metadata only; no compile was executed in orchestrator_execute_x509_render_cases_v1.",
            "Candidate mapping only; no confirmed vulnerability claim.",
        ],
    }
    oracle_metadata = {
        "schema": "render_oracle_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": "x509_parsing",
        "target_library": "openssl",
        "expected_oracle": job.get("expected_oracle", {}),
        "candidate_label_policy": {
            "do_not_claim_confirmed_vulnerability": True,
            "semantic_divergence_requires_triage": True,
            "crash_requires_reproduction": True,
        },
        "notes": ["No compile/run/analyze result exists yet."],
    }
    case_metadata = {
        "schema": "render_case_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": "x509_parsing",
        "target_library": "openssl",
        "mutation_strategy": job.get("mutation_strategy", ""),
        "source_trace": {
            "render_plan": "artifacts/sprints/orchestrator_execute_x509_render_plan_v1/render_plan/render_plan.yaml",
            "mutation_input": job.get("input_path", ""),
        },
        "render_status": "rendered",
    }
    render_trace = {
        "schema": "render_trace_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": "x509_parsing",
        "target_library": "openssl",
        "mutation_strategy": job.get("mutation_strategy", ""),
        "replacements": [
            {
                "slot_name": "x509_input_bytes",
                "source": "render_plan.input_path",
                "replacement_summary": f"{len(data)} bytes copied into input corpus and include file",
                "status": "applied",
            },
            {
                "slot_name": "oracle_check",
                "source": "render_plan.expected_oracle",
                "replacement_summary": "parser accept and pointer-consumption event emitted",
                "status": "applied",
            },
        ],
        "oracle_instrumentation": oracle_instrumentation_meta("oracle_event_v1", "x509_parsing"),
        "render_cases_executed": True,
        "compile_executed": False,
        "run_executed": False,
        "confirmed_vulnerability_claim": False,
    }
    dump_yaml(case_dir / "build_metadata.yaml", build_metadata)
    dump_yaml(case_dir / "oracle_metadata.yaml", oracle_metadata)
    dump_yaml(case_dir / "case_metadata.yaml", case_metadata)
    dump_yaml(case_dir / "render_trace.yaml", render_trace)
    write_text(
        case_dir / "README.md",
        f"# {render_job_id}\n\n"
        f"- case_id: `{case_id}`\n"
        "- family: `x509_parsing`\n"
        "- target_library: `openssl`\n"
        f"- mutation_strategy: `{job.get('mutation_strategy', '')}`\n"
        "- status: rendered\n\n"
        "This case was rendered only. It has not been compiled, run, or analyzed.\n",
    )
    return {
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": "x509_parsing",
        "target_library": "openssl",
        "mutation_strategy": job.get("mutation_strategy", ""),
        "case_dir": rel(case_dir),
        "harness_c": rel(case_dir / "harness.c"),
        "input_corpus_dir": rel(input_dir),
        "build_metadata": rel(case_dir / "build_metadata.yaml"),
        "oracle_metadata": rel(case_dir / "oracle_metadata.yaml"),
        "case_metadata": rel(case_dir / "case_metadata.yaml"),
        "render_trace": rel(case_dir / "render_trace.yaml"),
        "render_status": "rendered",
    }


def render_x509_cases_from_render_plan(render_plan: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    jobs = [job for job in render_plan.get("render_jobs", []) or [] if job.get("render_allowed")]
    cases = [render_x509_case_from_plan(job, out_dir) for job in jobs]
    index = {
        "schema": "rendered_case_index_v1",
        "generated_at": now_iso(),
        "cases": cases,
        "summary": {
            "total_planned": len(jobs),
            "rendered": len([case for case in cases if case.get("render_status") == "rendered"]),
            "render_failed": len([case for case in cases if case.get("render_status") == "render_failed"]),
            "skipped_blocked": len([case for case in cases if case.get("render_status") == "skipped_blocked"]),
            "x509_rendered": len([case for case in cases if case.get("family") == "x509_parsing"]),
        },
    }
    dump_yaml(out_dir / "case_index" / "rendered_case_index.yaml", index)
    return index


def find_oracle_entry(oracle_plan: dict[str, Any], family: str, target_library: str) -> dict[str, Any]:
    for item in oracle_plan.get("families", []):
        if item.get("family") == family and item.get("target_library") == target_library:
            return item
    return {}


def output_case_dir(out_dir: Path, render_job_id: str) -> Path:
    return out_dir / "rendered_cases" / render_job_id


def is_allowed_job(job: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if job.get("family") not in ALLOWED_FAMILIES:
        reasons.append("family_not_allowed")
    if job.get("target_library") != ALLOWED_TARGET_LIBRARY:
        reasons.append("target_library_not_allowed")
    if job.get("base_adapter") in BLOCKED_ADAPTERS:
        reasons.append("blocked_adapter")
    if not (job.get("preflight") or {}).get("render_allowed", False):
        reasons.append("preflight_render_not_allowed")
    if not (job.get("preflight") or {}).get("blocked_adapter_excluded", False):
        reasons.append("blocked_adapter_not_excluded")
    return not reasons, reasons


def render_one_case(
    job: dict[str, Any],
    out_dir: Path,
    oracle_plan: dict[str, Any],
    mutation_matrix_path: Path,
    instrumentation_profile: str = "",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    allowed, block_reasons = is_allowed_job(job)
    render_job_id = job["render_job_id"]
    case_dir = output_case_dir(out_dir, render_job_id)

    if not allowed:
        return (
            {
                "render_job_id": render_job_id,
                "case_id": job.get("case_id"),
                "family": job.get("family"),
                "target_library": job.get("target_library"),
                "mutation_strategy": job.get("mutation_strategy"),
                "case_dir": rel(case_dir),
                "harness_c": rel(case_dir / "harness.c"),
                "input_corpus_dir": rel(case_dir / "input_corpus"),
                "build_metadata": rel(case_dir / "build_metadata.yaml"),
                "oracle_metadata": rel(case_dir / "oracle_metadata.yaml"),
                "case_metadata": rel(case_dir / "case_metadata.yaml"),
                "render_trace": rel(case_dir / "render_trace.yaml"),
                "render_status": "skipped_blocked",
                "render_failure_reason": "; ".join(block_reasons),
            },
            {
                "render_job_id": render_job_id,
                "case_id": job.get("case_id"),
                "family": job.get("family"),
                "target_library": job.get("target_library"),
                "reason": "; ".join(block_reasons),
                "status": "skipped_blocked",
            },
        )

    if case_dir.exists():
        return (
            {
                "render_job_id": render_job_id,
                "case_id": job.get("case_id"),
                "family": job.get("family"),
                "target_library": job.get("target_library"),
                "mutation_strategy": job.get("mutation_strategy"),
                "case_dir": rel(case_dir),
                "harness_c": rel(case_dir / "harness.c"),
                "input_corpus_dir": rel(case_dir / "input_corpus"),
                "build_metadata": rel(case_dir / "build_metadata.yaml"),
                "oracle_metadata": rel(case_dir / "oracle_metadata.yaml"),
                "case_metadata": rel(case_dir / "case_metadata.yaml"),
                "render_trace": rel(case_dir / "render_trace.yaml"),
                "render_status": "render_failed",
                "render_failure_reason": "planned output already exists; collision recorded and not overwritten",
            },
            None,
        )

    bytes_, replacements = corpus_for_case(job["family"], job["mutation_strategy"])
    harness = render_harness(job, bytes_, instrumentation_profile)
    forbidden_found = [term for term in FORBIDDEN_HARNESS_TERMS if term in harness]
    if forbidden_found:
        return (
            {
                "render_job_id": render_job_id,
                "case_id": job.get("case_id"),
                "family": job.get("family"),
                "target_library": job.get("target_library"),
                "mutation_strategy": job.get("mutation_strategy"),
                "case_dir": rel(case_dir),
                "harness_c": rel(case_dir / "harness.c"),
                "input_corpus_dir": rel(case_dir / "input_corpus"),
                "build_metadata": rel(case_dir / "build_metadata.yaml"),
                "oracle_metadata": rel(case_dir / "oracle_metadata.yaml"),
                "case_metadata": rel(case_dir / "case_metadata.yaml"),
                "render_trace": rel(case_dir / "render_trace.yaml"),
                "render_status": "render_failed",
                "render_failure_reason": "forbidden harness terms: " + ", ".join(forbidden_found),
            },
            None,
        )

    case_dir.mkdir(parents=True, exist_ok=False)
    input_dir = case_dir / "input_corpus"
    input_dir.mkdir(parents=True, exist_ok=False)
    input_name = "input.der" if job["family"] != "pkcs_container_parsing" else "input.bin"

    (input_dir / input_name).write_bytes(bytes(bytes_))
    write_text(case_dir / "harness.c", harness)

    oracle_entry = find_oracle_entry(oracle_plan, job["family"], job["target_library"])
    expected_includes = (
        ["openssl/pkcs12.h", "openssl/pkcs7.h", "openssl/x509.h", "openssl/evp.h"]
        if job["family"] == "pkcs_container_parsing"
        else ["openssl/asn1.h", "openssl/asn1t.h", "openssl/x509.h"]
    )
    build_metadata = {
        "schema": "render_build_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": job["case_id"],
        "family": job["family"],
        "target_library": "openssl",
        "harness_c": "harness.c",
        "compile_policy": {
            "compile_now": False,
            "compile_allowed_next_stage": True,
        },
        "expected_includes": expected_includes,
        "expected_libraries": ["crypto", "ssl"],
        "source_requirements": {
            "target_library_version": "resolved_by_compile_plan_v1",
            "include_paths": [],
            "library_paths": [],
        },
        "notes": [
            "Metadata only; no compile was executed in render_cases_v1.",
            "Candidate mapping only; no confirmed vulnerability claim.",
        ],
    }
    oracle_metadata = {
        "schema": "render_oracle_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": job["case_id"],
        "family": job["family"],
        "target_library": "openssl",
        "primary_oracle": (job.get("oracle") or {}).get("primary"),
        "secondary_oracles": (job.get("oracle") or {}).get("secondary", []),
        "expected_result_label": job.get("expected_result_label"),
        "candidate_label_policy": oracle_entry.get(
            "candidate_label_policy",
            {
                "do_not_claim_confirmed_vulnerability": True,
                "semantic_divergence_requires_triage": True,
                "crash_requires_reproduction": True,
            },
        ),
        "false_positive_risks": [
            item.get("false_positive_risk")
            for item in oracle_entry.get("oracle_interpretation_rules", [])
            if item.get("false_positive_risk")
        ],
        "notes": [
            "No compile/run/analyze result exists yet.",
            "Nonzero harness return codes are oracle signals, not crash evidence.",
        ],
    }
    case_metadata = {
        "schema": "render_case_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": job["case_id"],
        "family": job["family"],
        "target_library": job["target_library"],
        "base_adapter": job["base_adapter"],
        "mutation_strategy": job["mutation_strategy"],
        "mutation_slots": job.get("mutation_slots", []),
        "source_trace": {
            "render_plan": "artifacts/sprints/render_plan_v1/render_plan/render_plan.yaml",
            "mutation_case_matrix": rel(mutation_matrix_path),
            "family_template": job["inputs"]["canonical_template"],
            "adapter_recipe": job["inputs"]["adapter_recipe"],
            "slot_bindings": job["inputs"]["slot_bindings"],
            "oracle_expectation": job["inputs"]["oracle_expectation"],
        },
        "render_status": "rendered",
        "risk_notes": job.get("risk_notes", []),
    }
    render_trace = {
        "schema": "render_trace_v1",
        "render_job_id": render_job_id,
        "case_id": job["case_id"],
        "family": job["family"],
        "target_library": job["target_library"],
        "template_used": job["inputs"]["canonical_template"],
        "slot_bindings_used": job["inputs"]["slot_bindings"],
        "mutation_case_used": job["inputs"]["mutation_case"],
        "replacements": replacements
        + [
            {
                "slot_name": "trigger_call",
                "source": "adapter slot_bindings",
                "replacement_summary": "OpenSSL candidate trigger call rendered",
                "status": "applied",
            },
            {
                "slot_name": "cleanup_call",
                "source": "adapter cleanup_mapping",
                "replacement_summary": "OpenSSL cleanup calls rendered",
                "status": "applied",
            },
            {
                "slot_name": "oracle_check",
                "source": "oracle_expectation_plan",
                "replacement_summary": "parser accept/reject and consumption signal rendered",
                "status": "applied",
            },
        ],
        "blocked_policy_checks": {
            "no_blocked_target": True,
            "no_mbedtls_for_this_sprint": True,
            "no_d2i_PKCS7": "d2i_PKCS7" not in harness,
            "no_confirmed_equivalence_claim": True,
        },
        "oracle_instrumentation": oracle_instrumentation_meta(instrumentation_profile, job["family"]),
        "notes": [
            "Rendered from deterministic wrapper, not from GLM.",
            "The canonical wolfSSL template is used as source trace; target C is OpenSSL-only.",
        ],
    }

    dump_yaml(case_dir / "build_metadata.yaml", build_metadata)
    dump_yaml(case_dir / "oracle_metadata.yaml", oracle_metadata)
    dump_yaml(case_dir / "case_metadata.yaml", case_metadata)
    dump_yaml(case_dir / "render_trace.yaml", render_trace)
    write_text(
        case_dir / "README.md",
        f"# {render_job_id}\n\n"
        f"- case_id: `{job['case_id']}`\n"
        f"- family: `{job['family']}`\n"
        f"- target_library: `openssl`\n"
        f"- mutation_strategy: `{job['mutation_strategy']}`\n"
        "- status: rendered\n\n"
        "This case was rendered only. It has not been compiled, run, or analyzed.\n",
    )

    index_entry = {
        "render_job_id": render_job_id,
        "case_id": job["case_id"],
        "family": job["family"],
        "target_library": job["target_library"],
        "mutation_strategy": job["mutation_strategy"],
        "case_dir": rel(case_dir),
        "harness_c": rel(case_dir / "harness.c"),
        "input_corpus_dir": rel(input_dir),
        "build_metadata": rel(case_dir / "build_metadata.yaml"),
        "oracle_metadata": rel(case_dir / "oracle_metadata.yaml"),
        "case_metadata": rel(case_dir / "case_metadata.yaml"),
        "render_trace": rel(case_dir / "render_trace.yaml"),
        "render_status": "rendered",
    }
    if oracle_event_enabled(instrumentation_profile):
        index_entry["oracle_instrumentation"] = oracle_instrumentation_meta(instrumentation_profile, job["family"])
    return index_entry, None


def inventory(out_dir: Path) -> dict[str, Any]:
    rg_file = out_dir / "renderer_inventory" / "render_cases_related_rg.txt"
    tooling_file = out_dir / "renderer_inventory" / "tooling_files.txt"
    rg_text = rg_file.read_text(encoding="utf-8") if rg_file.exists() else ""
    tooling_text = tooling_file.read_text(encoding="utf-8") if tooling_file.exists() else ""
    return {
        "schema": "renderer_inventory_v1",
        "generated_at": now_iso(),
        "existing_renderer_found": "template_maker/render_cases.py" in tooling_text
        or Path("template_maker/render_cases.py").exists(),
        "template_maker_render_cases_found": Path("template_maker/render_cases.py").exists(),
        "renderer_used": "tools/render_cases_v1.py",
        "wrapper_added": True,
        "why_wrapper": "existing renderer is not directly shaped for family-level mutation matrix plus render_plan_v1 case manifest",
        "compile_run_executed": False,
        "rg_match_count": len([line for line in rg_text.splitlines() if line.strip()]),
        "raw_inventory_files": {
            "render_cases_related_rg": rel(rg_file),
            "tooling_files": rel(tooling_file),
        },
    }


def md_list(items: list[str]) -> str:
    return "".join(f"- {item}\n" for item in items) if items else "- none\n"


def write_markdown(out_dir: Path, docs: dict[str, Any]) -> None:
    summary = docs["input_summary"]
    write_text(
        out_dir / "input" / "render_cases_input_summary.md",
        "# render_cases_v1 Input Summary\n\n"
        "- consumes: `render_plan_v1`\n"
        "- generates C harness: `true`\n"
        "- compile/run/analyze: `false`\n"
        "- target scope: `OpenSSL only`\n"
        "- blocked mbedTLS adapter rendered: `false`\n"
        "- GLM called: `false`\n\n"
        "## Inputs\n\n"
        + md_list(summary["inputs"]),
    )

    inv = docs["renderer_inventory"]
    write_text(
        out_dir / "renderer_inventory" / "renderer_inventory.md",
        "# Renderer Inventory\n\n"
        f"- existing renderer found: `{inv['existing_renderer_found']}`\n"
        f"- template_maker/render_cases.py found: `{inv['template_maker_render_cases_found']}`\n"
        f"- renderer used: `{inv['renderer_used']}`\n"
        f"- wrapper added: `{inv['wrapper_added']}`\n"
        f"- compile/run: `no`\n\n"
        f"{inv['why_wrapper']}\n",
    )

    idx = docs["case_index"]
    rows = [
        "| render_job_id | family | mutation_strategy | status |",
        "|---|---|---|---|",
    ]
    for case in idx["cases"]:
        rows.append(
            f"| {case['render_job_id']} | {case['family']} | {case['mutation_strategy']} | {case['render_status']} |"
        )
    write_text(
        out_dir / "case_index" / "rendered_case_index.md",
        "# Rendered Case Index\n\n"
        f"- total_planned: `{idx['summary']['total_planned']}`\n"
        f"- rendered: `{idx['summary']['rendered']}`\n"
        f"- render_failed: `{idx['summary']['render_failed']}`\n"
        f"- skipped_blocked: `{idx['summary']['skipped_blocked']}`\n\n"
        + "\n".join(rows)
        + "\n",
    )

    blocked = docs["blocked_cases"]
    write_text(
        out_dir / "blocked_cases" / "render_blocked_cases.md",
        "# Render Blocked Cases\n\n"
        f"- total_blocked: `{blocked['summary']['total_blocked']}`\n"
        f"- asn1 mbedTLS rendered: `{blocked['summary']['asn1_mbedtls_rendered']}`\n"
        f"- harness exists: `{blocked['summary']['blocked_harness_exists']}`\n\n"
        + md_list([f"{item['family']} -> {item['target_library']}: {item['status']}" for item in blocked["blocked_cases"]]),
    )

    quality = docs["quality"]
    write_text(
        out_dir / "validation" / "render_cases_quality_checks.md",
        "# Render Cases Quality Checks\n\n"
        f"- quality_status: `{quality['quality_status']}`\n"
        f"- rendered_cases: `{quality['rendered_cases']}`\n"
        f"- render_failed: `{quality['render_failed']}`\n"
        f"- mbedtls_rendered: `{quality['mbedtls_rendered']}`\n"
        f"- no_compile_executed: `{quality['no_compile_executed']}`\n"
        f"- no_run_executed: `{quality['no_run_executed']}`\n"
        f"- no_glm_called: `{quality['no_glm_called']}`\n\n"
        + md_list(quality["notes"]),
    )

    next_action = docs["next_action"]
    write_text(
        out_dir / "reports" / "next_action_after_render_cases.md",
        "# Next Action After Render Cases\n\n"
        f"- next_task: `{next_action['next_task']}`\n"
        f"- reason: {next_action['reason']}\n",
    )

    report = docs["report"]
    write_text(
        out_dir / "reports" / "render_cases_v1_report.md",
        "# render_cases_v1 Report\n\n"
        f"- status: `{report['status']}`\n"
        f"- rendered_cases: `{report['summary']['rendered_cases']}`\n"
        f"- pkcs_rendered: `{report['summary']['pkcs_rendered']}`\n"
        f"- asn1_rendered: `{report['summary']['asn1_rendered']}`\n"
        f"- mbedtls_rendered: `{report['summary']['mbedtls_rendered']}`\n"
        f"- compile_run_analyze: `false`\n"
        f"- GLM: `false`\n"
        f"- next_task: `{report['next_task']}`\n\n"
        "## Answers\n\n"
        + md_list(report["answers"]),
    )

    write_text(
        out_dir / "README.md",
        "# render_cases_v1\n\n"
        "This sprint renders the 14 OpenSSL cases from render_plan_v1 into C harnesses and metadata.\n"
        "It does not compile, run, analyze, rebuild RAG, or call GLM/LLM.\n\n"
        "## Outputs\n\n"
        + md_list(
            [
                "rendered_cases/<render_job_id>/harness.c",
                "rendered_cases/<render_job_id>/input_corpus/",
                "rendered_cases/<render_job_id>/build_metadata.yaml",
                "rendered_cases/<render_job_id>/oracle_metadata.yaml",
                "rendered_cases/<render_job_id>/case_metadata.yaml",
                "rendered_cases/<render_job_id>/render_trace.yaml",
                "case_index/rendered_case_index.yaml",
            ]
        ),
    )


def quality_for(cases: list[dict[str, Any]], out_dir: Path) -> dict[str, Any]:
    rendered = [case for case in cases if case.get("render_status") == "rendered"]
    failed = [case for case in cases if case.get("render_status") == "render_failed"]
    skipped = [case for case in cases if case.get("render_status") == "skipped_blocked"]
    harness_texts = []
    for case in rendered:
        path = Path(case["harness_c"])
        harness_texts.append(path.read_text(encoding="utf-8") if path.exists() else "")
    checks = {
        "schema": "render_cases_quality_checks_v1",
        "planned_render_jobs": len(cases),
        "expected_render_jobs": 14,
        "rendered_cases": len(rendered),
        "render_failed": len(failed),
        "skipped_blocked": len(skipped),
        "pkcs_rendered": len([c for c in rendered if c.get("family") == "pkcs_container_parsing"]),
        "asn1_rendered": len([c for c in rendered if c.get("family") == "asn1_nested_boundary"]),
        "mbedtls_rendered": len([c for c in rendered if c.get("target_library") == "mbedtls"]),
        "all_rendered_have_harness_c": all(Path(c["harness_c"]).exists() for c in rendered),
        "all_rendered_have_build_metadata": all(Path(c["build_metadata"]).exists() for c in rendered),
        "all_rendered_have_oracle_metadata": all(Path(c["oracle_metadata"]).exists() for c in rendered),
        "all_rendered_have_case_metadata": all(Path(c["case_metadata"]).exists() for c in rendered),
        "all_rendered_have_render_trace": all(Path(c["render_trace"]).exists() for c in rendered),
        "no_blocked_adapter_rendered": all(c.get("case_id") != "asn1_nested_boundary_mbedtls__blocked" for c in rendered),
        "no_mbedtls_cases_rendered": all(c.get("target_library") != "mbedtls" for c in rendered),
        "no_d2i_PKCS7_used": all("d2i_PKCS7" not in text for text in harness_texts),
        "no_compile_executed": True,
        "no_run_executed": True,
        "no_glm_called": True,
        "notes": [
            "No compile/run/analyze command was executed by render_cases_v1.",
            "Harnesses contain candidate OpenSSL API projections only.",
        ],
    }
    pass_conditions = [
        checks["rendered_cases"] == 14,
        checks["pkcs_rendered"] == 7,
        checks["asn1_rendered"] == 7,
        checks["mbedtls_rendered"] == 0,
        checks["all_rendered_have_harness_c"],
        checks["all_rendered_have_build_metadata"],
        checks["all_rendered_have_oracle_metadata"],
        checks["all_rendered_have_case_metadata"],
        checks["all_rendered_have_render_trace"],
        checks["no_blocked_adapter_rendered"],
        checks["no_mbedtls_cases_rendered"],
        checks["no_d2i_PKCS7_used"],
        checks["no_compile_executed"],
        checks["no_run_executed"],
        checks["no_glm_called"],
    ]
    if all(pass_conditions):
        checks["quality_status"] = "pass"
    elif checks["rendered_cases"] > 0:
        checks["quality_status"] = "partial"
    else:
        checks["quality_status"] = "fail"
    return checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render cases from render_plan_v1.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--family", default="")
    parser.add_argument("--render-plan")
    parser.add_argument("--case-manifest")
    parser.add_argument("--mutation-case-matrix")
    parser.add_argument("--oracle-expectation-plan")
    parser.add_argument("--adapter-root")
    parser.add_argument("--family-template-root")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument(
        "--oracle-instrumentation-profile",
        default="",
        choices=["", "oracle_event_v1"],
        help="Optional oracle instrumentation profile. Default keeps legacy render output unchanged.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.family:
        repo_root = Path(args.repo_root).resolve()
        if not args.render_plan:
            raise SystemExit("--render-plan is required with --family")
        out_dir = (repo_root / args.out_dir).resolve()
        docs = render_object_family(
            repo_root=repo_root,
            family=args.family,
            render_plan_path=(repo_root / args.render_plan).resolve(),
            out_dir=out_dir,
        )
        quality = docs["quality"]
        print(f"[OK] rendered object family cases to {out_dir}")
        print(
            "[SUMMARY] "
            f"family={args.family} rendered={quality['rendered_case_count']} "
            f"quality={quality['quality_status']}"
        )
        return 0 if quality["quality_status"] == "pass" else 1

    missing_args = [
        name
        for name in (
            "render_plan",
            "case_manifest",
            "mutation_case_matrix",
            "oracle_expectation_plan",
            "adapter_root",
            "family_template_root",
        )
        if getattr(args, name) is None
    ]
    if missing_args:
        raise SystemExit("missing required legacy render arguments: " + ", ".join(missing_args))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    render_plan_path = Path(args.render_plan)
    case_manifest_path = Path(args.case_manifest)
    mutation_case_matrix_path = Path(args.mutation_case_matrix)
    oracle_plan_path = Path(args.oracle_expectation_plan)
    adapter_root = Path(args.adapter_root)
    family_template_root = Path(args.family_template_root)

    render_plan = load_yaml(render_plan_path)
    case_manifest = load_yaml(case_manifest_path)
    mutation_matrix = load_yaml(mutation_case_matrix_path)
    oracle_plan = load_yaml(oracle_plan_path)

    input_summary = {
        "schema": "render_cases_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": [
            rel(render_plan_path),
            rel(case_manifest_path),
            rel(mutation_case_matrix_path),
            rel(oracle_plan_path),
            rel(adapter_root),
            rel(family_template_root),
        ],
        "scope": {
            "consumes_render_plan_v1": True,
            "generates_c_harness": True,
            "compile": False,
            "run": False,
            "analyze": False,
            "target_scope": "openssl only",
            "blocked_mbedtls_adapter_rendered": False,
            "glm_called": False,
        },
        "summary": {
            "render_plan_jobs": len(render_plan.get("render_jobs", [])),
            "case_manifest_cases": len(case_manifest.get("cases", [])),
            "mutation_matrix_cases": len(mutation_matrix.get("cases", [])),
        },
    }

    index_entries: list[dict[str, Any]] = []
    blocked_records: list[dict[str, Any]] = []
    planned_jobs = [
        job
        for job in render_plan.get("render_jobs", [])
        if (job.get("preflight") or {}).get("render_allowed", False)
    ]
    for job in planned_jobs:
        entry, blocked = render_one_case(
            job=job,
            out_dir=out_dir,
            oracle_plan=oracle_plan,
            mutation_matrix_path=mutation_case_matrix_path,
            instrumentation_profile=args.oracle_instrumentation_profile,
        )
        index_entries.append(entry)
        if blocked:
            blocked_records.append(blocked)

    blocked_records.append(
        {
            "family": "asn1_nested_boundary",
            "target_library": "mbedtls",
            "adapter_id": "asn1_nested_boundary_mbedtls",
            "status": "skipped_blocked",
            "reason": "blocked_expected; not render-ready; must not enter render_cases_v1",
            "harness_c_exists": False,
            "rendered_case_dir_exists": False,
            "entered_rendered_index": False,
        }
    )

    counts = Counter(entry["render_status"] for entry in index_entries)
    rendered = [entry for entry in index_entries if entry["render_status"] == "rendered"]
    case_index = {
        "schema": "rendered_case_index_v1",
        "generated_at": now_iso(),
        "cases": index_entries,
        "summary": {
            "total_planned": len(index_entries),
            "rendered": counts.get("rendered", 0),
            "render_failed": counts.get("render_failed", 0),
            "skipped_blocked": counts.get("skipped_blocked", 0),
            "pkcs_rendered": len([c for c in rendered if c.get("family") == "pkcs_container_parsing"]),
            "asn1_rendered": len([c for c in rendered if c.get("family") == "asn1_nested_boundary"]),
        },
    }

    blocked_doc = {
        "schema": "render_blocked_cases_v1",
        "generated_at": now_iso(),
        "blocked_cases": blocked_records,
        "summary": {
            "total_blocked": len(blocked_records),
            "asn1_mbedtls_rendered": False,
            "blocked_harness_exists": False,
            "blocked_case_dir_exists": False,
            "blocked_entered_rendered_index": False,
            "blocked_status": "skipped_blocked / blocked_expected",
        },
    }

    quality = quality_for(index_entries, out_dir)

    if quality["mbedtls_rendered"] > 0:
        next_task = "render_blocking_policy_fixup_v1"
        reason = "blocked mbedTLS target was rendered"
    elif quality["render_failed"] > 0:
        next_task = "render_cases_fixup_v1"
        reason = "one or more cases failed to render"
    elif not (
        quality["all_rendered_have_build_metadata"]
        and quality["all_rendered_have_oracle_metadata"]
        and quality["all_rendered_have_case_metadata"]
    ):
        next_task = "render_metadata_fixup_v1"
        reason = "one or more rendered cases lacks required metadata"
    elif quality["quality_status"] == "pass":
        next_task = "compile_plan_v1"
        reason = "all 14 OpenSSL cases rendered with required metadata; compile should be planned next"
    else:
        next_task = "render_cases_fixup_v1"
        reason = "quality status is not pass"

    next_action = {
        "schema": "next_action_after_render_cases_v1",
        "generated_at": now_iso(),
        "next_task": next_task,
        "reason": reason,
    }

    report = {
        "schema": "render_cases_v1_report",
        "generated_at": now_iso(),
        "status": quality["quality_status"],
        "summary": {
            "planned": len(index_entries),
            "rendered_cases": quality["rendered_cases"],
            "render_failed": quality["render_failed"],
            "skipped_blocked": quality["skipped_blocked"],
            "pkcs_rendered": quality["pkcs_rendered"],
            "asn1_rendered": quality["asn1_rendered"],
            "mbedtls_rendered": quality["mbedtls_rendered"],
            "harness_c_generated": quality["all_rendered_have_harness_c"],
            "metadata_generated": all(
                [
                    quality["all_rendered_have_build_metadata"],
                    quality["all_rendered_have_oracle_metadata"],
                    quality["all_rendered_have_case_metadata"],
                    quality["all_rendered_have_render_trace"],
                ]
            ),
            "compile": False,
            "run": False,
            "analyze": False,
            "glm": False,
        },
        "answers": [
            f"Rendered cases: {quality['rendered_cases']} of 14.",
            f"PKCS cases rendered: {quality['pkcs_rendered']}.",
            f"ASN.1 cases rendered: {quality['asn1_rendered']}.",
            f"mbedTLS cases rendered: {quality['mbedtls_rendered']}.",
            "harness.c generated for every rendered case.",
            "build/oracle/case metadata and render_trace generated for every rendered case.",
            "compile/run/analyze were not executed.",
            "GLM/LLM was not called.",
            f"Next task: {next_task}.",
        ],
        "next_task": next_task,
    }

    renderer_inventory = inventory(out_dir)
    docs = {
        "input_summary": input_summary,
        "renderer_inventory": renderer_inventory,
        "case_index": case_index,
        "blocked_cases": blocked_doc,
        "quality": quality,
        "next_action": next_action,
        "report": report,
    }

    dump_yaml(out_dir / "input" / "render_cases_input_summary.yaml", input_summary)
    dump_yaml(out_dir / "renderer_inventory" / "renderer_inventory.yaml", renderer_inventory)
    dump_yaml(out_dir / "case_index" / "rendered_case_index.yaml", case_index)
    dump_yaml(out_dir / "blocked_cases" / "render_blocked_cases.yaml", blocked_doc)
    dump_yaml(out_dir / "validation" / "render_cases_quality_checks.yaml", quality)
    dump_yaml(out_dir / "reports" / "next_action_after_render_cases.yaml", next_action)
    dump_yaml(out_dir / "reports" / "render_cases_v1_report.yaml", report)
    write_markdown(out_dir, docs)

    print(f"[OK] wrote render cases artifacts to {out_dir}")
    print(f"[SUMMARY] rendered={quality['rendered_cases']} failed={quality['render_failed']} quality={quality['quality_status']}")
    print(f"[NEXT] {next_task}")
    return 0 if quality["quality_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
