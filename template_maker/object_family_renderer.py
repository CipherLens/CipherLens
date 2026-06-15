"""Profile-driven renderer for OpenSSL object parsing families."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from template_maker.render_records import dump_yaml, load_yaml, now_iso, write_text


OBJECT_PARSING_FAMILIES = {"pkey_parsing", "pkcs8_parsing", "x509_crl_parsing"}
PKEY_PARSE_PATHS = [
    "PEM_read_bio_PrivateKey",
    "PEM_read_bio_PUBKEY",
    "d2i_AutoPrivateKey",
    "d2i_PUBKEY",
]


def resolve_render_plan(path: Path) -> Path:
    if path.exists():
        return path
    if path.name == "render_plan.yaml":
        sibling = path.with_name("family_render_plan.yaml")
        if sibling.exists():
            return sibling
    return path


def rel(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def c_string_literal(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def pkey_harness(case_id: str, family: str, mutation_strategy: str, input_name: str) -> str:
    return f"""/*
 * Rendered by generic object family renderer.
 * This harness is for local oracle observation only. It is not a confirmed
 * vulnerability, CVE, exploit, or API equivalence claim.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static unsigned char *read_file(const char *path, long *len)
{{
    FILE *f = fopen(path, "rb");
    unsigned char *buf = NULL;
    long size = 0;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {{
        fclose(f);
        return NULL;
    }}
    size = ftell(f);
    if (size < 0) {{
        fclose(f);
        return NULL;
    }}
    if (fseek(f, 0, SEEK_SET) != 0) {{
        fclose(f);
        return NULL;
    }}
    buf = (unsigned char *)OPENSSL_malloc((size_t)size + 1);
    if (buf == NULL) {{
        fclose(f);
        return NULL;
    }}
    if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {{
        OPENSSL_free(buf);
        fclose(f);
        return NULL;
    }}
    fclose(f);
    buf[size] = 0;
    *len = size;
    return buf;
}}

static void emit_event(const char *api, int accepted, long input_len, long consumed_len, int oracle_incomplete)
{{
    int full_consumption = 0;
    int full_consumption_gap = 0;

    if (oracle_incomplete) {{
        full_consumption = -1;
        full_consumption_gap = 0;
    }} else {{
        full_consumption = consumed_len == input_len ? 1 : 0;
        full_consumption_gap = accepted && consumed_len < input_len ? 1 : 0;
    }}

    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={c_string_literal(case_id)} family={c_string_literal(family)} mutation_strategy={c_string_literal(mutation_strategy)} target_library=openssl phase=parse api=%s accepted=%d parse_success=%d input_len=%ld consumed_len=%ld full_consumption=%d full_consumption_gap=%d oracle_incomplete=%d\\n",
           api, accepted, accepted, input_len, consumed_len, full_consumption,
           full_consumption_gap, oracle_incomplete);
}}

int main(void)
{{
    const char *input_path = "input_corpus/{c_string_literal(input_name)}";
    unsigned char *input = NULL;
    long input_len = 0;
    int any_accept = 0;

    input = read_file(input_path, &input_len);
    if (input == NULL) {{
        fprintf(stderr, "failed to read input: %s\\n", input_path);
        return 2;
    }}

    {{
        const unsigned char *p = input;
        EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &p, input_len);
        long consumed_len = (long)(p - input);
        int accepted = key != NULL ? 1 : 0;
        any_accept |= accepted;
        emit_event("d2i_AutoPrivateKey", accepted, input_len, consumed_len, 0);
        if (key != NULL)
            EVP_PKEY_free(key);
    }}

    {{
        const unsigned char *p = input;
        EVP_PKEY *key = d2i_PUBKEY(NULL, &p, input_len);
        long consumed_len = (long)(p - input);
        int accepted = key != NULL ? 1 : 0;
        any_accept |= accepted;
        emit_event("d2i_PUBKEY", accepted, input_len, consumed_len, 0);
        if (key != NULL)
            EVP_PKEY_free(key);
    }}

    {{
        BIO *bio = BIO_new_mem_buf(input, (int)input_len);
        EVP_PKEY *key = bio != NULL ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
        int accepted = key != NULL ? 1 : 0;
        any_accept |= accepted;
        emit_event("PEM_read_bio_PrivateKey", accepted, input_len, accepted ? input_len : 0, 1);
        if (key != NULL)
            EVP_PKEY_free(key);
        if (bio != NULL)
            BIO_free(bio);
    }}

    {{
        BIO *bio = BIO_new_mem_buf(input, (int)input_len);
        EVP_PKEY *key = bio != NULL ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
        int accepted = key != NULL ? 1 : 0;
        any_accept |= accepted;
        emit_event("PEM_read_bio_PUBKEY", accepted, input_len, accepted ? input_len : 0, 1);
        if (key != NULL)
            EVP_PKEY_free(key);
        if (bio != NULL)
            BIO_free(bio);
    }}

    OPENSSL_free(input);
    return any_accept ? 0 : 1;
}}
"""


def input_name_for(job: dict[str, Any]) -> str:
    fmt = str(job.get("seed_format") or "").lower()
    if fmt == "pem" or str(job.get("input_path", "")).lower().endswith(".pem"):
        return "input.pem"
    return "input.der"


def render_one(repo_root: Path, out_dir: Path, job: dict[str, Any]) -> dict[str, Any]:
    render_job_id = str(job.get("render_job_id") or job.get("case_id"))
    case_id = str(job.get("case_id") or render_job_id)
    family = str(job.get("family") or "")
    mutation_strategy = str(job.get("mutation_strategy") or "")
    case_dir = out_dir / "rendered_cases" / render_job_id
    input_dir = case_dir / "input_corpus"
    input_name = input_name_for(job)
    source_path = Path(str(job.get("input_path") or ""))
    if not source_path.is_absolute():
        source_path = repo_root / source_path

    case_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, input_dir / input_name)
    harness = pkey_harness(case_id, family, mutation_strategy, input_name)
    write_text(case_dir / "harness.c", harness)
    build_metadata = {
        "schema": "object_family_build_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": family,
        "target_library": "openssl",
        "harness_c": "harness.c",
        "compile_policy": {"compile_now": False, "compile_allowed_next_stage": True},
        "expected_includes": ["openssl/evp.h", "openssl/pem.h", "openssl/bio.h", "openssl/x509.h"],
        "expected_libraries": ["crypto", "ssl"],
    }
    oracle_metadata = {
        "schema": "object_family_oracle_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": family,
        "target_library": "openssl",
        "oracle_events": [
            "accepted",
            "parse_success",
            "full_consumption",
            "full_consumption_gap",
            "input_len",
            "consumed_len",
            "mutation_strategy",
        ],
        "parse_paths": PKEY_PARSE_PATHS,
        "candidate_label_policy": {
            "do_not_claim_confirmed_vulnerability": True,
            "semantic_divergence_requires_triage": True,
            "oracle_incomplete_requires_triage": True,
        },
    }
    case_metadata = {
        "schema": "object_family_case_metadata_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": family,
        "target_library": "openssl",
        "mutation_strategy": mutation_strategy,
        "seed_id": job.get("seed_id", ""),
        "seed_format": job.get("seed_format", ""),
        "source_input": rel(repo_root, source_path),
        "render_status": "rendered",
    }
    render_trace = {
        "schema": "object_family_render_trace_v1",
        "render_job_id": render_job_id,
        "case_id": case_id,
        "renderer": "template_maker.object_family_renderer",
        "profile_driven": True,
        "compile_executed": False,
        "run_executed": False,
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    dump_yaml(case_dir / "build_metadata.yaml", build_metadata)
    dump_yaml(case_dir / "oracle_metadata.yaml", oracle_metadata)
    dump_yaml(case_dir / "case_metadata.yaml", case_metadata)
    dump_yaml(case_dir / "render_trace.yaml", render_trace)
    return {
        "render_job_id": render_job_id,
        "case_id": case_id,
        "family": family,
        "target_library": "openssl",
        "mutation_strategy": mutation_strategy,
        "case_dir": rel(repo_root, case_dir),
        "harness_c": rel(repo_root, case_dir / "harness.c"),
        "input_file": rel(repo_root, input_dir / input_name),
        "build_metadata": rel(repo_root, case_dir / "build_metadata.yaml"),
        "oracle_metadata": rel(repo_root, case_dir / "oracle_metadata.yaml"),
        "case_metadata": rel(repo_root, case_dir / "case_metadata.yaml"),
        "render_trace": rel(repo_root, case_dir / "render_trace.yaml"),
        "render_status": "rendered",
    }


def render_object_family(repo_root: Path, family: str, render_plan_path: Path, out_dir: Path) -> dict[str, Any]:
    resolved_plan = resolve_render_plan(render_plan_path)
    render_plan = load_yaml(resolved_plan)
    selected = {
        "schema": "selected_object_family_v1",
        "generated_at": now_iso(),
        "family": family,
        "object_family": family in OBJECT_PARSING_FAMILIES,
        "render_plan": rel(repo_root, resolved_plan),
    }
    jobs = [
        job
        for job in render_plan.get("render_jobs", []) or []
        if job.get("family") == family and bool(job.get("render_allowed", False))
    ]
    rendered = [render_one(repo_root, out_dir, job) for job in jobs]
    case_index = {
        "schema": "rendered_case_index_v1",
        "generated_at": now_iso(),
        "family": family,
        "cases": rendered,
        "summary": {
            "render_job_count": len(jobs),
            "rendered_case_count": len(rendered),
            "harness_generated": all((repo_root / item["harness_c"]).exists() for item in rendered),
        },
    }
    qc = {
        "schema": "generic_object_family_renderer_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family_specific_renderer_created": False,
        "pkey_selected": family == "pkey_parsing",
        "render_plan_loaded": bool(render_plan),
        "object_family_renderer_used": True,
        "render_cases_executed": True,
        "rendered_case_count": len(rendered),
        "harness_generated": bool(rendered)
        and all((repo_root / item["harness_c"]).exists() for item in rendered),
        "case_index_generated": True,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if family == "pkey_parsing" and bool(render_plan) and len(rendered) >= 1
        else "blocked",
    }
    invocation = {
        "schema": "object_family_render_cases_invocation_v1",
        "generated_at": now_iso(),
        "module": "template_maker.family_case_renderer",
        "helper": "template_maker.object_family_renderer",
        "family": family,
        "render_plan": rel(repo_root, resolved_plan),
        "out_dir": rel(repo_root, out_dir),
        "compile_executed": False,
        "run_executed": False,
    }
    dump_yaml(out_dir / "selection/selected_family.yaml", selected)
    dump_yaml(out_dir / "execution/render_cases_invocation.yaml", invocation)
    dump_yaml(out_dir / "case_index/rendered_case_index.yaml", case_index)
    dump_yaml(out_dir / "validation/generic_object_family_renderer_quality_checks.yaml", qc)
    report = f"""# generic_object_family_case_renderer_v1 Report

## Renderer

- selected_family: {family}
- object_family_renderer: template_maker.object_family_renderer
- render_plan: {rel(repo_root, resolved_plan)}
- render_jobs: {len(jobs)}
- rendered_cases: {len(rendered)}

## Parse Paths

- PEM_read_bio_PrivateKey
- PEM_read_bio_PUBKEY
- d2i_AutoPrivateKey
- d2i_PUBKEY

## Policy

No family-specific renderer, tools script, compile, run, feedback, knowledge,
pattern-bank, adapter recipe, normalized template, GLM, git, CVE, exploitability,
or confirmed vulnerability claim was produced.

## Quality

- quality_status: {qc['quality_status']}
"""
    write_text(out_dir / "reports/generic_object_family_case_renderer_v1_report.md", report)
    return {"selected": selected, "invocation": invocation, "case_index": case_index, "quality": qc}
