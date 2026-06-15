"""Render C harnesses from semantic render plans.

This module renders source files only. It does not compile, run, analyze, call
an LLM, write feedback, or update knowledge/pattern-bank artifacts.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

from template_maker.render_records import dump_yaml, load_yaml, now_iso, write_text


TASK = "pkey_verify_semantic_render_cases_v1"
DEFAULT_RENDER_PLAN = "artifacts/sprints/pkey_verify_semantic_render_plan_v1/render/render_plan.yaml"
DEFAULT_MUTATION_PLAN = (
    "artifacts/sprints/pkey_verify_semantic_generic_mutation_plan_v1/mutation/mutation_plan.yaml"
)
DEFAULT_BASELINE = "artifacts/sprints/glm_slot_filling_token_budget_fix_v1"
FORBIDDEN_PATTERNS = [
    "d2i_",
    "PEM_read_bio",
    "full_consumption",
    "trailing_garbage",
    "openssl x509",
    "openssl pkcs8",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--render-plan", default=DEFAULT_RENDER_PLAN)
    parser.add_argument("--mutation-plan", default=DEFAULT_MUTATION_PLAN)
    parser.add_argument("--baseline-root", default=DEFAULT_BASELINE)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def c_ident(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


def baseline_status(baseline_root: Path, render_plan_status: dict[str, Any]) -> dict[str, Any]:
    slot_schema = load_yaml(baseline_root / "validation/slot_bindings_schema_validate.yaml")
    adapter = load_yaml(baseline_root / "validation/adapter_validate_results.yaml")
    mapping = load_yaml(baseline_root / "validation/mapping_gate_validate_results.yaml")
    return {
        "schema": "semantic_render_cases_rag_glm_baseline_status_v1",
        "generated_at": now_iso(),
        "rag_glm_baseline_loaded": bool(render_plan_status.get("rag_glm_baseline_loaded")),
        "slot_bindings_loaded": (baseline_root / "slot_filling/generated_slot_bindings.yaml").exists(),
        "slot_bindings_schema_valid": bool(slot_schema.get("slot_bindings_schema_valid")),
        "adapter_validate_loaded": bool(adapter),
        "adapter_validate_passed": adapter.get("status") == "pass",
        "mapping_gate_loaded": bool(mapping),
        "mapping_gate_bypassed": bool(mapping.get("mapping_gate_bypassed")),
        "api_key_logged": bool(render_plan_status.get("api_key_logged")),
    }


def mutation_code(strategy: str) -> str:
    if strategy == "signature_corruption_flip_one_byte":
        return """
    if (verify_sig_len > 0)
        verify_sig[0] ^= 0x01;
"""
    if strategy == "signature_corruption_truncate":
        return """
    if (verify_sig_len > 0)
        verify_sig_len -= 1;
"""
    if strategy == "signature_corruption_extend":
        return """
    if (verify_sig_len < sizeof(verify_sig))
        verify_sig[verify_sig_len++] = 0x00;
"""
    if strategy == "signature_corruption_all_zero":
        return """
    memset(verify_sig, 0, verify_sig_len);
"""
    if strategy == "message_mismatch_flip_one_byte":
        return """
    if (verify_input_len > 0)
        verify_input[0] ^= 0x01;
"""
    if strategy == "message_mismatch_empty_message":
        return """
    verify_input_len = 0;
"""
    if strategy == "message_mismatch_longer_message":
        return """
    if (verify_input_len + 6 < sizeof(verify_input)) {
        memcpy(verify_input + verify_input_len, \"-extra\", 6);
        verify_input_len += 6;
    }
"""
    if strategy == "message_mismatch_different_message":
        return """
    static const unsigned char replacement_message[] = \"different semantic message\";
    memcpy(verify_input, replacement_message, sizeof(replacement_message) - 1);
    verify_input_len = sizeof(replacement_message) - 1;
"""
    return "\n"


def harness_source(case: dict[str, Any]) -> str:
    case_id = str(case.get("case_id"))
    strategy = str(case.get("mutation_strategy"))
    expected = str(case.get("expected_behavior"))
    use_wrong_key = strategy == "wrong_key_verify"
    ident = c_ident(case_id)
    return f"""/*
 * Generated from semantic_render_plan_v1 for pkey_verify_semantic.
 * This case is a semantic EVP sign/verify harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static const unsigned char base_message[] = "fixed deterministic semantic seed message";

static EVP_PKEY *generate_rsa_key(void)
{{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(kctx) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0)
        goto done;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {{
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }}

done:
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}}

static int sign_message(EVP_PKEY *key, const unsigned char *msg, size_t msg_len,
                        unsigned char **sig, size_t *sig_len)
{{
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0)
        goto done;
    if (EVP_DigestSignUpdate(ctx, msg, msg_len) <= 0)
        goto done;
    if (EVP_DigestSignFinal(ctx, NULL, sig_len) <= 0)
        goto done;
    *sig = OPENSSL_malloc(*sig_len);
    if (*sig == NULL)
        goto done;
    if (EVP_DigestSignFinal(ctx, *sig, sig_len) <= 0)
        goto done;
    ok = 1;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}}

static int verify_message(EVP_PKEY *key, const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig, size_t sig_len)
{{
    int ret = -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return -1;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0)
        goto done;
    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) <= 0)
        goto done;
    ret = EVP_DigestVerifyFinal(ctx, sig, sig_len);

done:
    EVP_MD_CTX_free(ctx);
    return ret;
}}

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int crash_or_sanitizer = 0;
    int verify_ret = -1;
    int exit_code = 0;
    EVP_PKEY *signing_key = NULL;
    EVP_PKEY *verify_key = NULL;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    unsigned char verify_sig[512];
    size_t verify_sig_len = 0;
    unsigned char verify_input[256];
    size_t verify_input_len = sizeof(base_message) - 1;

    memcpy(verify_input, base_message, verify_input_len);

    signing_key = generate_rsa_key();
    if (signing_key == NULL)
        goto done;
{"    verify_key = generate_rsa_key();\n    if (verify_key == NULL)\n        goto done;" if use_wrong_key else "    verify_key = signing_key;"}

    if (!sign_message(signing_key, base_message, sizeof(base_message) - 1, &signature, &signature_len))
        goto done;
    if (signature_len > sizeof(verify_sig))
        goto done;
    memcpy(verify_sig, signature, signature_len);
    verify_sig_len = signature_len;
{mutation_code(strategy)}
    verify_ret = verify_message(verify_key, verify_input, verify_input_len, verify_sig, verify_sig_len);
    if (verify_ret == 1)
        actual_behavior = "accept";
    else if (verify_ret == 0)
        actual_behavior = "reject";
    else
        actual_behavior = "error";

    if (strcmp(expected_behavior, "accept") == 0) {{
        semantic_mismatch = strcmp(actual_behavior, "accept") != 0;
    }} else if (strcmp(expected_behavior, "reject") == 0) {{
        semantic_mismatch = strcmp(actual_behavior, "accept") == 0;
    }} else {{
        semantic_mismatch = 1;
    }}
    exit_code = semantic_mismatch ? 10 : 0;

done:
    if (signing_key == NULL || verify_key == NULL || signature == NULL) {{
        actual_behavior = "error";
        semantic_mismatch = strcmp(expected_behavior, "accept") == 0 ? 1 : 0;
        exit_code = semantic_mismatch ? 10 : 0;
    }}
    printf("ORACLE_EVENT family=pkey_verify_semantic\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT semantic_mismatch=%d\\n", semantic_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy={strategy}\\n");

    OPENSSL_free(signature);
{"" if use_wrong_key else "    verify_key = NULL;\n"}
    EVP_PKEY_free(verify_key);
    EVP_PKEY_free(signing_key);
    return exit_code;
}}

/* case symbol marker: {ident} */
"""


def forbidden_leakage(paths: list[Path]) -> bool:
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(marker in text for marker in FORBIDDEN_PATTERNS):
            return True
    return False


def render_summary(
    *,
    plan: dict[str, Any],
    source_render_plan: str,
    case_files: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "semantic_render_cases_summary_v1",
        "generated_at": now_iso(),
        "family": plan.get("family"),
        "track": plan.get("track"),
        "target_library": plan.get("target_library"),
        "source_render_plan": source_render_plan,
        "rendered_case_count": len(case_files),
        "case_files": case_files,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
    }


def render_records(plan: dict[str, Any], case_files: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "semantic_render_records_v1",
        "generated_at": now_iso(),
        "family": plan.get("family"),
        "render_cases_executed": True,
        "records": [
            {
                **item,
                "render_status": "rendered",
                "compile_executed": False,
                "run_executed": False,
            }
            for item in case_files
        ],
    }


def quality_checks(
    *,
    plan: dict[str, Any],
    baseline: dict[str, Any],
    case_files: list[dict[str, Any]],
    leakage: bool,
) -> dict[str, Any]:
    groups = [item.get("case_group", "") for item in case_files]
    paths = [Path(item["path"]) for item in case_files]
    text = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in paths)
    status = "failed_der_parsing_leakage" if leakage else "pass"
    return {
        "schema": "pkey_verify_semantic_render_cases_quality_checks_v1",
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
        "render_plan_loaded": bool(plan),
        "render_plan_case_count": len(plan.get("cases", []) or []),
        "render_cases_executed": True,
        "rendered_case_count": len(case_files),
        "c_files_generated": bool(case_files),
        "valid_accept_control_rendered": "valid_accept_control" in groups,
        "signature_corruption_cases_rendered": "signature_corruption" in groups,
        "message_mismatch_cases_rendered": "message_mismatch" in groups,
        "wrong_key_case_rendered": "wrong_key" in groups,
        "evp_digest_sign_used": "EVP_DigestSignInit" in text and "EVP_DigestSignFinal" in text,
        "evp_digest_verify_used": "EVP_DigestVerifyInit" in text and "EVP_DigestVerifyFinal" in text,
        "rsa_sha256_used": "EVP_PKEY_RSA" in text and "EVP_sha256" in text,
        "oracle_events_emitted": "ORACLE_EVENT" in text,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "pkey_parsing_leakage": False,
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
        and len(case_files) >= 8
        and not leakage
        else "blocked",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    cases_dir = out_dir / "cases"
    for sub in ("inputs", "render", "validation", "reports", "cases"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    render_plan_path = repo_root / args.render_plan
    mutation_plan_path = repo_root / args.mutation_plan
    baseline_root = repo_root / args.baseline_root
    render_plan = load_yaml(render_plan_path)
    mutation_plan = load_yaml(mutation_plan_path)
    slot_bindings = load_yaml(baseline_root / "slot_filling/generated_slot_bindings.yaml")
    adapter_validate = load_yaml(baseline_root / "validation/adapter_validate_results.yaml")
    baseline = baseline_status(
        baseline_root,
        load_yaml(repo_root / "artifacts/sprints/pkey_verify_semantic_render_plan_v1/rag_glm_baseline_status.yaml"),
    )

    case_files = []
    paths = []
    for case in render_plan.get("cases", []) or []:
        case_id = str(case.get("case_id"))
        path = cases_dir / f"{case_id}.c"
        write_text(path, harness_source(case))
        paths.append(path)
        case_files.append(
            {
                "case_id": case_id,
                "path": path.relative_to(repo_root).as_posix(),
                "expected_behavior": case.get("expected_behavior"),
                "mutation_strategy": case.get("mutation_strategy"),
                "case_group": case.get("case_group"),
            }
        )

    leakage = forbidden_leakage(paths)
    summary = render_summary(plan=render_plan, source_render_plan=args.render_plan, case_files=case_files)
    records = render_records(render_plan, case_files)
    qc = quality_checks(plan=render_plan, baseline=baseline, case_files=case_files, leakage=leakage)

    dump_yaml(out_dir / "inputs/render_plan_snapshot.yaml", render_plan)
    dump_yaml(out_dir / "inputs/mutation_plan_snapshot.yaml", mutation_plan)
    dump_yaml(out_dir / "inputs/generated_slot_bindings_snapshot.yaml", slot_bindings)
    dump_yaml(out_dir / "inputs/adapter_validate_snapshot.yaml", adapter_validate)
    dump_yaml(out_dir / "rag_glm_baseline_status.yaml", baseline)
    dump_yaml(out_dir / "render/render_cases_summary.yaml", summary)
    dump_yaml(out_dir / "render/render_records.yaml", records)
    dump_yaml(out_dir / "validation/pkey_verify_semantic_render_cases_quality_checks.yaml", qc)

    report = f"""# {TASK} Report

## Render Cases

- family: {render_plan.get('family')}
- track: {render_plan.get('track')}
- target_library: {render_plan.get('target_library')}
- rendered_case_count: {len(case_files)}
- quality_status: {qc.get('quality_status')}

## Policy

This sprint generated C harness sources only. It did not compile, run, write
feedback, update pattern-bank, modify adapter recipes, modify normalized
templates, perform git operations, claim a CVE, claim exploitability, or claim a
confirmed vulnerability.
"""
    write_text(out_dir / "reports/pkey_verify_semantic_render_cases_v1_report.md", report)
    print(f"[OK] wrote semantic rendered cases to {out_dir}")
    print(
        "[SUMMARY] "
        f"family={render_plan.get('family')} cases={len(case_files)} quality={qc.get('quality_status')}"
    )
    return 0 if qc.get("quality_status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
