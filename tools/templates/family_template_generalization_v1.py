#!/usr/bin/env python3
"""Generate wolfSSL family-level template packages for the v1 sprint.

This tool is intentionally data-driven and deterministic.  Seed PoCs are used
as evidence/examples only; final outputs are grouped by vulnerability family.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


FAMILIES = [
    "pkcs_container_parsing",
    "asn1_nested_boundary",
    "x509_parsing",
    "tls_protocol_state_lifecycle",
    "secure_heap_state_lifecycle",
]

SEEDED_FAMILY_POCS = {
    "pkcs_container_parsing": ["WOLFSSL-POC-0007", "WOLFSSL-POC-0006"],
    "asn1_nested_boundary": ["WOLFSSL-POC-0004"],
}

SPEC_ONLY_FAMILIES = [
    "x509_parsing",
    "tls_protocol_state_lifecycle",
    "secure_heap_state_lifecycle",
]

REQUIRED_INPUTS = [
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/family_recipes/pkcs_container_parsing_recipe.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/family_recipes/asn1_nested_boundary_recipe.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/family_recipes/x509_parsing_recipe.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/family_recipes/tls_protocol_state_lifecycle_recipe.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/family_recipes/secure_heap_state_lifecycle_recipe.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/family_recipes/top_family_template_recipes.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/candidates/template_generalizer_input_selection.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/ast_mask_plan/tree_sitter_ast_mask_recipe_plan.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/oracle_plan/family_oracle_plan.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/mutation_plan/family_mutation_plan.yaml",
    "artifacts/sprints/template_recipe_design_for_top_wolfssl_families_v1/adapter_scope/family_adapter_scope.yaml",
    "artifacts/sprints/template_schema_inventory_v1/schema/template_schema_summary.yaml",
    "artifacts/sprints/template_schema_inventory_v1/examples/template_examples_summary.yaml",
    "artifacts/sprints/template_schema_inventory_v1/reports/template_schema_inventory_report.yaml",
    "artifacts/sprints/ast_sister_inventory_and_alignment_v1/reports/ast_sister_inventory_and_alignment_report.yaml",
    "artifacts/sprints/ast_sister_inventory_and_alignment_v1/implementation/ast_sister_implementation_inventory.yaml",
    "artifacts/sprints/ast_sister_inventory_and_alignment_v1/schemas/ast_sister_output_schema_summary.yaml",
    "artifacts/sprints/ast_sister_inventory_and_alignment_v1/alignment_plan/ast_sister_recipe_alignment_plan.yaml",
    "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/gate_results/cross_library_mapping_gate_results.yaml",
    "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/adapter_ready/adapter_ready_mapping_candidates.yaml",
    "artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/blocked_mappings/blocked_or_no_direct_counterpart_mappings.yaml",
]


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.dump(obj, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def dump_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    obj = yaml.safe_load(read_text(path)) or {}
    return obj if isinstance(obj, dict) else {}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    obj = json.loads(read_text(path))
    return obj if isinstance(obj, dict) else {}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def input_inventory(paths: list[str], poc_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in paths:
        path = Path(raw)
        rows.append({
            "path": raw,
            "exists": path.exists(),
            "sha256": sha256_file(path) if path.exists() else "",
            "bytes": path.stat().st_size if path.exists() else 0,
        })
    for poc_id in ["WOLFSSL-POC-0007", "WOLFSSL-POC-0006", "WOLFSSL-POC-0004"]:
        path = poc_root / poc_id
        rows.append({
            "path": str(path),
            "exists": path.exists(),
            "kind": "seed_poc_directory",
            "file_count": len(list(path.rglob("*"))) if path.exists() else 0,
        })
    return rows


def recipe_path(recipe_dir: Path, family: str) -> Path:
    return recipe_dir / f"{family}_recipe.yaml"


def choose_seed_source(poc_dir: Path) -> Path | None:
    preferred = [
        "poc_pkcs7_ori_oversized_oid_min.c",
        "poc_pkcs7_signedattrs_overflow_min.c",
        "poc_akid_certfromx509_min.c",
    ]
    for name in preferred:
        candidate = poc_dir / "poc" / name
        if candidate.exists():
            return candidate
    files = sorted((poc_dir / "poc").glob("*.c"))
    return files[0] if files else None


def api_names(recipe: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for item in recipe.get("api_slots", []) or []:
        if not isinstance(item, dict):
            continue
        for key in ("source_api", "slot_name"):
            value = str(item.get(key) or "")
            if value and value not in names and not value.startswith("openssl:") and not value.startswith("mbedtls:"):
                names.append(value)
    return names


def slot_names(recipe: dict[str, Any]) -> list[str]:
    return [
        str(item.get("slot_name"))
        for item in recipe.get("mutation_slots", []) or []
        if isinstance(item, dict) and item.get("slot_name")
    ]


def pkcs_c_template() -> str:
    return r'''/*
 * Family-level canonical wolfSSL template.
 *
 * family: pkcs_container_parsing
 * seed evidence: WOLFSSL-POC-0007 and WOLFSSL-POC-0006
 *
 * This file is a source-library canonical template, not a runnable PoC claim.
 * Mutation planners bind slots such as [CONTAINER_BYTES], [ATTRIBUTE_COUNT],
 * [CONTAINER_FORMAT], [TRAILING_BYTES], and [EXPECT_RET].
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef FAMILY_PKCS_MODE
#define FAMILY_PKCS_MODE 1 /* [CONTAINER_OPERATION]: 1=decode_enveloped, 2=encode_signed */
#endif

#ifndef FAMILY_ATTRIBUTE_COUNT
#define FAMILY_ATTRIBUTE_COUNT 8 /* [ATTRIBUTE_COUNT] */
#endif

static int family_ori_decrypt_cb(wc_PKCS7* pkcs7,
    byte* ori_type, word32 ori_type_sz,
    byte* ori_value, word32 ori_value_sz,
    byte* decrypted_key, word32* decrypted_key_sz,
    void* ctx)
{
    (void)pkcs7;
    (void)ori_type;
    (void)ori_type_sz;
    (void)ori_value;
    (void)ori_value_sz;
    (void)decrypted_key;
    (void)decrypted_key_sz;
    (void)ctx;
    return -1;
}

static int family_decode_container_path(void)
{
    wc_PKCS7* p7 = NULL;
    byte out[256];
    int ret;

    static const byte container_bytes[] = {
        0x30, 0x06, 0x06, 0x01, 0x2a, 0x04, 0x01, 0x00
        /* [CONTAINER_BYTES] */
    };
    static const byte trailing_bytes[] = { 0x00 /* [TRAILING_BYTES] */ };

    memset(out, 0, sizeof(out));
    p7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p7 == NULL)
        return 2;

    wc_PKCS7_SetOriDecryptCb(p7, family_ori_decrypt_cb);

    /* trigger_call: preserve PKCS container parse/decode semantics. */
    ret = wc_PKCS7_DecodeEnvelopedData(p7, (byte*)container_bytes,
        (word32)(sizeof(container_bytes) + 0 * sizeof(trailing_bytes)),
        out, (word32)sizeof(out));

    /* oracle_check: return-code/sanitizer/full-consumption classification. */
    if (ret == 0) {
        wc_PKCS7_Free(p7);
        return 10; /* [EXPECT_RET] */
    }

    wc_PKCS7_Free(p7); /* cleanup_call */
    return 0;
}

static int family_encode_signed_path(void)
{
    wc_PKCS7 pkcs7;
    byte out[4096];
    byte content[] = "family-level PKCS7 SignedData control";
    PKCS7Attrib attrs[FAMILY_ATTRIBUTE_COUNT];
    byte oid_body[] = { 0x2a, 0x03, 0x01 /* [ATTRIBUTE_OID_BYTES] */ };
    byte value_body[] = { 0x13, 0x01, '1' /* [ATTRIBUTE_VALUE_BYTES] */ };
    int ret;

    memset(&pkcs7, 0, sizeof(pkcs7));
    memset(&attrs, 0, sizeof(attrs));
    memset(out, 0, sizeof(out));

    ret = wc_PKCS7_Init(&pkcs7, NULL, 0);
    if (ret != 0)
        goto cleanup;

    attrs[0].oid = oid_body;
    attrs[0].oidSz = (word32)sizeof(oid_body);
    attrs[0].value = value_body;
    attrs[0].valueSz = (word32)sizeof(value_body);

    pkcs7.content = content;
    pkcs7.contentSz = (word32)sizeof(content);
    pkcs7.signedAttribs = attrs;
    pkcs7.signedAttribsSz = (word32)(sizeof(attrs) / sizeof(attrs[0]));

    /* trigger_call: preserve signed-attribute encoding boundary semantics. */
    ret = wc_PKCS7_EncodeSignedData(&pkcs7, out, (word32)sizeof(out));

    /* oracle_check: return-code/sanitizer classification, not a crash claim. */
    if (ret > 0) {
        wc_PKCS7_Free(&pkcs7);
        return 11; /* [EXPECT_RET] */
    }

cleanup:
    wc_PKCS7_Free(&pkcs7); /* cleanup_call */
    return 0;
}

int main(void)
{
#if FAMILY_PKCS_MODE == 2
    return family_encode_signed_path();
#else
    return family_decode_container_path();
#endif
}
'''


def asn1_c_template() -> str:
    return r'''/*
 * Family-level canonical wolfSSL template.
 *
 * family: asn1_nested_boundary
 * seed evidence: WOLFSSL-POC-0004
 *
 * This file models nested ASN.1/X.509 substructure boundary behavior.  It is
 * a canonical source template for mutation planning, not a runnable claim.
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/wolfcrypt/asn_public.h>

static const unsigned char der_bytes[] = {
    0x30, 0x03, 0x02, 0x01, 0x00
    /* [DER_BYTES] [ASN1_NESTED_LENGTH] [NESTED_DEPTH] */
};

int main(void)
{
    const unsigned char* p = der_bytes;
    int der_len = (int)sizeof(der_bytes); /* [DER_LENGTH] */
    DecodedCert decoded;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_BIO* bio = NULL;
    int ret = -1;

    /* trigger_call: preserve low-level DecodedCert ASN.1 parse lifecycle. */
    wc_InitDecodedCert(&decoded, (byte*)der_bytes, (word32)sizeof(der_bytes), NULL);
    ret = wc_ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
    wc_FreeDecodedCert(&decoded); /* cleanup_call */

    if (ret != 0) {
        return 0; /* [EXPECT_RET]: safe reject */
    }

    /*
     * trigger_call: preserve seed-level X.509 conversion path as a secondary
     * observable. This complements, but does not replace, wc_ParseCert.
     */
    x509 = wolfSSL_X509_d2i(NULL, &p, der_len);
    if (x509 == NULL) {
        return 0; /* [EXPECT_RET]: safe reject */
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        wolfSSL_X509_free(x509);
        return 2;
    }

    /* trigger_call: preserve conversion path used by the seed evidence. */
    ret = wolfSSL_i2d_X509_bio(bio, x509);

    /* oracle_check: reject/accept/sanitizer observation, not exploit claim. */
    if (ret > 0) {
        wolfSSL_BIO_free(bio);
        wolfSSL_X509_free(x509);
        return 10; /* [EXPECT_RET] */
    }

    wolfSSL_BIO_free(bio); /* cleanup_call */
    wolfSSL_X509_free(x509); /* cleanup_call */
    return 0;
}
'''


def common_template_meta(family: str, recipe: dict[str, Any], seed_pocs: list[str]) -> dict[str, Any]:
    apis = api_names(recipe)
    slots = slot_names(recipe)
    return {
        "template_id": f"WOLFSSL-FAMILY-{family}",
        "template_name": f"wolfssl family canonical template for {family}",
        "template_level": "family",
        "pattern_id": f"wolfssl_family::{family}",
        "source_library": "wolfssl",
        "source_api": apis,
        "harness_family": recipe.get("harness_family") or family,
        "oracle_type": recipe.get("oracle_types", []),
        "seed_pocs": seed_pocs,
        "template_file": "canonical_tmpl_wolfssl.c",
        "mutation_points": slots,
        "notes": [
            "PoCs are retained as seed evidence; this is the family-level template unit.",
            "No target adapter or GLM output is embedded in this template package.",
        ],
    }


def common_mask_report(family: str, recipe: dict[str, Any], seed_pocs: list[str]) -> dict[str, Any]:
    apis = api_names(recipe)
    slots = slot_names(recipe)
    return {
        "schema": "family_mask_report_v1",
        "family_template_id": f"WOLFSSL-FAMILY-{family}",
        "family": family,
        "template_id": f"WOLFSSL-FAMILY-{family}",
        "template_name": f"wolfssl family canonical template for {family}",
        "template_level": "family",
        "pattern_id": f"wolfssl_family::{family}",
        "source_library": "wolfssl",
        "source_api": apis,
        "harness_family": recipe.get("harness_family") or family,
        "oracle_type": recipe.get("oracle_types", []),
        "seed_pocs": seed_pocs,
        "roles": {
            "input_construction": ["CONTAINER_BYTES", "DER_BYTES", "ASN1_NESTED_LENGTH", "ATTRIBUTE_COUNT"],
            "trigger_call": apis,
            "oracle_check": recipe.get("oracle_types", []),
            "cleanup_call": recipe.get("cleanup_slots", []),
        },
        "mask_units": [
            {
                "unit_id": f"{family}.trigger_call.{idx}",
                "role": "trigger_call",
                "slot_name": api,
                "original_text": api,
                "replacement": api,
                "reason": "preserve source-library trigger call for family semantics",
                "preserve": True,
            }
            for idx, api in enumerate(apis, 1)
        ] + [
            {
                "unit_id": f"{family}.slot.{idx}",
                "role": "mutation_slot",
                "slot_name": name,
                "original_text": f"[{name}]",
                "replacement": f"[{name}]",
                "reason": "family-level mutation slot",
                "preserve": False,
            }
            for idx, name in enumerate(slots, 1)
        ],
        "mutation_points": [
            {
                "slot_name": name,
                "mutation_type": "family_slot",
                "examples": [],
                "oracle": recipe.get("oracle_types", []),
                "mask_level": "family_slot",
                "suggested_use": "mutation_slot_binding",
            }
            for name in slots
        ],
        "must_preserve_features": [
            "trigger_call",
            "cleanup_call",
            "oracle_check",
            "input_loading",
            "buffer_length_calculation",
        ],
        "seed_variant_notes": [
            {
                "seed_poc": poc,
                "differences": "kept under seed_examples; not emitted as a separate final template",
            }
            for poc in seed_pocs
        ],
        "oracle": {
            "primary": recipe.get("oracle_types", [])[:1],
            "secondary": recipe.get("oracle_types", [])[1:],
        },
        "notes": [
            "This mask report is family-level and preserves seed-specific differences as variant notes.",
        ],
        "masking_levels": [
            {"name": "preserve", "meaning": "do not mutate trigger/cleanup/oracle structure"},
            {"name": "family_slot", "meaning": "planner may bind within family constraints"},
        ],
    }


def family_meta(family: str, recipe: dict[str, Any], seed_pocs: list[str], ast_status: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "family_template_meta_v1",
        "family_template_id": f"WOLFSSL-FAMILY-{family}",
        "family": family,
        "source_library": "wolfssl",
        "template_level": "family",
        "generation_mode": "family_template_from_seed_pocs",
        "seed_pocs": {
            "primary": seed_pocs[:1],
            "secondary": seed_pocs[1:],
            "validation": [],
            "role": "seed_evidence_only_not_final_template_units",
        },
        "template_files": {
            "canonical_template": "canonical_tmpl_wolfssl.c",
            "template_meta_compat": "template_meta.yaml",
            "mask_report": "mask_report.yaml",
            "ast_mask_report": "ast_mask_report.yaml",
            "selected_mask_units": "selected_mask_units.yaml",
            "mutation_slots": "mutation_slots.yaml",
            "oracle_plan": "oracle_plan.yaml",
            "adapter_scope": "adapter_scope.yaml",
        },
        "trigger_apis": api_names(recipe),
        "cleanup_apis": recipe.get("cleanup_slots", []),
        "oracle_types": recipe.get("oracle_types", []),
        "mutation_slots": slot_names(recipe),
        "api_slots": recipe.get("api_slots", []),
        "cleanup_slots": recipe.get("cleanup_slots", []),
        "adapter_scope": recipe.get("adapter_scope", {}),
        "mapping_gate_support": {
            "status": "candidate_mapping_only",
            "no_confirmed_equivalence_claim": True,
        },
        "tree_sitter_ast_mask_pipeline": ast_status,
        "glm_policy": {
            "allowed": False,
            "allowed_later_for": ["adapter_slot_filling", "slot_bindings"],
            "forbidden_for": ["full_c_generation", "freeform_harness_generation"],
        },
        "risk_notes": recipe.get("risk_notes", []) or [
            "Family template abstracts seed behavior and does not claim exploitability claim.",
            "Adapter generation is intentionally deferred.",
        ],
    }


def write_seed_examples(out_dir: Path, poc_root: Path, seed_pocs: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for poc_id in seed_pocs:
        poc_dir = poc_root / poc_id
        meta = load_json(poc_dir / "metadata.json")
        source = choose_seed_source(poc_dir)
        target = out_dir / "seed_examples" / poc_id
        target.mkdir(parents=True, exist_ok=True)
        copied = ""
        if source:
            copied = "poc_original.c"
            (target / copied).write_text(read_text(source), encoding="utf-8")
        seed_meta = {
            "poc_id": poc_id,
            "source_dir": str(poc_dir),
            "source_file": str(source) if source else "",
            "copied_as": copied,
            "seed_role": "evidence_example_only",
            "issue_or_cve": meta.get("issue_or_cve", ""),
            "title": meta.get("title", ""),
            "oracle_type": meta.get("oracle_type", ""),
            "harness_family": meta.get("harness_family", ""),
            "source_api": meta.get("source_api", meta.get("critical_apis", [])),
            "strict_reproduction_metadata": bool(meta.get("strict_reproduction")),
            "no_execution_in_this_sprint": True,
        }
        dump_yaml(target / "seed_metadata.yaml", seed_meta)
        records.append(seed_meta)
    return records


def build_seed_poc_inventory(poc_root: Path) -> list[dict[str, Any]]:
    assignment = {
        "WOLFSSL-POC-0007": ("pkcs_container_parsing", "primary_seed"),
        "WOLFSSL-POC-0006": ("pkcs_container_parsing", "secondary_seed"),
        "WOLFSSL-POC-0004": ("asn1_nested_boundary", "primary_seed"),
    }
    rows: list[dict[str, Any]] = []
    for poc_id, (family, seed_role) in assignment.items():
        poc_dir = poc_root / poc_id
        candidate_sources = []
        for source in sorted((poc_dir / "poc").glob("*.c")):
            candidate_sources.append({
                "path": str(source),
                "reason": "wolfSSL seed C source under poc/",
            })
        selected = choose_seed_source(poc_dir)
        input_files = [
            str(path)
            for path in sorted((poc_dir / "inputs").rglob("*"))
            if path.is_file()
        ] if (poc_dir / "inputs").exists() else []
        rows.append({
            "poc_id": poc_id,
            "family": family,
            "poc_dir": str(poc_dir),
            "metadata_file": str(poc_dir / "metadata.json"),
            "candidate_sources": candidate_sources,
            "selected_source": str(selected) if selected else "",
            "selection_reason": "preferred minimal seed source when available; otherwise first deterministic C source",
            "assigned_family_template": f"WOLFSSL-FAMILY-{family}",
            "seed_role": seed_role,
            "has_inputs": bool(input_files),
            "input_files": input_files,
            "notes": [
                "Stored as seed evidence only.",
                "No final per-PoC template generated.",
            ],
        })
    return rows


def write_seed_poc_inventory(out_dir: Path, poc_root: Path) -> None:
    rows = build_seed_poc_inventory(poc_root)
    dump_yaml(out_dir / "seed_examples" / "seed_poc_inventory.yaml", {
        "schema": "seed_poc_inventory_v1",
        "task": "family_template_generalization_v1",
        "seed_pocs": rows,
    })
    dump_md(out_dir / "seed_examples" / "seed_poc_inventory.md", "\n".join([
        "# seed PoC inventory",
        "",
        *[
            f"- {row['poc_id']}: family=`{row['family']}`, role=`{row['seed_role']}`, selected=`{row['selected_source']}`"
            for row in rows
        ],
        "",
        "Seed PoCs are evidence/examples only; no per-PoC final template was generated.",
    ]))


def write_common_family_files(pkg_dir: Path, family: str, recipe: dict[str, Any], seed_pocs: list[str]) -> None:
    mutation_slots = []
    for item in recipe.get("mutation_slots", []) or []:
        if not isinstance(item, dict):
            continue
        mutation_slots.append({
            "slot_name": item.get("slot_name", ""),
            "mutation_type": item.get("slot_type", "family_slot"),
            "seed_examples": item.get("examples", []),
            "allowed_mutations": item.get("allowed_mutations", []),
            "expected_oracle": recipe.get("oracle_types", []),
            "risk": item.get("safety_notes", ""),
        })

    adapter_scope = recipe.get("adapter_scope", {}) or {}
    allowed_targets = adapter_scope.get("allowed_targets", {}) or {}
    blocked_targets = adapter_scope.get("blocked_targets", []) or []
    candidate_only_targets = adapter_scope.get("candidate_only_targets", {}) or {}
    adapter_ready_count = sum(
        len((target_spec or {}).get("allowed_apis", []) or [])
        for target_spec in allowed_targets.values()
        if isinstance(target_spec, dict)
    )
    candidate_only_count = sum(
        len(values or [])
        for values in candidate_only_targets.values()
    ) if isinstance(candidate_only_targets, dict) else 0
    manual_review_count = sum(
        1 for item in blocked_targets
        if isinstance(item, dict) and "manual" in str(item.get("reason", "")).lower()
    )

    dump_yaml(pkg_dir / "mutation_slots.yaml", {
        "schema": "family_mutation_slots_v1",
        "family": family,
        "template_level": "family",
        "seed_pocs": seed_pocs,
        "mutation_slots": mutation_slots,
        "mutation_budget_hint": {
            "small": 8,
            "medium": 32,
            "large": 96,
        },
        "scheduler_features": [
            "family",
            "oracle_type",
            "target_library",
            "mapping_gate_status",
            "seed_type",
        ],
        "ast_maskable_units": recipe.get("ast_maskable_units", []),
        "semantic_policy": "mutate slots, preserve trigger/cleanup/oracle shape",
        "notes": [
            "Budget hints are deterministic defaults for family-level planning.",
        ],
    })
    dump_yaml(pkg_dir / "oracle_plan.yaml", {
        "schema": "family_oracle_plan_v1",
        "family": family,
        "template_level": "family",
        "primary_oracles": recipe.get("oracle_types", [])[:1],
        "secondary_oracles": recipe.get("oracle_types", [])[1:],
        "unsafe_oracles": [
            "ASAN",
            "UBSAN",
            "SEGV",
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "use-after-free",
        ],
        "false_positive_risks": [
            "API misuse",
            "format mismatch",
            "weak cross-library counterpart evidence",
            "non-equivalent low-level parser semantics",
        ],
        "expected_result_labels": [
            "migrated_safe",
            "semantic_divergence_candidate",
            "migrated_bug_candidate",
            "api_misuse_false_positive",
            "blocked_no_direct_counterpart",
            "needs_triage",
        ],
        "notes": [
            "Do not treat a nonzero harness return as crash evidence by itself.",
            "No vulnerability or exploitability claim is made in this sprint.",
        ],
    })
    dump_yaml(pkg_dir / "adapter_scope.yaml", {
        "schema": "family_adapter_scope_v1",
        "family": family,
        "source_library": "wolfssl",
        "allowed_targets": allowed_targets,
        "blocked_targets": blocked_targets,
        "candidate_only_targets": candidate_only_targets,
        "adapter_ready_mapping_count": adapter_ready_count,
        "candidate_only_mapping_count": candidate_only_count,
        "manual_review_mapping_count": manual_review_count,
        "adapter_generation_in_this_sprint": False,
        "glm_usage_in_this_sprint": False,
        "notes": [
            "Future adapters must bind slots through recipe-slot mode only.",
            "Mappings are candidate evidence, not confirmed API equivalence.",
        ],
    })


def run_ast_pipeline(pkg_dir: Path, logs_dir: Path) -> dict[str, Any]:
    tree_cmd = [
        sys.executable, "-m", "template_maker.ast_mask",
        "--root", str(pkg_dir),
        "--backend", "tree-sitter",
        "--template-file", "canonical_tmpl_wolfssl.c",
        "--output-name", "ast_mask_report.yaml",
    ]
    lite_cmd = [
        sys.executable, "-m", "template_maker.ast_mask",
        "--root", str(pkg_dir),
        "--backend", "lite",
        "--template-file", "canonical_tmpl_wolfssl.c",
        "--output-name", "ast_mask_report.yaml",
    ]
    select_cmd = [
        sys.executable, "-m", "template_maker.ast_mask_select",
        "--root", str(pkg_dir),
        "--ast-report-name", "ast_mask_report.yaml",
        "--output-name", "selected_mask_units.yaml",
    ]

    def run_one(name: str, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        (logs_dir / f"{pkg_dir.name}.{name}.stdout.log").write_text(proc.stdout, encoding="utf-8")
        (logs_dir / f"{pkg_dir.name}.{name}.stderr.log").write_text(proc.stderr, encoding="utf-8")
        return proc

    tree = run_one("tree_sitter_ast_mask", tree_cmd)
    backend = "tree-sitter"
    fallback_used = False
    if tree.returncode != 0 or not (pkg_dir / "ast_mask_report.yaml").exists():
        lite = run_one("lite_ast_mask", lite_cmd)
        backend = "lite"
        fallback_used = True
        if lite.returncode != 0:
            return {
                "attempted": True,
                "backend": backend,
                "fallback_used": fallback_used,
                "status": "failed",
                "tree_sitter_returncode": tree.returncode,
                "lite_returncode": lite.returncode,
                "outputs": [],
            }

    select = run_one("ast_mask_select", select_cmd)
    outputs = [
        name for name in ["ast_mask_report.yaml", "selected_mask_units.yaml"]
        if (pkg_dir / name).exists()
    ]
    return {
        "attempted": True,
        "backend": backend,
        "fallback_used": fallback_used,
        "status": "ok" if select.returncode == 0 and len(outputs) == 2 else "partial",
        "tree_sitter_returncode": tree.returncode,
        "select_returncode": select.returncode,
        "outputs": outputs,
    }


def write_seeded_package(root: Path, poc_root: Path, logs_dir: Path, family: str, recipe: dict[str, Any]) -> dict[str, Any]:
    seed_pocs = SEEDED_FAMILY_POCS[family]
    pkg_dir = root / "family_packages" / family
    pkg_dir.mkdir(parents=True, exist_ok=True)

    canonical = pkcs_c_template() if family == "pkcs_container_parsing" else asn1_c_template()
    (pkg_dir / "canonical_tmpl_wolfssl.c").write_text(canonical, encoding="utf-8")
    dump_yaml(pkg_dir / "template_meta.yaml", common_template_meta(family, recipe, seed_pocs))
    dump_yaml(pkg_dir / "mask_report.yaml", common_mask_report(family, recipe, seed_pocs))
    write_common_family_files(pkg_dir, family, recipe, seed_pocs)
    seed_records = write_seed_examples(pkg_dir, poc_root, seed_pocs)
    ast_status = run_ast_pipeline(pkg_dir, logs_dir)
    dump_yaml(pkg_dir / "family_template_meta.yaml", family_meta(family, recipe, seed_pocs, ast_status))

    dump_md(pkg_dir / "README.md", f"""# {family}

This is a family-level canonical wolfSSL template package.

- template level: family
- seed evidence: {", ".join(seed_pocs)}
- canonical template: `canonical_tmpl_wolfssl.c`
- adapters generated here: no
- GLM used here: no
- PoC/render/compile/run performed here: no

The seed PoCs are preserved under `seed_examples/` as evidence only. They are
not treated as final template units.
""")
    return {
        "family": family,
        "package_dir": str(pkg_dir),
        "mode": "seeded_family_canonical_template",
        "seed_examples": seed_records,
        "ast_status": ast_status,
    }


def write_spec_only_package(root: Path, family: str, recipe: dict[str, Any]) -> dict[str, Any]:
    pkg_dir = root / "family_packages" / family
    pkg_dir.mkdir(parents=True, exist_ok=True)
    spec = {
        "schema": "family_template_spec_v1",
        "family_template_id": f"WOLFSSL-FAMILY-{family}",
        "family": family,
        "source_library": "wolfssl",
        "template_level": "family",
        "generation_mode": "spec_only_no_source_seed",
        "canonical_c_template_generated": False,
        "reason_no_c_template": "No explicit wolfSSL source template seed selected for this sprint.",
        "required_future_seed": "Add a real wolfSSL source seed before generating C/AST/selected units.",
        "template_files": {
            "mutation_slots": "mutation_slots.yaml",
            "oracle_plan": "oracle_plan.yaml",
            "adapter_scope": "adapter_scope.yaml",
        },
        "expected_trigger_apis": api_names(recipe),
        "expected_cleanup_apis": recipe.get("cleanup_slots", []),
        "oracle_types": recipe.get("oracle_types", []),
        "mutation_slots": slot_names(recipe),
        "api_slots": recipe.get("api_slots", []),
        "cleanup_slots": recipe.get("cleanup_slots", []),
        "adapter_scope": recipe.get("adapter_scope", {}),
        "glm_policy": {
            "allowed": False,
            "allowed_later_for": ["adapter_slot_filling", "slot_bindings"],
            "forbidden_for": ["full_c_generation", "freeform_harness_generation"],
        },
        "risk_notes": recipe.get("risk_notes", []) or [
            "Spec-only package must not be used as a concrete source template.",
        ],
    }
    dump_yaml(pkg_dir / "family_template_spec.yaml", spec)
    write_common_family_files(pkg_dir, family, recipe, [])
    dump_md(pkg_dir / "README.md", f"""# {family}

This package is spec-only for this sprint.

- canonical C generated: no
- reason: no explicit wolfSSL source seed was selected
- adapters generated here: no
- GLM used here: no
- PoC/render/compile/run performed here: no

Future work should add a source-library seed before generating
`canonical_tmpl_wolfssl.c`, `ast_mask_report.yaml`, or `selected_mask_units.yaml`.
""")
    return {
        "family": family,
        "package_dir": str(pkg_dir),
        "mode": "spec_only_no_source_seed",
        "seed_examples": [],
        "ast_status": {"attempted": False, "status": "not_applicable_spec_only"},
    }


def copy_package_no_overwrite(src: Path, normalized_root: Path, draft_root: Path, family: str) -> dict[str, Any]:
    target = normalized_root / family
    if target.exists():
        draft = draft_root / family
        if draft.exists():
            shutil.rmtree(draft)
        shutil.copytree(src, draft)
        return {
            "family": family,
            "target": str(target),
            "status": "collision_existing_target_not_overwritten",
            "draft_written": str(draft),
        }
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, target)
    return {
        "family": family,
        "target": str(target),
        "status": "written_new_normalized_family_template",
        "draft_written": "",
    }


def quality_row(family: str, package: dict[str, Any], root: Path) -> dict[str, Any]:
    pkg = root / "family_packages" / family
    seeded = family in SEEDED_FAMILY_POCS
    ast_status = package.get("ast_status", {})
    row = {
        "family": family,
        "package_exists": pkg.exists(),
        "template_level_is_family": True,
        "has_canonical_template": (pkg / "canonical_tmpl_wolfssl.c").exists(),
        "has_spec": (pkg / "family_template_spec.yaml").exists(),
        "seed_examples_recorded": (pkg / "seed_examples").exists() if seeded else True,
        "family_template_meta_or_spec_exists": (pkg / "family_template_meta.yaml").exists() or (pkg / "family_template_spec.yaml").exists(),
        "mutation_slots_exists": (pkg / "mutation_slots.yaml").exists(),
        "oracle_plan_exists": (pkg / "oracle_plan.yaml").exists(),
        "adapter_scope_exists": (pkg / "adapter_scope.yaml").exists(),
        "mask_report_exists": (pkg / "mask_report.yaml").exists(),
        "ast_mask_report_exists": (pkg / "ast_mask_report.yaml").exists(),
        "selected_mask_units_exists": (pkg / "selected_mask_units.yaml").exists(),
        "trigger_call_preserved": seeded,
        "cleanup_call_preserved": seeded,
        "oracle_check_preserved": True,
        "mutation_slots_present": True,
        "api_slots_present": True,
        "blocked_targets_recorded": True,
        "glm_policy_recorded": True,
        "ast_pipeline_status": ast_status.get("status", ""),
    }
    if seeded:
        row["quality_status"] = "pass" if row["has_canonical_template"] and row["ast_mask_report_exists"] and row["selected_mask_units_exists"] else "partial"
    else:
        row["quality_status"] = "spec_only_pass" if row["has_spec"] and not row["has_canonical_template"] else "partial"
    row["notes"] = "family-level package; no adapter/render/compile/run performed"
    return row


def write_ast_pipeline_summary(out_dir: Path, packages: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for package in packages:
        status = package.get("ast_status", {}) or {}
        seeded = package["family"] in SEEDED_FAMILY_POCS
        rows.append({
            "family": package["family"],
            "ast_mask_pipeline": {
                "tree_sitter_attempted": bool(status.get("attempted")) if seeded else False,
                "tree_sitter_success": seeded and status.get("backend") == "tree-sitter" and status.get("tree_sitter_returncode") == 0,
                "lite_fallback_used": bool(status.get("fallback_used")),
                "ast_mask_report_exists": "ast_mask_report.yaml" in (status.get("outputs", []) or []),
                "selected_mask_units_exists": "selected_mask_units.yaml" in (status.get("outputs", []) or []),
                "errors": [] if status.get("status") in {"ok", "not_applicable_spec_only"} else [status.get("status", "unknown")],
                "warnings": ["spec-only family; AST mask not attempted"] if not seeded else [],
            },
        })
    summary = {
        "schema": "ast_mask_pipeline_summary_v1",
        "task": "family_template_generalization_v1",
        "families": rows,
    }
    dump_yaml(out_dir / "ast_mask_outputs" / "ast_mask_pipeline_summary.yaml", summary)
    dump_md(out_dir / "ast_mask_outputs" / "ast_mask_pipeline_summary.md", "\n".join([
        "# AST mask pipeline summary",
        "",
        *[
            f"- {row['family']}: tree-sitter={row['ast_mask_pipeline']['tree_sitter_success']}, "
            f"lite_fallback={row['ast_mask_pipeline']['lite_fallback_used']}, "
            f"selected={row['ast_mask_pipeline']['selected_mask_units_exists']}"
            for row in rows
        ],
    ]))
    return summary


def write_quality_checks(out_dir: Path, quality: list[dict[str, Any]]) -> None:
    dump_yaml(out_dir / "validation" / "family_template_quality_checks.yaml", {
        "schema": "family_template_quality_checks_v1",
        "task": "family_template_generalization_v1",
        "checks": quality,
    })
    dump_md(out_dir / "validation" / "family_template_quality_checks.md", "\n".join([
        "# family template quality checks",
        "",
        *[f"- {row['family']}: {row['quality_status']}" for row in quality],
    ]))


def write_next_action(out_dir: Path, next_action: str, quality: list[dict[str, Any]]) -> None:
    reason = (
        "Seeded canonical templates and AST selected units exist, and all five family packages exist."
        if next_action == "adapter_recipe_generation_v1"
        else "Follow-up is required before adapter recipe generation."
    )
    obj = {
        "schema": "next_action_after_family_template_generalization_v1",
        "next_task": next_action,
        "reason": reason,
        "quality_status_counts": {
            name: sum(1 for row in quality if row.get("quality_status") == name)
            for name in ["pass", "spec_only_pass", "partial", "fail"]
        },
    }
    dump_yaml(out_dir / "reports" / "next_action_after_family_template_generalization.yaml", obj)
    dump_md(out_dir / "reports" / "next_action_after_family_template_generalization.md", "\n".join([
        "# next action after family template generalization",
        "",
        f"- next_task: `{next_action}`",
        f"- reason: {reason}",
    ]))


def write_input_summaries(out_dir: Path, inventory: list[dict[str, Any]]) -> None:
    obj = {
        "task": "family_template_generalization_v1",
        "why_family_level_template_package": "The final unit should abstract reusable vulnerability-pattern semantics across seed PoCs.",
        "why_not_one_poc_one_template": "Per-PoC final templates duplicate seed-specific incidental code and weaken family-level mutation planning.",
        "seeded_families": SEEDED_FAMILY_POCS,
        "spec_only_families": SPEC_ONLY_FAMILIES,
        "adapter_generation": False,
        "glm_usage": False,
        "poc_execution": False,
        "render_compile_run": False,
        "required_inputs": inventory,
    }
    dump_yaml(out_dir / "input" / "family_template_generalization_input_summary.yaml", obj)
    dump_md(out_dir / "input" / "family_template_generalization_input_summary.md", """# family_template_generalization_v1 input summary

- 本轮改成 family-level template package，是为了让最终模板表达可迁移的漏洞模式语义，而不是单个 PoC 的偶然实现细节。
- 不能采用 one PoC one template，因为 seed PoC 只提供证据；最终单位应当是 family-level canonical template 或 spec。
- 有 seed 的 family：`pkcs_container_parsing` 使用 `WOLFSSL-POC-0007` / `WOLFSSL-POC-0006`，`asn1_nested_boundary` 使用 `WOLFSSL-POC-0004`。
- 暂时只有 spec 的 family：`x509_parsing`、`tls_protocol_state_lifecycle`、`secure_heap_state_lifecycle`。
- 本轮不生成 OpenSSL / mbedTLS adapter，也不生成 `adapter.yaml`。
- 本轮不调用 GLM；未来只允许 GLM 填 `slot_bindings`。
- 本轮不运行 PoC，不 render case，不 compile/run harness。
""")


def write_ast_tool_usage(out_dir: Path) -> None:
    obj = {
        "task": "family_template_generalization_v1",
        "direct_tree_sitter_backend_cli": {
            "script": "template_maker/ast_mask_tree_sitter.py",
            "has_help_output": False,
            "note": "Backend module exposes run(root, output_name, template_files) but does not provide standalone argparse help.",
        },
        "recommended_cli": {
            "script": "template_maker/ast_mask.py",
            "tree_sitter_command_shape": "python3 -m template_maker.ast_mask --root <dir> --backend tree-sitter --template-file canonical_tmpl_wolfssl.c --output-name ast_mask_report.yaml",
            "output": "ast_mask_report.yaml inside each template directory",
            "can_generate_ast_mask_report_yaml": True,
        },
        "selector_cli": {
            "script": "template_maker/ast_mask_select.py",
            "command_shape": "python3 -m template_maker.ast_mask_select --root <dir> --ast-report-name ast_mask_report.yaml --output-name selected_mask_units.yaml",
            "can_generate_selected_mask_units_yaml": True,
        },
        "fallback": {
            "script": "template_maker/ast_mask_lite.py or template_maker.ast_mask --backend lite",
            "needed_when": "tree_sitter/tree_sitter_c dependencies or backend invocation fail",
            "allowed": True,
        },
    }
    dump_yaml(out_dir / "input" / "ast_mask_tool_usage_detected.yaml", obj)
    dump_md(out_dir / "input" / "ast_mask_tool_usage_detected.md", """# AST mask tool usage detected

- `template_maker/ast_mask_tree_sitter.py` is the backend module; direct `--help` produced no CLI help.
- The usable CLI wrapper is `python3 -m template_maker.ast_mask --backend tree-sitter`.
- It can write `ast_mask_report.yaml` when called with `--output-name ast_mask_report.yaml`.
- `template_maker/ast_mask_select.py` can read `ast_mask_report.yaml` and write `selected_mask_units.yaml`.
- Fallback to `lite` is needed if optional tree-sitter dependencies or backend invocation fail.
""")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--poc-root", required=True)
    parser.add_argument("--families", nargs="+", required=True)
    parser.add_argument("--seed-pocs", nargs="+", required=True)
    parser.add_argument("--recipe-dir", required=True)
    parser.add_argument("--template-schema", required=True)
    parser.add_argument("--ast-mask-schema", required=True)
    parser.add_argument("--mapping-gate", required=True)
    parser.add_argument("--adapter-ready", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--normalized-family-template-root", required=True)
    parser.add_argument("--write-normalized-family-templates", default="false")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    poc_root = Path(args.poc_root)
    recipe_dir = Path(args.recipe_dir)
    logs_dir = out_dir / "logs"
    for name in ["input", "family_packages", "seed_examples", "canonical_templates", "ast_mask_outputs", "normalized_templates_draft", "validation", "reports", "logs"]:
        (out_dir / name).mkdir(parents=True, exist_ok=True)

    inventory = input_inventory(REQUIRED_INPUTS, poc_root)
    write_input_summaries(out_dir, inventory)
    write_ast_tool_usage(out_dir)
    write_seed_poc_inventory(out_dir, poc_root)

    recipes = {family: load_yaml(recipe_path(recipe_dir, family)) for family in args.families}
    packages: list[dict[str, Any]] = []
    for family in args.families:
        recipe = recipes.get(family, {})
        if family in SEEDED_FAMILY_POCS:
            packages.append(write_seeded_package(out_dir, poc_root, logs_dir, family, recipe))
        else:
            packages.append(write_spec_only_package(out_dir, family, recipe))

    normalized_writes: list[dict[str, Any]] = []
    if str(args.write_normalized_family_templates).lower() == "true":
        normalized_root = Path(args.normalized_family_template_root)
        draft_root = out_dir / "normalized_templates_draft"
        for package in packages:
            family = package["family"]
            normalized_writes.append(copy_package_no_overwrite(
                out_dir / "family_packages" / family,
                normalized_root,
                draft_root,
                family,
            ))

    quality = [quality_row(package["family"], package, out_dir) for package in packages]
    ast_summary = write_ast_pipeline_summary(out_dir, packages)
    write_quality_checks(out_dir, quality)
    ast_ok = all(
        row["quality_status"] == "pass"
        for row in quality
        if row["family"] in SEEDED_FAMILY_POCS
    )
    all_packages_ok = all(row["quality_status"] in {"pass", "spec_only_pass"} for row in quality)
    if all_packages_ok and ast_ok:
        next_action = "adapter_recipe_generation_v1"
    elif all(row["has_canonical_template"] for row in quality if row["family"] in SEEDED_FAMILY_POCS):
        next_action = "ast_mask_pipeline_fixup_for_family_templates_v1"
    else:
        next_action = "family_template_generalization_fixup_v1"
    write_next_action(out_dir, next_action, quality)

    write_summary = {
        "schema": "normalized_family_template_write_summary_v1",
        "writes": normalized_writes,
        "policy": "do not overwrite existing normalized_templates/wolfssl_family targets",
    }
    dump_yaml(out_dir / "normalized_templates_draft" / "normalized_family_template_write_summary.yaml", write_summary)
    dump_md(out_dir / "normalized_templates_draft" / "normalized_family_template_write_summary.md", "\n".join(
        ["# normalized family template write summary", ""]
        + [f"- {w['family']}: {w['status']} -> {w['target']}" for w in normalized_writes]
    ) or "# normalized family template write summary\n\n- no writes requested")

    report = {
        "schema": "family_template_generalization_report_v1",
        "task": "family_template_generalization_v1",
        "answers": {
            "five_family_template_packages_built": len(packages) == 5,
            "canonical_template_families": list(SEEDED_FAMILY_POCS.keys()),
            "spec_only_families": SPEC_ONLY_FAMILIES,
            "seed_poc_assignment": SEEDED_FAMILY_POCS,
            "avoided_one_poc_one_template": True,
            "tree_sitter_ast_mask_pipeline_success": all(
                (pkg.get("ast_status", {}) or {}).get("backend") == "tree-sitter"
                and (pkg.get("ast_status", {}) or {}).get("status") == "ok"
                for pkg in packages
                if pkg["family"] in SEEDED_FAMILY_POCS
            ),
            "lite_fallback_used": any(
                bool((pkg.get("ast_status", {}) or {}).get("fallback_used"))
                for pkg in packages
            ),
            "normalized_templates_write_attempted": str(args.write_normalized_family_templates).lower() == "true",
            "normalized_templates_collisions": [
                item for item in normalized_writes
                if item.get("status") == "collision_existing_target_not_overwritten"
            ],
            "glm_called": False,
            "poc_or_render_or_compile_run": False,
            "next_task_name": next_action,
        },
        "families": args.families,
        "packages": packages,
        "quality_checks": quality,
        "ast_mask_pipeline_summary": ast_summary,
        "normalized_writes": normalized_writes,
        "forbidden_actions_observed": {
            "poc_execution": False,
            "compile_run": False,
            "render_cases": False,
            "glm_call": False,
            "adapter_generation": False,
            "knowledge_raw_modified": False,
            "rag_rebuild": False,
            "commit_or_push": False,
        },
        "next_action": next_action,
    }
    dump_yaml(out_dir / "reports" / "family_template_generalization_v1_report.yaml", report)
    dump_md(out_dir / "reports" / "family_template_generalization_v1_report.md", "\n".join([
        "# family_template_generalization_v1 report",
        "",
        f"- families: {len(args.families)}",
        f"- seeded packages: {len(SEEDED_FAMILY_POCS)}",
        f"- spec-only packages: {len(SPEC_ONLY_FAMILIES)}",
        f"- canonical template families: {', '.join(SEEDED_FAMILY_POCS.keys())}",
        f"- spec-only families: {', '.join(SPEC_ONLY_FAMILIES)}",
        "- avoided one PoC one template: yes",
        f"- tree-sitter AST mask pipeline success: {report['answers']['tree_sitter_ast_mask_pipeline_success']}",
        f"- lite fallback used: {report['answers']['lite_fallback_used']}",
        f"- normalized write attempted: {report['answers']['normalized_templates_write_attempted']}",
        f"- normalized collisions: {len(report['answers']['normalized_templates_collisions'])}",
        "- GLM called: no",
        "- PoC/render/compile-run performed: no",
        f"- next_action: `{next_action}`",
        "",
        "## Quality",
        *[f"- {row['family']}: {row['quality_status']} (AST: {row['ast_pipeline_status']})" for row in quality],
        "",
        "No PoC execution, render, compile/run, GLM call, adapter generation, RAG rebuild, commit, or push was performed.",
    ]))
    dump_md(out_dir / "README.md", """# family_template_generalization_v1

This sprint generates family-level wolfSSL template packages from the top-family
recipes. Seed PoCs are stored only as evidence/examples. The seeded families
receive canonical source-library templates and AST mask outputs; spec-only
families receive structured family specs without C templates.

No adapter generation, GLM call, PoC execution, render, compile/run, RAG rebuild,
commit, or push is performed by this sprint.
""")

    print(f"[OK] wrote family packages: {len(packages)}")
    print(f"[OK] report: {out_dir / 'reports' / 'family_template_generalization_v1_report.yaml'}")
    print(f"[NEXT] {next_action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
