#!/usr/bin/env python3
"""Design top wolfSSL family template recipes without generating templates."""

from __future__ import annotations

import argparse
import collections
from pathlib import Path
from typing import Any

import yaml


TOP_FAMILIES = [
    "pkcs_container_parsing",
    "asn1_nested_boundary",
    "x509_parsing",
    "tls_protocol_state_lifecycle",
    "secure_heap_state_lifecycle",
]

PRIORITY_POCS = ["WOLFSSL-POC-0007", "WOLFSSL-POC-0006", "WOLFSSL-POC-0004"]

FAMILY_SPEC = {
    "pkcs_container_parsing": {
        "candidate_pocs": ["WOLFSSL-POC-0007", "WOLFSSL-POC-0006"],
        "harness_family": "x509_asn1_inner_boundary",
        "must_preserve": ["input_loading", "buffer_length_calculation", "target_api_call", "return_code_check", "cleanup_call", "oracle_observable"],
        "apis": ["wc_PKCS12_parse", "wc_PKCS7_VerifySignedData", "wc_PKCS7_DecodeSignedData", "PKCS12_parse", "PKCS7_verify"],
        "blocked_apis": ["mbedTLS PKCS7/PKCS12 no_direct_counterpart", "d2i_PKCS7 until weak evidence is reviewed"],
        "mutation_slots": [
            ("CONTAINER_BYTES", "byte_array", ["valid_pkcs12_der", "malformed_pkcs7_der"], "parser_reject_accept", "container data must remain bounded"),
            ("CONTAINER_FORMAT", "enum", ["DER", "PEM"], "return_code_semantics", "avoid format/API mismatch false positives"),
            ("TRAILING_BYTES", "byte_array", ["empty", "00", "ff00"], "full_consumption", "only meaningful for APIs exposing consumption"),
            ("NESTED_LENGTH_DELTA", "integer", ["-1", "0", "+1", "large"], "parser_reject_accept", "nested length mutation can become generic parse failure"),
            ("EXPECT_RET", "enum", ["success", "reject"], "return_code_semantics", "do not hard-code library numeric values"),
        ],
        "oracle_types": ["parser_reject_accept", "return_code_semantics", "full_consumption", "cleanup_required"],
    },
    "asn1_nested_boundary": {
        "candidate_pocs": ["WOLFSSL-POC-0004"],
        "harness_family": "x509_asn1_inner_boundary",
        "must_preserve": ["input_loading", "buffer_length_calculation", "target_api_call", "return_code_check", "cleanup_call", "oracle_observable"],
        "apis": ["wc_InitDecodedCert", "wc_ParseCert", "wc_FreeDecodedCert", "ASN1_item_d2i", "mbedtls_x509_crt_parse_der"],
        "blocked_apis": ["wc_ParseCert mappings require manual review before adapter generation"],
        "mutation_slots": [
            ("ASN1_NESTED_LENGTH", "integer", ["short", "exact", "long"], "parser_reject_accept", "RAG v2 wc_ParseCert recall is weaker; use as risk, not block"),
            ("DER_BYTES", "byte_array", ["well_formed", "truncated", "malformed_tag"], "return_code_semantics", "keep DER buffer and len paired"),
            ("TRAILING_GARBAGE", "byte_array", ["none", "00", "random_tail"], "full_consumption", "needs pointer/consumption observable"),
            ("NESTED_DEPTH", "integer", ["1", "2", "8"], "parser_reject_accept", "deep nesting may trigger resource limits"),
            ("EXPECT_RET", "enum", ["accept", "reject"], "return_code_semantics", "semantic labels preferred over numeric codes"),
        ],
        "oracle_types": ["parser_reject_accept", "full_consumption", "return_code_semantics"],
    },
    "x509_parsing": {
        "candidate_pocs": [],
        "harness_family": "x509_asn1_inner_boundary",
        "must_preserve": ["input_loading", "buffer_length_calculation", "target_api_call", "return_code_check", "cleanup_call", "oracle_observable"],
        "apis": ["wolfSSL_X509_load_certificate_file", "wolfSSL_X509_free", "d2i_X509", "X509_free", "mbedtls_x509_crt_parse_der", "mbedtls_x509_crt_free"],
        "blocked_apis": ["wc_ParseCert x509 mappings currently need manual review under gate"],
        "mutation_slots": [
            ("CERT_INPUT", "byte_array_or_path", ["DER", "PEM", "malformed"], "parser_reject_accept", "file/path APIs need fixture handling in later template generation"),
            ("SUBJECT_FIELD", "asn1_field", ["valid_cn", "malformed_cn"], "return_code_semantics", "field mutation may be app-level not parser-level"),
            ("ISSUER_FIELD", "asn1_field", ["valid_issuer", "truncated_issuer"], "return_code_semantics", "avoid interpreting policy rejection as parser bug"),
            ("TRAILING_DATA", "byte_array", ["none", "tail"], "full_consumption", "only if API preserves input consumption signal"),
            ("INVALID_LENGTH", "integer", ["short", "long"], "parser_reject_accept", "length mismatch should be bounded"),
        ],
        "oracle_types": ["parser_reject_accept", "return_code_semantics", "cleanup_required"],
    },
    "tls_protocol_state_lifecycle": {
        "candidate_pocs": [],
        "harness_family": "object_state_lifecycle",
        "must_preserve": ["input_loading", "target_api_call", "return_code_check", "cleanup_call", "oracle_observable"],
        "apis": ["wolfSSL_CTX_new", "wolfSSL_CTX_free", "wolfSSL_new", "wolfSSL_free", "wolfSSL_connect", "wolfSSL_accept", "wolfSSL_read", "wolfSSL_write", "SSL_CTX_new", "SSL_new", "SSL_connect", "SSL_accept", "mbedtls_ssl_config_init", "mbedtls_ssl_init", "mbedtls_ssl_handshake"],
        "blocked_apis": [],
        "mutation_slots": [
            ("INIT_ORDER", "sequence", ["ctx_before_ssl", "ssl_without_ctx"], "lifecycle_state", "API misuse must be labeled false-positive risk"),
            ("SETUP_ORDER", "sequence", ["missing_config", "partial_config"], "return_code_semantics", "distinguish expected safe error from vulnerability"),
            ("HANDSHAKE_STATE", "enum", ["before", "during", "after"], "lifecycle_state", "requires deterministic mocked I/O later"),
            ("IO_BEFORE_HANDSHAKE", "enum", ["read", "write"], "return_code_semantics", "normal API misuse can dominate signal"),
            ("CLEANUP_REPEAT", "integer", ["0", "1", "2"], "crash_or_sanitizer", "double cleanup must not be overreported without crash evidence"),
        ],
        "oracle_types": ["lifecycle_state", "return_code_semantics", "crash_or_sanitizer"],
    },
    "secure_heap_state_lifecycle": {
        "candidate_pocs": [],
        "harness_family": "object_state_lifecycle",
        "must_preserve": ["target_api_call", "return_code_check", "cleanup_call", "oracle_observable"],
        "apis": ["wolfSSL_Malloc", "wolfSSL_Free", "wolfSSL_SetAllocators", "XMALLOC", "XFREE", "OPENSSL_malloc", "OPENSSL_free", "CRYPTO_set_mem_functions", "CRYPTO_secure_malloc", "CRYPTO_secure_free", "mbedtls_calloc", "mbedtls_free", "mbedtls_platform_set_calloc_free"],
        "blocked_apis": [],
        "mutation_slots": [
            ("ALLOCATOR_INITIALIZED", "boolean", ["true", "false"], "lifecycle_state", "uninitialized allocator behavior may be expected safe rejection"),
            ("MALLOC_SIZE", "size_t", ["0", "1", "16", "large"], "return_code_semantics", "avoid unbounded allocation"),
            ("FREE_ORDER", "sequence", ["free_once", "free_before_use", "free_after_replace"], "cleanup_required", "API misuse must be down-ranked"),
            ("DOUBLE_FREE_CANDIDATE", "boolean", ["false", "true"], "crash_or_sanitizer", "requires explicit sanitizer evidence"),
            ("ALLOCATOR_REPLACEMENT", "enum", ["default", "custom"], "lifecycle_state", "custom allocator must be deterministic"),
        ],
        "oracle_types": ["cleanup_required", "lifecycle_state", "crash_or_sanitizer"],
    },
}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return {"_load_error": str(exc)}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, Dumper=NoAliasDumper, sort_keys=False, allow_unicode=True), encoding="utf-8")


def render_md(data: Any, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{pad}- {key}:")
                lines.extend(render_md(value, indent + 1))
            else:
                lines.append(f"{pad}- {key}: {value}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.extend(render_md(item, indent + 1))
            else:
                lines.append(f"{pad}- {item}")
    else:
        lines.append(f"{pad}- {data}")
    return lines


def dump_md(path: Path, title: str, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", ""]
    lines.extend(render_md(data))
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_pair(base: Path, title: str, data: Any) -> None:
    dump_yaml(base.with_suffix(".yaml"), data)
    dump_md(base.with_suffix(".md"), title, data)


def as_items(data: Any, keys: list[str]) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
    return []


def load_items(path: str | Path, keys: list[str]) -> list[dict[str, Any]]:
    return as_items(load_yaml(Path(path)), keys)


def input_summary(args: argparse.Namespace) -> dict[str, Any]:
    paths = {
        "template_schema": args.template_schema,
        "template_coverage": args.template_coverage,
        "template_candidates": args.template_candidates,
        "template_generalizer_plan": "artifacts/sprints/template_schema_inventory_v1/reports/template_generalizer_v1_plan.yaml",
        "ast_mask_inventory": args.ast_mask_inventory,
        "ast_mask_schema": args.ast_mask_schema,
        "ast_mask_alignment": args.ast_mask_alignment,
        "adapter_ready": args.adapter_ready,
        "mapping_gate": args.mapping_gate,
        "blocked_mappings": args.blocked_mappings,
        "corrected_candidates": args.corrected_candidates,
        "wolfssl_cards": args.wolfssl_cards,
        "counterpart_cards": args.counterpart_cards,
        "wolfssl_constraints": "knowledge_raw/api_constraints/wolfssl_top_family_api_constraints.yaml",
        "cross_constraints": "knowledge_raw/api_constraints/cross_library_counterpart_api_constraints.yaml",
        "wolfssl_call_sequences": "knowledge_raw/api_constraints/wolfssl_call_sequences.yaml",
        "cross_call_sequences": "knowledge_raw/api_constraints/cross_library_counterpart_call_sequences.yaml",
    }
    return {
        "input_paths": {
            key: {"path": value, "exists": all(Path(p).exists() for p in value) if isinstance(value, list) else Path(value).exists()}
            for key, value in paths.items()
        },
        "why_family_recipe_first": [
            "Top wolfSSL families have no existing family template and no wolfSSL source template.",
            "Family recipe defines must-preserve semantics, mutation slots, oracle style, and AST mask expectations before source template generation.",
            "Direct template generation would risk changing the vulnerability path or inventing C structure.",
            "This sprint emits recipe artifacts only; template_generalizer_v1 will later consume family recipe plus tree-sitter AST mask pipeline outputs.",
        ],
        "strict_non_actions": {
            "generate_c_template": False,
            "run_poc": False,
            "compile_run": False,
            "render": False,
            "glm": False,
        },
    }


def mappings_by_family(items: list[dict[str, Any]], family: str) -> list[dict[str, Any]]:
    return sorted([x for x in items if x.get("family") == family], key=lambda x: (str(x.get("target_library", "")), str(x.get("wolfssl_api", "")), str(x.get("target_api", ""))))


def api_slots_for_family(family: str, gate_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    slots = []
    for api in FAMILY_SPEC[family]["apis"]:
        matching = [x for x in gate_items if x.get("family") == family and (x.get("wolfssl_api") == api or x.get("target_api") == api)]
        allowed_targets = sorted({f"{x.get('target_library')}:{x.get('target_api')}" for x in matching if x.get("adapter_usable")})
        blocked_targets = sorted({f"{x.get('target_library')}:{x.get('target_api')}" for x in matching if not x.get("adapter_usable")})
        slots.append({
            "slot_name": api,
            "source_api": api if api.startswith(("wc_", "wolfSSL", "X", "XMALLOC")) else "",
            "allowed_target_apis": allowed_targets,
            "blocked_target_apis": blocked_targets,
            "mapping_gate_status": sorted({str(x.get("gate_status")) for x in matching}) or ["not_in_mapping_gate"],
            "notes": "candidate mapping only; not confirmed equivalence",
        })
    return slots


def adapter_scope_for_family(family: str, gate_items: list[dict[str, Any]], blocked: list[dict[str, Any]]) -> dict[str, Any]:
    fam = mappings_by_family(gate_items, family)
    fam_blocked = mappings_by_family(blocked, family)
    scope = {
        "family": family,
        "source_library": "wolfssl",
        "allowed_targets": {
            "openssl": {"allowed_apis": [], "candidate_only_apis": []},
            "mbedtls": {"allowed_apis": [], "candidate_only_apis": []},
        },
        "blocked_targets": [],
        "adapter_ready_mapping_count": 0,
        "candidate_only_mapping_count": 0,
        "manual_review_mapping_count": 0,
        "notes": ["usable_for_adapter remains candidate mapping, not confirmed equivalence"],
    }
    for item in fam:
        target_lib = str(item.get("target_library") or "")
        target_api = str(item.get("target_api") or "")
        if target_lib not in scope["allowed_targets"]:
            continue
        if item.get("adapter_usable"):
            scope["adapter_ready_mapping_count"] += 1
            status = str(item.get("gate_status") or "")
            if status == "usable_for_adapter":
                scope["allowed_targets"][target_lib]["allowed_apis"].append(target_api)
            else:
                scope["candidate_only_mapping_count"] += 1
                scope["allowed_targets"][target_lib]["candidate_only_apis"].append(target_api)
        if str(item.get("gate_status")) == "needs_manual_review":
            scope["manual_review_mapping_count"] += 1
    for item in fam_blocked:
        scope["blocked_targets"].append({
            "target_library": item.get("target_library"),
            "target_api": item.get("target_api"),
            "reason": item.get("reason"),
            "source_api": item.get("wolfssl_api"),
        })
    for target in scope["allowed_targets"].values():
        target["allowed_apis"] = sorted(set(filter(None, target["allowed_apis"])))
        target["candidate_only_apis"] = sorted(set(filter(None, target["candidate_only_apis"])))
    return scope


def make_recipe(family: str, gate_items: list[dict[str, Any]], blocked: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    spec = FAMILY_SPEC[family]
    fam_candidates = [x for x in candidates if x.get("family") == family and x.get("source_library") == "wolfssl"]
    candidate_pocs = spec["candidate_pocs"] or [str(x.get("poc_id")) for x in fam_candidates[:5]]
    scope = adapter_scope_for_family(family, gate_items, blocked)
    mode = "source_template_from_poc" if candidate_pocs else "needs_new_family_recipe"
    return {
        "recipe_id": f"{family}_wolfssl_template_recipe_v1",
        "family": family,
        "source_library": "wolfssl",
        "candidate_pocs": candidate_pocs,
        "harness_family": spec["harness_family"],
        "recommended_generalization_mode": mode,
        "template_files_to_generate": ["poc_original.c", "tmpl_wolfssl.c", "template_meta.yaml", "mask_report.yaml", "ast_mask_report.yaml", "selected_mask_units.yaml"],
        "must_preserve_semantics": spec["must_preserve"],
        "ast_mask_preserve_units": [
            {"unit_type": "trigger_call", "node_kind_hint": "call_expression", "reason": "preserve source API path and oracle trigger"},
            {"unit_type": "cleanup_call", "node_kind_hint": "call_expression", "reason": "preserve ownership/lifecycle semantics"},
            {"unit_type": "oracle_check", "node_kind_hint": "if_statement or return_statement", "reason": "preserve observable safe/bug/triage classification"},
        ],
        "ast_maskable_units": [
            {"unit_type": "api_argument", "slot_name": slot[0], "node_kind_hint": "argument or literal", "reason": slot[4]}
            for slot in spec["mutation_slots"]
        ],
        "mutation_slots": [
            {"slot_name": name, "slot_type": typ, "examples": examples, "allowed_mutations": ["boundary", "malformed", "valid_control"], "safety_notes": notes}
            for name, typ, examples, _oracle, notes in spec["mutation_slots"]
        ],
        "api_slots": api_slots_for_family(family, gate_items),
        "cleanup_slots": [
            {"slot_name": "cleanup_call", "source_cleanup": "family-specific wolfSSL cleanup/free API", "target_cleanup_candidates": sorted({x.get("target_api") for x in mappings_by_family(gate_items, family) if "free" in str(x.get("target_api", "")).lower() or "Free" in str(x.get("wolfssl_api", ""))}), "required": True}
        ],
        "oracle_types": spec["oracle_types"],
        "adapter_scope": {
            "allowed_targets": scope["allowed_targets"],
            "blocked_targets": scope["blocked_targets"],
            "candidate_only_targets": {
                lib: data["candidate_only_apis"] for lib, data in scope["allowed_targets"].items()
            },
        },
        "rag_evidence_required": ["source_api_card", "target_api_card", "mapping_gate", "constraints", "call_sequence"],
        "tree_sitter_ast_mask_pipeline": {
            "expected_script": ["template_maker/ast_mask_tree_sitter.py", "template_maker/ast_mask_lite.py", "template_maker/ast_mask_select.py"],
            "expected_outputs": ["ast_mask_report.yaml", "selected_mask_units.yaml"],
            "canonical_schema": {"ast_units_field": "ast_mask_units", "selected_units_field": "selected_units"},
            "fallback_allowed": True,
        },
        "glm_allowed": {
            "default": False,
            "allowed_later_for": ["adapter_slot_filling", "slot_bindings"],
            "forbidden_for": ["full_c_generation", "freeform_harness_generation", "ast_selection"],
        },
        "risk_notes": spec["blocked_apis"] + ["Do not report candidate mapping as confirmed equivalence or vulnerability."],
    }


def ast_mask_plan() -> dict[str, Any]:
    return {
        "tree_sitter_ast_mask_plan": {
            "expected_inputs": ["poc_original.c", "tmpl_wolfssl.c", "family_recipe.yaml", "mapping_gate_results.yaml", "rag_evidence"],
            "expected_outputs": ["ast_mask_report.yaml", "selected_mask_units.yaml"],
            "preserve_node_kinds": ["function_definition", "call_expression", "if_statement", "return_statement", "cleanup call_expression"],
            "maskable_node_kinds": ["argument", "identifier", "number_literal", "string_literal", "array_initializer", "preproc_def"],
            "mutation_node_kinds": ["byte array literals", "length constants", "enum constants", "parser mode arguments", "lifecycle sequence calls"],
            "validation_rules": [
                "must include trigger_call selected unit",
                "must include oracle or preserve_oracle selected unit",
                "must include cleanup unit when family requires cleanup",
                "must preserve harness_family and trigger_apis compatibility",
                "must not allow GLM to freely rewrite AST or generate C",
            ],
            "fallback": {"lite_backend_allowed": True, "reason": "tree-sitter dependencies are optional; AST-lite keeps deterministic role-aware extraction available"},
        }
    }


def oracle_plan(recipes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    family_items = []
    for family in TOP_FAMILIES:
        oracles = recipes[family]["oracle_types"]
        family_items.append({
            "family": family,
            "primary_oracles": oracles[:2],
            "secondary_oracles": oracles[2:],
            "unsafe_oracles": ["crash_or_sanitizer without ASAN/UBSAN/SEGV evidence", "nonzero return code treated as crash"],
            "false_positive_risks": ["API misuse", "candidate mapping mistaken for confirmed equivalence", "no_direct_counterpart forced into adapter"],
            "expected_result_labels": ["migrated_safe", "semantic_divergence_candidate", "migrated_bug_candidate", "api_misuse_false_positive", "blocked_no_direct_counterpart", "needs_triage"],
        })
    return {"families": family_items}


def mutation_plan(recipes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "families": [
            {
                "family": family,
                "mutation_slots": [
                    {
                        "slot_name": slot["slot_name"],
                        "mutation_type": slot["slot_type"],
                        "examples": slot["examples"],
                        "expected_oracle": next((x[3] for x in FAMILY_SPEC[family]["mutation_slots"] if x[0] == slot["slot_name"]), ""),
                        "risk": slot["safety_notes"],
                    }
                    for slot in recipes[family]["mutation_slots"]
                ],
                "mutation_budget_hint": {"small": 8, "medium": 32, "large": 96},
                "scheduler_features": ["family", "oracle_type", "target_library", "mapping_gate_status", "seed_type"],
                "notes": "Slots support controlled variants around API semantics and oracle observables, not only replay of historical PoC bytes.",
            }
            for family in TOP_FAMILIES
        ]
    }


def select_generalizer_inputs(candidates: list[dict[str, Any]], scopes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    selected = []
    for poc in PRIORITY_POCS:
        item = next((x for x in candidates if x.get("poc_id") == poc), None)
        if not item:
            continue
        family = str(item.get("family"))
        scope = scopes.get(family, {})
        openssl_allowed = scope.get("allowed_targets", {}).get("openssl", {}).get("allowed_apis", [])
        mbedtls_allowed = scope.get("allowed_targets", {}).get("mbedtls", {}).get("allowed_apis", [])
        first_target = f"openssl:{openssl_allowed[0]}" if openssl_allowed else (f"mbedtls:{mbedtls_allowed[0]}" if mbedtls_allowed else "")
        selected.append({
            "poc_id": poc,
            "family": family,
            "source_library": "wolfssl",
            "recommended_recipe": f"family_recipes/{family}_recipe.yaml",
            "recommended_first_target": first_target,
            "blocked_targets": scope.get("blocked_targets", []),
            "why_selected": "priority wolfSSL PoC with adapter-ready support and source_template_from_poc mode",
            "expected_template_mode": "source_template_from_poc",
            "priority": "high",
        })
    return {"selected_candidates": selected}


def next_action(recipes: dict[str, dict[str, Any]], selected: dict[str, Any]) -> dict[str, Any]:
    clear = len(recipes) == len(TOP_FAMILIES) and bool(selected.get("selected_candidates"))
    return {
        "next_task_name": "template_generalizer_v1" if clear else "family_mapping_gap_followup_v1",
        "why": "Family recipes are clear and selected wolfSSL candidates are explicit." if clear else "Recipe or candidate selection is incomplete.",
    }


def final_report(recipes: dict[str, dict[str, Any]], scopes: dict[str, dict[str, Any]], selected: dict[str, Any], next_step: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_recipes_for_top_families": sorted(recipes.keys()),
        "recipe_summaries": {
            family: {
                "must_preserve_semantics": recipe["must_preserve_semantics"],
                "maskable_slots": [x["slot_name"] for x in recipe["mutation_slots"]],
                "oracle_types": recipe["oracle_types"],
            }
            for family, recipe in recipes.items()
        },
        "tree_sitter_ast_mask_pipeline_usage": "template_generalizer_v1 should run tree-sitter AST mask pipeline after source template creation, then ast_mask_select.py to produce selected_mask_units.yaml.",
        "adapter_scope": scopes,
        "template_generalizer_candidates": selected["selected_candidates"],
        "generated_new_templates": False,
        "ran_poc": False,
        "ran_glm": False,
        "ran_render": False,
        "modified_pattern_bank": False,
        "modified_scheduler_seed": False,
        "modified_knowledge_raw": False,
        "next_task_name": next_step["next_task_name"],
    }


def readme(next_step: dict[str, Any]) -> dict[str, Any]:
    return {
        "sprint": "template_recipe_design_for_top_wolfssl_families_v1",
        "purpose": "Design family-specific wolfSSL source-template recipes for template_generalizer_v1.",
        "terminology": "Use tree-sitter AST mask pipeline / AST mask pipeline, not AST-SISTER, as the conceptual name.",
        "strict_non_actions": {"run_poc": False, "compile_run": False, "render": False, "glm": False, "template_generation": False},
        "next_task_name": next_step["next_task_name"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template-schema", required=True)
    parser.add_argument("--template-coverage", required=True)
    parser.add_argument("--template-candidates", required=True)
    parser.add_argument("--ast-mask-inventory", required=True)
    parser.add_argument("--ast-mask-schema", required=True)
    parser.add_argument("--ast-mask-alignment", required=True)
    parser.add_argument("--adapter-ready", required=True)
    parser.add_argument("--mapping-gate", required=True)
    parser.add_argument("--blocked-mappings", required=True)
    parser.add_argument("--corrected-candidates", required=True)
    parser.add_argument("--wolfssl-cards", required=True)
    parser.add_argument("--counterpart-cards", nargs="+", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out_dir)
    for sub in ["input", "existing_schema", "family_recipes", "ast_mask_plan", "oracle_plan", "adapter_scope", "mutation_plan", "candidates", "reports", "logs", "validation"]:
        (out / sub).mkdir(parents=True, exist_ok=True)

    gate_items = load_items(args.mapping_gate, ["gate_results"])
    blocked = load_items(args.blocked_mappings, ["blocked_or_no_direct_counterpart_mappings"])
    candidates = load_items(args.template_candidates, ["top_candidates"])
    recipes = {family: make_recipe(family, gate_items, blocked, candidates) for family in TOP_FAMILIES}
    scopes = {family: adapter_scope_for_family(family, gate_items, blocked) for family in TOP_FAMILIES}
    selected = select_generalizer_inputs(candidates, scopes)
    next_step = next_action(recipes, selected)

    write_pair(out / "input/template_recipe_input_summary", "Template Recipe Input Summary", input_summary(args))
    dump_yaml(out / "existing_schema/template_schema_inputs_observed.yaml", {
        "template_schema": load_yaml(Path(args.template_schema)),
        "ast_mask_schema": load_yaml(Path(args.ast_mask_schema)),
        "ast_mask_alignment": load_yaml(Path(args.ast_mask_alignment)),
    })
    for family, recipe in recipes.items():
        dump_yaml(out / f"family_recipes/{family}_recipe.yaml", recipe)
    write_pair(out / "family_recipes/top_family_template_recipes", "Top Family Template Recipes", {"recipes": list(recipes.values())})
    write_pair(out / "ast_mask_plan/tree_sitter_ast_mask_recipe_plan", "Tree-Sitter AST Mask Recipe Plan", ast_mask_plan())
    write_pair(out / "oracle_plan/family_oracle_plan", "Family Oracle Plan", oracle_plan(recipes))
    write_pair(out / "adapter_scope/family_adapter_scope", "Family Adapter Scope", {"families": list(scopes.values())})
    write_pair(out / "mutation_plan/family_mutation_plan", "Family Mutation Plan", mutation_plan(recipes))
    write_pair(out / "candidates/template_generalizer_input_selection", "Template Generalizer Input Selection", selected)
    write_pair(out / "reports/next_action_after_template_recipe_design", "Next Action After Template Recipe Design", next_step)
    write_pair(out / "reports/template_recipe_design_for_top_wolfssl_families_report", "Template Recipe Design For Top wolfSSL Families Report", final_report(recipes, scopes, selected, next_step))
    dump_md(out / "README.md", "template_recipe_design_for_top_wolfssl_families_v1", readme(next_step))

    print(f"template_recipe_design_for_top_wolfssl_families_v1 complete: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
