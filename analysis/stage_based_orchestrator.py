#!/usr/bin/env python3
"""Stage-contract mainline orchestrator.

This module creates traceable plans from taxonomy/card/mapping-gate contracts.
It intentionally does not render, compile, run, or analyze runtime harnesses.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
from pathlib import Path
from typing import Any, Callable

import yaml

from analysis.card_contract_loader import (
    TARGET_RUNTIME_STATUS,
    load_card_bundle,
    normalize_target_name,
    split_csv,
    target_preflight,
    target_runtime_status,
    write_text,
    write_yaml,
)
from analysis.fault_surface import fault_surface_engine
from analysis.glm_client import call_glm_structured
from analysis.runtime_harness_bridge import run_runtime_harness_bridge
from tools.templates.template_schema_inventory_v1 import build_template_pack


TASK_NAME = "stage_based_orchestrator_v1"


def emit_progress(
    progress_callback: Callable[[dict[str, Any]], None] | None,
    stage_id: str,
    status: str,
    message: str,
    summary: dict[str, Any] | None = None,
) -> None:
    if progress_callback is None:
        return
    progress_callback(
        {
            "stage": stage_id,
            "status": status,
            "message": message,
            "summary": summary or {},
        }
    )

LEGACY_FAMILY_ALIASES = {
    "parser_full_consumption": "der_pointer_consumption",
    "der_parser_full_consumption": "der_pointer_consumption",
    "roundtrip": "protocol_policy_semantic",
    "roundtrip_metamorphic": "protocol_policy_semantic",
    "pkey_sign_verify": "protocol_policy_semantic",
    "mac_digest_lifecycle": "object_state_lifecycle",
    "aead_lifecycle": "object_state_lifecycle",
}

SLOT_BINDING_ALLOWED_FIELDS = [
    "target",
    "framework_family",
    "concrete_pattern",
    "selected_api",
    "selected_headers",
    "selected_libraries",
    "setup_sequence",
    "call_sequence",
    "teardown_sequence",
    "mutation_values",
    "expected_oracle",
    "confidence_level",
    "needs_human_review",
    "evidence_paths",
    "blocked_reason",
    "notes",
]

OPTIONAL_SLOT_BINDING_FIELDS = {"blocked_reason", "notes"}

REVIEW_WARNING_REASONS = {
    "needs_human_review",
    "selected_api_requires_human_review",
    "selected_api_teardown_without_trigger_call_sequence",
}

SELECTED_API_TRIGGER_CORRECTIONS = {
    (
        "object_state_lifecycle",
        "asn1_store_named_data_zero_len_stale_state",
        "mbedtls_asn1_free_named_data_list",
    ): "mbedtls_asn1_store_named_data",
}

TARGET_API_PREFIX_POLICY = {
    "openssl": {
        "allowed_prefixes": ["d2i_", "i2d_", "EVP_", "OSSL_", "BIO_", "ASN1_", "X509_", "RSA_"],
        "forbidden_prefixes": [],
    },
    "mbedtls": {
        "allowed_prefixes": ["mbedtls_", "psa_"],
        "forbidden_prefixes": ["d2i_", "EVP_", "OSSL_", "BIO_"],
    },
    "botan": {
        "allowed_prefixes": ["Botan::", "botan_"],
        "forbidden_prefixes": ["d2i_", "EVP_", "OSSL_", "mbedtls_", "psa_"],
    },
    "wolfssl": {
        "allowed_prefixes": ["wolfSSL_", "wc_", "wolfCrypt"],
        "forbidden_prefixes": ["d2i_", "EVP_", "OSSL_", "mbedtls_", "psa_"],
    },
}

STAGE_TARGET_ALIASES = {
    "wolfssl-5.9.1": "wolfssl-5.9.1",
    "wolfssl-5.9.1-asan": "wolfssl-5.9.1",
}

STAGE_TARGET_RUNTIME_STATUS = {
    "wolfssl-5.9.1": "runtime_ready",
}

C_LIKE_MARKERS = [
    r"#\s*include\b",
    r"\bint\s+main\s*\(",
    r"\bvoid\s+main\s*\(",
    r"\bgcc\b",
    r"\bclang\b",
    r"\bcmake\b",
]


def _target_policy_key(target: str) -> str:
    if target.startswith("mbedtls"):
        return "mbedtls"
    if target.startswith("botan"):
        return "botan"
    if target.startswith("wolfssl"):
        return "wolfssl"
    return "openssl" if target == "openssl" else target


def _stage_normalize_target_name(target: str) -> str:
    return STAGE_TARGET_ALIASES.get(target, normalize_target_name(target))


def _stage_target_runtime_status(target: str) -> str:
    canonical = _stage_normalize_target_name(target)
    return STAGE_TARGET_RUNTIME_STATUS.get(canonical, target_runtime_status(canonical))


def _canonical_families(bundle: dict[str, Any], requested: list[str], max_families: int) -> tuple[list[str], list[dict[str, str]]]:
    available = list(bundle["framework_families"].keys())
    requested = requested or available
    selected: list[str] = []
    unsupported: list[dict[str, str]] = []
    for item in requested:
        family = LEGACY_FAMILY_ALIASES.get(item, item)
        if family in bundle["framework_families"]:
            if family not in selected:
                selected.append(family)
        else:
            unsupported.append({"requested_family": item, "reason": "not_in_framework_taxonomy"})
    return selected[:max_families], unsupported


def _target_rows(requested_targets: list[str]) -> list[dict[str, Any]]:
    rows = []
    for raw in requested_targets:
        target = _stage_normalize_target_name(raw)
        preflight = target_preflight(raw)
        status = preflight.get("runtime_status") or _stage_target_runtime_status(target)
        if target in STAGE_TARGET_RUNTIME_STATUS:
            status = STAGE_TARGET_RUNTIME_STATUS[target]
        rows.append(
            {
                "requested_target": raw,
                "target": target,
                "runtime_status": status,
                "stage_contract_policy": "runtime_blocked" if status == "blocked_runtime" else "syntax_only_planning",
                "knowledge_card_expected": True,
                "preflight": preflight,
            }
        )
    return rows


def _patterns_by_family(bundle: dict[str, Any], selected_families: list[str]) -> dict[str, list[str]]:
    by_family: dict[str, list[str]] = {family: [] for family in selected_families}
    for pattern_id, pattern in bundle["concrete_patterns"].items():
        family = pattern.get("framework_family")
        if family in by_family:
            by_family[family].append(pattern_id)
    for family in by_family:
        if not by_family[family]:
            by_family[family].append(f"{family}_framework_level_placeholder")
    return by_family


def _target_card_present(bundle: dict[str, Any], target: str, family: str) -> bool:
    return f"{target}/{family}" in bundle["api_cards"]


def _round_robin_cases(
    bundle: dict[str, Any],
    selected_families: list[str],
    target_rows: list[dict[str, Any]],
    max_cases: int,
) -> list[dict[str, Any]]:
    coverage_by_family = bundle["coverage_by_family"]
    family_cards = bundle["family_cards"]
    patterns_by_family = _patterns_by_family(bundle, selected_families)
    cases: list[dict[str, Any]] = []

    max_pattern_depth = max((len(items) for items in patterns_by_family.values()), default=0)
    for depth in range(max_pattern_depth):
        for family in selected_families:
            patterns = patterns_by_family[family]
            if depth >= len(patterns):
                continue
            pattern_id = patterns[depth]
            coverage = coverage_by_family.get(family, {})
            family_card = family_cards.get(family, {})
            for target_row in target_rows:
                if len(cases) >= max_cases:
                    return cases
                target = target_row["target"]
                runtime_status = target_row["runtime_status"]
                card_present = _target_card_present(bundle, target, family)
                target_coverage = (coverage.get("framework_target_cards", {}) or {}).get(target, {})
                if runtime_status == "blocked_runtime":
                    mapping_status = "blocked_runtime"
                elif card_present and target_coverage.get("api_card"):
                    mapping_status = "candidate_mapping_from_card"
                else:
                    mapping_status = "missing_or_partial_mapping"
                cases.append(
                    {
                        "case_id": f"{family}__{pattern_id}__{target}",
                        "framework_family": family,
                        "concrete_pattern": pattern_id,
                        "requested_target": target_row["requested_target"],
                        "target": target,
                        "target_runtime_status": runtime_status,
                        "mapping_status": mapping_status,
                        "card_status": coverage.get("orchestrator_consumable", "missing_or_not_found"),
                        "target_card_status": target_coverage.get("status", "missing_or_not_found"),
                        "harness_shape": family_card.get("harness_shape", {}),
                        "oracle_contract": family_card.get("oracle_contract", {}),
                        "planned_stage": "render_plan_only",
                        "runtime_harness_executed": False,
                    }
                )
    return cases


def _oracle_stage_connected(repo_root: Path) -> bool:
    path = repo_root / "analysis" / "central_oracle_dispatcher.py"
    if not path.exists():
        return False
    return importlib.util.spec_from_file_location("central_oracle_dispatcher", path) is not None


def _build_fault_surface_seed_context(
    *,
    campaign_plan: dict[str, Any],
    render_plan: dict[str, Any],
    template_pack: dict[str, Any],
    slot_doc: dict[str, Any],
    slot_validation_report: dict[str, Any],
    mutation_plan: dict[str, Any],
    runtime_summary: dict[str, Any],
) -> dict[str, Any]:
    """Collect existing stage outputs for the embedded fault-surface hook."""

    bindings = slot_validation_report.get("usable_slot_bindings")
    if not isinstance(bindings, list):
        bindings = slot_doc.get("slot_bindings", [])
    return {
        "seed_id": campaign_plan.get("task_name"),
        "framework_family": ",".join(campaign_plan.get("families", [])),
        "target_libraries": campaign_plan.get("targets", []),
        "campaign_plan": campaign_plan,
        "render_plan": render_plan,
        "template_pack": template_pack,
        "slot_bindings": bindings,
        "mutation_plan": mutation_plan,
        "runtime_results": runtime_summary,
        "hook_position": "runtime_to_oracle",
    }


def _strip_yaml_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped


def _fallback_slot_binding(case: dict[str, Any]) -> dict[str, Any]:
    target = case.get("target", "")
    family = case.get("framework_family", "")
    pattern = case.get("concrete_pattern", "")
    if target == "wolfssl":
        headers = ["wolfssl/options.h", "wolfssl/ssl.h"]
        libs = ["wolfssl", "pthread"]
        api = "wolfSSL_Init"
        setup = ["wolfSSL_Init"]
        teardown = ["wolfSSL_Cleanup"]
    else:
        headers = ["stdio.h"]
        libs = []
        api = "runtime_smoke_placeholder"
        setup = []
        teardown = []
    oracle = (case.get("oracle_contract") or {}).get("oracle_type", "runtime_smoke_observation")
    return {
        "target": target,
        "framework_family": family,
        "concrete_pattern": pattern,
        "selected_api": api,
        "selected_headers": headers,
        "selected_libraries": libs,
        "setup_sequence": setup,
        "call_sequence": [api],
        "teardown_sequence": teardown,
        "mutation_values": {"smoke_variant": "bounded_runtime_smoke"},
        "expected_oracle": oracle,
        "confidence_level": "schema_ready_smoke",
        "needs_human_review": False,
        "evidence_paths": [],
    }


def _build_slot_filling_plan(plan_cases: list[dict[str, Any]], out_dir: Path) -> dict[str, Any]:
    items = []
    for case in plan_cases:
        if case.get("target_runtime_status") != "runtime_ready":
            continue
        items.append(
            {
                "target": case.get("target"),
                "framework_family": case.get("framework_family"),
                "concrete_pattern": case.get("concrete_pattern"),
                "oracle_type": (case.get("oracle_contract") or {}).get("oracle_type", ""),
                "required_output_fields": SLOT_BINDING_ALLOWED_FIELDS,
            }
        )
    plan = {
        "schema": "slot_filling_plan_v1",
        "status": "ready",
        "allowed_generation_mode": "yaml_slots_only",
        "forbidden_generation": [
            "free_form_c_code",
            "free_form_adapter_code",
            "unbounded_mutation",
        ],
        "slot_binding_schema": SLOT_BINDING_ALLOWED_FIELDS,
        "items": items,
        "notes": ["GLM may fill YAML slots only; runtime rendering remains template/bridge-owned."],
    }
    write_yaml(out_dir / "slot_filling_plan.yaml", plan)
    return plan


def _card_api_candidates(card: dict[str, Any]) -> list[Any]:
    candidates = card.get("api_candidates")
    if not isinstance(candidates, list):
        candidates = card.get("candidate_apis")
    return candidates if isinstance(candidates, list) else []


def _api_names(api_candidates: Any, *, trigger_only: bool = True) -> list[str]:
    names: list[str] = []
    if isinstance(api_candidates, list):
        for item in api_candidates:
            if isinstance(item, dict) and item.get("api"):
                if trigger_only and str(item.get("role", "trigger")) == "teardown":
                    continue
                names.append(str(item["api"]))
            elif isinstance(item, str):
                names.append(item)
    return sorted(set(names))


def _candidate_values(api_candidates: Any, field: str, *, trigger_only: bool = False) -> list[str]:
    values: list[str] = []
    if isinstance(api_candidates, list):
        for item in api_candidates:
            if not isinstance(item, dict):
                continue
            if trigger_only and str(item.get("role", "trigger")) == "teardown":
                continue
            value = item.get(field)
            if value:
                values.append(str(value))
    return sorted(set(values))


def _usable_api_card(card: dict[str, Any]) -> bool:
    if not isinstance(card, dict):
        return False
    if str(card.get("status", "")) == "no_target_api_evidence":
        return False
    return bool(_api_names(_card_api_candidates(card), trigger_only=True))


def _usable_support_card(section: str, card: dict[str, Any]) -> bool:
    if not isinstance(card, dict):
        return False
    if str(card.get("status", "")) in {"draft", "skeleton_only"}:
        return False
    if section == "constraints":
        return any(
            bool(card.get(field))
            for field in [
                "selected_api_must_be_public",
                "selected_api_must_be_trigger_api",
                "teardown_api_must_not_be_selected_api",
            ]
        ) or str(card.get("status", "")) == "no_target_api_evidence"
    if section == "call_sequences":
        return bool(card.get("call_sequence_candidates")) or str(card.get("status", "")) == "no_target_api_evidence"
    return True


def _knowledge_card_for_case(
    bundle: dict[str, Any],
    section: str,
    target: str,
    family: str,
    pattern: str,
    *,
    require_usable_api: bool = False,
) -> tuple[str, dict[str, Any], str, dict[str, Any]]:
    cards = bundle.get(section, {})
    pattern_key = f"{target}/{pattern}"
    family_key = f"{target}/{family}"
    pattern_card = cards.get(pattern_key)
    family_card = cards.get(family_key)
    if require_usable_api:
        if isinstance(pattern_card, dict) and _usable_api_card(pattern_card):
            return pattern_key, pattern_card, "pattern_card", {}
        if isinstance(family_card, dict) and _usable_api_card(family_card):
            return family_key, family_card, "family_card_fallback", pattern_card if isinstance(pattern_card, dict) else {}
        if isinstance(pattern_card, dict):
            return pattern_key, pattern_card, "pattern_card_no_usable_api", {}
        if isinstance(family_card, dict):
            return family_key, family_card, "family_card_no_usable_api", {}
        return "", {}, "missing", {}
    if section in {"constraints", "call_sequences"}:
        if isinstance(pattern_card, dict) and _usable_support_card(section, pattern_card):
            return pattern_key, pattern_card, "pattern_card", {}
        if isinstance(family_card, dict) and _usable_support_card(section, family_card):
            return family_key, family_card, "family_card_fallback", pattern_card if isinstance(pattern_card, dict) else {}
        if isinstance(pattern_card, dict):
            return pattern_key, pattern_card, "pattern_card_no_usable_evidence", {}
        if isinstance(family_card, dict):
            return family_key, family_card, "family_card_no_usable_evidence", {}
        return "", {}, "missing", {}
    if isinstance(pattern_card, dict):
        return pattern_key, pattern_card, "pattern_card", {}
    if isinstance(family_card, dict):
        return family_key, family_card, "family_card_fallback", {}
    return "", {}, "missing", {}


def _sequence_candidates(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _target_api_candidate_block(bundle: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    target = str(item.get("target", ""))
    family = str(item.get("framework_family", ""))
    pattern = str(item.get("concrete_pattern", ""))
    card_key, card, source, skipped_pattern_card = _knowledge_card_for_case(
        bundle, "api_cards", target, family, pattern, require_usable_api=True
    )
    constraint_key, constraint_card, constraint_source, _ = _knowledge_card_for_case(
        bundle, "constraints", target, family, pattern
    )
    sequence_key, sequence_card, sequence_source, _ = _knowledge_card_for_case(
        bundle, "call_sequences", target, family, pattern
    )
    api_candidates = _card_api_candidates(card) if card else []
    candidates = _api_names(api_candidates, trigger_only=True) if card else []
    confidence = str(card.get("confidence_level", "evidence_backed")) if candidates else "missing"
    selected_headers = _sequence_candidates(card.get("required_headers")) if card else []
    selected_libraries = _sequence_candidates(card.get("link_libraries")) if card else []
    if not selected_headers:
        selected_headers = _candidate_values(api_candidates, "header", trigger_only=False)
    if not selected_libraries:
        selected_libraries = _candidate_values(api_candidates, "library", trigger_only=False)
    setup_candidates = _sequence_candidates(sequence_card.get("setup_sequence")) if sequence_card else []
    call_candidates = _sequence_candidates(sequence_card.get("call_sequence_candidates")) if sequence_card else []
    if not call_candidates:
        call_candidates = _sequence_candidates(sequence_card.get("call_sequence")) if sequence_card else []
    teardown_candidates = _sequence_candidates(sequence_card.get("teardown_sequence")) if sequence_card else []
    return {
        "target_api_candidates": {
            "source": source,
            "api_card_path": f"knowledge_raw/api_cards/{card_key}.yaml" if card_key else "",
            "api_candidates": candidates,
            "confidence_level": confidence,
            "needs_human_review": bool(card.get("needs_human_review", True)) if card else True,
            "skipped_pattern_card_path": f"knowledge_raw/api_cards/{target}/{pattern}.yaml" if skipped_pattern_card else "",
            "skipped_pattern_card_reason": "no_usable_api_candidates" if skipped_pattern_card else "",
        },
        "constraint_candidates": {
            "source": constraint_source,
            "constraint_card_path": f"knowledge_raw/constraints/{constraint_key}.yaml" if constraint_key else "",
            "selected_api_must_be_public": bool(constraint_card.get("selected_api_must_be_public", False)) if constraint_card else False,
            "selected_api_must_be_trigger_api": bool(constraint_card.get("selected_api_must_be_trigger_api", False)) if constraint_card else False,
            "teardown_api_must_not_be_selected_api": bool(constraint_card.get("teardown_api_must_not_be_selected_api", False)) if constraint_card else False,
        },
        "call_sequence_candidates": {
            "source": sequence_source,
            "call_sequence_card_path": f"knowledge_raw/call_sequences/{sequence_key}.yaml" if sequence_key else "",
        },
        "allowed_values": {
            "api_candidates": candidates,
            "selected_headers": selected_headers,
            "selected_libraries": selected_libraries,
            "setup_sequence_candidates": setup_candidates,
            "call_sequence_candidates": call_candidates,
            "teardown_sequence_candidates": teardown_candidates,
            "mutation_slots": [],
            "expected_oracle_candidates": [item.get("oracle_type")] if item.get("oracle_type") else [],
        },
        "blocked_policy": {
            "if_no_target_api_candidate": "selected_api must be unknown; do not render runtime case"
        }
        if not candidates
        else {},
    }


def _attach_template_refs_to_slot_plan(
    slot_plan: dict[str, Any],
    template_pack: dict[str, Any],
    bundle: dict[str, Any],
    out_dir: Path,
) -> dict[str, Any]:
    by_family = {
        item.get("framework_family"): item
        for item in template_pack.get("template_sources", [])
        if isinstance(item, dict)
    }
    for item in slot_plan.get("items", []):
        source = by_family.get(item.get("framework_family"), {})
        item["template_evidence"] = {
            "normalized_template_paths": source.get("normalized_template_paths", []),
            "adapter_recipe_paths": source.get("adapter_recipe_paths", []),
            "note": "Template evidence is not automatically target API evidence.",
        }
        item["template_status"] = source.get("template_status", "missing_or_needs_review")
        item["normalized_template_paths"] = source.get("normalized_template_paths", [])
        item["adapter_recipe_paths"] = source.get("adapter_recipe_paths", [])
        item["template_pack_source"] = "template_pack.yaml"
        item.update(_target_api_candidate_block(bundle, item))
        item["usable_binding_policy"] = {
            "selected_api_must_be_in_api_candidates": True,
            "selected_headers_must_be_in_selected_headers": True,
            "expected_oracle_must_be_in_candidates": True,
            "needs_human_review_false_required_for_runtime": True,
        }
    slot_plan["inputs"] = sorted(set(slot_plan.get("inputs", []) + ["campaign_plan.yaml", "render_plan.yaml", "template_pack.yaml"]))
    slot_plan["notes"] = slot_plan.get("notes", []) + [
        "Slot filling plan is constrained by template_pack.yaml when template evidence exists.",
        "OpenSSL adapter recipe evidence must not become mbedTLS/Botan/wolfSSL api_candidates.",
        "If allowed_values.api_candidates is empty, selected_api must be unknown.",
    ]
    write_yaml(out_dir / "slot_filling_plan.yaml", slot_plan)
    return slot_plan


def _focus_manual_slot_plan(slot_plan: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    items = [item for item in slot_plan.get("items", []) if isinstance(item, dict)]
    if not items:
        return slot_plan
    targets = {str(item.get("target", "")) for item in items}
    if not targets:
        return slot_plan
    focused = []
    skipped = []
    for item in items:
        allowed = item.get("allowed_values") if isinstance(item.get("allowed_values"), dict) else {}
        candidates = allowed.get("api_candidates", []) if isinstance(allowed, dict) else []
        if candidates:
            focused.append(item)
        else:
            skipped.append(
                {
                    "target": item.get("target"),
                    "framework_family": item.get("framework_family"),
                    "concrete_pattern": item.get("concrete_pattern"),
                    "skip_reason": "no_target_api_candidates",
                }
            )
    if not focused:
        return slot_plan
    updated = dict(slot_plan)
    updated["items"] = focused
    updated["status"] = "focused_ready"
    updated["focused_filter"] = {
        "enabled": True,
        "reason": "manual_handoff_only_uses_items_with_target_api_candidates",
        "included_item_count": len(focused),
        "skipped_item_count": len(skipped),
        "skipped_items": skipped,
    }
    updated["notes"] = updated.get("notes", []) + [
        "Focused manual handoff excludes items without target_api_candidates.",
    ]
    write_yaml(out_dir / "slot_filling_plan.yaml", updated)
    return updated


def _manual_glm_expected_schema() -> dict[str, Any]:
    return {
        "generated_by": "manual_glm_slot_filling",
        "status": "draft",
        "generation_mode": "yaml_slots_only",
        "bindings": [
            {
                "target": "",
                "framework_family": "",
                "concrete_pattern": "",
                "selected_api": "",
                "selected_headers": [],
                "selected_libraries": [],
                "setup_sequence": [],
                "call_sequence": [],
                "teardown_sequence": [],
                "mutation_values": {},
                "expected_oracle": "",
                "confidence_level": "",
                "needs_human_review": True,
                "evidence_paths": [],
                "blocked_reason": "",
                "notes": [],
            }
        ],
    }


def _write_manual_glm_handoff(slot_plan: dict[str, Any], template_pack: dict[str, Any], out_dir: Path) -> None:
    schema = _manual_glm_expected_schema()
    write_yaml(out_dir / "manual_glm_expected_output_schema.yaml", schema)
    targets = sorted({str(item.get("target", "")) for item in slot_plan.get("items", []) if isinstance(item, dict)})
    target_policy_keys = {_target_policy_key(target) for target in targets}
    target_scope = "本轮只处理当前 slot_filling_plan 中列出的 target。"
    target_guard_lines = [
        "selected_api 必须从 allowed_values.api_candidates 中选择。",
        "template_evidence 和 adapter_recipe_paths 只是证据路径，不等于 target-specific api_candidates。",
    ]
    if target_policy_keys and target_policy_keys <= {"botan", "wolfssl"}:
        target_scope = "本轮只处理 Botan / wolfSSL target。"
        target_guard_lines = [
            "selected_api 必须从 allowed_values.api_candidates 中选择。",
            "禁止把 OpenSSL API 填到 Botan 或 wolfSSL target。",
            "禁止把 mbedTLS/PSA API 填到 Botan 或 wolfSSL target。",
            "禁止把 Botan API 填到 wolfSSL target。",
            "禁止把 wolfSSL API 填到 Botan target。",
            "template_evidence 和 adapter_recipe_paths 只是证据路径，不等于 target-specific api_candidates。",
        ]
    elif target_policy_keys == {"mbedtls"}:
        target_scope = "本轮只处理 mbedTLS target。"
        target_guard_lines = [
            "selected_api 必须从 allowed_values.api_candidates 中选择。",
            "禁止把 OpenSSL API 填到 mbedTLS target。",
            "template_evidence 和 adapter_recipe_paths 只是证据路径，不等于 target-specific api_candidates。",
        ]
    request = "\n".join(
        [
            "# Manual GLM Slot Filling Request",
            "",
            "你是 slot filling agent，不是代码生成 agent。",
            "你只能输出 YAML。",
            "不要 Markdown。",
            "不要代码块。",
            "不要解释。",
            "禁止输出 C 代码。",
            "禁止输出 adapter 代码。",
            "禁止自由发挥 API。",
            "只能根据下面的 slot_filling_plan、template_pack、api_candidates、constraints、call_sequences 填充 slot_bindings。",
            "必须只从每个 item 的 allowed_values.api_candidates 中选择 selected_api。",
            "如果 allowed_values.api_candidates 为空，selected_api 必须写 unknown。",
            target_scope,
            *target_guard_lines,
            "不能输出 d2i_* / EVP_* / OSSL_* / BIO_*。",
            "如果你不能填出 selected_headers / selected_libraries / call_sequence，就设置 needs_human_review: true。",
            "只有当 selected_api、headers、libraries、call_sequence、expected_oracle 都来自 allowed_values 或 evidence 时，才允许 needs_human_review: false。",
            "",
            "输出必须满足 manual_glm_expected_output_schema.yaml；建议顶层字段使用 `bindings:`。",
            "不要输出 Markdown 解释，不要输出代码块围栏。",
            "",
            "## manual_glm_expected_output_schema",
            "",
            yaml.safe_dump(schema, sort_keys=False, allow_unicode=True).rstrip(),
            "",
            "## slot_filling_plan",
            "",
            yaml.safe_dump(slot_plan, sort_keys=False, allow_unicode=True).rstrip(),
            "",
            "## template_pack",
            "",
            yaml.safe_dump(template_pack, sort_keys=False, allow_unicode=True).rstrip(),
        ]
    )
    write_text(out_dir / "manual_glm_request.md", request + "\n")


def _load_external_slot_bindings(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return {"bindings": [], "slot_bindings": [], "_slot_binding_input_key": "missing"}
    if isinstance(data.get("bindings"), list):
        input_key = "bindings"
        bindings = data.get("bindings", [])
    elif isinstance(data.get("slot_bindings"), list):
        input_key = "slot_bindings"
        bindings = data.get("slot_bindings", [])
    else:
        input_key = "missing"
        bindings = []
    normalized = dict(data)
    normalized["bindings"] = bindings
    normalized["slot_bindings"] = bindings
    normalized["_slot_binding_input_key"] = input_key
    return normalized


def _call_glm_for_slots(slot_plan: dict[str, Any], probe_mode: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if probe_mode != "live":
        bindings = [_fallback_slot_binding({"target": item["target"], "framework_family": item["framework_family"], "concrete_pattern": item["concrete_pattern"], "oracle_contract": {"oracle_type": item.get("oracle_type", "")}}) for item in slot_plan.get("items", [])]
        return (
            {"slot_bindings": bindings},
            {
                "schema": "glm_slot_filling_report_v1",
                "probe_mode": probe_mode,
                "glm_attempted": False,
                "glm_success_count": 0,
                "fallback_used": False,
                "used_existing_probe_slots": True,
                "status": "existing_probe_slots_loaded",
            },
        )

    prompt_items = slot_plan.get("items", [])[:12]
    system = (
        "You fill YAML slot bindings for a crypto research runtime smoke pipeline. "
        "Return YAML only. Do not generate C code, adapter code, markdown, or explanations."
    )
    user = (
        "Create slot_bindings for these items. The only allowed fields per binding are: "
        + ", ".join(SLOT_BINDING_ALLOWED_FIELDS)
        + "\nItems:\n"
        + yaml.safe_dump(prompt_items, sort_keys=False, allow_unicode=True)
        + "\nReturn shape:\nslot_bindings:\n- target: ...\n"
    )
    model = os.environ.get("GLM_MODEL", "glm-4-flash-250414")
    try:
        result = call_glm_structured(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            model=model,
            max_tokens=3000,
            temperature=0.0,
        )
        parsed = yaml.safe_load(_strip_yaml_fence(result.content)) or {}
        if not isinstance(parsed, dict) or not isinstance(parsed.get("slot_bindings"), list):
            return (
                {"slot_bindings": []},
                {
                    "schema": "glm_slot_filling_report_v1",
                    "probe_mode": probe_mode,
                    "glm_attempted": True,
                    "glm_success_count": 0,
                    "fallback_used": False,
                    "status": "failed_unparseable_yaml",
                    "reason": "GLM response did not parse as slot_bindings YAML",
                    "api_key_logged": False,
                },
            )
        return (
            parsed,
            {
                "schema": "glm_slot_filling_report_v1",
                "probe_mode": probe_mode,
                "glm_attempted": True,
                "glm_success_count": 1,
                "fallback_used": False,
                "status": "ok",
                "model": model,
                "finish_reason": result.finish_reason,
                "completion_tokens": result.completion_tokens,
                "reasoning_tokens": result.reasoning_tokens,
                "api_key_logged": False,
            },
        )
    except Exception as exc:
        return (
            {"slot_bindings": []},
            {
                "schema": "glm_slot_filling_report_v1",
                "probe_mode": probe_mode,
                "glm_attempted": True,
                "glm_success_count": 0,
                "fallback_used": False,
                "status": "failed_glm_call",
                "reason": type(exc).__name__,
                "message": str(exc)[:300],
                "api_key_logged": False,
            },
        )


def _slot_plan_index(slot_plan: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in slot_plan.get("items", []):
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("target", "")),
            str(item.get("framework_family", "")),
            str(item.get("concrete_pattern", "")),
        )
        indexed[key] = item
    return indexed


def _api_prefix_violation(target: str, selected_api: str) -> str:
    if selected_api in {"", "unknown", "blocked_mapping"}:
        return ""
    policy = TARGET_API_PREFIX_POLICY.get(_target_policy_key(target), {})
    for prefix in policy.get("forbidden_prefixes", []):
        if selected_api.startswith(prefix):
            return f"selected_api_prefix_forbidden_for_target:{prefix}"
    allowed = policy.get("allowed_prefixes", [])
    if allowed and not any(selected_api.startswith(prefix) for prefix in allowed):
        return "selected_api_prefix_not_allowed_for_target"
    return ""


def _sequence_contains_api(sequence: Any, api_name: str) -> bool:
    if isinstance(sequence, list):
        return any(api_name in str(item) for item in sequence)
    return api_name in str(sequence)


def _correct_selected_api_if_teardown(binding: dict[str, Any]) -> tuple[str, dict[str, str] | None]:
    family = str(binding.get("framework_family", ""))
    pattern = str(binding.get("concrete_pattern", ""))
    selected_api = str(binding.get("selected_api", ""))
    trigger_api = SELECTED_API_TRIGGER_CORRECTIONS.get((family, pattern, selected_api))
    if not trigger_api:
        return selected_api, None
    if _sequence_contains_api(binding.get("call_sequence", []), trigger_api):
        binding["selected_api"] = trigger_api
        return trigger_api, {"old_selected_api": selected_api, "new_selected_api": trigger_api}
    binding["needs_human_review"] = True
    return selected_api, None


def _validate_slots(slot_doc: dict[str, Any], out_dir: Path, slot_plan: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    errors = []
    warnings = []
    cross_library_api_violations = []
    usable_bindings = []
    blocked_bindings = []
    needs_review_bindings = []
    invalid_bindings = []
    slot_binding_input_key = str(slot_doc.get("_slot_binding_input_key") or "")
    if not slot_binding_input_key:
        slot_binding_input_key = "bindings" if isinstance(slot_doc.get("bindings"), list) else "slot_bindings"
    bindings = slot_doc.get("bindings") if isinstance(slot_doc.get("bindings"), list) else slot_doc.get("slot_bindings", [])
    plan_index = _slot_plan_index(slot_plan or {})
    for idx, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            errors.append({"index": idx, "reason": "binding_not_mapping"})
            invalid_bindings.append({"index": idx, "reason": "binding_not_mapping"})
            continue
        binding = dict(binding)
        bindings[idx] = binding
        defaulted_fields = []
        for field in sorted(OPTIONAL_SLOT_BINDING_FIELDS):
            if field not in binding:
                binding[field] = ""
                defaulted_fields.append(field)
        if defaulted_fields:
            warnings.append({"index": idx, "reason": "optional_fields_defaulted", "fields": defaulted_fields})
        extra = sorted(set(binding) - set(SLOT_BINDING_ALLOWED_FIELDS))
        if extra:
            errors.append({"index": idx, "reason": "unexpected_fields", "fields": extra})
        missing = [field for field in SLOT_BINDING_ALLOWED_FIELDS if field not in binding]
        if missing:
            errors.append({"index": idx, "reason": "missing_fields", "fields": missing})
        text = yaml.safe_dump(binding, sort_keys=False, allow_unicode=True)
        markers = [pattern for pattern in C_LIKE_MARKERS if re.search(pattern, text)]
        if markers:
            errors.append({"index": idx, "reason": "free_form_code_marker", "markers": markers})
        target = str(binding.get("target", ""))
        family = str(binding.get("framework_family", ""))
        pattern = str(binding.get("concrete_pattern", ""))
        selected_api = str(binding.get("selected_api", ""))
        corrected_api, correction = _correct_selected_api_if_teardown(binding)
        if correction:
            selected_api = corrected_api
            warnings.append({"index": idx, "reason": "selected_api_corrected_from_teardown_to_trigger", **correction})
        elif binding.get("needs_human_review") and (family, pattern, selected_api) in SELECTED_API_TRIGGER_CORRECTIONS:
            warnings.append(
                {
                    "index": idx,
                    "reason": "selected_api_teardown_without_trigger_call_sequence",
                    "selected_api": selected_api,
                    "expected_trigger_api": SELECTED_API_TRIGGER_CORRECTIONS[(family, pattern, selected_api)],
                }
            )
        plan_item = plan_index.get((target, family, pattern), {})
        allowed_apis = []
        allowed_values = plan_item.get("allowed_values") if isinstance(plan_item, dict) else {}
        if isinstance(allowed_values, dict):
            allowed_apis = [str(api) for api in allowed_values.get("api_candidates", [])]
        if selected_api in {"unknown", "blocked_mapping"}:
            blocked_bindings.append({"index": idx, "target": target, "framework_family": family, "concrete_pattern": pattern, "selected_api": selected_api, "reason": "selected_api_not_target_specific"})
            warnings.append({"index": idx, "reason": "selected_api_requires_human_review", "selected_api": selected_api})
            continue
        if selected_api and selected_api not in allowed_apis:
            reason = "selected_api_not_in_allowed_values"
            errors.append({"index": idx, "reason": reason, "target": target, "selected_api": selected_api, "allowed_api_candidates": allowed_apis})
            invalid_bindings.append({"index": idx, "target": target, "framework_family": family, "concrete_pattern": pattern, "selected_api": selected_api, "reason": reason})
        prefix_violation = _api_prefix_violation(target, selected_api)
        if prefix_violation:
            violation = {"index": idx, "target": target, "framework_family": family, "concrete_pattern": pattern, "selected_api": selected_api, "reason": prefix_violation}
            cross_library_api_violations.append(violation)
            errors.append(violation)
            invalid_bindings.append(violation)
        if binding.get("needs_human_review"):
            warnings.append({"index": idx, "reason": "needs_human_review"})
            needs_review_bindings.append({"index": idx, "target": target, "framework_family": family, "concrete_pattern": pattern, "selected_api": selected_api, "reason": "binding_marked_needs_human_review"})
            continue
        if not any(item.get("index") == idx for item in invalid_bindings) and not any(item.get("index") == idx for item in blocked_bindings):
            usable_bindings.append(binding)
    status = "pass" if not errors else "fail"
    if status == "pass" and any(item.get("reason") in REVIEW_WARNING_REASONS for item in warnings if isinstance(item, dict)):
        status = "pass_with_needs_review"
    slot_report = {
        "schema": "slot_validation_report_v1",
        "status": status,
        "slot_binding_input_key": slot_binding_input_key,
        "slot_validation_passed": status in {"pass", "pass_with_needs_review"},
        "validated_bindings": len(bindings),
        "binding_count": len(bindings),
        "usable_bindings": len(usable_bindings),
        "blocked_bindings": len(blocked_bindings),
        "needs_review_bindings": len(needs_review_bindings),
        "invalid_bindings": len({item.get("index") for item in invalid_bindings}),
        "cross_library_api_violations": len(cross_library_api_violations),
        "usable_slot_bindings": usable_bindings,
        "blocked_binding_records": blocked_bindings,
        "needs_review_binding_records": needs_review_bindings,
        "invalid_binding_records": invalid_bindings,
        "cross_library_api_violation_records": cross_library_api_violations,
        "errors": errors,
        "warnings": warnings,
    }
    adapter_report = {
        "schema": "adapter_validation_report_v1",
        "status": status,
        "slot_binding_input_key": slot_binding_input_key,
        "adapter_validation_passed": status in {"pass", "pass_with_needs_review"},
        "validated_binding_count": len(bindings),
        "usable_bindings": len(usable_bindings),
        "blocked_bindings": len(blocked_bindings),
        "needs_review_bindings": len(needs_review_bindings),
        "invalid_bindings": len({item.get("index") for item in invalid_bindings}),
        "cross_library_api_violations": len(cross_library_api_violations),
        "validation_scope": "yaml_slot_schema_only",
        "free_form_adapter_code_allowed": False,
        "errors": errors,
        "warnings": warnings,
    }
    write_yaml(out_dir / "slot_validation_report.yaml", slot_report)
    write_yaml(out_dir / "adapter_validation_report.yaml", adapter_report)
    return slot_report, adapter_report


def _build_mutation_plan(slot_doc: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    items = []
    for binding in slot_doc.get("slot_bindings", []):
        items.append(
            {
                "target": binding.get("target"),
                "framework_family": binding.get("framework_family"),
                "concrete_pattern": binding.get("concrete_pattern"),
                "mutation_values": binding.get("mutation_values", {}),
                "expected_oracle": binding.get("expected_oracle"),
                "bounded_smoke": True,
            }
        )
    plan = {
        "schema": "mutation_plan_v1",
        "status": "ready" if items else "partial",
        "mutation_plan_created": bool(items),
        "full_fuzzing": False,
        "unbounded_mutation": False,
        "items": items,
        "reason": "" if items else "no_valid_slot_bindings",
        "next_action": "" if items else "repair_or_regenerate_slot_bindings",
    }
    write_yaml(out_dir / "mutation_plan.yaml", plan)
    return plan


def run_stage_based_orchestrator(
    repo_root: Path,
    out_dir: Path,
    targets: list[str],
    families: list[str],
    execution_mode: str,
    oracle_mode: str,
    probe_mode: str,
    max_families: int,
    max_cases: int,
    max_compile_jobs: int,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    emit_progress(progress_callback, "family_selection", "running", "Loading family taxonomy and target runtime preflight.")
    bundle = load_card_bundle(repo_root)
    selected_families, unsupported_families = _canonical_families(bundle, families, max_families)
    target_rows = _target_rows(targets)
    plan_cases = _round_robin_cases(bundle, selected_families, target_rows, max_cases)
    oracle_connected = _oracle_stage_connected(repo_root) if oracle_mode == "dispatch" else True

    family_set = sorted({row["framework_family"] for row in plan_cases})
    target_set = sorted({row["target"] for row in plan_cases})
    blocked_targets = sorted({row["target"] for row in target_rows if row["runtime_status"] == "blocked_runtime"})
    baseline_targets = sorted({row["target"] for row in target_rows if row["runtime_status"] == "baseline_only"})
    ready_targets = sorted({row["target"] for row in target_rows if row["runtime_status"] == "runtime_ready"})
    emit_progress(
        progress_callback,
        "family_selection",
        "completed" if selected_families else "partial",
        "Family and target inputs selected." if selected_families else "No supported family was selected.",
        {"selected_family_count": len(selected_families), "ready_target_count": len(ready_targets), "blocked_target_count": len(blocked_targets)},
    )
    emit_progress(progress_callback, "knowledge_retrieval", "running", "Loading knowledge cards and stage contract.")

    stage_trace = {
        "schema": "stage_trace_v1",
        "task_name": TASK_NAME,
        "orchestrator_mode": "stage_contract",
        "stages": [
            {"stage": "load_taxonomy", "status": "planned_complete", "runtime_executed": False},
            {"stage": "load_cards", "status": "planned_complete", "runtime_executed": False},
            {"stage": "validate_card_contract", "status": "planned_complete", "runtime_executed": False},
            {"stage": "mapping_gate", "status": "planned_complete", "runtime_executed": False},
            {"stage": "campaign_plan", "status": "planned_complete", "runtime_executed": False},
            {"stage": "load_templates", "status": "pending", "runtime_executed": False},
            {"stage": "render_plan", "status": "planned_complete", "runtime_executed": False},
            {"stage": "slot_filling_plan", "status": "planned_complete", "runtime_executed": False},
            {"stage": "glm_slot_filling", "status": "pending", "runtime_executed": False},
            {"stage": "manual_glm_handoff", "status": "pending", "runtime_executed": False},
            {"stage": "slot_validation", "status": "pending", "runtime_executed": False},
            {"stage": "adapter_validation", "status": "pending", "runtime_executed": False},
            {"stage": "mutation_plan", "status": "pending", "runtime_executed": False},
            {"stage": "syntax_only_execution_plan", "status": "planned_complete", "runtime_executed": False},
            {"stage": "oracle_plan", "status": "planned_complete", "runtime_executed": False},
            {"stage": "triage_plan", "status": "planned_complete", "runtime_executed": False},
            {"stage": "feedback_plan", "status": "planned_complete", "runtime_executed": False},
        ],
    }
    write_yaml(out_dir / "stage_trace.yaml", stage_trace)

    write_yaml(
        out_dir / "taxonomy_report.yaml",
        {
            "schema": "taxonomy_report_v1",
            "framework_family_count": bundle["summary"]["framework_family_count"],
            "concrete_pattern_count": bundle["summary"]["concrete_pattern_count"],
            "selected_families": selected_families,
            "unsupported_families": unsupported_families,
        },
    )
    write_yaml(
        out_dir / "card_load_report.yaml",
        {
            "schema": "card_load_report_v1",
            **bundle["summary"],
            "target_status": target_rows,
        },
    )
    card_contract_valid = bundle["summary"]["missing_required_field_count"] == 0
    write_yaml(
        out_dir / "card_contract_validation.yaml",
        {
            "schema": "card_contract_validation_v1",
            "card_contract_valid": card_contract_valid,
            "missing_required_fields": bundle["missing_required_fields"],
            "contract_path": "config/orchestrator_card_contract.yaml",
            "stage_contract_path": "config/mainline_stage_contract.yaml",
        },
    )
    emit_progress(
        progress_callback,
        "knowledge_retrieval",
        "completed" if bundle["summary"]["framework_family_cards_loaded"] else "partial",
        "Knowledge card context loaded.",
        {"family_card_count": bundle["summary"]["framework_family_cards_loaded"], "api_card_count": bundle["summary"]["target_api_cards_loaded"], "constraint_count": bundle["summary"]["constraints_loaded"], "call_sequence_count": bundle["summary"]["call_sequences_loaded"]},
    )

    mapping_gate = {
        "schema": "mapping_gate_report_v1",
        "families": [],
    }
    for family in selected_families:
        rows = [row for row in plan_cases if row["framework_family"] == family]
        mapping_gate["families"].append(
            {
                "framework_family": family,
                "planned_case_count": len(rows),
                "targets": sorted({row["target"] for row in rows}),
                "candidate_mapping_count": sum(1 for row in rows if row["mapping_status"] == "candidate_mapping_from_card"),
                "blocked_runtime_count": sum(1 for row in rows if row["mapping_status"] == "blocked_runtime"),
                "missing_or_partial_mapping_count": sum(1 for row in rows if row["mapping_status"] == "missing_or_partial_mapping"),
            }
        )
    write_yaml(out_dir / "mapping_gate_report.yaml", mapping_gate)

    campaign_plan = {
        "schema": "campaign_plan_v1",
        "task_name": TASK_NAME,
        "orchestrator_mode": "stage_contract",
        "execution_mode": execution_mode,
        "oracle_mode": oracle_mode,
        "probe_mode": probe_mode,
        "max_cases": max_cases,
        "max_compile_jobs": max_compile_jobs,
        "families": family_set,
        "targets": target_set,
        "target_status": target_rows,
        "cases": plan_cases,
    }
    write_yaml(out_dir / "campaign_plan.yaml", campaign_plan)

    template_pack = build_template_pack(
        repo_root=repo_root,
        selected_families=family_set,
        generated_by="template_usage_audit_and_manual_glm_handoff_v1",
    )
    write_yaml(out_dir / "template_pack.yaml", template_pack)
    write_yaml(
        out_dir / "template_usage_audit.yaml",
        {
            "schema": "template_usage_audit_v1",
            "task_name": "template_usage_audit_and_manual_glm_handoff_v1",
            "current_orchestrator_reads_normalized_templates": True,
            "current_orchestrator_template_mechanism": "load_templates stage writes template_pack.yaml from normalized_templates and adapter_recipes",
            "prior_observation": "normalized_templates currently observed but not fully connected to stage-based runtime path.",
            "render_plan_references_template": True,
            "slot_filling_plan_references_template": True,
            "mutation_plan_references_template": False,
            "rendered_cases_from_template": False,
            "manual_handoff_required_before_runtime": probe_mode == "manual" and not (out_dir / "slot_bindings.yaml").exists(),
        },
    )

    render_plan = {
        "schema": "render_plan_v1",
        "status": "planned_only" if execution_mode != "runtime_smoke" else "runtime_smoke_bridge_input",
        "render_executed": False,
        "case_count": len(plan_cases),
        "families": family_set,
        "targets": target_set,
        "template_pack": "template_pack.yaml",
        "template_status_by_family": {
            item.get("framework_family"): item.get("template_status")
            for item in template_pack.get("template_sources", [])
            if isinstance(item, dict)
        },
    }
    write_yaml(out_dir / "render_plan.yaml", render_plan)
    slot_plan = _attach_template_refs_to_slot_plan(_build_slot_filling_plan(plan_cases, out_dir), template_pack, bundle, out_dir)
    if probe_mode == "manual":
        slot_plan = _focus_manual_slot_plan(slot_plan, out_dir)
    external_slot_doc = _load_external_slot_bindings(out_dir / "slot_bindings.yaml")
    manual_waiting = probe_mode == "manual" and external_slot_doc is None
    _write_manual_glm_handoff(slot_plan, template_pack, out_dir)
    if manual_waiting:
        slot_doc = {"slot_bindings": []}
        glm_report = {
            "schema": "glm_slot_filling_report_v1",
            "probe_mode": probe_mode,
            "glm_attempted": False,
            "glm_success_count": 0,
            "fallback_used": False,
            "manual_glm_request_created": True,
            "manual_slot_bindings_required": True,
            "status": "waiting_for_manual_slot_bindings",
            "next_action": "Run manual_glm_request.md with GLM externally, save YAML as slot_bindings.yaml, then rerun with probe-mode existing/manual.",
        }
    elif external_slot_doc is not None:
        slot_doc = external_slot_doc
        write_yaml(out_dir / "slot_bindings.yaml", slot_doc)
        glm_report = {
            "schema": "glm_slot_filling_report_v1",
            "probe_mode": probe_mode,
            "glm_attempted": False,
            "glm_success_count": 0,
            "fallback_used": False,
            "manual_glm_request_created": True,
            "manual_slot_bindings_required": False,
            "used_external_slot_bindings": True,
            "status": "external_manual_slot_bindings_loaded",
        }
    else:
        emit_progress(progress_callback, "model_proposal", "running", "Running model-assisted slot filling.")
        slot_doc, glm_report = _call_glm_for_slots(slot_plan, probe_mode)
        write_yaml(out_dir / "slot_bindings.yaml", slot_doc)
    emit_progress(
        progress_callback,
        "model_proposal",
        "completed" if glm_report.get("status") in {"ok", "existing_probe_slots_loaded", "external_manual_slot_bindings_loaded"} else "partial",
        "Model-assisted slot filling completed.",
        glm_report,
    )
    emit_progress(progress_callback, "validation", "running", "Validating slot bindings and adapter compatibility.")
    write_yaml(out_dir / "glm_slot_filling_report.yaml", glm_report)
    slot_validation_report, adapter_validation_report = _validate_slots(slot_doc, out_dir, slot_plan)
    if not manual_waiting:
        write_yaml(out_dir / "slot_bindings.yaml", slot_doc)
    usable_slot_doc = {"slot_bindings": slot_validation_report.get("usable_slot_bindings", [])}
    mutation_plan = _build_mutation_plan(usable_slot_doc, out_dir)
    if manual_waiting:
        slot_validation_report = {
            "schema": "slot_validation_report_v1",
            "status": "waiting_for_manual_slot_bindings",
            "slot_validation_passed": False,
            "binding_count": 0,
            "errors": [],
            "warnings": [{"reason": "manual_glm_request_created_no_slot_bindings_yet"}],
        }
        adapter_validation_report = {
            "schema": "adapter_validation_report_v1",
            "status": "waiting_for_manual_slot_bindings",
            "adapter_validation_passed": False,
            "validated_binding_count": 0,
            "validation_scope": "yaml_slot_schema_only",
            "free_form_adapter_code_allowed": False,
            "errors": [],
            "warnings": [{"reason": "manual_glm_request_created_no_slot_bindings_yet"}],
        }
        write_yaml(out_dir / "slot_validation_report.yaml", slot_validation_report)
        write_yaml(out_dir / "adapter_validation_report.yaml", adapter_validation_report)
    slot_ok = (
        slot_validation_report.get("slot_validation_passed")
        and adapter_validation_report.get("adapter_validation_passed")
        and int(slot_validation_report.get("usable_bindings", 0) or 0) > 0
    )
    emit_progress(
        progress_callback,
        "validation",
        "completed" if slot_ok else "partial",
        "Slot validation produced usable runtime bindings." if slot_ok else "Slot validation did not produce usable runtime bindings.",
        {"slot_validation_passed": slot_validation_report.get("slot_validation_passed", False), "usable_bindings": slot_validation_report.get("usable_bindings", 0), "invalid_bindings": slot_validation_report.get("invalid_bindings", 0)},
    )
    emit_progress(
        progress_callback,
        "binding",
        "completed" if slot_ok else "blocked",
        "Runtime binding prepared." if slot_ok else "Runtime smoke is unavailable because no usable runtime binding was produced.",
        {"usable_bindings": slot_validation_report.get("usable_bindings", 0)},
    )
    if manual_waiting:
        write_yaml(
            out_dir / "rendered_cases_manifest.yaml",
            {
                "schema": "rendered_cases_manifest_v1",
                "status": "waiting_for_manual_slot_bindings",
                "reason": "manual_glm_request_created_no_slot_bindings_yet",
                "next_action": "save external GLM YAML response as slot_bindings.yaml and rerun",
            },
        )
        write_yaml(out_dir / "compile_report.yaml", {"schema": "compile_report_v1", "status": "waiting_for_manual_slot_bindings", "reason": "manual_glm_request_created_no_slot_bindings_yet"})
        write_yaml(out_dir / "run_report.yaml", {"schema": "run_report_v1", "status": "waiting_for_manual_slot_bindings", "reason": "manual_glm_request_created_no_slot_bindings_yet"})
        write_yaml(out_dir / "runtime_analyze_report.yaml", {"schema": "runtime_analyze_report_v1", "status": "waiting_for_manual_slot_bindings", "reason": "manual_glm_request_created_no_slot_bindings_yet"})
    elif execution_mode == "runtime_smoke" and not slot_ok:
        emit_progress(progress_callback, "testcase_generation", "blocked", "Testcase rendering blocked because no usable runtime binding was produced.")
        emit_progress(progress_callback, "build", "blocked", "Build blocked because no runtime testcase was rendered.")
        emit_progress(progress_callback, "runtime", "blocked", "Runtime smoke is unavailable because no usable runtime binding was produced.")
        reason = "no_usable_slot_bindings" if slot_validation_report.get("slot_validation_passed") else "slot_validation_failed"
        status = "waiting_for_valid_slot_bindings" if reason == "no_usable_slot_bindings" else "partial"
        write_yaml(
            out_dir / "rendered_cases_manifest.yaml",
            {
                "schema": "rendered_cases_manifest_v1",
                "status": status,
                "reason": reason,
                "runtime_harness_executed": False,
                "cases_rendered": 0,
                "cases_compiled": 0,
                "cases_run": 0,
                "used_internal_smoke_fallback": False,
                "rendered_from_slot_bindings": False,
                "runtime_skip_reason": reason,
                "render_filter": {
                    "source": "slot_validation_report.yaml",
                    "included_binding_class": "usable_bindings_only",
                    "excluded_binding_classes": ["needs_review_bindings", "invalid_bindings", "blocked_bindings"],
                },
                "rendered_cases": [],
                "skipped_bindings": (
                    slot_validation_report.get("blocked_binding_records", [])
                    + slot_validation_report.get("invalid_binding_records", [])
                    + slot_validation_report.get("needs_review_binding_records", [])
                ),
                "next_action": "repair_or_regenerate_slot_bindings",
            },
        )
        write_yaml(out_dir / "compile_report.yaml", {"schema": "compile_report_v1", "status": status, "reason": reason, "runtime_harness_executed": False, "cases_compiled": 0, "used_internal_smoke_fallback": False, "next_action": "repair_or_regenerate_slot_bindings"})
        write_yaml(out_dir / "run_report.yaml", {"schema": "run_report_v1", "status": status, "reason": reason, "runtime_harness_executed": False, "cases_run": 0, "used_internal_smoke_fallback": False, "next_action": "repair_or_regenerate_slot_bindings"})
        write_yaml(out_dir / "runtime_analyze_report.yaml", {"schema": "runtime_analyze_report_v1", "status": status, "reason": reason, "runtime_harness_executed": False, "runtime_smoke": execution_mode == "runtime_smoke", "full_fuzzing": False, "cases_rendered": 0, "cases_compiled": 0, "cases_run": 0, "used_internal_smoke_fallback": False, "rendered_from_slot_bindings": False, "runtime_skip_reason": reason, "observations": [], "analysis": [], "next_action": "repair_or_regenerate_slot_bindings"})
    runtime_summary: dict[str, Any] = {
        "runtime_harness_executed": False,
        "runtime_smoke": False,
        "full_fuzzing": False,
        "cases_rendered": 0,
        "cases_compiled": 0,
        "cases_run": 0,
        "compile_success": 0,
        "compile_failed": 0,
        "run_success": 0,
        "run_failed": 0,
        "timeout_count": 0,
        "crash_observation_count": 0,
        "sanitizer_observation_count": 0,
        "semantic_observation_count": 0,
        "candidate_event_count": 0,
        "binary_artifacts_created": False,
    }
    write_yaml(
        out_dir / "syntax_only_execution_plan.yaml",
        {
            "schema": "syntax_only_execution_plan_v1",
            "status": "planned_only" if execution_mode != "runtime_smoke" else "superseded_by_runtime_smoke_bridge",
            "runtime_harness_executed": False,
            "compile_executed": False,
            "binary_artifacts_created": False,
            "max_compile_jobs": max_compile_jobs,
        },
    )
    write_yaml(
        out_dir / "oracle_plan.yaml",
        {
            "schema": "oracle_plan_v1",
            "oracle_mode": oracle_mode,
            "oracle_stage_connected": oracle_connected,
            "planned_oracles": sorted(
                {
                    (row.get("oracle_contract") or {}).get("oracle_type", "unknown_oracle")
                    for row in plan_cases
                }
            ),
        },
    )
    write_yaml(
        out_dir / "triage_plan.yaml",
        {
            "schema": "triage_plan_v1",
            "status": "planned_only",
            "triage_outputs": ["candidate_event", "semantic_observation", "safe_reject", "unsupported", "blocked"],
            "claim_policy": "observation_only_until_runtime_evidence",
        },
    )
    write_yaml(
        out_dir / "feedback_plan.yaml",
        {
            "schema": "feedback_plan_v1",
            "status": "planned_only",
            "main_feedback_written": False,
            "knowledge_modified": False,
            "pattern_bank_modified": False,
        },
    )
    if execution_mode == "runtime_smoke" and slot_ok and not manual_waiting:
        emit_progress(progress_callback, "testcase_generation", "running", "Rendering runtime smoke testcase sources.")
        emit_progress(progress_callback, "build", "running", "Compiling runtime smoke testcases.")
        emit_progress(progress_callback, "runtime", "running", "Executing runtime smoke harnesses.")
        runtime_summary = run_runtime_harness_bridge(
            repo_root=repo_root,
            out_dir=out_dir,
            campaign_plan_path=out_dir / "campaign_plan.yaml",
            render_plan_path=out_dir / "render_plan.yaml",
            slot_bindings_path=out_dir / "slot_bindings.yaml",
            slot_validation_path=out_dir / "slot_validation_report.yaml",
            execution_mode="runtime_smoke",
            max_cases=max_cases,
            max_compile_jobs=max_compile_jobs,
            timeout_seconds=10,
        )
        emit_progress(progress_callback, "testcase_generation", "completed", "Runtime smoke testcase sources rendered.", runtime_summary)
        emit_progress(
            progress_callback,
            "build",
            "completed" if runtime_summary.get("compile_failed", 0) == 0 else "failed",
            "Runtime smoke build completed.",
            runtime_summary,
        )
        emit_progress(
            progress_callback,
            "runtime",
            "completed" if runtime_summary.get("runtime_harness_executed") else "blocked",
            "Runtime smoke execution completed." if runtime_summary.get("runtime_harness_executed") else "Runtime smoke did not execute.",
            runtime_summary,
        )
    elif execution_mode != "runtime_smoke":
        emit_progress(progress_callback, "testcase_generation", "planned", "Runtime testcase generation is not part of syntax check.")
        emit_progress(progress_callback, "build", "planned", "Runtime build is not part of syntax check.")
        emit_progress(progress_callback, "runtime", "planned", "Runtime was not executed by syntax check level.")

    fault_surface_report = fault_surface_engine.run(
        _build_fault_surface_seed_context(
            campaign_plan=campaign_plan,
            render_plan=render_plan,
            template_pack=template_pack,
            slot_doc=slot_doc,
            slot_validation_report=slot_validation_report,
            mutation_plan=mutation_plan,
            runtime_summary=runtime_summary,
        )
    )
    write_yaml(out_dir / "fault_surface_report.yaml", fault_surface_report)
    emit_progress(progress_callback, "evaluation", "running", "Evaluating runtime smoke observations.")

    expected_all_family = len(family_set) == len(bundle["framework_families"])
    expected_all_target = len(target_set) == len(TARGET_RUNTIME_STATUS)
    quality_status = "pass_stage_contract_syntax_only_planning"
    if not (bundle["summary"]["taxonomy_loaded"] and bundle["summary"]["coverage_loaded"] and oracle_connected):
        quality_status = "failed_stage_contract_planning"
    if glm_report.get("glm_attempted") and glm_report.get("glm_success_count", 0) < 1:
        quality_status = f"failed_{glm_report.get('status', 'glm_slot_filling')}"
    if not slot_ok:
        quality_status = "waiting_for_valid_slot_bindings" if slot_validation_report.get("slot_validation_passed") else "failed_slot_validation"
    if manual_waiting:
        quality_status = "waiting_for_manual_slot_bindings"
    if execution_mode == "runtime_smoke" and runtime_summary.get("runtime_harness_executed"):
        if runtime_summary.get("compile_failed", 0) or runtime_summary.get("run_failed", 0) or runtime_summary.get("timeout_count", 0):
            quality_status = "partial_runtime_smoke_with_failures"
        else:
            quality_status = "pass_runtime_smoke_bridge"
    quality = {
        "schema": "stage_based_orchestrator_quality_report_v1",
        "task_name": TASK_NAME,
        "quality_status": quality_status,
        "orchestrator_mode": "stage_contract",
        "stage_based_orchestrator_connected": True,
        "taxonomy_loaded": bundle["summary"]["taxonomy_loaded"],
        "cards_loaded": bundle["summary"]["framework_family_cards_loaded"] > 0,
        "card_contract_valid": card_contract_valid,
        "mapping_gate_loaded": bundle["summary"]["mapping_gate_loaded"] > 0,
        "campaign_plan_created": True,
        "render_plan_created": True,
        "template_pack_created": True,
        "template_pack_status": template_pack.get("status"),
        "normalized_templates_audited": True,
        "syntax_only_execution_plan_created": True,
        "oracle_stage_connected": oracle_connected,
        "fault_surface_engine_connected": True,
        "fault_surface_hook_stage": "runtime_to_oracle",
        "fault_surface_status": fault_surface_report.get("status"),
        "fault_surface_mutation_count": (fault_surface_report.get("mutation_plan") or {}).get("mutation_count", 0),
        "fault_surface_observation_count": (fault_surface_report.get("differential_oracle") or {}).get("observation_count", 0),
        "triage_plan_created": True,
        "feedback_plan_created": True,
        "runtime_harness_executed": bool(runtime_summary.get("runtime_harness_executed")),
        "runtime_smoke": bool(runtime_summary.get("runtime_smoke")),
        "full_fuzzing": False,
        "binary_artifacts_created": bool(runtime_summary.get("binary_artifacts_created")),
        "api_key_logged": False,
        "family_count": len(family_set),
        "target_count": len(target_set),
        "case_count": len(plan_cases),
        "all_framework_families_covered": expected_all_family,
        "all_targets_covered": expected_all_target,
        "ready_targets": ready_targets,
        "blocked_targets": blocked_targets,
        "baseline_targets": baseline_targets,
        "unsupported_family_count": len(unsupported_families),
        "slot_filling_plan_created": True,
        "slot_bindings_created": bool(slot_doc.get("slot_bindings")),
        "manual_glm_request_created": (out_dir / "manual_glm_request.md").exists(),
        "manual_slot_bindings_required": bool(manual_waiting),
        "next_action": "Run manual_glm_request.md with GLM externally, save YAML as slot_bindings.yaml, then rerun with probe-mode existing/manual." if manual_waiting else "",
        "glm_attempted": glm_report.get("glm_attempted", False),
        "glm_success_count": glm_report.get("glm_success_count", 0),
        "fallback_used": glm_report.get("fallback_used", False),
        "used_internal_smoke_fallback": False,
        "slot_binding_input_key": slot_validation_report.get("slot_binding_input_key", ""),
        "slot_validation_passed": slot_validation_report.get("slot_validation_passed", False),
        "adapter_validation_passed": adapter_validation_report.get("adapter_validation_passed", False),
        "mutation_plan_created": mutation_plan.get("mutation_plan_created", False),
        "rendered_cases_manifest_created": (out_dir / "rendered_cases_manifest.yaml").exists(),
        "cases_rendered": runtime_summary.get("cases_rendered", 0),
        "cases_compiled": runtime_summary.get("cases_compiled", 0),
        "cases_run": runtime_summary.get("cases_run", 0),
        "compile_success": runtime_summary.get("compile_success", 0),
        "compile_failed": runtime_summary.get("compile_failed", 0),
        "run_success": runtime_summary.get("run_success", 0),
        "run_failed": runtime_summary.get("run_failed", 0),
        "timeout_count": runtime_summary.get("timeout_count", 0),
        "crash_observation_count": runtime_summary.get("crash_observation_count", 0),
        "sanitizer_observation_count": runtime_summary.get("sanitizer_observation_count", 0),
        "semantic_observation_count": runtime_summary.get("semantic_observation_count", 0),
        "candidate_event_count": runtime_summary.get("candidate_event_count", 0),
    }
    write_yaml(out_dir / "quality_report.yaml", quality)
    emit_progress(progress_callback, "evaluation", "completed", "Evaluation artifacts updated.", quality)
    emit_progress(progress_callback, "result_record", "completed", "Result record summary updated.", quality)
    emit_progress(
        progress_callback,
        "context_exploration",
        "not_triggered",
        "Context exploration is only routed when candidate artifacts are emitted.",
        quality,
    )
    write_text(
        out_dir / "README.md",
        "\n".join(
            [
                "# Stage-Based Orchestrator Dry Run",
                "",
                "This directory contains a stage-contract planning run only.",
                "No runtime harnesses were rendered, compiled, or executed.",
                "",
                f"- quality_status: `{quality_status}`",
                f"- families: {len(family_set)}",
                f"- targets: {len(target_set)}",
                f"- planned cases: {len(plan_cases)}",
                "",
            ]
        ),
    )
    return quality


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--targets", required=True)
    parser.add_argument("--families", required=True)
    parser.add_argument("--execution-mode", default="syntax_only")
    parser.add_argument("--oracle-mode", default="dispatch")
    parser.add_argument("--probe-mode", default="existing")
    parser.add_argument("--max-families", type=int, default=8)
    parser.add_argument("--max-cases", type=int, default=80)
    parser.add_argument("--max-compile-jobs", type=int, default=80)
    args = parser.parse_args()
    quality = run_stage_based_orchestrator(
        repo_root=Path(args.repo_root),
        out_dir=Path(args.out_dir),
        targets=split_csv(args.targets),
        families=split_csv(args.families),
        execution_mode=args.execution_mode,
        oracle_mode=args.oracle_mode,
        probe_mode=args.probe_mode,
        max_families=args.max_families,
        max_cases=args.max_cases,
        max_compile_jobs=args.max_compile_jobs,
    )
    print(
        "stage-based orchestrator:",
        quality.get("quality_status"),
        "families=",
        quality.get("family_count"),
        "targets=",
        quality.get("target_count"),
        "cases=",
        quality.get("case_count"),
    )


if __name__ == "__main__":
    main()
