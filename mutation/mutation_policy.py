"""Mutation strategy and policy helpers.

The functions here keep strategy naming and render gating in one place so
planning modules do not each invent their own labels.
"""

from __future__ import annotations

from typing import Any


FAMILY_STRATEGIES: dict[str, list[tuple[str, list[tuple[str, str, str]], str]]] = {
    "pkcs_container_parsing": [
        (
            "seed_preserving_baseline",
            [
                ("CONTAINER_BYTES", "valid_control", "valid_family_seed"),
                ("EXPECT_RET", "valid_control", "reject_or_accept_as_seed"),
            ],
            "migrated_safe",
        ),
        ("trailing_garbage", [("TRAILING_BYTES", "boundary", "ff00")], "semantic_divergence_candidate"),
        ("malformed_length", [("NESTED_LENGTH_DELTA", "malformed", "-1")], "needs_triage"),
        (
            "nested_length_mismatch",
            [
                ("NESTED_LENGTH_DELTA", "boundary", "+1"),
                ("CONTAINER_BYTES", "malformed", "length_field_mismatch"),
            ],
            "semantic_divergence_candidate",
        ),
        ("invalid_container_structure", [("CONTAINER_BYTES", "malformed", "malformed_pkcs7_der")], "migrated_safe"),
        ("pem_der_format_toggle", [("CONTAINER_FORMAT", "boundary", "PEM_vs_DER_toggle")], "api_misuse_false_positive"),
        ("expected_return_flip", [("EXPECT_RET", "malformed", "flip_accept_reject_expectation")], "needs_triage"),
    ],
    "asn1_nested_boundary": [
        (
            "seed_preserving_baseline",
            [
                ("DER_BYTES", "valid_control", "well_formed"),
                ("EXPECT_RET", "valid_control", "reject_or_accept_as_seed"),
            ],
            "migrated_safe",
        ),
        ("trailing_garbage", [("TRAILING_GARBAGE", "boundary", "random_tail")], "semantic_divergence_candidate"),
        ("short_length", [("ASN1_NESTED_LENGTH", "boundary", "short")], "migrated_safe"),
        ("long_length", [("ASN1_NESTED_LENGTH", "boundary", "long")], "needs_triage"),
        (
            "nested_length_mismatch",
            [
                ("ASN1_NESTED_LENGTH", "malformed", "length_field_mismatch"),
                ("DER_BYTES", "malformed", "truncated"),
            ],
            "semantic_divergence_candidate",
        ),
        ("nested_depth_variation", [("NESTED_DEPTH", "boundary", "8")], "needs_triage"),
        ("expected_return_flip", [("EXPECT_RET", "malformed", "flip_accept_reject_expectation")], "needs_triage"),
    ],
}


def normalize_strategy_name(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def strategies_for_family(family: str, max_cases: int) -> list[tuple[str, list[tuple[str, str, str]], str]]:
    return FAMILY_STRATEGIES.get(family, [])[:max_cases]


def supplemental_render_allowed(case: dict[str, Any]) -> bool:
    return case.get("refinement_strategy") != "seed_required_pending"


def supplemental_render_block_reason(case: dict[str, Any]) -> str:
    if supplemental_render_allowed(case):
        return ""
    return "missing_valid_pkcs_seed"


def build_policy_refinement(sem_doc: dict[str, Any]) -> dict[str, Any]:
    raw = sem_doc.get("raw_observations", {}) or {}
    return {
        "schema": "mutation_policy_refinement_v1",
        "generated_at": "",
        "reason": {
            "accepted_true": raw.get("accepted_true", 0),
            "all_cases_rejected": (sem_doc.get("semantic_outcome", {}) or {}).get("all_cases_rejected", False),
            "current_policy_issue": "mutation_too_strong_for_accept_path",
        },
        "refinement_goals": [
            "increase_successful_parse_path_probability",
            "preserve_valid_prefix",
            "mutate_trailing_region_only",
            "preserve_outer_container_validity",
            "reduce_length_corruption_strength",
        ],
        "family_policies": [
            {
                "family": "pkcs_container_parsing",
                "current_problem": "existing PKCS mutations all rejected before useful accepted-path full-consumption observation",
                "refined_strategies": [
                    "valid_pkcs_container_plus_trailing_garbage",
                    "preserve_outer_container_mutate_inner_optional_field",
                    "valid_prefix_invalid_tail",
                    "near_valid_length_delta_small",
                ],
                "seed_requirement": "requires verified valid PKCS12/PKCS7 seed before render_allowed cases",
                "limitations": [
                    "candidate .p12 sources exist but are not validated in this planning step",
                    "seed_required_pending cases must not enter render plan",
                ],
            },
            {
                "family": "asn1_nested_boundary",
                "current_problem": "existing ASN.1 mutations all rejected; need valid DER prefix preservation",
                "refined_strategies": [
                    "valid_der_object_plus_trailing_garbage",
                    "valid_outer_sequence_mutate_inner_length_small_delta",
                    "valid_prefix_truncated_tail",
                    "nested_depth_near_valid",
                ],
                "seed_requirement": "existing DER/certificate-like seeds are available for valid-prefix planning",
                "limitations": [
                    "render must preserve byte/length pairing",
                    "accepted path still requires later compile/run observation",
                ],
            },
        ],
    }
