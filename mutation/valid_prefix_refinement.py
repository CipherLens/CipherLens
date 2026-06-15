"""Generate valid-prefix mutation refinement artifacts.

This is a planning-only module. It does not render, compile, run, analyze
runtime results, call an LLM, or write feedback.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from mutation.mutation_case_records import assignment, dump_yaml, load_yaml, now_iso, write_md
from mutation.mutation_policy import (
    build_policy_refinement,
    supplemental_render_allowed,
    supplemental_render_block_reason,
)


FAMILIES = ["pkcs_container_parsing", "asn1_nested_boundary"]


def short_path(path: Path) -> str:
    return path.as_posix()


def find_seed_sources() -> dict[str, list[dict[str, Any]]]:
    roots = [
        Path("artifacts/sprints/render_cases_v1/rendered_cases"),
        Path("artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases"),
        Path("data/pocs"),
        Path("data/wolfssl_collect"),
        Path("datasets/openssl/poc_artifacts"),
    ]
    patterns = ["*.der", "*.pem", "*.crt", "*.p12", "*.p7b", "*.bin"]
    found: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in patterns:
            found.extend(root.rglob(pattern))

    pkcs_sources: list[dict[str, Any]] = []
    asn1_sources: list[dict[str, Any]] = []
    for path in sorted(set(found)):
        text = path.as_posix().lower()
        suffix = path.suffix.lower()
        source_type = suffix.lstrip(".") or "unknown"
        if suffix in {".p12", ".p7b"} or "pkcs" in text:
            pkcs_sources.append(
                {
                    "path": short_path(path),
                    "source_type": source_type,
                    "likely_valid": "unknown",
                    "notes": "candidate PKCS-like seed source found on disk; validity not proven in this planning step",
                }
            )
        if suffix in {".der", ".crt", ".pem"} or "asn1" in text or "cert" in text or "x509" in text:
            asn1_sources.append(
                {
                    "path": short_path(path),
                    "source_type": source_type,
                    "likely_valid": True if suffix in {".der", ".crt", ".pem"} else "unknown",
                    "notes": "usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve byte/length pairing",
                }
            )
    return {
        "pkcs_container_parsing": pkcs_sources[:12],
        "asn1_nested_boundary": asn1_sources[:12],
    }


def build_seed_inventory() -> dict[str, Any]:
    sources = find_seed_sources()
    pkcs_available = False
    asn1_available = bool(sources["asn1_nested_boundary"])
    return {
        "schema": "valid_prefix_seed_inventory_v1",
        "generated_at": now_iso(),
        "families": [
            {
                "family": "pkcs_container_parsing",
                "available_seed_sources": sources["pkcs_container_parsing"],
                "valid_prefix_seed_available": pkcs_available,
                "near_valid_seed_available": bool(sources["pkcs_container_parsing"]),
                "trailing_only_possible": pkcs_available,
                "limitations": [
                    "pending_valid_seed: PKCS-like .p12/.p7b or rendered .bin sources need validation before render_allowed supplemental cases",
                    "do not fabricate valid PKCS12/PKCS7 bytes in this planning step",
                ],
            },
            {
                "family": "asn1_nested_boundary",
                "available_seed_sources": sources["asn1_nested_boundary"],
                "valid_prefix_seed_available": asn1_available,
                "near_valid_seed_available": asn1_available,
                "trailing_only_possible": asn1_available,
                "limitations": [
                    "render must preserve outer DER object validity for accepted-path probes",
                    "certificate-like seeds may be app-level valid but still need per-API acceptance checks later",
                ],
            },
        ],
        "summary": {
            "pkcs_seed_available": pkcs_available,
            "asn1_seed_available": asn1_available,
            "families_without_valid_seed": ["pkcs_container_parsing"] if not pkcs_available else [],
        },
    }


def family_template_status(root: Path) -> dict[str, Any]:
    status = {}
    for family in FAMILIES:
        base = root / family
        status[family] = {
            "mutation_slots": (base / "mutation_slots.yaml").exists(),
            "oracle_plan": (base / "oracle_plan.yaml").exists(),
            "selected_mask_units": (base / "selected_mask_units.yaml").exists(),
        }
    return status


def build_input_summary(args: argparse.Namespace, sem_doc: dict[str, Any]) -> dict[str, Any]:
    raw = sem_doc.get("raw_observations", {}) or {}
    return {
        "schema": "mutation_policy_refinement_input_summary_v1",
        "generated_at": now_iso(),
        "inputs": {
            "oracle_aware_analysis": args.oracle_aware_analysis,
            "oracle_semantics": args.oracle_semantics,
            "mutation_effectiveness": args.mutation_effectiveness,
            "original_mutation_case_matrix": args.original_mutation_case_matrix,
            "rendered_case_index": args.rendered_case_index,
            "instrumented_case_index": args.instrumented_case_index,
            "family_template_root": args.family_template_root,
        },
        "why_refinement_needed": {
            "accepted_true": raw.get("accepted_true", 0),
            "accepted_false": raw.get("accepted_false", 0),
            "all_cases_rejected": (sem_doc.get("semantic_outcome", {}) or {}).get("all_cases_rejected", False),
            "reason": "accepted_true=0 means current mutations did not reach successful parser paths; refinement should produce valid-prefix / near-valid / trailing-only variants.",
        },
        "full_consumption_false_policy": "full_consumption=false on reject/error paths is not a full-consumption gap by itself.",
        "scope": {
            "generate_supplemental_mutation_cases_only": True,
            "render": False,
            "compile": False,
            "run": False,
            "feedback": False,
            "glm": False,
        },
        "family_template_status": family_template_status(Path(args.family_template_root)),
    }


def build_supplemental_cases() -> dict[str, Any]:
    cases = [
        {
            "supplemental_case_id": "asn1_nested_boundary_openssl__supp_001__valid_der_plus_trailing_garbage",
            "base_family": "asn1_nested_boundary",
            "derived_from_case_id": "asn1_nested_boundary_openssl__mut_002__trailing_garbage",
            "refinement_strategy": "valid_object_plus_trailing_garbage",
            "mutation_assignments": [
                assignment("DER_BYTES", "valid_control", "reuse_valid_der_seed_prefix", True, True, "high"),
                assignment("TRAILING_GARBAGE", "boundary", "append_00_after_valid_object", True, True, "high"),
            ],
            "expected_result_label": "full_consumption_probe",
        },
        {
            "supplemental_case_id": "asn1_nested_boundary_openssl__supp_002__valid_prefix_trailing_only_ff00",
            "base_family": "asn1_nested_boundary",
            "derived_from_case_id": "asn1_nested_boundary_openssl__mut_002__trailing_garbage",
            "refinement_strategy": "valid_prefix_trailing_only",
            "mutation_assignments": [
                assignment("DER_BYTES", "valid_control", "preserve_seed_exact", True, True, "high"),
                assignment("TRAILING_GARBAGE", "boundary", "append_ff00_after_valid_object", True, True, "high"),
            ],
            "expected_result_label": "full_consumption_probe",
        },
        {
            "supplemental_case_id": "asn1_nested_boundary_openssl__supp_003__outer_sequence_inner_length_plus_one",
            "base_family": "asn1_nested_boundary",
            "derived_from_case_id": "asn1_nested_boundary_openssl__mut_005__nested_length_mismatch",
            "refinement_strategy": "preserve_outer_container_mutate_inner",
            "mutation_assignments": [
                assignment("DER_BYTES", "valid_control", "preserve_outer_sequence_seed", True, True, "medium"),
                assignment("ASN1_NESTED_LENGTH", "boundary", "small_delta_plus_one_inner_only", True, True, "medium"),
            ],
            "expected_result_label": "near_valid_reject_probe",
        },
        {
            "supplemental_case_id": "asn1_nested_boundary_openssl__supp_004__outer_sequence_inner_length_minus_one",
            "base_family": "asn1_nested_boundary",
            "derived_from_case_id": "asn1_nested_boundary_openssl__mut_003__short_length",
            "refinement_strategy": "near_valid_small_length_delta",
            "mutation_assignments": [
                assignment("DER_BYTES", "valid_control", "preserve_outer_sequence_seed", True, True, "medium"),
                assignment("ASN1_NESTED_LENGTH", "boundary", "small_delta_minus_one_inner_only", True, True, "medium"),
            ],
            "expected_result_label": "near_valid_reject_probe",
        },
        {
            "supplemental_case_id": "asn1_nested_boundary_openssl__supp_005__valid_prefix_truncated_tail_one_byte",
            "base_family": "asn1_nested_boundary",
            "derived_from_case_id": "asn1_nested_boundary_openssl__mut_003__short_length",
            "refinement_strategy": "valid_prefix_trailing_only",
            "mutation_assignments": [
                assignment("DER_BYTES", "boundary", "preserve_valid_prefix_truncate_tail_one_byte", True, False, "medium"),
            ],
            "expected_result_label": "near_valid_reject_probe",
        },
        {
            "supplemental_case_id": "asn1_nested_boundary_openssl__supp_006__nested_depth_near_valid",
            "base_family": "asn1_nested_boundary",
            "derived_from_case_id": "asn1_nested_boundary_openssl__mut_006__nested_depth_variation",
            "refinement_strategy": "preserve_outer_container_mutate_inner",
            "mutation_assignments": [
                assignment("DER_BYTES", "valid_control", "preserve_seed_exact", True, True, "medium"),
                assignment("NESTED_DEPTH", "boundary", "increase_depth_by_one_only", True, True, "medium"),
            ],
            "expected_result_label": "accept_path_probe",
        },
        {
            "supplemental_case_id": "pkcs_container_parsing_openssl__supp_001__valid_pkcs12_seed_required",
            "base_family": "pkcs_container_parsing",
            "derived_from_case_id": "pkcs_container_parsing_openssl__mut_001__seed_preserving_baseline",
            "refinement_strategy": "seed_required_pending",
            "mutation_assignments": [
                assignment("CONTAINER_BYTES", "valid_control", "verified_valid_pkcs12_der_required", True, True, "unknown"),
            ],
            "expected_result_label": "seed_required_pending",
        },
        {
            "supplemental_case_id": "pkcs_container_parsing_openssl__supp_002__valid_pkcs12_plus_trailing_seed_required",
            "base_family": "pkcs_container_parsing",
            "derived_from_case_id": "pkcs_container_parsing_openssl__mut_002__trailing_garbage",
            "refinement_strategy": "seed_required_pending",
            "mutation_assignments": [
                assignment("CONTAINER_BYTES", "valid_control", "verified_valid_pkcs12_der_required", True, True, "unknown"),
                assignment("TRAILING_BYTES", "boundary", "append_00_after_valid_pkcs_object", True, True, "unknown"),
            ],
            "expected_result_label": "seed_required_pending",
        },
        {
            "supplemental_case_id": "pkcs_container_parsing_openssl__supp_003__preserve_outer_pkcs_mutate_inner_seed_required",
            "base_family": "pkcs_container_parsing",
            "derived_from_case_id": "pkcs_container_parsing_openssl__mut_004__nested_length_mismatch",
            "refinement_strategy": "seed_required_pending",
            "mutation_assignments": [
                assignment("CONTAINER_BYTES", "valid_control", "verified_valid_pkcs_container_required", True, True, "unknown"),
                assignment("NESTED_LENGTH_DELTA", "boundary", "small_inner_delta_only", True, True, "unknown"),
            ],
            "expected_result_label": "seed_required_pending",
        },
        {
            "supplemental_case_id": "pkcs_container_parsing_openssl__supp_004__near_valid_pkcs_length_delta_seed_required",
            "base_family": "pkcs_container_parsing",
            "derived_from_case_id": "pkcs_container_parsing_openssl__mut_003__malformed_length",
            "refinement_strategy": "seed_required_pending",
            "mutation_assignments": [
                assignment("CONTAINER_BYTES", "valid_control", "verified_valid_pkcs_container_required", True, True, "unknown"),
                assignment("NESTED_LENGTH_DELTA", "boundary", "small_delta_minus_one_only", True, True, "unknown"),
            ],
            "expected_result_label": "seed_required_pending",
        },
    ]
    for case in cases:
        case.update(
            {
                "target_library": "openssl",
                "oracle_focus": ["accepted", "full_consumption", "consumed_len", "openssl_error"],
                "render_allowed": supplemental_render_allowed(case),
                "render_block_reason": supplemental_render_block_reason(case),
                "notes": [
                    "supplemental planning case only; no render/compile/run performed",
                    "accepted-path observation must be validated in a later sprint",
                ],
            }
        )
    return {
        "schema": "supplemental_mutation_case_matrix_v1",
        "generated_at": now_iso(),
        "base_reason": "accepted_true_zero_in_oracle_aware_analysis",
        "cases": cases,
        "summary": {
            "total_cases": len(cases),
            "render_allowed_cases": len([c for c in cases if c["render_allowed"]]),
            "pending_seed_cases": len([c for c in cases if not c["render_allowed"]]),
            "pkcs_cases": len([c for c in cases if c["base_family"] == "pkcs_container_parsing"]),
            "asn1_cases": len([c for c in cases if c["base_family"] == "asn1_nested_boundary"]),
        },
    }


def build_render_plan(matrix: dict[str, Any]) -> dict[str, Any]:
    candidates = []
    blocked = []
    for case in matrix["cases"]:
        if case["render_allowed"]:
            candidates.append(
                {
                    "supplemental_case_id": case["supplemental_case_id"],
                    "family": case["base_family"],
                    "target_library": "openssl",
                    "refinement_strategy": case["refinement_strategy"],
                    "render_allowed": True,
                    "reason": "accepted-path supplemental probe with available ASN.1 valid-prefix seed source",
                    "required_inputs": [
                        "family_template",
                        "adapter_recipe",
                        "slot_bindings",
                        "supplemental_mutation_case",
                        "oracle_expectation",
                    ],
                }
            )
        else:
            blocked.append(
                {
                    "supplemental_case_id": case["supplemental_case_id"],
                    "family": case["base_family"],
                    "reason": case["render_block_reason"],
                }
            )
    return {
        "schema": "supplemental_render_candidate_plan_v1",
        "generated_at": now_iso(),
        "render_candidates": candidates,
        "blocked_cases": blocked,
        "summary": {
            "total_supplemental_cases": len(matrix["cases"]),
            "render_allowed": len(candidates),
            "render_blocked": len(blocked),
        },
    }


def build_quality(sem_doc: dict[str, Any], matrix: dict[str, Any], render_plan: dict[str, Any]) -> dict[str, Any]:
    raw = sem_doc.get("raw_observations", {}) or {}
    semantic = sem_doc.get("semantic_outcome", {}) or {}
    quality_pass = (
        raw.get("accepted_true") == 0
        and semantic.get("all_cases_rejected") is True
        and bool(matrix["cases"])
        and all(c["target_library"] == "openssl" for c in matrix["cases"])
    )
    return {
        "schema": "mutation_policy_refinement_quality_checks_v1",
        "generated_at": now_iso(),
        "accepted_true_from_previous_analysis": raw.get("accepted_true", 0),
        "all_cases_rejected_previous": semantic.get("all_cases_rejected", False),
        "seed_inventory_generated": True,
        "policy_refinement_generated": True,
        "supplemental_cases_generated": bool(matrix["cases"]),
        "render_candidates_generated": bool(render_plan["render_candidates"]),
        "original_mutation_matrix_modified": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "glm_called": False,
        "mbedtls_included": False,
        "no_confirmed_vulnerability_claim": True,
        "quality_status": "pass" if quality_pass else "partial",
        "notes": [
            "planning-only sprint",
            "supplemental cases are OpenSSL-only",
            "PKCS cases are blocked until a valid PKCS seed is verified",
        ],
    }


def build_next_action(render_plan: dict[str, Any], seed_inventory: dict[str, Any]) -> dict[str, Any]:
    allowed = render_plan["summary"]["render_allowed"]
    missing_seed = bool(seed_inventory["summary"]["families_without_valid_seed"])
    if allowed > 0:
        task = "render_plan_valid_prefix_v1"
        reason = "ASN.1 supplemental valid-prefix cases are render_allowed; PKCS seed-required cases remain blocked."
    elif missing_seed:
        task = "valid_seed_discovery_v1"
        reason = "No render_allowed supplemental cases exist and at least one family lacks valid seed."
    else:
        task = "mutation_refinement_fixup_v1"
        reason = "Refinement did not produce renderable accepted-path probes."
    return {
        "schema": "next_action_after_mutation_policy_refinement_v1",
        "generated_at": now_iso(),
        "next_task_name": task,
        "reason": reason,
    }


def build_report(
    sem_doc: dict[str, Any],
    seed_inventory: dict[str, Any],
    matrix: dict[str, Any],
    render_plan: dict[str, Any],
    quality: dict[str, Any],
    next_action: dict[str, Any],
) -> dict[str, Any]:
    raw = sem_doc.get("raw_observations", {}) or {}
    return {
        "schema": "mutation_policy_refinement_for_valid_prefix_v1_report",
        "task": "mutation_policy_refinement_for_valid_prefix_v1",
        "generated_at": now_iso(),
        "why_refinement_needed": "accepted_true=0; prior mutations only exercised reject paths",
        "previous_accepted_true": raw.get("accepted_true", 0),
        "seed_inventory_generated": True,
        "pkcs_valid_seed_available": seed_inventory["summary"]["pkcs_seed_available"],
        "asn1_valid_prefix_path_available": seed_inventory["summary"]["asn1_seed_available"],
        "supplemental_cases": matrix["summary"]["total_cases"],
        "render_allowed_supplemental_cases": matrix["summary"]["render_allowed_cases"],
        "pending_seed_cases": matrix["summary"]["pending_seed_cases"],
        "original_mutation_matrix_modified": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "glm_called": False,
        "quality_status": quality["quality_status"],
        "next_task_name": next_action["next_task_name"],
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
        "render_plan_summary": render_plan["summary"],
    }


def refine_valid_prefix(args: argparse.Namespace) -> dict[str, Any]:
    sem_doc = load_yaml(Path(args.oracle_semantics))
    load_yaml(Path(args.oracle_aware_analysis))
    load_yaml(Path(args.mutation_effectiveness))
    load_yaml(Path(args.original_mutation_case_matrix))
    load_yaml(Path(args.rendered_case_index))
    load_yaml(Path(args.instrumented_case_index))

    input_summary = build_input_summary(args, sem_doc)
    seed_inventory = build_seed_inventory()
    policy = build_policy_refinement(sem_doc)
    policy["generated_at"] = now_iso()
    matrix = build_supplemental_cases()
    render_plan = build_render_plan(matrix)
    quality = build_quality(sem_doc, matrix, render_plan)
    next_doc = build_next_action(render_plan, seed_inventory)
    report = build_report(sem_doc, seed_inventory, matrix, render_plan, quality, next_doc)
    return {
        "input_summary": input_summary,
        "seed_inventory": seed_inventory,
        "policy": policy,
        "matrix": matrix,
        "render_plan": render_plan,
        "quality": quality,
        "next_action": next_doc,
        "report": report,
    }


def write_refinement(out: Path, docs: dict[str, Any]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    dump_yaml(out / "input/mutation_policy_refinement_input_summary.yaml", docs["input_summary"])
    write_md(out / "input/mutation_policy_refinement_input_summary.md", "Input Summary", docs["input_summary"])
    dump_yaml(out / "seed_inventory/seed_inventory.yaml", docs["seed_inventory"])
    write_md(out / "seed_inventory/seed_inventory.md", "Seed Inventory", docs["seed_inventory"])
    dump_yaml(out / "policy_refinement/mutation_policy_refinement.yaml", docs["policy"])
    write_md(out / "policy_refinement/mutation_policy_refinement.md", "Policy Refinement", docs["policy"])
    dump_yaml(out / "supplemental_cases/supplemental_mutation_case_matrix.yaml", docs["matrix"])
    write_md(out / "supplemental_cases/supplemental_mutation_case_matrix.md", "Supplemental Mutation Case Matrix", docs["matrix"])
    dump_yaml(out / "render_candidate_plan/supplemental_render_candidate_plan.yaml", docs["render_plan"])
    write_md(out / "render_candidate_plan/supplemental_render_candidate_plan.md", "Supplemental Render Candidate Plan", docs["render_plan"])
    dump_yaml(out / "validation/mutation_policy_refinement_quality_checks.yaml", docs["quality"])
    write_md(out / "validation/mutation_policy_refinement_quality_checks.md", "Quality Checks", docs["quality"])
    dump_yaml(out / "reports/next_action_after_mutation_policy_refinement.yaml", docs["next_action"])
    write_md(out / "reports/next_action_after_mutation_policy_refinement.md", "Next Action", docs["next_action"])
    dump_yaml(out / "reports/mutation_policy_refinement_for_valid_prefix_v1_report.yaml", docs["report"])
    write_md(out / "reports/mutation_policy_refinement_for_valid_prefix_v1_report.md", "Mutation Policy Refinement Report", docs["report"])
    out.joinpath("README.md").write_text(
        "\n".join(
            [
                "# mutation_policy_refinement_for_valid_prefix_v1",
                "",
                "Planning-only mutation policy refinement after oracle-aware analysis observed accepted_true=0.",
                "",
                f"- supplemental_cases: {docs['matrix']['summary']['total_cases']}",
                f"- render_allowed_cases: {docs['matrix']['summary']['render_allowed_cases']}",
                f"- pending_seed_cases: {docs['matrix']['summary']['pending_seed_cases']}",
                f"- pkcs_valid_seed_available: {docs['seed_inventory']['summary']['pkcs_seed_available']}",
                f"- asn1_seed_available: {docs['seed_inventory']['summary']['asn1_seed_available']}",
                f"- next_task_name: {docs['next_action']['next_task_name']}",
                "",
                "No render, compile, run, feedback, GLM call, or vulnerability claim was performed.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-aware-analysis", required=True)
    parser.add_argument("--oracle-semantics", required=True)
    parser.add_argument("--mutation-effectiveness", required=True)
    parser.add_argument("--original-mutation-case-matrix", required=True)
    parser.add_argument("--rendered-case-index", required=True)
    parser.add_argument("--instrumented-case-index", required=True)
    parser.add_argument("--family-template-root", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    docs = refine_valid_prefix(args)
    out = Path(args.out_dir)
    write_refinement(out, docs)
    matrix = docs["matrix"]
    quality = docs["quality"]
    next_doc = docs["next_action"]
    print(f"[OK] wrote mutation policy refinement artifacts to {out}")
    print(
        "[SUMMARY] "
        f"supplemental_cases={matrix['summary']['total_cases']} "
        f"render_allowed={matrix['summary']['render_allowed_cases']} "
        f"pending_seed={matrix['summary']['pending_seed_cases']} "
        f"quality={quality['quality_status']}"
    )
    print(f"[NEXT] {next_doc['next_task_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
