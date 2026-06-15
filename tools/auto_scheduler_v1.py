#!/usr/bin/env python3
"""Read-only scheduler for crypto vulnerability-pattern family triage.

This tool summarizes pattern-bank, scheduler-seed, feedback, and pattern-note
inputs into family inventory, conservative route/gate decisions, and next-task
recommendations. It intentionally does not render cases, run harnesses, call
LLMs, or write back to the Pattern Bank.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


REQUIRED_FAMILIES = [
    "mac_lifecycle",
    "der_full_consumption",
    "secure_heap_state_lifecycle",
    "cipher_aead_lifecycle",
    "asn1_nested_boundary",
    "bignum_serialization_boundary",
    "bignum_arithmetic_precondition",
    "pkey_verify_semantic",
    "x509_parsing",
    "ossl_store_decoder_boundary",
    "evp_pkey_context_lifecycle",
    "provider_fetch_lifecycle",
]

ALIAS_TO_REQUIRED = {
    "memory_length_boundary": "bignum_serialization_boundary",
    "bn_mpi_arithmetic": "bignum_arithmetic_precondition",
    "api_state_machine": "evp_pkey_context_lifecycle",
}

COMPLETED_FAMILIES = {
    "mac_lifecycle",
    "der_full_consumption",
    "secure_heap_state_lifecycle",
    "cipher_aead_lifecycle",
    "asn1_nested_boundary",
}

SCHEDULER_ACTIONS = {
    "promote",
    "keep",
    "demote",
    "close",
    "block",
    "external_validation",
}


def load_yaml(path: Path, errors: list[dict[str, str]]) -> Any:
    if not path.exists():
        errors.append({"path": str(path), "error": "missing"})
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # pragma: no cover - reported in artifacts
        errors.append({"path": str(path), "error": str(exc)})
        return {}


def load_jsonl(path: Path, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for idx, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception as exc:
                    errors.append({"path": str(path), "line": str(idx), "error": str(exc)})
                    continue
                if isinstance(obj, dict):
                    obj["_feedback_file"] = str(path)
                    obj["_feedback_line"] = idx
                    rows.append(obj)
    except Exception as exc:
        errors.append({"path": str(path), "error": str(exc)})
    return rows


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def write_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def flatten_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    if isinstance(value, dict):
        out: list[str] = []
        for key, val in value.items():
            out.append(str(key))
            out.extend(flatten_values(val))
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(flatten_values(item))
        return out
    return [str(value)]


def text_blob(value: Any) -> str:
    return " ".join(flatten_values(value)).lower()


def normalize_family(family: str) -> str:
    return ALIAS_TO_REQUIRED.get(family, family)


def collect_schema_files(schema_dir: Path) -> list[Path]:
    rels = [
        "schema/family_profile_schema.yaml",
        "schema/route_decision_schema.yaml",
        "gates/evidence_gate.yaml",
        "gates/a_path_glm_gate.yaml",
        "schema/feedback_schema.yaml",
        "scheduler/scheduler_scoring_schema.yaml",
        "automation_plan/auto_scheduler_v1_design.yaml",
    ]
    return [schema_dir / rel for rel in rels]


def infer_action(row: dict[str, Any]) -> str:
    raw = " ".join(
        str(row.get(key, ""))
        for key in [
            "scheduler_action",
            "next_action",
            "classification",
            "final_classification",
            "verdict",
            "feedback_category",
            "validation_status",
            "audit_result",
            "seed_status",
            "observed_behavior",
        ]
    ).lower()
    if "external_validation" in raw or "validated_new_state_candidate" in raw:
        return "external_validation"
    if "blocked_seed_missing" in raw or "seed_missing" in raw or "placeholder_only" in raw:
        return "block"
    if (
        "closed_negative" in raw
        or "do_not_promote" in raw
        or "legal_semantics" in raw
        or "negative feedback" in raw
        or "negative_feedback" in raw
        or "downgrade" in raw
        or "lower_priority" in raw
    ):
        return "close" if "closed" in raw or "do_not_promote" in raw else "demote"
    if "app_level_validation_gap_candidate" in raw or "promote" in raw:
        return "promote"
    if "migrated_safe" in raw or "needs_triage" in raw or "safe_negative" in raw:
        return "keep"
    if row.get("negative_feedback") is True:
        return "demote"
    return "keep"


def infer_evidence_strength(family: str, info: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    blob = text_blob(info) + " " + text_blob(rows)
    if "blocked_seed_missing" in blob or "placeholder_only" in blob or "missing_seed" in blob or "seed_missing" in blob:
        return "insufficient"
    if "strong" in blob or "validated_new_state_candidate" in blob or "app_level_validation_gap_candidate" in blob:
        return "strong"
    if family in {"mac_lifecycle", "pkey_verify_semantic", "x509_parsing"}:
        return "medium"
    if family in {"ossl_store_decoder_boundary", "provider_fetch_lifecycle", "evp_pkey_context_lifecycle"}:
        return "weak"
    return "medium"


def discover_knowledge_families(knowledge_dir: Path, errors: list[dict[str, str]]) -> tuple[set[str], list[str]]:
    families: set[str] = set()
    files: list[str] = []
    for path in sorted(knowledge_dir.glob("*.md")):
        files.append(str(path))
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        for match in re.finditer(r"Family:\s*([A-Za-z0-9_\\-]+)", text):
            families.add(normalize_family(match.group(1)))
    return families, files


def build_feedback_summary(feedback_rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in feedback_rows:
        family = row.get("family")
        if not family:
            continue
        grouped[normalize_family(str(family))].append(row)

    summary = {}
    for family, rows in sorted(grouped.items()):
        counts = Counter(infer_action(row) for row in rows)
        dominant = "keep"
        for action in ["block", "external_validation", "close", "demote", "promote", "keep"]:
            if counts.get(action, 0):
                dominant = action
                break
        latest = rows[-1].copy()
        summary[family] = {
            "family": family,
            "record_count": len(rows),
            "promote_count": counts.get("promote", 0),
            "keep_count": counts.get("keep", 0),
            "demote_count": counts.get("demote", 0),
            "close_count": counts.get("close", 0),
            "block_count": counts.get("block", 0),
            "external_validation_count": counts.get("external_validation", 0),
            "latest_feedback": latest,
            "dominant_scheduler_action": dominant,
        }
    return {"feedback_summary": summary}


def known_sprints_from_values(value: Any) -> list[str]:
    paths = []
    for item in flatten_values(value):
        if "artifacts/sprints/" in item or "artifacts/triage/" in item:
            paths.append(item)
    sprint_names = set()
    for item in paths:
        parts = Path(item).parts
        if "sprints" in parts:
            idx = parts.index("sprints")
            if idx + 1 < len(parts):
                sprint_names.add(parts[idx + 1])
        if "triage" in parts:
            idx = parts.index("triage")
            if idx + 1 < len(parts):
                sprint_names.add(parts[idx + 1])
    return sorted(sprint_names)


def family_seed_available(info: dict[str, Any], rows: list[dict[str, Any]]) -> bool:
    blob = text_blob(info) + " " + text_blob(rows)
    if "real_seed_not_found" in blob or "placeholder_only" in blob or "seed_missing" in blob:
        return False
    return bool(info.get("patterns") or info.get("seed_inventory") or any(row.get("seed_id") or row.get("seed_issue") for row in rows))


def classify_inventory_status(family: str, scheduler_info: dict[str, Any], pb_summary: Any, rows: list[dict[str, Any]]) -> tuple[str, list[str], list[str], list[str]]:
    blob = " ".join([text_blob(scheduler_info), text_blob(pb_summary), text_blob(rows)])
    blockers: list[str] = []
    negative: list[str] = []
    positive: list[str] = []

    if "blocked_seed_missing" in blob or "placeholder_only" in blob or "real_seed_not_found" in blob:
        blockers.append("seed_missing_or_placeholder_only")
    if "mapping_gap" in blob:
        blockers.append("mapping_gap")
    if "closed_negative_feedback" in blob or "legal_semantics" in blob or "negative_feedback" in blob:
        negative.append("closed_or_legal_semantics_negative_feedback")
    if "app_level_validation_gap_candidate" in blob:
        positive.append("app_level_validation_gap_candidate")
    if "validated_new_state_candidate" in blob:
        positive.append("validated_new_state_candidate")
    if "crash_candidate" in blob and "can_claim_confirmed_vulnerability false" in blob:
        positive.append("current_version_crash_or_robustness_candidate")
    if "migrated_safe" in blob or "needs_triage" in blob:
        positive.append("migrated_safe_or_needs_triage")

    if "seed_missing_or_placeholder_only" in blockers:
        status = "blocked_seed_missing"
    elif "external_validation" in blob or "milestone_closed_pending_external_validation" in blob:
        status = "external_validation"
    elif family == "cipher_aead_lifecycle" and negative:
        status = "closed_negative_feedback"
    elif family == "der_full_consumption":
        status = "minimal_reproducer_or_upstream_track"
    elif family == "mac_lifecycle":
        status = "a_path_template_needs_triage"
    elif family in {"pkey_verify_semantic"} and "stable_safe_negative_baseline" in blob:
        status = "closed_negative_feedback"
    elif not scheduler_info and not rows:
        status = "candidate_family"
    else:
        status = str(scheduler_info.get("triage_status") or scheduler_info.get("milestone_status") or "ready_for_triage")
    return status, positive, negative, blockers


def build_inventory(
    pattern_bank: dict[str, Any],
    scheduler_seed: dict[str, Any],
    feedback_summary: dict[str, Any],
    knowledge_families: set[str],
) -> dict[str, Any]:
    families = set(REQUIRED_FAMILIES)
    families.update(knowledge_families)
    families.update(normalize_family(f) for f in (scheduler_seed.get("families") or {}).keys())
    families.update(normalize_family(f) for f in (pattern_bank.get("feedback_summary") or {}).keys())
    for pat in pattern_bank.get("patterns", []) or []:
        if isinstance(pat, dict) and pat.get("family"):
            families.add(normalize_family(str(pat["family"])))
    families.update(feedback_summary["feedback_summary"].keys())

    inventory = []
    raw_scheduler_families = scheduler_seed.get("families") or {}
    pb_feedback = pattern_bank.get("feedback_summary") or {}
    pattern_counts = Counter()
    for pat in pattern_bank.get("patterns", []) or []:
        if isinstance(pat, dict) and pat.get("family"):
            pattern_counts[normalize_family(str(pat["family"]))] += 1

    for family in sorted(families):
        aliases = [src for src, dst in ALIAS_TO_REQUIRED.items() if dst == family]
        scheduler_info = dict(raw_scheduler_families.get(family) or {})
        for alias in aliases:
            if alias in raw_scheduler_families:
                scheduler_info.setdefault("alias_sources", []).append(alias)
                for key, val in (raw_scheduler_families.get(alias) or {}).items():
                    scheduler_info.setdefault(key, val)
        pb_summary = pb_feedback.get(family) or {}
        for alias in aliases:
            if alias in pb_feedback and not pb_summary:
                pb_summary = pb_feedback[alias]
        rows = []
        if family in feedback_summary["feedback_summary"]:
            latest = feedback_summary["feedback_summary"][family].get("latest_feedback")
            rows = [latest] if latest else []
        status, positive, negative, blockers = classify_inventory_status(family, scheduler_info, pb_summary, rows)
        known_feedback = []
        if family in feedback_summary["feedback_summary"]:
            known_feedback.append(family)
        for alias in aliases:
            if alias in feedback_summary["feedback_summary"]:
                known_feedback.append(alias)
        known_sprints = sorted(set(known_sprints_from_values(scheduler_info) + known_sprints_from_values(pb_summary) + known_sprints_from_values(rows)))
        inventory.append(
            {
                "family": family,
                "status": status,
                "known_sprints": known_sprints,
                "known_feedback": known_feedback,
                "positive_signals": sorted(set(positive)),
                "negative_feedback": sorted(set(negative)),
                "blockers": sorted(set(blockers)),
                "available_seed": family_seed_available(scheduler_info, rows),
                "evidence_strength": infer_evidence_strength(family, scheduler_info, rows),
                "last_known_outcome": scheduler_info.get("triage_status")
                or scheduler_info.get("milestone_status")
                or scheduler_info.get("recommended_path")
                or status,
                "pattern_count": pattern_counts.get(family, 0),
                "candidate_only": family not in COMPLETED_FAMILIES,
            }
        )
    return {"families": inventory, "family_count": len(inventory)}


def score_family(item: dict[str, Any], feedback: dict[str, Any]) -> dict[str, Any]:
    family = item["family"]
    status = item["status"]
    evidence = item["evidence_strength"]
    fb = feedback.get(family, {})

    historical_seed_quality = 1
    if item["available_seed"]:
        historical_seed_quality = min(5, 2 + min(3, item.get("pattern_count", 0)))
    if "seed_missing" in item["blockers"]:
        historical_seed_quality = 1

    oracle_clarity = 2
    if "app_level_validation_gap_candidate" in item["positive_signals"]:
        oracle_clarity = 5
    elif "validated_new_state_candidate" in item["positive_signals"]:
        oracle_clarity = 4
    elif family in {"mac_lifecycle", "cipher_aead_lifecycle", "pkey_verify_semantic"}:
        oracle_clarity = 3
    elif evidence == "weak":
        oracle_clarity = 2
    elif evidence == "insufficient":
        oracle_clarity = 1

    api_mapping_clarity = 2
    if family in {"mac_lifecycle", "secure_heap_state_lifecycle", "pkey_verify_semantic", "der_full_consumption"}:
        api_mapping_clarity = 4
    elif family in {"x509_parsing", "bignum_serialization_boundary", "bignum_arithmetic_precondition"}:
        api_mapping_clarity = 3
    if "mapping_gap" in item["blockers"]:
        api_mapping_clarity = 1

    mutation_space_quality = 2
    if family in {"cipher_aead_lifecycle", "secure_heap_state_lifecycle", "pkey_verify_semantic", "mac_lifecycle"}:
        mutation_space_quality = 4
    elif family in {"x509_parsing", "provider_fetch_lifecycle", "evp_pkey_context_lifecycle", "ossl_store_decoder_boundary"}:
        mutation_space_quality = 3
    if status == "blocked_seed_missing":
        mutation_space_quality = 1

    prior_positive_signal = 0
    if item["positive_signals"]:
        prior_positive_signal = min(5, len(item["positive_signals"]) + 2)
    if family == "secure_heap_state_lifecycle":
        prior_positive_signal = 5
    if status in {"closed_negative_feedback", "blocked_seed_missing"}:
        prior_positive_signal = min(prior_positive_signal, 1)

    novelty_potential = 3
    if item["candidate_only"]:
        novelty_potential = 4
    if family in {"provider_fetch_lifecycle", "ossl_store_decoder_boundary", "evp_pkey_context_lifecycle", "x509_parsing"}:
        novelty_potential = 4
    if status in {"closed_negative_feedback", "blocked_seed_missing"}:
        novelty_potential = 1

    execution_cost = -1
    if family in {"x509_parsing", "asn1_nested_boundary", "provider_fetch_lifecycle"}:
        execution_cost = -2
    if family == "secure_heap_state_lifecycle":
        execution_cost = -2

    negative_feedback_penalty = 0
    if fb.get("demote_count", 0) or fb.get("close_count", 0) or item["negative_feedback"]:
        negative_feedback_penalty = -min(5, fb.get("demote_count", 0) + fb.get("close_count", 0) + len(item["negative_feedback"]))
    if family == "cipher_aead_lifecycle":
        negative_feedback_penalty = min(negative_feedback_penalty, -4)
    if status == "closed_negative_feedback":
        negative_feedback_penalty = min(negative_feedback_penalty, -5)

    seed_missing_penalty = -5 if status == "blocked_seed_missing" else 0
    external_validation_penalty = -3 if status == "external_validation" else 0

    # Keep completed tracks from crowding out genuinely next-step candidates.
    if family == "mac_lifecycle":
        external_validation_penalty -= 4
    if family == "der_full_consumption":
        external_validation_penalty -= 4
    if family == "secure_heap_state_lifecycle":
        external_validation_penalty -= 5

    final_score = sum(
        [
            historical_seed_quality,
            oracle_clarity,
            api_mapping_clarity,
            mutation_space_quality,
            prior_positive_signal,
            novelty_potential,
            execution_cost,
            negative_feedback_penalty,
            seed_missing_penalty,
            external_validation_penalty,
        ]
    )

    route, next_task = decide_route_and_task(family, status, evidence, item)
    return {
        "family": family,
        "historical_seed_quality": historical_seed_quality,
        "oracle_clarity": oracle_clarity,
        "api_mapping_clarity": api_mapping_clarity,
        "mutation_space_quality": mutation_space_quality,
        "prior_positive_signal": prior_positive_signal,
        "novelty_potential": novelty_potential,
        "execution_cost": execution_cost,
        "negative_feedback_penalty": negative_feedback_penalty,
        "seed_missing_penalty": seed_missing_penalty,
        "external_validation_penalty": external_validation_penalty,
        "final_score": final_score,
        "recommended_route": route,
        "recommended_next_task": next_task,
        "explanation": explain_score(family, status),
    }


def decide_route_and_task(family: str, status: str, evidence: str, item: dict[str, Any]) -> tuple[str, str]:
    if status == "blocked_seed_missing":
        return "blocked", f"{family}_seed_recovery_or_blocked_review"
    if status == "closed_negative_feedback":
        return "closed_negative_feedback", f"{family}_closed_negative_feedback"
    if status == "external_validation":
        return "external_validation", f"{family}_external_validation_track"
    if family == "mac_lifecycle":
        return "A_recipe_slot_cross_library_migration", "mac_lifecycle_documentation_and_caller_impact_triage"
    if family == "der_full_consumption":
        return "C_app_level_validation_gap", "der_full_consumption_minimal_reproducer_or_upstream_inquiry"
    if family == "cipher_aead_lifecycle":
        return "closed_negative_feedback", "cipher_aead_lifecycle_non_gcm_triage_later"
    if family == "secure_heap_state_lifecycle":
        return "external_validation", "secure_heap_external_validation_track"
    if family in {"provider_fetch_lifecycle", "evp_pkey_context_lifecycle"}:
        return "B_controlled_family_mutation", f"{family}_triage_v1"
    if family in {"ossl_store_decoder_boundary", "x509_parsing"}:
        return "C_app_level_validation_gap", f"{family}_triage_v1"
    if family in {"bignum_serialization_boundary", "bignum_arithmetic_precondition"}:
        return "needs_more_evidence", f"{family}_evidence_triage_v1"
    if evidence in {"weak", "insufficient"}:
        return "needs_more_evidence", f"{family}_evidence_triage_v1"
    return "B_controlled_family_mutation", f"{family}_triage_v1"


def explain_score(family: str, status: str) -> str:
    if family == "cipher_aead_lifecycle":
        return "GCM candidates are closed as negative feedback; only non-GCM spaces remain later."
    if family == "asn1_nested_boundary":
        return "Blocked because real seed is missing and placeholder-only evidence cannot support D-path."
    if family == "secure_heap_state_lifecycle":
        return "Strong current-version signal, but moved to external validation rather than main exploration."
    if family == "der_full_consumption":
        return "Strong app-level behavior candidate; next step is minimal reproducer/upstream inquiry, not repeat C-path."
    if family == "mac_lifecycle":
        return "Successful A-path template; keep for triage/documentation rather than immediate new run."
    if status == "candidate_family":
        return "Candidate family with limited prior artifacts; scheduler may triage before render/run."
    return f"Status: {status}."


def apply_gates(score: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    route = score["recommended_route"]
    evidence_strength = item["evidence_strength"]
    blockers = set(item.get("blockers") or [])
    negative = set(item.get("negative_feedback") or [])

    evidence_passed = evidence_strength in {"strong", "medium"} and not blockers
    evidence_actions = []
    if "seed_missing_or_placeholder_only" in blockers:
        evidence_actions.extend(["no_D_path_reproduction", "no_crash_claim"])
    if "mapping_gap" in blockers:
        evidence_actions.append("no_A_path")
    if evidence_strength in {"weak", "insufficient"}:
        evidence_actions.append("no_auto_render")
    if negative:
        evidence_actions.append("write_negative_feedback_or_demote")

    a_path_passed = (
        route == "A_recipe_slot_cross_library_migration"
        and evidence_passed
        and score["api_mapping_clarity"] >= 4
        and score["oracle_clarity"] >= 3
    )
    glm_allowed = a_path_passed and route == "A_recipe_slot_cross_library_migration"
    auto_render_allowed = False
    auto_run_allowed = False

    return {
        "family": item["family"],
        "recommended_route": route,
        "evidence_gate": {
            "passed": evidence_passed,
            "strength": evidence_strength,
            "actions": evidence_actions,
        },
        "a_path_gate": {
            "passed": a_path_passed,
            "reason": "passed" if a_path_passed else "not an eligible A-path family or evidence/mapping/oracle gate did not pass",
        },
        "glm_gate": {
            "glm_allowed": glm_allowed,
            "glm_role": "strict_slot_bindings_only" if glm_allowed else "none",
        },
        "auto_render_allowed": auto_render_allowed,
        "auto_run_allowed": auto_run_allowed,
    }


def markdown_table(rows: list[dict[str, Any]], headers: list[str]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    return "\n".join(lines) + "\n"


def make_reports(
    sprint_root: Path,
    input_summary: dict[str, Any],
    inventory: dict[str, Any],
    feedback_summary: dict[str, Any],
    scores: list[dict[str, Any]],
    gates: list[dict[str, Any]],
    route_decisions: list[dict[str, Any]],
    next_rec: dict[str, Any],
) -> None:
    inv_rows = inventory["families"]
    write_md(
        sprint_root / "input/auto_scheduler_input_summary.md",
        "# auto_scheduler_v1 Input Summary\n\n"
        + "## Loaded Sources\n\n"
        + yaml.safe_dump(input_summary["loaded_sources"], sort_keys=False)
        + "\n## Missing Sources\n\n"
        + yaml.safe_dump(input_summary["missing_sources"], sort_keys=False)
        + "\n## Parse Errors\n\n"
        + yaml.safe_dump(input_summary["parse_errors"], sort_keys=False),
    )
    write_md(
        sprint_root / "parsed/family_inventory.md",
        "# Family Inventory\n\n"
        + markdown_table(
            inv_rows,
            ["family", "status", "evidence_strength", "available_seed", "last_known_outcome"],
        ),
    )
    fb_rows = list(feedback_summary["feedback_summary"].values())
    write_md(
        sprint_root / "parsed/feedback_summary.md",
        "# Feedback Summary\n\n"
        + markdown_table(
            fb_rows,
            [
                "family",
                "record_count",
                "promote_count",
                "keep_count",
                "demote_count",
                "close_count",
                "block_count",
                "external_validation_count",
                "dominant_scheduler_action",
            ],
        ),
    )
    write_md(
        sprint_root / "scoring/family_scores.md",
        "# Family Scores\n\n"
        + markdown_table(
            scores,
            ["family", "final_score", "recommended_route", "recommended_next_task", "explanation"],
        ),
    )
    gate_rows = [
        {
            "family": g["family"],
            "recommended_route": g["recommended_route"],
            "evidence_gate": g["evidence_gate"]["passed"],
            "a_path_gate": g["a_path_gate"]["passed"],
            "glm_allowed": g["glm_gate"]["glm_allowed"],
            "auto_render_allowed": g["auto_render_allowed"],
            "auto_run_allowed": g["auto_run_allowed"],
        }
        for g in gates
    ]
    write_md(
        sprint_root / "gates/gate_results.md",
        "# Gate Results\n\n"
        + markdown_table(
            gate_rows,
            [
                "family",
                "recommended_route",
                "evidence_gate",
                "a_path_gate",
                "glm_allowed",
                "auto_render_allowed",
                "auto_run_allowed",
            ],
        ),
    )
    write_md(
        sprint_root / "output/route_decisions.md",
        "# Route Decisions\n\n"
        + markdown_table(
            route_decisions,
            [
                "family",
                "recommended_route",
                "evidence_gate",
                "a_path_gate",
                "glm_allowed",
                "auto_render_allowed",
                "auto_run_allowed",
                "next_task_name",
            ],
        ),
    )
    write_md(
        sprint_root / "output/next_task_recommendation.md",
        "# Next Task Recommendation\n\n"
        + yaml.safe_dump(next_rec, sort_keys=False),
    )
    report = {
        "sprint": "auto_scheduler_v1",
        "input_sources": input_summary["loaded_sources"],
        "family_count": inventory["family_count"],
        "top_1_family": next_rec.get("top_1_family"),
        "top_2_family": next_rec.get("top_2_family"),
        "top_3_family": next_rec.get("top_3_family"),
        "why_not_previous_families": next_rec["why_not_previous_families"],
        "evidence_gate_effect": "blocked seed-missing and weak-evidence families; legal semantics negative feedback demotes AEAD-GCM.",
        "a_path_glm_gate_effect": "GLM is allowed only for MAC lifecycle A-path template, but auto render/run remains disabled in this scheduler-only sprint.",
        "auto_render_allowed": False,
        "auto_run_allowed": False,
        "recommended_next_task": next_rec["recommended_next_task"],
        "pattern_bank_write_back": False,
        "vulnerability_found": False,
        "next_stage": "route_planner_v1 or gated_auto_triage_v1 after reviewing scheduler output",
    }
    write_yaml(sprint_root / "reports/auto_scheduler_v1_report.yaml", report)
    report_md = (
        "# auto_scheduler_v1 Report\n\n"
        f"- Family count: `{report['family_count']}`\n"
        f"- Top-1: `{report['top_1_family']}`\n"
        f"- Top-2: `{report['top_2_family']}`\n"
        f"- Top-3: `{report['top_3_family']}`\n"
        f"- Recommended next task: `{report['recommended_next_task']}`\n"
        "- Pattern Bank write-back: `false`\n"
        "- Auto render/run: `false` / `false`\n"
        "- Vulnerability found: `false`\n\n"
        "## Why Not Previous Families\n\n"
        + yaml.safe_dump(report["why_not_previous_families"], sort_keys=False)
        + "\n## Gate Effects\n\n"
        + f"{report['evidence_gate_effect']}\n\n{report['a_path_glm_gate_effect']}\n"
    )
    write_md(sprint_root / "reports/auto_scheduler_v1_report.md", report_md)
    write_md(
        sprint_root / "README.md",
        "# auto_scheduler_v1\n\n"
        "Read-only scheduler sprint. It reads Pattern Bank, Scheduler Seed, feedback JSONL, knowledge pattern notes, and schema design artifacts, then emits family inventory, scores, route/gate decisions, and next-task recommendation.\n\n"
        "No Pattern Bank write-back, GLM call, harness render, harness compile/run, or vulnerability claim is performed.\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only auto scheduler v1")
    parser.add_argument("--pattern-bank", required=True)
    parser.add_argument("--scheduler-seed", required=True)
    parser.add_argument("--feedback-dir", required=True)
    parser.add_argument("--knowledge-dir", required=True)
    parser.add_argument("--schema-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-back", default="false", choices=["false"])
    args = parser.parse_args()

    pattern_bank_path = Path(args.pattern_bank)
    scheduler_seed_path = Path(args.scheduler_seed)
    feedback_dir = Path(args.feedback_dir)
    knowledge_dir = Path(args.knowledge_dir)
    schema_dir = Path(args.schema_dir)
    out_dir = Path(args.out_dir)
    sprint_root = out_dir.parent

    parse_errors: list[dict[str, str]] = []
    schema_files = collect_schema_files(schema_dir)
    schemas = {str(path): load_yaml(path, parse_errors) for path in schema_files}
    pattern_bank = load_yaml(pattern_bank_path, parse_errors)
    scheduler_seed = load_yaml(scheduler_seed_path, parse_errors)

    feedback_files = sorted(feedback_dir.glob("*.jsonl"))
    feedback_rows = []
    for path in feedback_files:
        feedback_rows.extend(load_jsonl(path, parse_errors))

    knowledge_families, knowledge_files = discover_knowledge_families(knowledge_dir, parse_errors)
    missing_sources = []
    for path in [pattern_bank_path, scheduler_seed_path, feedback_dir, knowledge_dir, schema_dir, *schema_files]:
        if not path.exists():
            missing_sources.append(str(path))

    input_summary = {
        "loaded_sources": {
            "pattern_bank": str(pattern_bank_path) if pattern_bank_path.exists() else None,
            "scheduler_seed": str(scheduler_seed_path) if scheduler_seed_path.exists() else None,
            "feedback_files": [str(path) for path in feedback_files],
            "schema_files": [str(path) for path in schema_files if path.exists()],
            "knowledge_raw_files": knowledge_files,
        },
        "missing_sources": missing_sources,
        "parse_errors": parse_errors,
        "schema_keys_loaded": sorted(schemas.keys()),
        "write_back": False,
    }

    feedback_summary = build_feedback_summary(feedback_rows)
    inventory = build_inventory(pattern_bank, scheduler_seed, feedback_summary, knowledge_families)
    feedback_by_family = feedback_summary["feedback_summary"]
    scores = [score_family(item, feedback_by_family) for item in inventory["families"]]
    scores.sort(key=lambda item: (item["final_score"], item["family"]), reverse=True)
    inventory_by_family = {item["family"]: item for item in inventory["families"]}
    gates = [apply_gates(score, inventory_by_family[score["family"]]) for score in scores]
    gate_by_family = {item["family"]: item for item in gates}
    route_decisions = []
    for score in scores:
        gate = gate_by_family[score["family"]]
        route_decisions.append(
            {
                "family": score["family"],
                "recommended_route": score["recommended_route"],
                "reason": score["explanation"],
                "evidence_gate": gate["evidence_gate"]["passed"],
                "a_path_gate": gate["a_path_gate"]["passed"],
                "glm_allowed": gate["glm_gate"]["glm_allowed"],
                "auto_render_allowed": gate["auto_render_allowed"],
                "auto_run_allowed": gate["auto_run_allowed"],
                "next_task_name": score["recommended_next_task"],
            }
        )

    # Choose next task conservatively: prefer a not-completed candidate family with
    # gates that do not demand immediate render/run. If none exists, use top score.
    top_candidates = [s for s in scores if s["recommended_route"] not in {"blocked", "closed_negative_feedback", "external_validation"}]
    next_score = top_candidates[0] if top_candidates else scores[0]
    top3 = scores[:3]
    why_not_previous = {
        "secure_heap": "Moved to external validation after current-version init_failed_then_query candidate; not main exploratory top-1.",
        "cipher_aead_lifecycle": "GCM cases closed or demoted as legal semantics/mapping gaps; non-GCM spaces can wait.",
        "asn1_nested_boundary": "Blocked by real seed missing / placeholder-only evidence.",
        "der_full_consumption": "Strong app-level candidate, but next step is minimal reproducer/upstream inquiry rather than another scheduler-selected experiment.",
        "mac_lifecycle": "Successful A-path template; useful as reference, not urgent next discovery loop target.",
    }
    next_rec = {
        "top_1_family": top3[0]["family"] if len(top3) > 0 else None,
        "top_2_family": top3[1]["family"] if len(top3) > 1 else None,
        "top_3_family": top3[2]["family"] if len(top3) > 2 else None,
        "recommended_next_task": next_score["recommended_next_task"],
        "recommended_route": next_score["recommended_route"],
        "glm_allowed": gate_by_family[next_score["family"]]["glm_gate"]["glm_allowed"],
        "auto_render_allowed": False,
        "auto_run_allowed": False,
        "why_not_previous_families": why_not_previous,
        "selected_family": next_score["family"],
        "selection_reason": next_score["explanation"],
    }

    write_yaml(sprint_root / "input/auto_scheduler_input_summary.yaml", input_summary)
    write_json(sprint_root / "parsed/feedback_summary.json", feedback_summary)
    write_json(sprint_root / "parsed/family_inventory.json", inventory)
    write_json(sprint_root / "scoring/family_scores.json", {"family_scores": scores})
    write_json(sprint_root / "gates/gate_results.json", {"gate_results": gates})
    write_json(sprint_root / "output/route_decisions.json", {"route_decisions": route_decisions})
    write_json(sprint_root / "output/next_task_recommendation.json", next_rec)
    make_reports(sprint_root, input_summary, inventory, feedback_summary, scores, gates, route_decisions, next_rec)

    print(f"auto_scheduler_v1 completed: families={inventory['family_count']} selected={next_rec['selected_family']} next={next_rec['recommended_next_task']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
