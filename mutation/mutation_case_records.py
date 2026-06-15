"""Shared mutation case record helpers.

This module is intentionally data-oriented.  It provides YAML helpers and small
record builders used by mutation planning modules; it does not render, compile,
run, call GLM, or write feedback.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )


def write_md(path: Path, title: str, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=100)
    path.write_text(f"# {title}\n\n```yaml\n{text}```\n", encoding="utf-8")


def adapter_slug(adapter_id: str) -> str:
    return adapter_id.replace(".", "_").replace(" ", "_")


def result_by_id(results_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("adapter_id"): item
        for item in results_doc.get("results", []) or []
        if isinstance(item, dict) and item.get("adapter_id")
    }


def mutation_slot_lookup(mutation_slots_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("slot_name"): item
        for item in mutation_slots_doc.get("mutation_slots", []) or []
        if isinstance(item, dict) and item.get("slot_name")
    }


def selected_unit_slots(selected_doc: Any) -> set[str]:
    slots: set[str] = set()
    if isinstance(selected_doc, dict):
        units = selected_doc.get("selected_units") or selected_doc.get("selected_mask_units") or []
    elif isinstance(selected_doc, list):
        units = selected_doc
    else:
        units = []
    for unit in units:
        if not isinstance(unit, dict):
            continue
        slot_name = str(unit.get("slot_name", ""))
        placeholder = str(unit.get("placeholder", ""))
        if slot_name:
            slots.add(slot_name)
        if placeholder.startswith("[") and placeholder.endswith("]"):
            slots.add(placeholder[1:-1])
    return slots


def assignment(
    slot: str,
    mutation_type: str,
    strategy: str,
    preserves_valid_prefix: bool,
    preserves_outer_container: bool,
    probability: str,
) -> dict[str, Any]:
    return {
        "slot_name": slot,
        "mutation_type": mutation_type,
        "mutation_value_strategy": strategy,
        "preserves_valid_prefix": preserves_valid_prefix,
        "preserves_outer_container": preserves_outer_container,
        "expected_accept_path_probability": probability,
    }


def build_family_case(
    idx: int,
    adapter_id: str,
    family: str,
    target_library: str,
    strategy: str,
    slot_specs: list[tuple[str, str, str]],
    result_label: str,
    slot_lookup: dict[str, dict[str, Any]],
    oracle_types: list[str],
) -> dict[str, Any]:
    primary = oracle_types[0] if oracle_types else "parser_reject_accept"
    secondary = oracle_types[1:] if len(oracle_types) > 1 else []
    return {
        "case_id": f"{adapter_slug(adapter_id)}__mut_{idx:03d}__{strategy}",
        "family": family,
        "target_library": target_library,
        "base_adapter": adapter_id,
        "template_level": "family",
        "mutation_strategy": strategy,
        "mutation_slots": [
            {
                "slot_name": slot,
                "mutation_type": mutation_type,
                "mutation_value": value,
                "source": "family_mutation_slots" if slot in slot_lookup else "oracle_plan",
                "safety_notes": slot_lookup.get(slot, {}).get("safety_notes", ""),
            }
            for slot, mutation_type, value in slot_specs
        ],
        "expected_oracle": {
            "primary": primary,
            "secondary": secondary,
            "expected_result_label": result_label,
        },
        "render_allowed": True,
        "render_block_reason": "",
        "risk_notes": [
            "case spec only; no C generated",
            "candidate mapping only; downstream analyze_results must triage",
        ],
    }


def render_plan_counts(render_plan: dict[str, Any]) -> dict[str, int]:
    summary = render_plan.get("summary", {}) or {}
    return {
        "total_cases": int(summary.get("total_cases", summary.get("total_supplemental_cases", 0)) or 0),
        "render_allowed": int(summary.get("render_allowed", summary.get("render_allowed_cases", 0)) or 0),
        "render_blocked": int(summary.get("render_blocked", summary.get("pending_seed_cases", 0)) or 0),
    }
