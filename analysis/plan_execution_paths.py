from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


DEFAULT_QUEUE = Path("artifacts/candidate_queue/candidate_queue.yaml")
DEFAULT_SCHEDULER = Path("artifacts/pattern_bank/scheduler_seed.yaml")
DEFAULT_BANK = Path("artifacts/pattern_bank/unified_pattern_bank.yaml")
DEFAULT_OUT = Path("artifacts/execution_plan")


PATH_LABELS = {
    "A": "recipe-slot cross-library migration",
    "B": "controlled family mutation sprint",
    "C": "app-level validation gap triage",
    "D": "crash/sanitizer evidence audit",
}

API_LEVEL_FAMILIES = {
    "pkey_verify_semantic",
    "mac_lifecycle",
    "cipher_aead_lifecycle",
    "api_state_machine",
    "x509_parsing",
    "asn1_nested_boundary",
    "memory_length_boundary",
}

CONTROLLED_MUTATION_FAMILIES = {
    "der_full_consumption",
    "pkey_verify_semantic",
}

APP_LEVEL_FAMILIES = {
    "der_full_consumption",
}

CRASH_ORACLES = {
    "crash_or_sanitizer",
}


def read_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def family_seed(scheduler: dict[str, Any], family: str) -> dict[str, Any]:
    return ((scheduler.get("families") or {}).get(family) or {})


def bank_by_pattern(bank: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for entry in bank.get("patterns") or []:
        if isinstance(entry, dict) and entry.get("pattern_id"):
            indexed[str(entry["pattern_id"])] = entry
    return indexed


def contains_any(text: str, tokens: set[str]) -> bool:
    lower = text.lower()
    return any(token in lower for token in tokens)


def recommend_path(candidate: dict[str, Any], seed: dict[str, Any]) -> str:
    family = str(candidate.get("family") or "")
    oracle = str(candidate.get("oracle_type") or "")
    action = str(candidate.get("recommended_action") or "")
    status = str(candidate.get("migration_status") or "")
    reason_text = yaml.safe_dump(candidate, sort_keys=True).lower()
    seed_reasons = " ".join(str(x) for x in as_list(seed.get("reasons"))).lower()

    if family in APP_LEVEL_FAMILIES or contains_any(reason_text + seed_reasons, {"app_level", "app-level", "storeutl"}):
        return "C"
    if family == "mac_lifecycle":
        return "A"
    if oracle in CRASH_ORACLES or "manual_crash_repro_audit" in action:
        return "D"
    if status == "stable_safe_negative" or str(candidate.get("pattern_id", "")).startswith("PKEY_VERIFY_FAMILY"):
        return "B"
    if family in CONTROLLED_MUTATION_FAMILIES and "controlled" in seed_reasons:
        return "B"
    if family in API_LEVEL_FAMILIES:
        return "A"
    return "B"


def flags_for_path(path: str, family: str) -> dict[str, bool]:
    if path == "A":
        return {
            "requires_ast_mask": True,
            "requires_selected_mask_units": True,
            "requires_llm_slot_filling": True,
            "requires_adapter_validate": True,
            "requires_controlled_renderer": True,
            "requires_app_runner": False,
            "requires_sanitizer_audit": family in {"memory_length_boundary"},
        }
    if path == "B":
        return {
            "requires_ast_mask": False,
            "requires_selected_mask_units": False,
            "requires_llm_slot_filling": False,
            "requires_adapter_validate": False,
            "requires_controlled_renderer": True,
            "requires_app_runner": family == "der_full_consumption",
            "requires_sanitizer_audit": False,
        }
    if path == "C":
        return {
            "requires_ast_mask": False,
            "requires_selected_mask_units": False,
            "requires_llm_slot_filling": False,
            "requires_adapter_validate": False,
            "requires_controlled_renderer": True,
            "requires_app_runner": True,
            "requires_sanitizer_audit": False,
        }
    return {
        "requires_ast_mask": False,
        "requires_selected_mask_units": False,
        "requires_llm_slot_filling": False,
        "requires_adapter_validate": False,
        "requires_controlled_renderer": False,
        "requires_app_runner": False,
        "requires_sanitizer_audit": True,
    }


def next_action(candidate: dict[str, Any], path: str) -> str:
    family = str(candidate.get("family") or "")
    pattern_id = str(candidate.get("pattern_id") or "")
    existing = str(candidate.get("recommended_action") or "")
    if path == "A":
        if family == "mac_lifecycle":
            return "prepare recipe-slot adapter, validate slot bindings, then render a small MAC lifecycle matrix"
        return "run recipe-slot adapter generation through adapter_validate before rendering harnesses"
    if path == "B":
        if pattern_id.startswith("PKEY_VERIFY_FAMILY"):
            return "retain as stable safe-negative regression baseline and use feedback-guided dimensions for v2"
        return existing or "run controlled family mutation sprint with render_matrix"
    if path == "C":
        return "triage app-level command behavior with output artifacts, exit status, and malformed-tail controls"
    return "audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family"


def reason_for(candidate: dict[str, Any], path: str, seed: dict[str, Any], bank_entry: dict[str, Any]) -> str:
    family = str(candidate.get("family") or "")
    oracle = str(candidate.get("oracle_type") or "")
    seed_reasons = ", ".join(str(x) for x in as_list(seed.get("reasons")))
    if path == "A":
        return (
            f"{family} is an API-level cross-library semantic migration path; "
            "it keeps AST-lite mask, selected_mask_units, LLM slot_bindings, adapter_validate, "
            "and the controlled renderer as local recipe-slot steps."
        )
    if path == "B":
        return (
            f"{family} has family-level mutation dimensions or a stable feedback baseline; "
            f"scheduler reasons: {seed_reasons or 'none'}."
        )
    if path == "C":
        return (
            "DER full-consumption is currently app-level CLI/application behavior: "
            "the oracle is command success/output artifact/stderr under valid-prefix plus trailing-byte mutations, "
            "so AST masking is not required for this path."
        )
    return (
        f"{oracle or bank_entry.get('oracle_type') or 'crash/sanitizer'} evidence must be audited first; "
        "do not expand it into a runnable family until the crash signature and harness validity are confirmed."
    )


def build_plan(queue: dict[str, Any], scheduler: dict[str, Any], bank: dict[str, Any]) -> dict[str, Any]:
    patterns = bank_by_pattern(bank)
    planned = []
    counts: Counter[str] = Counter()
    for candidate in queue.get("candidates") or []:
        if not isinstance(candidate, dict):
            continue
        family = str(candidate.get("family") or "")
        pattern_id = str(candidate.get("pattern_id") or "")
        seed = family_seed(scheduler, family)
        bank_entry = patterns.get(pattern_id, {})
        path = recommend_path(candidate, seed)
        flags = flags_for_path(path, family)
        row = {
            "candidate_id": candidate.get("candidate_id") or f"{family}:{pattern_id}",
            "pattern_id": pattern_id,
            "family": family,
            "recommended_path": path,
            **flags,
            "readiness_score": float(candidate.get("readiness_score") or 0.0),
            "severity_score": float(candidate.get("severity_score") or 0.0),
            "combined_score": float(candidate.get("combined_score") or 0.0),
            "recommended_next_action": next_action(candidate, path),
            "reason": reason_for(candidate, path, seed, bank_entry),
        }
        planned.append(row)
        counts[path] += 1
    planned.sort(key=lambda item: (-item["combined_score"], item["recommended_path"], item["candidate_id"]))
    return {
        "schema_version": 1,
        "inputs": {
            "candidate_queue": str(DEFAULT_QUEUE),
            "scheduler_seed": str(DEFAULT_SCHEDULER),
            "unified_pattern_bank": str(DEFAULT_BANK),
        },
        "path_definitions": PATH_LABELS,
        "framework_positioning": {
            "ast_mask_llm_status": "retained",
            "note": "AST-lite mask, selected_mask_units, and LLM slot filling are required local modules of path A, not deleted from the framework.",
            "der_app_level_note": "DER app-level validation-gap triage does not require AST masking because it tests CLI/app behavior and output artifacts.",
            "mac_lifecycle_note": "MAC lifecycle should enter path A, or A followed by B, with recipe-slot adapters rather than free-form C generation.",
        },
        "summary": {
            "total_candidates": len(planned),
            "by_path": {key: counts.get(key, 0) for key in ["A", "B", "C", "D"]},
        },
        "candidates": planned,
    }


def render_markdown(plan: dict[str, Any]) -> str:
    rows = plan.get("candidates") or []
    lines = [
        "# Execution Path Plan",
        "",
        "This planner routes candidate-queue entries into four execution paths. The new framework does not remove AST-lite masking, selected mask units, or LLM slot filling; it scopes them to path A where recipe-slot cross-library migration needs structured source and target API binding.",
        "",
        "## Paths",
        "",
    ]
    for key, label in PATH_LABELS.items():
        lines.append(f"- {key}: {label}")
    lines.extend(
        [
            "",
            "## Module Scope",
            "",
            "- Path A requires AST-lite mask, selected_mask_units, LLM slot_bindings, adapter_validate, and controlled template rendering.",
            "- Path B uses family-level controlled mutation matrices and controlled renderers; it does not require source-PoC AST for every family.",
            "- Path C tests app/CLI behavior with exit status, output artifacts, stderr, and malformed-input controls.",
            "- Path D audits crash logs, sanitizer signatures, versions, and harness validity before any family expansion.",
            "",
            "DER v2 is routed to path C because its current evidence is app-level valid-prefix plus malformed-tail acceptance. MAC lifecycle is routed to path A as the next API-level recipe-slot family, with optional path B mutation expansion after adapter validation.",
            "",
            "## Summary",
            "",
        ]
    )
    by_path = plan.get("summary", {}).get("by_path", {})
    for key in ["A", "B", "C", "D"]:
        lines.append(f"- {key}: {by_path.get(key, 0)} candidates")
    lines.extend(
        [
            "",
            "## Candidate Table",
            "",
            "| candidate_id | path | readiness | severity | combined | next action |",
            "| --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for row in rows:
        lines.append(
            "| {candidate_id} | {recommended_path} | {readiness_score:.4f} | {severity_score:.4f} | {combined_score:.4f} | {recommended_next_action} |".format(
                **row
            )
        )
    lines.append("")
    return "\n".join(lines)


def render_readme(plan: dict[str, Any]) -> str:
    return """# Execution Path Planner

`analysis/plan_execution_paths.py` consumes the candidate queue, scheduler seed, and unified pattern bank, then emits a deterministic A/B/C/D execution plan.

The important integration point is that AST-lite masking, selected_mask_units, and LLM slot filling are still part of the framework. They are required for path A, where a source API pattern is migrated to a target API through recipe-slot adapters and `adapter_validate`.

DER app-level full-consumption does not require AST masking in its current path because the observable is application behavior: command exit status, generated output artifact, stderr, and malformed-tail controls. MAC lifecycle should return to the recipe-slot route next: normalized template, mask report, selected mask units, slot bindings, adapter validation, controlled rendering, and then a small mutation matrix.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Plan A/B/C/D execution paths for migration candidates.")
    parser.add_argument("--candidate-queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--scheduler-seed", type=Path, default=DEFAULT_SCHEDULER)
    parser.add_argument("--pattern-bank", type=Path, default=DEFAULT_BANK)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    queue = read_yaml(args.candidate_queue)
    scheduler = read_yaml(args.scheduler_seed)
    bank = read_yaml(args.pattern_bank)
    plan = build_plan(queue, scheduler, bank)
    plan["inputs"] = {
        "candidate_queue": str(args.candidate_queue),
        "scheduler_seed": str(args.scheduler_seed),
        "unified_pattern_bank": str(args.pattern_bank),
    }

    write_yaml(args.out_root / "execution_paths.yaml", plan)
    write_text(args.out_root / "execution_paths.md", render_markdown(plan))
    write_text(args.out_root / "README.md", render_readme(plan))
    print(f"Wrote execution plan for {plan['summary']['total_candidates']} candidates to {args.out_root}")


if __name__ == "__main__":
    main()
