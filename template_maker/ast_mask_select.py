import argparse
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


HIGH_VALUE_CONTEXT_KEYWORDS = [
    "canary",
    "prepare_output_with_canary",
    "buffer",
    "buf",
    "limb",
    "X->p",
    "X->n",
    "raw",
    "CANARY_SIZE",
    "BUFLEN",
]

PREFERRED_PLACEHOLDER_NAMES = {
    "VALUE",
    "RADIX",
    "BUFLEN",
    "CANARY_SIZE",
    "A_VALUE",
    "B_VALUE",
    "A_BASE",
    "B_BASE",
    "A_RADIX",
    "B_RADIX",
    "X_LIMB_COUNT",
    "OUTPUT_LIMBS",
    "KEY_BITS",
    "HASH_LEN",
    "SIG_LEN",
    "MD_ALG",
    "PK_VERIFY_TYPE",
    "EXPECTED_SALT_LEN",
}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}
    return obj if isinstance(obj, dict) else {}


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def clean_code(code: Any) -> str:
    return " ".join(str(code or "").split())


def placeholder_name(placeholder: str) -> str:
    return str(placeholder or "").strip("[]")


def contains_context_keyword(unit: Dict[str, Any]) -> bool:
    text = " ".join(
        str(unit.get(key, ""))
        for key in ["code", "reason", "source", "function", "placeholder"]
    )
    lower_text = text.lower()
    return any(k.lower() in lower_text for k in HIGH_VALUE_CONTEXT_KEYWORDS)


def priority_value(priority: Any) -> int:
    table = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    return table.get(str(priority or "").lower(), 2)


def base_score(unit: Dict[str, Any]) -> int:
    score = 0
    role = unit.get("role", "")
    level = unit.get("mask_level", "")
    placeholder = unit.get("placeholder", "")
    code = unit.get("code", "")

    if role == "mutation_point":
        score += 30
    if level in {"value", "api_argument"}:
        score += 20
    if role == "trigger_call" and level in {"function_call", "statement"}:
        score += 50
    if role == "oracle" and level in {"statement", "block"}:
        score += 45
    if role in {"input_preparation", "helper_function"} and contains_context_keyword(unit):
        score += 22
    if role == "cleanup":
        score += 8
    if placeholder:
        score += 10
    if placeholder_name(placeholder) in PREFERRED_PLACEHOLDER_NAMES:
        score += 8
    if contains_context_keyword(unit):
        score += 6
    if unit.get("function") and unit.get("function") in code:
        score += 5

    score += priority_value(unit.get("priority", "")) * 2
    return score


def suggested_use_for(unit: Dict[str, Any]) -> str:
    role = unit.get("role", "")
    level = unit.get("mask_level", "")

    if role == "trigger_call":
        return "migrate_api_call"
    if role == "oracle":
        return "preserve_oracle"
    if role == "cleanup":
        return "preserve_cleanup"
    if role in {"input_preparation", "helper_function"}:
        return "preserve_input_preparation"
    if level == "value":
        return "mutate_value"
    if level == "api_argument":
        return "mutate_api_argument"
    return "llm_reconstruction_context"


def selection_reason_for(unit: Dict[str, Any], rule: str) -> str:
    role = unit.get("role", "")
    level = unit.get("mask_level", "")
    placeholder = unit.get("placeholder", "")

    if rule == "mutation_point":
        return f"Selected because {placeholder or 'this unit'} is a mutation point with {level} granularity."
    if rule == "trigger_call":
        return "Required trigger_call unit for preserving and migrating the source API invocation."
    if rule == "oracle":
        return "Required oracle unit for preserving the vulnerability signal and fixed/safe behavior checks."
    if rule == "context":
        return "Selected as high-value input/helper context because it references canary, buffer, limb, or output-boundary state."
    if rule == "cleanup":
        return "Selected limited cleanup context needed to keep generated harnesses well-scoped."
    return f"Selected by AST-lite policy for role={role}, mask_level={level}."


def clone_selected(unit: Dict[str, Any], rule: str) -> Dict[str, Any]:
    out = dict(unit)
    out["selection_reason"] = selection_reason_for(unit, rule)
    out["suggested_use"] = suggested_use_for(unit)
    out["selection_score"] = base_score(unit)
    return out


def unit_key(unit: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        clean_code(unit.get("code", "")),
        str(unit.get("placeholder", "")),
        str(unit.get("role", "")),
        str(unit.get("mask_level", "")),
    )


def code_seen_key(unit: Dict[str, Any]) -> str:
    return clean_code(unit.get("code", ""))


def add_selected(
    selected: List[Dict[str, Any]],
    rejected: List[Dict[str, Any]],
    unit: Dict[str, Any],
    rule: str,
    seen_exact: set,
    seen_code: set,
    dedupe_by_code: bool = False,
) -> None:
    exact = unit_key(unit)
    code_key = code_seen_key(unit)
    if exact in seen_exact or (dedupe_by_code and code_key in seen_code):
        rejected.append({"unit_id": unit.get("unit_id"), "reason": "duplicate_code_or_unit", "role": unit.get("role"), "mask_level": unit.get("mask_level")})
        return

    seen_exact.add(exact)
    if code_key:
        seen_code.add(code_key)
    selected.append(clone_selected(unit, rule))


def choose_best_by_placeholder(units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best: Dict[str, Dict[str, Any]] = {}
    for unit in units:
        placeholder = unit.get("placeholder", "")
        if not placeholder:
            continue
        name = placeholder_name(placeholder)
        if name not in PREFERRED_PLACEHOLDER_NAMES:
            continue
        current = best.get(placeholder)
        if current is None or base_score(unit) > base_score(current):
            best[placeholder] = unit
    return sorted(best.values(), key=lambda u: (placeholder_name(u.get("placeholder", "")), u.get("unit_id", "")))


def select_units(ast_report: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    units = ast_report.get("ast_mask_units", []) or []
    selected: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    seen_exact = set()
    seen_code = set()

    for unit in choose_best_by_placeholder(units):
        add_selected(selected, rejected, unit, "mutation_point", seen_exact, seen_code)

    for unit in sorted(units, key=lambda u: (-base_score(u), u.get("unit_id", ""))):
        if unit.get("role") == "mutation_point" and unit.get("mask_level") in {"value", "api_argument"}:
            add_selected(selected, rejected, unit, "mutation_point", seen_exact, seen_code)

    for unit in sorted(units, key=lambda u: (-base_score(u), u.get("unit_id", ""))):
        if unit.get("role") == "trigger_call" and unit.get("mask_level") in {"function_call", "statement"}:
            add_selected(selected, rejected, unit, "trigger_call", seen_exact, seen_code, dedupe_by_code=True)

    for unit in sorted(units, key=lambda u: (-base_score(u), u.get("unit_id", ""))):
        if unit.get("role") == "oracle" and unit.get("mask_level") in {"statement", "block"}:
            add_selected(selected, rejected, unit, "oracle", seen_exact, seen_code, dedupe_by_code=True)

    for unit in sorted(units, key=lambda u: (-base_score(u), u.get("unit_id", ""))):
        if unit.get("role") in {"input_preparation", "helper_function"} or unit.get("mask_level") == "block":
            if contains_context_keyword(unit):
                add_selected(selected, rejected, unit, "context", seen_exact, seen_code, dedupe_by_code=True)

    cleanup_count = 0
    for unit in sorted(units, key=lambda u: (-base_score(u), u.get("unit_id", ""))):
        if unit.get("role") != "cleanup":
            continue
        if cleanup_count >= 2:
            rejected.append({"unit_id": unit.get("unit_id"), "reason": "cleanup_limit_reached", "role": unit.get("role"), "mask_level": unit.get("mask_level")})
            continue
        before = len(selected)
        add_selected(selected, rejected, unit, "cleanup", seen_exact, seen_code, dedupe_by_code=True)
        if len(selected) > before:
            cleanup_count += 1

    selected.sort(
        key=lambda u: (
            -base_score(u),
            u.get("role", ""),
            u.get("placeholder", ""),
            u.get("unit_id", ""),
        )
    )
    return selected, rejected


def summarize(units: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    return dict(sorted(Counter(str(u.get(field, "")) for u in units).items()))


def rejected_summary(rejected: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "count": len(rejected),
        "by_reason": dict(sorted(Counter(str(x.get("reason", "")) for x in rejected).items())),
    }


def build_selected_report(template_dir: Path) -> Dict[str, Any]:
    ast_report = load_yaml(template_dir / "ast_mask_report.yaml")
    mask_report = load_yaml(template_dir / "mask_report.yaml")
    meta = load_yaml(template_dir / "template_meta.yaml")

    selected, rejected = select_units(ast_report)

    template_id = ast_report.get("template_id") or mask_report.get("template_id") or meta.get("template_id", "")
    template_name = ast_report.get("template_name") or mask_report.get("template_name") or meta.get("template_name", "")
    source_api = ast_report.get("source_api") or mask_report.get("source_api") or meta.get("source_api", {}).get("function", "")

    return {
        "template_id": template_id,
        "template_name": template_name,
        "source_api": source_api,
        "selection_policy": {
            "method": "ast_lite_high_value_mask_unit_selection",
            "rules": [
                "Prefer role=mutation_point units.",
                "Prefer mask_level=value or api_argument units.",
                "Always retain trigger_call function_call/statement units.",
                "Always retain oracle statement/block units.",
                "Retain input_preparation/helper_function/block only when boundary keywords are present.",
                "Limit cleanup units to one or two representative statements.",
                "Deduplicate repeated code snippets.",
            ],
            "context_keywords": HIGH_VALUE_CONTEXT_KEYWORDS,
        },
        "selected_units": selected,
        "selection_summary": {
            "selected_count": len(selected),
            "source_unit_count": len(ast_report.get("ast_mask_units", []) or []),
            "by_role": summarize(selected, "role"),
            "by_mask_level": summarize(selected, "mask_level"),
            "by_suggested_use": summarize(selected, "suggested_use"),
        },
        "rejected_summary": rejected_summary(rejected),
    }


def find_report_dirs(root: Path) -> List[Path]:
    return sorted(path.parent for path in root.rglob("ast_mask_report.yaml"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Select high-value AST-lite mask units.")
    parser.add_argument("--root", default="normalized_templates")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        parser.error(f"root not found: {root}")

    count = 0
    for template_dir in find_report_dirs(root):
        report = build_selected_report(template_dir)
        out_path = template_dir / "selected_mask_units.yaml"
        dump_yaml(out_path, report)
        print(f"[OK] wrote {out_path} selected={len(report.get('selected_units', []))}")
        count += 1

    print("=" * 80)
    print(f"[SUMMARY] ast reports scanned: {count}")
    print(f"[SUMMARY] root: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
