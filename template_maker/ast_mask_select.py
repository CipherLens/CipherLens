import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FAMILY_RULES_PATH = Path("config/harness_family_ast_rules.yaml")


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

FAMILY_CONTEXT_KEYWORDS = {
    "buffer_canary_boundary": [
        "canary",
        "prepare_output_with_canary",
        "buffer",
        "buf",
        "CANARY_SIZE",
        "BUFLEN",
        "output",
        "memset",
    ],
    "der_pointer_consumption": [
        "base_hex",
        "trailing",
        "TRAILING_GARBAGE",
        "consumed_len",
        "der_len",
        "p - der",
        "ppin",
        "d2i_",
        "select_base_der_hex",
        "build_der_with_trailing_garbage",
    ],
    "x509_asn1_inner_boundary": [
        "x509",
        "X509",
        "ASN1",
        "asn1",
        "der",
        "certificate",
        "inner",
        "boundary",
        "d2i_X509",
    ],
    "return_code_outlen_semantic": [
        "ret",
        "out",
        "out_len",
        "output",
        "padding",
        "final",
        "finish",
        "error path",
        "EVP_DecryptFinal_ex",
        "EVP_CipherFinal_ex",
    ],
    "crash_sanitizer_oracle": [
        "AddressSanitizer",
        "UndefinedBehaviorSanitizer",
        "SEGV",
        "crash",
        "overflow",
        "use-after-free",
    ],
    "object_state_lifecycle": [
        "state",
        "lifecycle",
        "init",
        "free",
        "reuse",
        "zero",
        "stale",
    ],
    "null_deref_dispatch": [
        "NULL",
        "null",
        "dispatch",
        "type",
        "opaque",
        "context",
        "pk_verify_ext",
    ],
}

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
    "DER_KIND",
    "PARSE_API_KIND",
    "TRAILING_GARBAGE_BYTES",
    "TRAILING_GARBAGE_LEN",
    "EXPECT_RET",
    "TOP_LEVEL_SEQUENCE_END_CHECK",
    "RSA_PRIVATE_PARSE_CALL",
    "RSA_PUBLIC_PARSE_CALL",
}

LOG_LABEL_PLACEHOLDER_NAMES = {
    "OK",
    "BUG",
    "INFO",
    "WARN",
    "ERROR",
    "FAIL",
    "PASS",
    "DIFF",
}

PLACEHOLDER_PATTERN = re.compile(r"\[[A-Z0-9_]+\]")


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


def placeholder_count(code: Any) -> int:
    return len(set(PLACEHOLDER_PATTERN.findall(str(code or ""))))


def is_log_label_placeholder(unit: Dict[str, Any]) -> bool:
    return placeholder_name(unit.get("placeholder", "")) in LOG_LABEL_PLACEHOLDER_NAMES


def is_comment_like(code: str) -> bool:
    stripped = code.lstrip()
    return stripped.startswith("/*") or stripped.startswith("* -") or stripped.startswith("//")


def has_header_or_prototype_noise(code: str) -> bool:
    lower = code.lower()
    if "#include" in code:
        return True
    if "#ifndef" in code or "#define" in code or "#error" in code:
        return True
    if "parser functions exist" in lower or "public header may not expose" in lower:
        return True
    if is_function_prototype_like(code):
        return True
    return False


def is_function_prototype_like(code: str) -> bool:
    compact = clean_code(code)
    if "ret =" in compact or "=" in compact:
        return False
    if not compact.endswith(";"):
        return False
    return bool(re.match(
        r"^(?:extern\s+)?(?:int|void|long|size_t|[A-Za-z_][A-Za-z0-9_\s\*]*?\*)\s+"
        r"[A-Za-z_][A-Za-z0-9_]*\s*\([^{};]*\);$",
        compact,
    ))


def normalize_family_rules(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    rules = dict(raw)
    for family, spec in list(raw.items()):
        if not isinstance(spec, dict):
            continue
        for alias in spec.get("aliases", []) or []:
            rules.setdefault(str(alias), spec)
    return rules


def load_family_rules(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    return normalize_family_rules(load_yaml(path))


def family_rule_for(harness_family: str = "", family_rules: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rules = family_rules or {}
    spec = rules.get(str(harness_family or ""), {})
    return spec if isinstance(spec, dict) else {}


def rule_list(spec: Dict[str, Any], key: str) -> List[str]:
    value = spec.get(key, []) if isinstance(spec, dict) else []
    if not isinstance(value, list):
        return []
    return [str(x) for x in value if str(x or "").strip()]


def context_keywords_for(harness_family: str = "", family_rules: Optional[Dict[str, Any]] = None) -> List[str]:
    keywords: List[str] = []

    default_spec = family_rule_for("default", family_rules)
    family_spec = family_rule_for(harness_family, family_rules)

    configured_default = rule_list(default_spec, "context_keywords")
    configured_family = rule_list(family_spec, "context_keywords")

    if configured_family:
        sources = [configured_family]
    else:
        sources = [
            configured_default or HIGH_VALUE_CONTEXT_KEYWORDS,
            FAMILY_CONTEXT_KEYWORDS.get(str(harness_family or ""), []),
        ]

    for source in sources:
        for item in source:
            if item not in keywords:
                keywords.append(item)
    return keywords


def int_rule(spec: Dict[str, Any], key: str, default: int) -> int:
    try:
        return int(spec.get(key, default))
    except Exception:
        return default


def collect_trigger_apis(ast_report: Dict[str, Any], mask_report: Dict[str, Any], meta: Dict[str, Any]) -> List[str]:
    apis: List[str] = []

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in apis:
            apis.append(text)

    for source in (ast_report, mask_report):
        for api in source.get("trigger_apis", []) or []:
            add(api)
        add(source.get("source_api"))

    source_api = meta.get("source_api")
    if isinstance(source_api, dict):
        add(source_api.get("function"))
    elif isinstance(source_api, str):
        add(source_api)

    add(meta.get("source_api_name"))
    add(meta.get("poc_source", {}).get("api"))
    for api in meta.get("internal_apis", []) or []:
        add(api)

    return apis


def is_actual_trigger_call(unit: Dict[str, Any], trigger_apis: Optional[Iterable[str]] = None) -> bool:
    code = clean_code(unit.get("code", ""))
    function = str(unit.get("function", "") or "")
    apis = [str(api) for api in (trigger_apis or []) if str(api or "").strip()]

    if function and function in apis:
        return True

    if not apis:
        apis = [
            "mbedtls_rsa_parse_key",
            "mbedtls_rsa_parse_pubkey",
            "mbedtls_pk_parse_key",
            "parse_with_selected_api",
        ]

    for api in apis:
        if re.search(rf"\b{re.escape(api)}\s*\(", code):
            return True
    return False


def is_actual_oracle_statement(unit: Dict[str, Any]) -> bool:
    code = clean_code(unit.get("code", ""))
    if not any(token in code for token in ["ret", "[BUG]", "[OK]", "return 1", "return 0"]):
        return False
    return code.startswith("if ") or code.startswith("if (") or code.startswith("printf(") or " return " in code


def is_noise_unit(unit: Dict[str, Any], trigger_apis: Optional[Iterable[str]] = None) -> bool:
    code = str(unit.get("code", "") or "")
    source = str(unit.get("source", "") or "")
    role = str(unit.get("role", "") or "")

    if unit.get("function") in {"setbuf"}:
        return True

    if role == "oracle":
        return False

    if is_log_label_placeholder(unit):
        return True

    if source == "template_meta.mutation_points":
        return False

    if role == "mutation_point" and (unit.get("placeholder") or unit.get("placeholder_dependencies")):
        return False

    if source == "tmpl_mbedtls.c.function_call" and code.lstrip().startswith("*/"):
        return True

    if has_header_or_prototype_noise(code):
        return True

    if source == "tmpl_mbedtls.c.function_call" and not unit.get("enclosing_function") and "ret =" not in clean_code(code):
        return True

    if is_actual_trigger_call(unit, trigger_apis):
        return False
    if role == "oracle" and is_actual_oracle_statement(unit):
        return False
    if role == "cleanup":
        return False

    placeholders = placeholder_count(code)

    if "#include" in code and placeholders >= 2:
        return True

    if source == "tmpl_mbedtls.c.placeholder_statement" and len(code) > 800:
        return True

    if is_comment_like(code) and not (
        (is_actual_trigger_call(unit, trigger_apis) or is_actual_oracle_statement(unit))
    ):
        return True

    if has_header_or_prototype_noise(code) and placeholders >= 1:
        return True

    return False


def unit_search_text(unit: Dict[str, Any]) -> str:
    return " ".join(
        str(unit.get(key, ""))
        for key in [
            "code",
            "reason",
            "source",
            "function",
            "placeholder",
            "enclosing_function",
            "called_function",
        ]
    )


def contains_context_keyword(unit: Dict[str, Any], context_keywords: Optional[Iterable[str]] = None) -> bool:
    text = unit_search_text(unit)
    lower_text = text.lower()
    keywords = list(context_keywords or HIGH_VALUE_CONTEXT_KEYWORDS)
    return any(str(k).lower() in lower_text for k in keywords)


def contains_rule_variable(unit: Dict[str, Any], variables: Optional[Iterable[str]] = None) -> bool:
    text = unit_search_text(unit)
    lower_text = text.lower()
    for variable in variables or []:
        var = str(variable or "").strip()
        if not var:
            continue
        if re.search(rf"\b{re.escape(var)}\b", text) or var.lower() in lower_text:
            return True
    return False


def family_rule_bonus(unit: Dict[str, Any], family_rule: Optional[Dict[str, Any]] = None) -> int:
    if not family_rule:
        return 0

    bonus = 0
    role = str(unit.get("role", "") or "")
    preferred_roles = rule_list(family_rule, "preferred_roles")
    oracle_variables = rule_list(family_rule, "oracle_variables")

    if role in preferred_roles:
        # Earlier roles in the family policy are slightly more important.
        bonus += max(1, len(preferred_roles) - preferred_roles.index(role)) * 2

    if oracle_variables and contains_rule_variable(unit, oracle_variables):
        if role == "oracle":
            bonus += 20
        elif role == "trigger_call":
            bonus += 8
        else:
            bonus += 6

    return bonus


def has_oracle_variable(unit: Dict[str, Any], family_rule: Optional[Dict[str, Any]] = None) -> bool:
    return contains_rule_variable(unit, rule_list(family_rule or {}, "oracle_variables"))


def priority_value(priority: Any) -> int:
    table = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    return table.get(str(priority or "").lower(), 2)


def base_score(
    unit: Dict[str, Any],
    context_keywords: Optional[Iterable[str]] = None,
    trigger_apis: Optional[Iterable[str]] = None,
    family_rule: Optional[Dict[str, Any]] = None,
) -> int:
    score = 0
    role = unit.get("role", "")
    level = unit.get("mask_level", "")
    placeholder = unit.get("placeholder", "")
    code = unit.get("code", "")

    if role == "mutation_point":
        score += 30
    if unit.get("source") == "template_meta.mutation_points":
        score += 35
    if level in {"value", "api_argument"}:
        score += 20
    if role == "trigger_call" and level in {"function_call", "statement"}:
        score += 50
    if is_actual_trigger_call(unit, trigger_apis):
        score += 30
    if role == "oracle" and level in {"statement", "block"}:
        score += 45
    if role == "oracle" and is_actual_oracle_statement(unit):
        score += 20
    if role in {"input_preparation", "helper_function"} and contains_context_keyword(unit, context_keywords):
        score += 22
    if role == "cleanup":
        score += 8
    if placeholder:
        score += 10
    if placeholder_name(placeholder) in PREFERRED_PLACEHOLDER_NAMES:
        score += 8
    if contains_context_keyword(unit, context_keywords):
        score += 6
    if unit.get("function") and unit.get("function") in code:
        score += 5

    score += priority_value(unit.get("priority", "")) * 2
    score += family_rule_bonus(unit, family_rule)
    return score


def suggested_use_for(unit: Dict[str, Any], trigger_apis: Optional[Iterable[str]] = None) -> str:
    role = unit.get("role", "")
    level = unit.get("mask_level", "")

    if role == "trigger_call" or is_actual_trigger_call(unit, trigger_apis):
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


def selection_reason_for(unit: Dict[str, Any], rule: str, harness_family: str = "") -> str:
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
        return f"Selected as high-value input/helper context for harness_family={harness_family or 'generic'}."
    if rule == "cleanup":
        return "Selected limited cleanup context needed to keep generated harnesses well-scoped."
    return f"Selected by AST-lite policy for role={role}, mask_level={level}."


def clone_selected(
    unit: Dict[str, Any],
    rule: str,
    context_keywords: Optional[Iterable[str]] = None,
    trigger_apis: Optional[Iterable[str]] = None,
    harness_family: str = "",
    family_rule: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out = dict(unit)
    out["selection_reason"] = selection_reason_for(unit, rule, harness_family)
    out["suggested_use"] = suggested_use_for(unit, trigger_apis)
    out["selection_score"] = base_score(unit, context_keywords, trigger_apis, family_rule)
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
    context_keywords: Optional[Iterable[str]] = None,
    trigger_apis: Optional[Iterable[str]] = None,
    harness_family: str = "",
    family_rule: Optional[Dict[str, Any]] = None,
) -> None:
    if is_noise_unit(unit, trigger_apis):
        rejected.append({"unit_id": unit.get("unit_id"), "reason": "noise_header_comment_or_log_label", "role": unit.get("role"), "mask_level": unit.get("mask_level")})
        return

    exact = unit_key(unit)
    code_key = code_seen_key(unit)
    if exact in seen_exact or (dedupe_by_code and code_key in seen_code):
        rejected.append({"unit_id": unit.get("unit_id"), "reason": "duplicate_code_or_unit", "role": unit.get("role"), "mask_level": unit.get("mask_level")})
        return

    seen_exact.add(exact)
    if code_key:
        seen_code.add(code_key)
    selected.append(clone_selected(unit, rule, context_keywords, trigger_apis, harness_family, family_rule))


def choose_best_by_placeholder(
    units: List[Dict[str, Any]],
    context_keywords: Optional[Iterable[str]] = None,
    trigger_apis: Optional[Iterable[str]] = None,
    family_rule: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    best: Dict[str, Dict[str, Any]] = {}
    for unit in units:
        placeholder = unit.get("placeholder", "")
        if not placeholder:
            continue
        name = placeholder_name(placeholder)
        if name not in PREFERRED_PLACEHOLDER_NAMES:
            continue
        current = best.get(placeholder)
        if current is None or base_score(unit, context_keywords, trigger_apis, family_rule) > base_score(current, context_keywords, trigger_apis, family_rule):
            best[placeholder] = unit
    return sorted(best.values(), key=lambda u: (placeholder_name(u.get("placeholder", "")), u.get("unit_id", "")))


def select_units(
    ast_report: Dict[str, Any],
    context_keywords: Optional[Iterable[str]] = None,
    trigger_apis: Optional[Iterable[str]] = None,
    harness_family: str = "",
    family_rule: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    units = ast_report.get("ast_mask_units", []) or []
    selected: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    seen_exact = set()
    seen_code = set()
    family_rule = family_rule or {}

    for unit in choose_best_by_placeholder(units, context_keywords, trigger_apis, family_rule):
        add_selected(selected, rejected, unit, "mutation_point", seen_exact, seen_code, context_keywords=context_keywords, trigger_apis=trigger_apis, harness_family=harness_family, family_rule=family_rule)

    for unit in sorted(units, key=lambda u: (-base_score(u, context_keywords, trigger_apis, family_rule), u.get("unit_id", ""))):
        if unit.get("role") == "mutation_point" and (
            unit.get("mask_level") in {"value", "api_argument", "statement"}
            or unit.get("placeholder")
            or unit.get("placeholder_dependencies")
        ):
            add_selected(selected, rejected, unit, "mutation_point", seen_exact, seen_code, context_keywords=context_keywords, trigger_apis=trigger_apis, harness_family=harness_family, family_rule=family_rule)

    for unit in sorted(units, key=lambda u: (-base_score(u, context_keywords, trigger_apis, family_rule), u.get("unit_id", ""))):
        role = unit.get("role")
        level = unit.get("mask_level")
        if (
            (role == "trigger_call" and (level in {"function_call", "statement"} or is_actual_trigger_call(unit, trigger_apis)))
            or (is_actual_trigger_call(unit, trigger_apis) and level in {"function_call", "statement"})
        ):
            add_selected(selected, rejected, unit, "trigger_call", seen_exact, seen_code, dedupe_by_code=True, context_keywords=context_keywords, trigger_apis=trigger_apis, harness_family=harness_family, family_rule=family_rule)

    for unit in sorted(units, key=lambda u: (-base_score(u, context_keywords, trigger_apis, family_rule), u.get("unit_id", ""))):
        if unit.get("role") == "oracle" and (
            unit.get("mask_level") in {"statement", "block"}
            or is_actual_oracle_statement(unit)
            or has_oracle_variable(unit, family_rule)
        ):
            add_selected(selected, rejected, unit, "oracle", seen_exact, seen_code, dedupe_by_code=True, context_keywords=context_keywords, trigger_apis=trigger_apis, harness_family=harness_family, family_rule=family_rule)

    context_count = 0
    context_limit = int_rule(family_rule, "context_limit", 12)
    for unit in sorted(units, key=lambda u: (-base_score(u, context_keywords, trigger_apis, family_rule), u.get("unit_id", ""))):
        if unit.get("role") in {"input_preparation", "helper_function"} or unit.get("mask_level") == "block":
            if not contains_context_keyword(unit, context_keywords):
                continue
            if context_count >= context_limit:
                rejected.append({"unit_id": unit.get("unit_id"), "reason": "context_limit_reached", "role": unit.get("role"), "mask_level": unit.get("mask_level")})
                continue
            before = len(selected)
            add_selected(selected, rejected, unit, "context", seen_exact, seen_code, dedupe_by_code=True, context_keywords=context_keywords, trigger_apis=trigger_apis, harness_family=harness_family, family_rule=family_rule)
            if len(selected) > before:
                context_count += 1

    cleanup_count = 0
    cleanup_limit = int_rule(family_rule, "cleanup_limit", 2)
    for unit in sorted(units, key=lambda u: (-base_score(u, context_keywords, trigger_apis, family_rule), u.get("unit_id", ""))):
        if unit.get("role") != "cleanup":
            continue
        if cleanup_count >= cleanup_limit:
            rejected.append({"unit_id": unit.get("unit_id"), "reason": "cleanup_limit_reached", "role": unit.get("role"), "mask_level": unit.get("mask_level")})
            continue
        before = len(selected)
        add_selected(selected, rejected, unit, "cleanup", seen_exact, seen_code, dedupe_by_code=True, context_keywords=context_keywords, trigger_apis=trigger_apis, harness_family=harness_family, family_rule=family_rule)
        if len(selected) > before:
            cleanup_count += 1

    selected.sort(
        key=lambda u: (
            -base_score(u, context_keywords, trigger_apis, family_rule),
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


def build_selected_report(
    template_dir: Path,
    family_rules: Optional[Dict[str, Any]] = None,
    family_rules_path: Optional[Path] = None,
    ast_report_name: str = "ast_mask_report.yaml",
) -> Dict[str, Any]:
    ast_report = load_yaml(template_dir / ast_report_name)
    mask_report = load_yaml(template_dir / "mask_report.yaml")
    meta = load_yaml(template_dir / "template_meta.yaml")

    harness_family = str(ast_report.get("harness_family") or mask_report.get("harness_family") or meta.get("harness_family") or "")
    family_rule = family_rule_for(harness_family, family_rules)
    context_keywords = context_keywords_for(harness_family, family_rules)
    trigger_apis = collect_trigger_apis(ast_report, mask_report, meta)
    selected, rejected = select_units(ast_report, context_keywords, trigger_apis, harness_family, family_rule)

    template_id = ast_report.get("template_id") or mask_report.get("template_id") or meta.get("template_id", "")
    template_name = ast_report.get("template_name") or mask_report.get("template_name") or meta.get("template_name", "")
    source_api = ast_report.get("source_api") or mask_report.get("source_api") or meta.get("source_api", {}).get("function", "")

    return {
        "template_id": template_id,
        "template_name": template_name,
        "source_api": source_api,
        "trigger_apis": trigger_apis,
        "harness_family": harness_family,
        "selection_policy": {
            "method": "ast_lite_high_value_mask_unit_selection",
            "rules": [
                "Prefer role=mutation_point units.",
                "Prefer mask_level=value or api_argument units.",
                "Always retain trigger_call function_call/statement units.",
                "Always retain oracle statement/block units.",
                "Retain input_preparation/helper_function/block only when harness-family context keywords are present.",
                "Use configured preferred_roles as scoring hints for each harness family.",
                "Use configured oracle_variables to prioritize oracle-observable units.",
                "Limit input/helper context to representative high-scoring units.",
                "Limit cleanup units to one or two representative statements.",
                "Deduplicate repeated code snippets.",
            ],
            "context_keywords": context_keywords,
            "ast_report_name": ast_report_name,
            "family_rules_source": str(family_rules_path) if family_rules_path else "built_in_fallback",
            "family_rule": {
                "context_keywords": rule_list(family_rule, "context_keywords"),
                "oracle_variables": rule_list(family_rule, "oracle_variables"),
                "preferred_roles": rule_list(family_rule, "preferred_roles"),
                "context_limit": int_rule(family_rule, "context_limit", 12),
                "cleanup_limit": int_rule(family_rule, "cleanup_limit", 2),
            } if family_rule else {},
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


def find_report_dirs(root: Path, ast_report_name: str = "ast_mask_report.yaml") -> List[Path]:
    return sorted(path.parent for path in root.rglob(ast_report_name))


def main() -> int:
    parser = argparse.ArgumentParser(description="Select high-value AST-lite mask units.")
    parser.add_argument("--root", default="normalized_templates")
    parser.add_argument(
        "--family-rules",
        default=str(DEFAULT_FAMILY_RULES_PATH),
        help="YAML file containing family-aware AST selection rules.",
    )
    parser.add_argument(
        "--ast-report-name",
        default="ast_mask_report.yaml",
        help="AST report filename to read inside each template directory.",
    )
    parser.add_argument(
        "--output-name",
        default="selected_mask_units.yaml",
        help="Selected mask unit YAML filename to write inside each template directory.",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        parser.error(f"root not found: {root}")

    family_rules_path = Path(args.family_rules) if args.family_rules else None
    family_rules = load_family_rules(family_rules_path)

    count = 0
    for template_dir in find_report_dirs(root, args.ast_report_name):
        report = build_selected_report(
            template_dir,
            family_rules,
            family_rules_path if family_rules else None,
            ast_report_name=args.ast_report_name,
        )
        out_path = template_dir / args.output_name
        dump_yaml(out_path, report)
        print(f"[OK] wrote {out_path} selected={len(report.get('selected_units', []))}")
        count += 1

    print("=" * 80)
    print(f"[SUMMARY] ast reports scanned: {count}")
    print(f"[SUMMARY] root: {root}")
    print(f"[SUMMARY] ast report name: {args.ast_report_name}")
    print(f"[SUMMARY] output name: {args.output_name}")
    print(f"[SUMMARY] family rules: {family_rules_path if family_rules else 'built_in_fallback'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
