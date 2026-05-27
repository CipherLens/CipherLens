import argparse
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml


PLACEHOLDER_PATTERN = re.compile(r"\[[A-Z0-9_]+\]")

IGNORED_BRACKET_TAGS = {
    "[OK]",
    "[BUG]",
    "[INFO]",
    "[WARN]",
    "[ERROR]",
    "[DIFF]",
    "[FAIL]",
    "[PASS]",
}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def find_template_dirs(root: Path) -> List[Path]:
    return sorted(p.parent for p in root.rglob("template_meta.yaml"))


def find_poc_pattern_by_template_id(template_id: str, pattern_root: Path = Path("knowledge_raw/poc_patterns")) -> Dict[str, Any]:
    """
    Find a structured PoC pattern YAML by template_id.

    This layer records real root cause, trigger condition, mutation point rationale,
    vulnerability-path features, and migration guidance.
    """
    if not template_id or not pattern_root.exists():
        return {}

    for yml in sorted(list(pattern_root.rglob("*.yaml")) + list(pattern_root.rglob("*.yml"))):
        try:
            obj = load_yaml(yml)
        except Exception:
            continue

        if obj.get("template_id") == template_id:
            obj["_poc_pattern_file"] = str(yml)
            return obj

    return {}


def compact_poc_pattern_for_report(poc_pattern: Dict[str, Any]) -> Dict[str, Any]:
    if not poc_pattern:
        return {}

    return {
        "pattern_id": poc_pattern.get("pattern_id"),
        "pattern_file": poc_pattern.get("_poc_pattern_file"),
        "source": poc_pattern.get("source", {}),
        "classification": poc_pattern.get("classification", {}),
        "root_cause": poc_pattern.get("root_cause", {}),
        "trigger": poc_pattern.get("trigger", {}),
        "buggy_behavior": poc_pattern.get("buggy_behavior", {}),
        "fixed_behavior": poc_pattern.get("fixed_behavior", {}),
        "mutation_points": poc_pattern.get("mutation_points", []),
        "occlusion_candidates": poc_pattern.get("occlusion_candidates", {}),
        "vulnerability_path_features": poc_pattern.get("vulnerability_path_features", {}),
        "migration_guidance": poc_pattern.get("migration_guidance", {}),
        "expected_oracle": poc_pattern.get("expected_oracle", {}),
        "evidence_files": poc_pattern.get("evidence_files", {}),
    }


def build_poc_pattern_rag_context(poc_pattern: Dict[str, Any]) -> str:
    if not poc_pattern:
        return ""

    parts = []
    parts.append("## PoC Pattern Knowledge")
    parts.append(f"pattern_id: {poc_pattern.get('pattern_id', '')}")

    root_cause = poc_pattern.get("root_cause", {})
    if root_cause:
        parts.append(f"root_cause_summary: {root_cause.get('summary', '')}")
        parts.append(f"root_cause_location: {root_cause.get('root_cause_location', {})}")
        parts.append(f"buggy_logic: {root_cause.get('buggy_logic', [])}")
        parts.append(f"fixed_logic: {root_cause.get('fixed_logic', [])}")

    trigger = poc_pattern.get("trigger", {})
    if trigger:
        parts.append(f"trigger: {trigger}")

    features = poc_pattern.get("vulnerability_path_features", {})
    if features:
        parts.append(f"must_preserve_features: {features.get('must_preserve', [])}")
        parts.append(f"optional_features: {features.get('optional', [])}")
        parts.append(f"not_required_features: {features.get('not_required', [])}")

    guidance = poc_pattern.get("migration_guidance", {})
    if guidance:
        parts.append(f"good_target_api_features: {guidance.get('good_target_api_features', [])}")
        parts.append(f"bad_target_api_features: {guidance.get('bad_target_api_features', [])}")

    return "\n".join(parts)


def remove_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text

def strip_string_literals(text: str) -> str:
    """
    Remove string literal content before role classification.

    This prevents a log string such as
        "[BUG] ... mbedtls_mpi_sub_abs ..."
    from being mistaken as a real trigger API call.
    """
    out = []
    in_str = False
    quote = ""
    escape = False

    for ch in text:
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                in_str = False
                out.append(ch)
            else:
                out.append(" ")
            continue

        if ch in ("'", '"'):
            in_str = True
            quote = ch
            out.append(ch)
        else:
            out.append(ch)

    return "".join(out)


def extract_placeholders(text: str) -> List[str]:
    tags = set(PLACEHOLDER_PATTERN.findall(text))
    tags -= IGNORED_BRACKET_TAGS
    return sorted(tags)


def extract_includes(text: str) -> List[str]:
    includes = []
    for line in text.splitlines():
        m = re.match(r'\s*#\s*include\s+[<"]([^>"]+)[>"]', line)
        if m:
            includes.append(m.group(1))
    return includes


def extract_defines(text: str) -> Dict[str, str]:
    defines = {}
    for line in text.splitlines():
        m = re.match(r'\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$', line)
        if m:
            defines[m.group(1)] = m.group(2).strip()
    return defines


def collect_statements(text: str) -> List[str]:
    """
    Lightweight C statement collector.
    It is not a full C parser, but keeps multiline call statements together.
    """
    cleaned = remove_comments(text)
    stmts = []
    buf = []
    paren_depth = 0

    for line in cleaned.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Skip preprocessor lines here; they are handled separately.
        if stripped.startswith("#"):
            continue

        buf.append(stripped)

        for ch in stripped:
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)

        if ";" in stripped and paren_depth == 0:
            stmt = " ".join(buf)
            parts = stmt.split(";")
            for part in parts[:-1]:
                p = part.strip()
                if p:
                    stmts.append(p + ";")
            tail = parts[-1].strip()
            buf = [tail] if tail else []

    return stmts


def extract_calls_from_statement(stmt: str) -> List[Dict[str, Any]]:
    calls = []

    # Match normal C function names and namespaced C++ functions.
    # This is intentionally broad because we only use it as metadata.
    pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(')

    for m in pattern.finditer(stmt):
        func = m.group(1)

        if func in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue

        calls.append({
            "function": func,
            "statement": stmt,
            "placeholders": extract_placeholders(stmt),
        })

    return calls


def extract_all_calls(text: str) -> List[Dict[str, Any]]:
    calls = []
    for idx, stmt in enumerate(collect_statements(text)):
        for c in extract_calls_from_statement(stmt):
            c["order"] = idx
            calls.append(c)
    return calls


def classify_statement_role(stmt: str, trigger_api: str) -> str:
    s = stmt
    code_only = strip_string_literals(s)

    # Oracle should be recognized before trigger matching.
    # Otherwise log strings containing the API name may be misclassified.
    if any(x in code_only for x in [
        "canary_corrupted",
        "expected",
        "AddressSanitizer",
    ]) or any(x in s for x in ["[BUG]", "[OK]"]):
        return "oracle"

    if any(x in code_only for x in [
        "prepare_output_with_canary",
        "mbedtls_mpi_lset",
        "mbedtls_mpi_read_string",
        "BN_set_word",
        "BN_set_negative",
        "BN_hex2bn",
        "BN_dec2bn",
        "Botan::BigInt",
    ]):
        return "input_construction"

    if trigger_api and trigger_api in code_only:
        return "trigger_call"

    if any(x in code_only for x in [
        "mbedtls_mpi_init",
        "mbedtls_pk_init",
        "BN_new",
        "psa_crypto_init",
    ]):
        return "init"

    if any(x in code_only for x in [
        "mbedtls_mpi_free",
        "mbedtls_pk_free",
        "BN_free",
        "free(",
        "cleanup",
    ]):
        return "cleanup"

    return "other"


def build_macro_level(original: str, masked: str) -> List[Dict[str, Any]]:
    original_defines = extract_defines(original)
    masked_defines = extract_defines(masked)

    out = []

    for name, masked_value in masked_defines.items():
        placeholders = extract_placeholders(masked_value)
        if not placeholders:
            continue

        out.append({
            "macro": name,
            "original": f"#define {name} {original_defines.get(name, '<not found>')}",
            "masked": f"#define {name} {masked_value}",
            "placeholders": placeholders,
            "ast_kind": "preproc_def",
            "mask_level": "macro_level",
        })

    return out


def build_placeholder_map(meta: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result = {}

    for mp in meta.get("mutation_points", []):
        ph = mp.get("placeholder")
        if ph:
            result[ph] = {
                "name": mp.get("name"),
                "type": mp.get("type"),
                "default": mp.get("default"),
                "values": mp.get("values"),
                "strategy": mp.get("strategy"),
                "constraint": mp.get("constraint"),
                "priority": mp.get("priority"),
            }

    return result


def build_argument_level(masked: str, meta: Dict[str, Any], trigger_api: str) -> List[Dict[str, Any]]:
    placeholder_info = build_placeholder_map(meta)
    calls = extract_all_calls(masked)
    out = []

    for call in calls:
        phs = call.get("placeholders", [])
        if not phs:
            continue

        role = classify_statement_role(call["statement"], trigger_api)

        for ph in phs:
            out.append({
                "api_or_function": call["function"],
                "role": role,
                "statement": call["statement"],
                "placeholder": ph,
                "mutation_point": placeholder_info.get(ph, {}),
                "ast_kind": "call_expression_or_argument",
                "mask_level": "api_argument_level" if role in {"trigger_call", "input_construction"} else "value_level",
            })

    return out


def build_roles(masked: str, trigger_api: str) -> Dict[str, List[Dict[str, Any]]]:
    stmts = collect_statements(masked)

    roles: Dict[str, List[Dict[str, Any]]] = {
        "init": [],
        "input_construction": [],
        "trigger_call": [],
        "oracle": [],
        "cleanup": [],
        "other_context": [],
    }

    for idx, stmt in enumerate(stmts):
        role = classify_statement_role(stmt, trigger_api)
        entry = {
            "order": idx,
            "code": stmt,
            "placeholders": extract_placeholders(stmt),
        }

        if role == "other":
            # Only keep context statements that contain placeholders or crypto APIs.
            if entry["placeholders"] or "mbedtls_" in stmt or "BN_" in stmt or "Botan::" in stmt:
                roles["other_context"].append(entry)
        else:
            roles[role].append(entry)

    return roles


def build_rag_query_context(meta: Dict[str, Any], roles: Dict[str, List[Dict[str, Any]]]) -> str:
    parts = []

    parts.append(f"template_id: {meta.get('template_id', '')}")
    parts.append(f"api: {meta.get('poc_source', {}).get('api', '')}")
    parts.append(f"operation: {meta.get('operation', {}).get('abstract', '')}")
    parts.append(f"bug_class: {' '.join(meta.get('operation', {}).get('bug_class', []))}")

    for role_name in ["input_construction", "trigger_call", "oracle"]:
        for item in roles.get(role_name, []):
            parts.append(f"{role_name}: {item['code']}")

    return "\n".join(parts)


def generate_report(template_dir: Path) -> Dict[str, Any]:
    meta = load_yaml(template_dir / "template_meta.yaml")
    poc_pattern = find_poc_pattern_by_template_id(meta.get("template_id", ""))

    poc_path = template_dir / "poc_original.c"
    tmpl_path = template_dir / "tmpl_mbedtls.c"

    if not poc_path.exists():
        raise FileNotFoundError(f"missing poc_original.c in {template_dir}")

    if not tmpl_path.exists():
        raise FileNotFoundError(f"missing tmpl_mbedtls.c in {template_dir}")

    original = read_text(poc_path)
    masked = read_text(tmpl_path)

    trigger_api = meta.get("poc_source", {}).get("api", "")

    roles = build_roles(masked, trigger_api)
    macro_level = build_macro_level(original, masked)
    argument_level = build_argument_level(masked, meta, trigger_api)

    report = {
        "template_id": meta.get("template_id", ""),
        "template_name": meta.get("template_name", ""),
        "source_file": meta.get("poc_source", {}).get("file", ""),
        "source_library": meta.get("poc_source", {}).get("library", ""),
        "source_api": trigger_api,
        "language": meta.get("language", "c"),
        "masking_design": {
            "mode": "ast_aware_lightweight",
            "preserve_compilable_skeleton": True,
            "note": (
                "This report records AST-like masking roles and source-level contexts. "
                "The generated C template remains compilable; block-level masks are recorded "
                "as metadata rather than replacing code with <|BLOCK|>."
            ),
        },
        "poc_pattern": compact_poc_pattern_for_report(poc_pattern),
        "includes": extract_includes(masked),
        "roles": roles,
        "masking_levels": {
            "macro_level": macro_level,
            "api_argument_or_value_level": argument_level,
            "statement_level": {
                "enabled": True,
                "strategy": "classify statements into init/input/trigger/oracle/cleanup roles",
            },
            "block_level": {
                "enabled": "metadata_only",
                "strategy": "record logical blocks without replacing compilable C blocks",
            },
        },
        "rag_query_context": build_rag_query_context(meta, roles),
        "cross_generation_hints": {
            "semantic_operation": meta.get("operation", {}).get("abstract", ""),
            "api_family": meta.get("operation", {}).get("api_family", ""),
            "bug_class": meta.get("operation", {}).get("bug_class", []),
            "must_preserve": [
                "input construction role",
                "trigger API role",
                "oracle role",
                "cleanup role",
            ],
        },
    }

    poc_ctx = build_poc_pattern_rag_context(poc_pattern)
    if poc_ctx:
        report["rag_query_context"] = report.get("rag_query_context", "") + "\n\n" + poc_ctx

    return report


def process_template_dir(template_dir: Path) -> None:
    report = generate_report(template_dir)
    dump_yaml(template_dir / "mask_report.yaml", report)
    print(f"[OK] wrote {template_dir / 'mask_report.yaml'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AST-aware mask_report.yaml for templates.")
    parser.add_argument(
        "--root",
        default="normalized_templates",
        help="Template root. Default: normalized_templates",
    )
    args = parser.parse_args()

    root = Path(args.root)

    if not root.exists():
        print(f"[ERROR] root not found: {root}")
        return 1

    template_dirs = find_template_dirs(root)

    if not template_dirs:
        print(f"[ERROR] no template_meta.yaml found under {root}")
        return 1

    for td in template_dirs:
        process_template_dir(td)

    print("=" * 80)
    print(f"[SUMMARY] generated mask reports: {len(template_dirs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
