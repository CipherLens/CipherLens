import argparse
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

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


FAMILY_ROLE_KEYWORDS = {
    "buffer_canary_boundary": {
        "input_construction": [
            "canary",
            "buffer",
            "buf",
            "BUFLEN",
            "CANARY_SIZE",
            "prepare_output_with_canary",
            "memset",
        ],
        "oracle": [
            "canary_corrupted",
            "AddressSanitizer",
            "out-of-bounds",
        ],
    },
    "der_pointer_consumption": {
        "input_construction": [
            "base_hex",
            "TRAILING_GARBAGE",
            "build_der_with_trailing_garbage",
            "select_base_der_hex",
        ],
        "oracle": [
            "consumed_len",
            "der_len",
            "trailing garbage",
            "end != p + len",
            "p + len",
        ],
    },
    "x509_asn1_inner_boundary": {
        "input_construction": [
            "der",
            "DER",
            "ASN1",
            "X509",
            "certificate",
        ],
        "oracle": [
            "ret",
            "ASN1",
            "rejected",
            "out_of_data",
        ],
    },
    "return_code_outlen_semantic": {
        "input_construction": [
            "out",
            "out_len",
            "output",
            "padding",
            "final",
        ],
        "oracle": [
            "ret",
            "out_len",
            "output length",
            "error path",
        ],
    },
    "null_deref_dispatch": {
        "input_construction": [
            "type",
            "opaque",
            "dispatch",
            "context",
        ],
        "oracle": [
            "null",
            "NULL",
            "segmentation",
            "AddressSanitizer",
        ],
    },
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


def add_unique(out: List[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in out:
        out.append(text)


def collect_trigger_apis(meta: Dict[str, Any], poc_pattern: Dict[str, Any]) -> List[str]:
    apis: List[str] = []

    source_api = meta.get("source_api")
    if isinstance(source_api, dict):
        add_unique(apis, source_api.get("function"))
    elif isinstance(source_api, str):
        add_unique(apis, source_api)

    add_unique(apis, meta.get("source_api_name"))
    add_unique(apis, meta.get("poc_source", {}).get("api"))

    for api in meta.get("internal_apis", []) or []:
        add_unique(apis, api)

    pattern_source = poc_pattern.get("source", {}) or {}
    add_unique(apis, pattern_source.get("api"))
    for key in ["related_apis", "internal_functions"]:
        for api in pattern_source.get(key, []) or []:
            add_unique(apis, api)

    library = poc_pattern.get("library", {}) or {}
    for api in library.get("affected_api", []) or []:
        add_unique(apis, api)

    return apis


def get_harness_family(meta: Dict[str, Any], poc_pattern: Dict[str, Any]) -> str:
    return str(
        meta.get("harness_family")
        or poc_pattern.get("harness_family")
        or poc_pattern.get("classification", {}).get("harness_family")
        or ""
    )


def family_keywords(harness_family: str, role: str) -> List[str]:
    return FAMILY_ROLE_KEYWORDS.get(harness_family, {}).get(role, [])


def contains_any_keyword(text: str, keywords: Iterable[str]) -> bool:
    lower = text.lower()
    return any(str(k).lower() in lower for k in keywords)


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


def collect_statement_entries(text: str) -> List[Dict[str, Any]]:
    """
    Lightweight C statement collector with source line ranges.
    It is not a full C parser, but keeps multiline call statements together
    and avoids merging function/block braces into the next statement.
    """
    cleaned = remove_comments(text)
    entries: List[Dict[str, Any]] = []
    buf: List[str] = []
    buf_start_line = 1
    paren_depth = 0

    def flush(line_end: int) -> None:
        nonlocal buf, buf_start_line, paren_depth
        stmt = " ".join(part for part in buf if part).strip()
        if stmt:
            entries.append({
                "code": stmt,
                "line_start": buf_start_line,
                "line_end": line_end,
            })
        buf = []
        buf_start_line = line_end + 1
        paren_depth = 0

    for line_no, line in enumerate(cleaned.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # Skip preprocessor lines here; they are handled separately.
        if stripped.startswith("#"):
            continue

        if stripped == "}":
            if buf:
                flush(line_no - 1)
            entries.append({"code": stripped, "line_start": line_no, "line_end": line_no})
            buf_start_line = line_no + 1
            continue

        if not buf:
            buf_start_line = line_no

        buf.append(stripped)

        for ch in stripped:
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)

        if paren_depth == 0 and stripped.endswith("{"):
            flush(line_no)
            continue

        if ";" in stripped and paren_depth == 0:
            stmt = " ".join(buf)
            parts = stmt.split(";")
            current_start = buf_start_line
            for part in parts[:-1]:
                p = part.strip()
                if p:
                    entries.append({
                        "code": p + ";",
                        "line_start": current_start,
                        "line_end": line_no,
                    })
                    current_start = line_no
            tail = parts[-1].strip()
            buf = [tail] if tail else []
            buf_start_line = line_no if tail else line_no + 1

    if buf:
        flush(len(cleaned.splitlines()))

    return entries


def collect_statements(text: str) -> List[str]:
    return [entry["code"] for entry in collect_statement_entries(text)]


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
    for idx, entry in enumerate(collect_statement_entries(text)):
        stmt = entry["code"]
        for c in extract_calls_from_statement(stmt):
            c["order"] = idx
            c["line_start"] = entry.get("line_start")
            c["line_end"] = entry.get("line_end")
            calls.append(c)
    return calls


def classify_statement_role(
    stmt: str,
    trigger_apis: Iterable[str],
    harness_family: str = "",
) -> str:
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

    for api in trigger_apis:
        if not api or not re.search(rf"\b{re.escape(api)}\s*\(", code_only):
            continue
        # Function prototypes/declarations mention trigger APIs but do not execute them.
        if code_only.strip().endswith(";") and "ret" not in code_only and "=" not in code_only:
            return "other"
        return "trigger_call"

    if contains_any_keyword(code_only, family_keywords(harness_family, "oracle")):
        if any(x in code_only for x in ["if", "return", "[BUG]", "[OK]"]):
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
    ]) or contains_any_keyword(code_only, family_keywords(harness_family, "input_construction")):
        return "input_construction"

    if any(x in code_only for x in [
        "mbedtls_mpi_init",
        "mbedtls_pk_init",
        "mbedtls_rsa_init",
        "BN_new",
        "psa_crypto_init",
    ]):
        return "init"

    if any(x in code_only for x in [
        "mbedtls_mpi_free",
        "mbedtls_pk_free",
        "mbedtls_rsa_free",
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


def build_argument_level(
    masked: str,
    meta: Dict[str, Any],
    trigger_apis: Iterable[str],
    harness_family: str,
) -> List[Dict[str, Any]]:
    placeholder_info = build_placeholder_map(meta)
    calls = extract_all_calls(masked)
    out = []

    for call in calls:
        phs = call.get("placeholders", [])
        if not phs:
            continue

        role = classify_statement_role(call["statement"], trigger_apis, harness_family)

        for ph in phs:
            out.append({
                "api_or_function": call["function"],
                "role": role,
                "statement": call["statement"],
                "placeholder": ph,
                "mutation_point": placeholder_info.get(ph, {}),
                "ast_kind": "call_expression_or_argument",
                "mask_level": "api_argument_level" if role in {"trigger_call", "input_construction"} else "value_level",
                "line_start": call.get("line_start"),
                "line_end": call.get("line_end"),
            })

    return out


def build_roles(
    masked: str,
    trigger_apis: Iterable[str],
    harness_family: str,
) -> Dict[str, List[Dict[str, Any]]]:
    entries = collect_statement_entries(masked)

    roles: Dict[str, List[Dict[str, Any]]] = {
        "init": [],
        "input_construction": [],
        "trigger_call": [],
        "oracle": [],
        "cleanup": [],
        "other_context": [],
    }

    for idx, stmt_entry in enumerate(entries):
        stmt = stmt_entry["code"]
        role = classify_statement_role(stmt, trigger_apis, harness_family)
        entry = {
            "order": idx,
            "code": stmt,
            "placeholders": extract_placeholders(stmt),
            "line_start": stmt_entry.get("line_start"),
            "line_end": stmt_entry.get("line_end"),
        }

        if role == "other":
            # Only keep context statements that contain placeholders or crypto APIs.
            if (
                entry["placeholders"]
                or "mbedtls_" in stmt
                or "BN_" in stmt
                or "Botan::" in stmt
                or contains_any_keyword(stmt, family_keywords(harness_family, "input_construction"))
                or contains_any_keyword(stmt, family_keywords(harness_family, "oracle"))
            ):
                roles["other_context"].append(entry)
        else:
            roles[role].append(entry)

    return roles


def build_rag_query_context(
    meta: Dict[str, Any],
    roles: Dict[str, List[Dict[str, Any]]],
    trigger_apis: Iterable[str],
    harness_family: str,
) -> str:
    parts = []

    parts.append(f"template_id: {meta.get('template_id', '')}")
    parts.append(f"api: {meta.get('poc_source', {}).get('api', '')}")
    parts.append(f"trigger_apis: {list(trigger_apis)}")
    parts.append(f"harness_family: {harness_family}")
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

    trigger_apis = collect_trigger_apis(meta, poc_pattern)
    trigger_api = trigger_apis[0] if trigger_apis else meta.get("poc_source", {}).get("api", "")
    harness_family = get_harness_family(meta, poc_pattern)

    roles = build_roles(masked, trigger_apis, harness_family)
    macro_level = build_macro_level(original, masked)
    argument_level = build_argument_level(masked, meta, trigger_apis, harness_family)

    report = {
        "template_id": meta.get("template_id", ""),
        "template_name": meta.get("template_name", ""),
        "source_file": meta.get("poc_source", {}).get("file", ""),
        "source_library": meta.get("poc_source", {}).get("library", ""),
        "source_api": trigger_api,
        "trigger_apis": trigger_apis,
        "harness_family": harness_family,
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
        "rag_query_context": build_rag_query_context(meta, roles, trigger_apis, harness_family),
        "cross_generation_hints": {
            "semantic_operation": meta.get("operation", {}).get("abstract", ""),
            "api_family": meta.get("operation", {}).get("api_family", ""),
            "bug_class": meta.get("operation", {}).get("bug_class", []),
            "harness_family": harness_family,
            "trigger_apis": trigger_apis,
            "family_context_keywords": FAMILY_ROLE_KEYWORDS.get(harness_family, {}),
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
