import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


PLACEHOLDER_RE = re.compile(r"\[[A-Z0-9_]+\]")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
TYPE_DECL_RE = re.compile(
    r"^\s*(?:const\s+)?(?:unsigned\s+char|char|int|size_t|long|unsigned\s+long|"
    r"mbedtls_[A-Za-z0-9_]+|psa_[A-Za-z0-9_]+)\s+[\*A-Za-z_][A-Za-z0-9_\*\s]*(?:\[.*\])?\s*(?:=.*)?;"
)
CONTROL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
}


def infer_template_library(template_file: str, meta: Optional[Dict[str, Any]] = None, mask_report: Optional[Dict[str, Any]] = None) -> str:
    name = Path(str(template_file or "")).name.lower()
    if "openssl" in name:
        return "openssl"
    if "mbedtls" in name:
        return "mbedtls"
    if "botan" in name:
        return "botan"
    meta = meta or {}
    mask_report = mask_report or {}
    return str(mask_report.get("source_library") or meta.get("source_library") or "")


def normalize_api_list(value: Any) -> List[str]:
    out: List[str] = []

    def add(item: Any) -> None:
        if isinstance(item, dict):
            item = item.get("function") or item.get("api") or ""
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)

    if isinstance(value, list):
        for item in value:
            add(item)
    else:
        add(value)
    return out


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


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""


def clean_code(code: Any) -> str:
    text = str(code or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def placeholders_in(text: str) -> List[str]:
    seen = []
    for item in PLACEHOLDER_RE.findall(text or ""):
        if item not in seen:
            seen.append(item)
    return seen


def placeholder_name(placeholder: str) -> str:
    return placeholder.strip("[]")


def normalize_mask_level(level: Any, placeholder: str = "", code: str = "") -> str:
    raw = str(level or "").strip()
    mapping = {
        "value_level": "value",
        "api_argument_level": "api_argument",
        "api_argument_or_value_level": "api_argument",
        "macro_level": "value",
        "oracle_level": "value",
        "memory_layout_level": "api_argument",
        "identifier_level": "identifier",
        "statement_level": "statement",
        "block_level": "block",
        "type_level": "type",
        "function_call_level": "function_call",
    }
    if raw in mapping:
        return mapping[raw]
    if raw in {"value", "identifier", "type", "api_argument", "function_call", "statement", "block"}:
        return raw

    name = placeholder_name(placeholder)
    if placeholder:
        if name.endswith(("RADIX", "BASE", "BUFLEN", "LEN", "LIMB_COUNT", "SIZE", "ALG", "TYPE")):
            return "api_argument"
        return "value"
    if CALL_RE.search(code or ""):
        return "function_call"
    return "statement"


def collect_trigger_apis(meta: Dict[str, Any], mask_report: Dict[str, Any], template_library: str = "") -> List[str]:
    apis: List[str] = []

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in apis:
            apis.append(text)

    for api in mask_report.get("trigger_apis", []) or []:
        add(api)

    for api in normalize_api_list(meta.get("source_api")):
        add(api)

    add(meta.get("source_api_name"))
    add(meta.get("poc_source", {}).get("api"))

    for api in meta.get("internal_apis", []) or []:
        add(api)

    template_library = str(template_library or "").strip()
    if template_library:
        cross_lib = meta.get("cross_library", {}) or {}
        lib_spec = cross_lib.get(template_library, {}) if isinstance(cross_lib, dict) else {}
        if isinstance(lib_spec, dict):
            add(lib_spec.get("target_api"))

    pattern_source = mask_report.get("poc_pattern", {}).get("source", {}) or {}
    add(pattern_source.get("api"))
    for key in ["related_apis", "internal_functions"]:
        for api in pattern_source.get(key, []) or []:
            add(api)

    return apis


def is_trigger_call_text(code: str, trigger_apis: Iterable[str]) -> bool:
    text = code or ""
    for api in trigger_apis:
        if api and re.search(rf"\b{re.escape(api)}\s*\(", text):
            return True
    return False


def infer_role(
    code: str,
    source_api: str = "",
    helper_names: Optional[Iterable[str]] = None,
    trigger_apis: Optional[Iterable[str]] = None,
) -> str:
    text = code or ""
    helper_set = set(helper_names or [])
    api_set = list(trigger_apis or ([] if not source_api else [source_api]))

    if is_trigger_call_text(text, api_set):
        return "trigger_call"
    if any(re.search(rf"\b{re.escape(name)}\s*\(", text) for name in helper_set):
        if "canary" in text or "[BUG]" in text or "[OK]" in text:
            return "oracle"
        return "input_preparation"
    if "canary_corrupted" in text or "[BUG]" in text or "[OK]" in text or "expected fixed" in text:
        return "oracle"
    if "cleanup" in text or "_free(" in text or re.search(r"\bfree\s*\(", text) or "goto cleanup" in text:
        return "cleanup"
    if "_init(" in text or "psa_crypto_init" in text:
        return "input_preparation"
    if any(token in text for token in ["read_string", "_lset", "memset", "setup", "gen_key", "import_into_psa", "set_padding"]):
        return "input_construction"
    return "mutation_point" if placeholders_in(text) else "helper_function"


def make_unit(
    mask_level: str,
    role: str,
    placeholder: str,
    code: str,
    source: str,
    reason: str,
    priority: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    unit = {
        "unit_id": "",
        "mask_level": mask_level,
        "role": role,
        "placeholder": placeholder or "",
        "code": clean_code(code),
        "source": source,
        "reason": str(reason or ""),
        "priority": str(priority or "medium"),
    }
    if extra:
        unit.update(extra)
    return unit


def add_unit(units: List[Dict[str, Any]], seen: set, unit: Dict[str, Any]) -> None:
    key = (
        unit.get("mask_level", ""),
        unit.get("role", ""),
        unit.get("placeholder", ""),
        unit.get("code", ""),
        unit.get("source", ""),
    )
    if key in seen:
        return
    seen.add(key)
    units.append(unit)


def extract_statement_spans(c_text: str) -> List[Dict[str, Any]]:
    spans: List[Dict[str, Any]] = []
    current: List[str] = []
    start_line = 1
    paren_depth = 0

    for line_no, line in enumerate(c_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        if not current:
            start_line = line_no

        current.append(stripped)
        paren_depth += stripped.count("(") - stripped.count(")")

        terminates = (
            stripped.endswith(";")
            or stripped.endswith("{")
            or stripped.endswith("}")
            or stripped.endswith(":")
        )
        if terminates and paren_depth <= 0:
            code = clean_code(" ".join(current))
            if code:
                spans.append({
                    "line": start_line,
                    "line_start": start_line,
                    "line_end": line_no,
                    "code": code,
                })
            current = []
            paren_depth = 0

    if current:
        spans.append({
            "line": start_line,
            "line_start": start_line,
            "line_end": start_line + len(current) - 1,
            "code": clean_code(" ".join(current)),
        })

    return spans


def find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for idx in range(open_index, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def line_number_at(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def extract_helper_blocks(c_text: str) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []
    pattern = re.compile(
        r"\bstatic\s+[A-Za-z_][A-Za-z0-9_\s\*]*?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{",
        re.M,
    )
    for match in pattern.finditer(c_text):
        name = match.group(1)
        open_index = c_text.find("{", match.start())
        close_index = find_matching_brace(c_text, open_index)
        if close_index < 0:
            continue
        block = c_text[match.start() : close_index + 1]
        line_start = line_number_at(c_text, match.start())
        line_end = line_number_at(c_text, close_index)
        blocks.append(
            {
                "name": name,
                "line": line_start,
                "line_start": line_start,
                "line_end": line_end,
                "code": block.strip(),
            }
        )
    return blocks


def function_calls_in(code: str) -> List[str]:
    calls = []
    for name in CALL_RE.findall(code or ""):
        if name in CONTROL_WORDS:
            continue
        if name not in calls:
            calls.append(name)
    return calls


def line_extra(obj: Dict[str, Any]) -> Dict[str, Any]:
    extra: Dict[str, Any] = {}
    line_start = obj.get("line_start", obj.get("line"))
    line_end = obj.get("line_end", line_start)
    if line_start not in (None, ""):
        extra["line"] = line_start
        extra["line_start"] = line_start
    if line_end not in (None, ""):
        extra["line_end"] = line_end
    return extra


def enclosing_function_for_line(line: Any, helper_blocks: List[Dict[str, Any]]) -> str:
    try:
        line_no = int(line)
    except Exception:
        return ""

    for block in helper_blocks:
        start = block.get("line_start", block.get("line"))
        end = block.get("line_end", start)
        try:
            if int(start) <= line_no <= int(end):
                return str(block.get("name", ""))
        except Exception:
            continue
    return ""


def find_mutation_point(meta: Dict[str, Any], mask_report: Dict[str, Any], placeholder: str) -> Dict[str, Any]:
    for source in (meta, mask_report.get("poc_pattern", {}), mask_report):
        for item in source.get("mutation_points", []) or []:
            if item.get("placeholder") == placeholder:
                return item
    return {}


def units_from_mutation_points(meta: Dict[str, Any], mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    merged: Dict[str, Dict[str, Any]] = {}

    for source_name, source in (
        ("template_meta.mutation_points", meta),
        ("mask_report.poc_pattern.mutation_points", mask_report.get("poc_pattern", {})),
    ):
        for item in source.get("mutation_points", []) or []:
            placeholder = str(item.get("placeholder") or "")
            if not placeholder:
                continue
            existing = merged.setdefault(placeholder, {})
            existing.update({k: v for k, v in item.items() if v not in (None, "")})
            existing.setdefault("_source", source_name)

    for placeholder, item in merged.items():
        level = normalize_mask_level(item.get("mask_level"), placeholder)
        out.append(
            make_unit(
                mask_level=level,
                role="mutation_point",
                placeholder=placeholder,
                code=str(item.get("source_expr") or item.get("name") or placeholder),
                source=item.get("_source", "mutation_points"),
                reason=item.get("reason") or item.get("constraint") or "Template mutation point.",
                priority=item.get("priority", "medium"),
                extra={
                    "mutation_name": item.get("name", placeholder_name(placeholder)),
                    "mutation_type": item.get("type", ""),
                    "default": item.get("default", ""),
                    "values": item.get("values", []),
                },
            )
        )
    return out


def units_from_roles(mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    roles = mask_report.get("roles", {}) or {}

    role_map = {
        "init": "input_preparation",
        "input_construction": "input_construction",
        "trigger_call": "trigger_call",
        "oracle": "oracle",
        "cleanup": "cleanup",
        "other_context": "helper_function",
    }

    for raw_role, items in roles.items():
        role = role_map.get(raw_role, raw_role)
        for item in items or []:
            code = item.get("code", "")
            phs = item.get("placeholders") or placeholders_in(code)
            if not phs:
                phs = [""]
            for ph in phs:
                level = normalize_mask_level("", ph, code)
                if not ph:
                    level = "statement"
                out.append(
                    make_unit(
                        mask_level=level if level != "function_call" else "statement",
                        role=role,
                        placeholder=ph,
                        code=code,
                        source=f"mask_report.roles.{raw_role}",
                        reason=f"Role-aware statement recorded by mask_report role '{raw_role}'.",
                        priority="medium",
                        extra={
                            "order": item.get("order", ""),
                            **line_extra(item),
                            "node_type": "statement",
                        },
                    )
                )
    return out


def units_from_masking_levels(mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    levels = mask_report.get("masking_levels", {}) or {}

    for item in levels.get("macro_level", []) or []:
        for ph in item.get("placeholders", []) or []:
            out.append(
                make_unit(
                    mask_level="value",
                    role="mutation_point",
                    placeholder=ph,
                    code=item.get("masked") or item.get("original") or item.get("macro", ""),
                    source="mask_report.masking_levels.macro_level",
                    reason="Macro-level placeholder controls a generated constant or buffer size.",
                    priority="medium",
                    extra={"macro": item.get("macro", ""), "node_type": "preproc_def"},
                )
            )

    for item in levels.get("api_argument_or_value_level", []) or []:
        ph = item.get("placeholder", "")
        mutation = item.get("mutation_point", {}) or {}
        out.append(
            make_unit(
                mask_level=normalize_mask_level(item.get("mask_level"), ph, item.get("statement", "")),
                role=item.get("role", "mutation_point"),
                placeholder=ph,
                code=item.get("statement", ""),
                source="mask_report.masking_levels.api_argument_or_value_level",
                reason=mutation.get("reason") or mutation.get("constraint") or "API argument/value mask from mask_report.",
                priority=mutation.get("priority", "medium"),
                extra={
                    "api_or_function": item.get("api_or_function", ""),
                    **line_extra(item),
                    "node_type": item.get("ast_kind", "call_expression_or_argument"),
                },
            )
        )

    return out


def units_from_occlusion(mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    candidates = mask_report.get("poc_pattern", {}).get("occlusion_candidates", {}) or {}
    for raw_level, values in candidates.items():
        level = normalize_mask_level(raw_level)
        for value in values or []:
            out.append(
                make_unit(
                    mask_level=level,
                    role="mutation_point",
                    placeholder="",
                    code=str(value),
                    source=f"mask_report.poc_pattern.occlusion_candidates.{raw_level}",
                    reason="PoC pattern occlusion candidate for multi-granularity masking.",
                    priority="medium",
                )
            )
    return out


def units_from_c_template(
    c_text: str,
    source_api: str,
    trigger_apis: List[str],
    meta: Dict[str, Any],
    mask_report: Dict[str, Any],
    template_file: str = "tmpl_mbedtls.c",
    template_library: str = "",
) -> List[Dict[str, Any]]:
    out = []
    helper_blocks = extract_helper_blocks(c_text)
    helper_names = [b["name"] for b in helper_blocks]
    spans = extract_statement_spans(c_text)

    for block in helper_blocks:
        out.append(
            make_unit(
                mask_level="block",
                role="helper_function",
                placeholder="",
                code=block["code"],
                source=f"{template_file}.helper_function",
                reason=f"Static helper function block '{block['name']}' identified by AST-lite brace matching.",
                priority="medium",
                extra={
                    "function": block["name"],
                    **line_extra(block),
                    "node_type": "function_definition",
                    "enclosing_function": block["name"],
                    "template_file": template_file,
                    "template_library": template_library,
                },
            )
        )

    for span in spans:
        code = span["code"]
        phs = placeholders_in(code)
        role = infer_role(code, source_api, helper_names, trigger_apis)

        if phs:
            for ph in phs:
                mp = find_mutation_point(meta, mask_report, ph)
                out.append(
                    make_unit(
                        mask_level=normalize_mask_level(mp.get("mask_level"), ph, code),
                        role=role,
                        placeholder=ph,
                        code=code,
                        source=f"{template_file}.placeholder_statement",
                        reason=mp.get("reason") or mp.get("constraint") or "Statement contains a template placeholder.",
                        priority=mp.get("priority", "medium"),
                        extra={**line_extra(span), "enclosing_function": enclosing_function_for_line(span.get("line_start", span.get("line")), helper_blocks), "node_type": "statement", "template_file": template_file, "template_library": template_library},
                    )
                )

        if is_trigger_call_text(code, trigger_apis):
            out.append(
                make_unit(
                    mask_level="statement",
                    role="trigger_call",
                    placeholder="",
                    code=code,
                    source=f"{template_file}.source_api_statement",
                    reason="Statement invokes the source API trigger.",
                    priority="high",
                    extra={**line_extra(span), "enclosing_function": enclosing_function_for_line(span.get("line_start", span.get("line")), helper_blocks), "node_type": "statement", "template_file": template_file, "template_library": template_library},
                )
            )

        if TYPE_DECL_RE.match(code):
            out.append(
                make_unit(
                    mask_level="type",
                    role=infer_role(code, source_api, helper_names, trigger_apis),
                    placeholder=phs[0] if phs else "",
                    code=code,
                    source=f"{template_file}.type_declaration",
                    reason="Type declaration identified by AST-lite declaration matching.",
                    priority="medium",
                    extra={**line_extra(span), "enclosing_function": enclosing_function_for_line(span.get("line_start", span.get("line")), helper_blocks), "node_type": "statement", "template_file": template_file, "template_library": template_library},
                )
            )

        if role in {"oracle", "cleanup"}:
            out.append(
                make_unit(
                    mask_level="statement",
                    role=role,
                    placeholder="",
                    code=code,
                    source=f"{template_file}.role_statement",
                    reason=f"Statement classified as {role} by AST-lite role rules.",
                    priority="medium",
                    extra={**line_extra(span), "enclosing_function": enclosing_function_for_line(span.get("line_start", span.get("line")), helper_blocks), "node_type": "statement", "template_file": template_file, "template_library": template_library},
                )
            )

        for call in function_calls_in(code):
            call_role = "trigger_call" if call in trigger_apis else infer_role(code, source_api, helper_names, trigger_apis)
            if call in helper_names and call_role not in {"oracle", "trigger_call"}:
                call_role = "input_preparation"
            out.append(
                make_unit(
                    mask_level="function_call",
                    role=call_role,
                    placeholder=phs[0] if phs else "",
                    code=code,
                    source=f"{template_file}.function_call",
                    reason=f"Function call '{call}' identified by AST-lite call matching.",
                    priority="high" if call in trigger_apis else "medium",
                    extra={"function": call, "called_function": call, **line_extra(span), "enclosing_function": enclosing_function_for_line(span.get("line_start", span.get("line")), helper_blocks), "node_type": "call_expression", "template_file": template_file, "template_library": template_library},
                )
            )

    return out


def add_unit_ids(units: List[Dict[str, Any]]) -> None:
    for idx, unit in enumerate(units, start=1):
        unit["unit_id"] = f"ASTLITE-{idx:04d}"


def summarize(units: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    return dict(sorted(Counter(str(u.get(field, "")) for u in units).items()))


def build_report(template_dir: Path, template_file: str = "tmpl_mbedtls.c") -> Dict[str, Any]:
    meta = load_yaml(template_dir / "template_meta.yaml")
    mask_report = load_yaml(template_dir / "mask_report.yaml")
    c_text = read_text(template_dir / template_file)
    template_library = infer_template_library(template_file, meta, mask_report)

    source_api_values = normalize_api_list(mask_report.get("source_api") or meta.get("source_api"))
    source_api = source_api_values[0] if source_api_values else str(meta.get("poc_source", {}).get("api") or "")
    source_library = (
        mask_report.get("source_library")
        or source_api_obj.get("library")
        or meta.get("poc_source", {}).get("library")
        or ""
    )
    trigger_apis = collect_trigger_apis(meta, mask_report, template_library=template_library)
    if source_api and source_api not in trigger_apis:
        trigger_apis.insert(0, source_api)
    harness_family = str(mask_report.get("harness_family") or meta.get("harness_family") or "")

    raw_units: List[Dict[str, Any]] = []
    raw_units.extend(units_from_mutation_points(meta, mask_report))
    raw_units.extend(units_from_roles(mask_report))
    raw_units.extend(units_from_masking_levels(mask_report))
    raw_units.extend(units_from_occlusion(mask_report))
    raw_units.extend(units_from_c_template(c_text, source_api, trigger_apis, meta, mask_report, template_file=template_file, template_library=template_library))

    units: List[Dict[str, Any]] = []
    seen = set()
    for unit in raw_units:
        add_unit(units, seen, unit)
    add_unit_ids(units)

    return {
        "template_id": mask_report.get("template_id") or meta.get("template_id", ""),
        "template_name": mask_report.get("template_name") or meta.get("template_name", ""),
        "source_api": source_api,
        "source_library": source_library,
        "template_file": template_file,
        "template_library": template_library,
        "trigger_apis": trigger_apis,
        "harness_family": harness_family,
        "summary": {
            "method": "ast_lite_regex_template_role_aware",
            "template_dir": str(template_dir),
            "template_file": template_file,
            "template_library": template_library,
            "unit_count": len(units),
            "note": (
                "Lightweight AST-like report generated from template metadata, "
                "mask_report roles, and regex/template-aware analysis of tmpl_mbedtls.c."
            ),
        },
        "ast_mask_units": units,
        "role_summary": summarize(units, "role"),
        "mask_level_summary": summarize(units, "mask_level"),
    }


def find_template_dirs(root: Path) -> List[Path]:
    return sorted(path.parent for path in root.rglob("template_meta.yaml"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate lightweight role-aware multi-granularity AST mask reports."
    )
    parser.add_argument("--root", default="normalized_templates")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        parser.error(f"root not found: {root}")

    count = 0
    for template_dir in find_template_dirs(root):
        report = build_report(template_dir)
        out_path = template_dir / "ast_mask_report.yaml"
        dump_yaml(out_path, report)
        print(f"[OK] wrote {out_path} units={len(report.get('ast_mask_units', []))}")
        count += 1

    print("=" * 80)
    print(f"[SUMMARY] template dirs scanned: {count}")
    print(f"[SUMMARY] root: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
