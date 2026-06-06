import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from template_maker import ast_mask_lite


IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
ASSIGNMENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:[+\-*/%&|^]?=)")
DECLARATION_NODE_TYPES = {
    "declaration",
    "init_declarator",
    "parameter_declaration",
}
STATEMENT_NODE_TYPES = {
    "declaration",
    "do_statement",
    "else_clause",
    "expression_statement",
    "for_statement",
    "if_statement",
    "return_statement",
    "switch_statement",
    "while_statement",
}
PREPROCESSOR_NODE_TYPES = {
    "preproc_call",
    "preproc_def",
    "preproc_function_def",
    "preproc_if",
    "preproc_ifdef",
}


def load_tree_sitter_c() -> Tuple[Any, Any]:
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c
    except ImportError as e:
        raise RuntimeError(
            "tree-sitter AST backend requires optional dependencies: "
            "tree_sitter and tree_sitter_c. Install them or run with --backend lite."
        ) from e

    raw_language = tree_sitter_c.language()
    try:
        language = Language(raw_language)
    except TypeError:
        language = raw_language

    try:
        parser = Parser(language)
    except TypeError:
        parser = Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language

    return parser, language


def node_text(node: Any, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def clean_code(text: str) -> str:
    return ast_mask_lite.clean_code(text)


def node_range(node: Any) -> Dict[str, int]:
    start_row, start_col = node.start_point
    end_row, end_col = node.end_point
    return {
        "line": start_row + 1,
        "line_start": start_row + 1,
        "line_end": end_row + 1,
        "column_start": start_col + 1,
        "column_end": end_col + 1,
    }


def iter_nodes(node: Any) -> Iterable[Any]:
    yield node
    for child in getattr(node, "children", []) or []:
        yield from iter_nodes(child)


def first_descendant_of_type(node: Any, node_type: str) -> Optional[Any]:
    for candidate in iter_nodes(node):
        if candidate.type == node_type:
            return candidate
    return None


def direct_child_by_type(node: Any, node_type: str) -> Optional[Any]:
    for child in getattr(node, "children", []) or []:
        if child.type == node_type:
            return child
    return None


def extract_function_name(function_node: Any, source_bytes: bytes) -> str:
    declarator = function_node.child_by_field_name("declarator")
    if declarator is None:
        declarator = direct_child_by_type(function_node, "function_declarator")
    if declarator is None:
        return ""

    identifiers = [
        node_text(node, source_bytes)
        for node in iter_nodes(declarator)
        if node.type == "identifier"
    ]
    return identifiers[-1] if identifiers else ""


def extract_called_function(call_node: Any, source_bytes: bytes) -> str:
    fn_node = call_node.child_by_field_name("function")
    if fn_node is None:
        fn_node = getattr(call_node, "children", [None])[0]
    if fn_node is None:
        return ""

    identifiers = [
        node_text(node, source_bytes)
        for node in iter_nodes(fn_node)
        if node.type in {"identifier", "field_identifier"}
    ]
    if identifiers:
        return identifiers[-1]
    return clean_code(node_text(fn_node, source_bytes))


def enclosing_function_for_node(
    node: Any,
    function_ranges: List[Dict[str, Any]],
) -> str:
    line = node.start_point[0] + 1
    best: Optional[Dict[str, Any]] = None

    for item in function_ranges:
        if item["line_start"] <= line <= item["line_end"]:
            if best is None or item["line_start"] >= best["line_start"]:
                best = item

    return str(best.get("name", "")) if best else ""


def nearest_statement_node(node: Any) -> Any:
    current = node
    fallback = node
    while current is not None:
        if current.type in STATEMENT_NODE_TYPES or current.type in PREPROCESSOR_NODE_TYPES:
            return current
        if current.type == "compound_statement":
            fallback = current
        current = getattr(current, "parent", None)
    return fallback


def identifiers_in_node(node: Any, source_bytes: bytes) -> List[str]:
    seen: List[str] = []
    for item in iter_nodes(node):
        if item.type not in {"identifier", "field_identifier"}:
            continue
        text = node_text(item, source_bytes)
        if text and text not in seen:
            seen.append(text)
    return seen


def identifiers_written_by_text(text: str) -> List[str]:
    seen: List[str] = []
    for name in ASSIGNMENT_RE.findall(text or ""):
        if name not in seen:
            seen.append(name)
    return seen


def identifiers_read_from_text(text: str, called_function: str = "") -> List[str]:
    written = set(identifiers_written_by_text(text))
    calls = set(ast_mask_lite.function_calls_in(text))
    excluded = written | calls | {called_function}
    seen: List[str] = []

    for name in IDENTIFIER_RE.findall(text or ""):
        if name in ast_mask_lite.CONTROL_WORDS or name in excluded:
            continue
        if name not in seen:
            seen.append(name)

    return seen


def placeholder_dependencies(text: str) -> List[str]:
    return ast_mask_lite.placeholders_in(text)


def make_ts_unit(
    *,
    node: Any,
    source_bytes: bytes,
    mask_level: str,
    role: str,
    source: str,
    reason: str,
    priority: str = "medium",
    function_ranges: Optional[List[Dict[str, Any]]] = None,
    placeholder: str = "",
    called_function: str = "",
    code_override: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    code = code_override or node_text(node, source_bytes)
    deps = placeholder_dependencies(code)
    written = identifiers_written_by_text(code)
    unit_extra: Dict[str, Any] = {
        **node_range(node),
        "node_type": node.type,
        "enclosing_function": enclosing_function_for_node(node, function_ranges or []),
        "placeholder_dependencies": deps,
        "identifiers_read": identifiers_read_from_text(code, called_function),
        "identifiers_written": written,
    }
    if called_function:
        unit_extra["called_function"] = called_function
    if extra:
        unit_extra.update(extra)

    return ast_mask_lite.make_unit(
        mask_level=mask_level,
        role=role,
        placeholder=placeholder or (deps[0] if deps else ""),
        code=code,
        source=source,
        reason=reason,
        priority=priority,
        extra=unit_extra,
    )


def function_ranges(root_node: Any, source_bytes: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for node in iter_nodes(root_node):
        if node.type != "function_definition":
            continue
        name = extract_function_name(node, source_bytes)
        rng = node_range(node)
        out.append(
            {
                "name": name,
                "line_start": rng["line_start"],
                "line_end": rng["line_end"],
            }
        )
    return out


def collect_units_from_tree(
    root_node: Any,
    source_bytes: bytes,
    source_api: str,
    trigger_apis: List[str],
) -> List[Dict[str, Any]]:
    units: List[Dict[str, Any]] = []
    seen: Set[Tuple[Any, ...]] = set()
    functions = function_ranges(root_node, source_bytes)
    helper_names = [item["name"] for item in functions if item.get("name") and item.get("name") != "main"]

    for node in iter_nodes(root_node):
        code = clean_code(node_text(node, source_bytes))
        if not code:
            continue

        if node.type == "function_definition":
            name = extract_function_name(node, source_bytes)
            role = "entrypoint" if name == "main" else "helper_function"
            ast_mask_lite.add_unit(
                units,
                seen,
                make_ts_unit(
                    node=node,
                    source_bytes=source_bytes,
                    mask_level="block",
                    role=role,
                    source="tmpl_mbedtls.c.tree_sitter.function_definition",
                    reason="Function definition identified by tree-sitter C parser.",
                    priority="high" if name == "main" else "medium",
                    function_ranges=functions,
                    extra={"function": name},
                ),
            )
            continue

        if node.type == "call_expression":
            called = extract_called_function(node, source_bytes)
            statement = nearest_statement_node(node)
            statement_code = clean_code(node_text(statement, source_bytes))
            if called in trigger_apis:
                role = "trigger_call"
                unit_code = statement_code
            else:
                role = ast_mask_lite.infer_role(code, source_api, helper_names, trigger_apis)
                unit_code = code
            ast_mask_lite.add_unit(
                units,
                seen,
                make_ts_unit(
                    node=node,
                    source_bytes=source_bytes,
                    mask_level="function_call",
                    role=role,
                    source="tmpl_mbedtls.c.tree_sitter.call_expression",
                    reason=f"Function call '{called}' identified by tree-sitter C parser.",
                    priority="high" if role == "trigger_call" else "medium",
                    function_ranges=functions,
                    called_function=called,
                    code_override=unit_code,
                    extra={"call_node_code": code},
                ),
            )
            continue

        if node.type in STATEMENT_NODE_TYPES:
            placeholders = placeholder_dependencies(code)
            role = ast_mask_lite.infer_role(code, source_api, helper_names, trigger_apis)
            if node.type == "declaration" and not placeholders:
                continue
            if role == "trigger_call" and node.type != "expression_statement":
                continue
            should_keep = bool(placeholders) or role in {"oracle", "cleanup", "trigger_call"}
            if should_keep:
                ast_mask_lite.add_unit(
                    units,
                    seen,
                    make_ts_unit(
                        node=node,
                        source_bytes=source_bytes,
                        mask_level="statement",
                        role=role,
                        source="tmpl_mbedtls.c.tree_sitter.statement",
                        reason="Statement selected by tree-sitter role and placeholder analysis.",
                        priority="high" if role in {"oracle", "trigger_call"} else "medium",
                        function_ranges=functions,
                    ),
                )
            continue

        if node.type in PREPROCESSOR_NODE_TYPES and placeholder_dependencies(code):
            ast_mask_lite.add_unit(
                units,
                seen,
                make_ts_unit(
                    node=node,
                    source_bytes=source_bytes,
                    mask_level="value",
                    role="mutation_point",
                    source="tmpl_mbedtls.c.tree_sitter.preprocessor",
                    reason="Preprocessor node contains template placeholder.",
                    priority="high",
                    function_ranges=functions,
                ),
            )

    ast_mask_lite.add_unit_ids(units)
    return units


def build_report(template_dir: Path, parser: Any) -> Dict[str, Any]:
    meta = ast_mask_lite.load_yaml(template_dir / "template_meta.yaml")
    mask_report = ast_mask_lite.load_yaml(template_dir / "mask_report.yaml")
    c_text = ast_mask_lite.read_text(template_dir / "tmpl_mbedtls.c")
    source_bytes = c_text.encode("utf-8")
    tree = parser.parse(source_bytes)

    source_api_obj = meta.get("source_api", {}) if isinstance(meta.get("source_api"), dict) else {}
    source_api = (
        mask_report.get("source_api")
        or source_api_obj.get("function")
        or meta.get("poc_source", {}).get("api")
        or ""
    )
    source_library = (
        mask_report.get("source_library")
        or source_api_obj.get("library")
        or meta.get("poc_source", {}).get("library")
        or ""
    )
    trigger_apis = ast_mask_lite.collect_trigger_apis(meta, mask_report)
    if source_api and source_api not in trigger_apis:
        trigger_apis.insert(0, source_api)

    units = collect_units_from_tree(tree.root_node, source_bytes, source_api, trigger_apis)
    return {
        "template_id": mask_report.get("template_id") or meta.get("template_id", ""),
        "template_name": mask_report.get("template_name") or meta.get("template_name", ""),
        "source_api": source_api,
        "source_library": source_library,
        "trigger_apis": trigger_apis,
        "harness_family": str(mask_report.get("harness_family") or meta.get("harness_family") or ""),
        "summary": {
            "method": "tree_sitter_c_role_aware",
            "backend": "tree-sitter",
            "template_dir": str(template_dir),
            "unit_count": len(units),
            "parse_has_error": bool(getattr(tree.root_node, "has_error", False)),
            "note": (
                "Tree-sitter C report generated from concrete syntax nodes. "
                "This backend is optional and is intended to complement AST-lite."
            ),
        },
        "ast_mask_units": units,
        "role_summary": dict(sorted(Counter(str(u.get("role", "")) for u in units).items())),
        "mask_level_summary": dict(sorted(Counter(str(u.get("mask_level", "")) for u in units).items())),
    }


def run(root: Path, output_name: str) -> int:
    if not root.exists():
        raise FileNotFoundError(f"root not found: {root}")

    parser, _language = load_tree_sitter_c()
    count = 0

    for template_dir in ast_mask_lite.find_template_dirs(root):
        report = build_report(template_dir, parser)
        out_path = template_dir / output_name
        ast_mask_lite.dump_yaml(out_path, report)
        print(f"[OK] wrote {out_path} units={len(report.get('ast_mask_units', []))}")
        count += 1

    print("=" * 80)
    print("[SUMMARY] backend: tree-sitter")
    print(f"[SUMMARY] template dirs scanned: {count}")
    print(f"[SUMMARY] root: {root}")
    return count
