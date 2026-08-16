"""Source-level caller discovery for low-level crypto API candidates.

This v2 discovery path searches a local source workspace directly.  It is
read-only: no source modification, builds, tests, package installs, network
access, or unknown project commands are performed.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from caller_audit.io_utils import load_yaml, write_yaml


RESULT_SCHEMA = "cipherlens_source_caller_discovery_v1"
CONTEXT_PACK_SCHEMA = "cipherlens_candidate_context_pack_v1"
GENERATED_BY = "caller_audit.source_caller_discovery"
DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schemas" / "caller_discovery_source_v1.yaml"

SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".m",
    ".mm",
    ".go",
    ".rs",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "build-debug",
    "build-release",
    "cmake-build-debug",
    "cmake-build-release",
    "node_modules",
    "vendor",
    "third_party",
    "artifacts",
    "generated_templates",
    "rendered_cases",
    "runner/results",
}
LOW_PATH_MARKERS = (
    "/test/",
    "/tests/",
    "/example/",
    "/examples/",
    "/benchmark/",
    "/benchmarks/",
    "/fuzz/",
    "/demo/",
    "/demos/",
)
HIGH_TERMS = (
    "authentication",
    "authenticate",
    "certificate",
    "x509",
    "signature verification",
    "verify",
    "x509_verify",
    "rsa_verify",
    "public key",
    "public-key",
    "publickey",
    "private key",
    "private-key",
    "key parsing",
    "key loading",
    "key management",
    "credential",
    "handshake",
    "protocol",
    "tls",
    "ssh",
    "vpn",
    "dkim",
    "mls",
)
MEDIUM_TERMS = (
    "parse",
    "parser",
    "spki",
    "der",
    "pem",
    "pkcs8",
    "pkcs#8",
    "privatekeyinfo",
    "openssl",
    "evp_pkey",
    "asn1",
)
CONTROL_NAMES = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "sizeof",
}
RELEVANCE_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class SearchHit:
    path: Path
    line: int
    text: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _append_unique(items: list[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in items:
        items.append(text)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _source_file(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_SUFFIXES


def _api_occurs_exact(line: str, api: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(api)}(?![A-Za-z0-9_])", line) is not None


def _api_call_occurs(line: str, api: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "/*", "*", "//")):
        return False
    match = re.search(rf"(?<![A-Za-z0-9_]){re.escape(api)}\s*\(", stripped)
    if match is None:
        return False
    before = stripped[: match.start()].strip()
    if not before:
        return True
    if "=" in before or before.endswith(("return", "(", ",")):
        return True
    return False


def _skip_path(path: Path) -> bool:
    parts = set(path.parts)
    if parts & SKIP_DIRS:
        return True
    return any(part.startswith(("install-", "build-")) for part in path.parts)


def _display_repo_name(path: Path) -> str:
    config = path / ".git" / "config"
    if config.is_file():
        text = _read_text(config)
        match = re.search(r"url\s*=\s*(.+)", text)
        if match:
            url = match.group(1).strip().rstrip("/")
            if url.endswith(".git"):
                url = url[:-4]
            if "/" in url:
                return url.rsplit("/", 1)[-1]
    return path.name


def _display_symbol(symbol: str) -> str:
    parts = [part for part in str(symbol or "").split("::") if part]
    if len(parts) > 3:
        return "::".join(parts[-3:])
    return "::".join(parts) if parts else "<unknown>"


def _repository_for_path(workspace: Path, file_path: Path) -> Path:
    workspace = workspace.resolve()
    file_path = file_path.resolve()
    if (workspace / ".git").exists():
        return workspace
    try:
        relative = file_path.relative_to(workspace)
    except ValueError:
        return workspace
    if len(relative.parts) <= 1:
        return workspace
    first_child = workspace / relative.parts[0]
    if first_child.is_dir():
        return first_child
    return workspace


def _run_rg(workspace: Path, api: str) -> list[SearchHit] | None:
    if shutil.which("rg") is None:
        return None
    command = [
        "rg",
        "--line-number",
        "--no-heading",
        "--fixed-strings",
        "--glob",
        "!**/.git/**",
        "--glob",
        "!**/build*/**",
        "--glob",
        "!**/node_modules/**",
        api,
        str(workspace),
    ]
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in (0, 1):
        return None
    hits: list[SearchHit] = []
    for line in completed.stdout.splitlines():
        path_text, sep, rest = line.partition(":")
        if not sep:
            continue
        line_text, sep, text = rest.partition(":")
        if not sep or not line_text.isdigit():
            continue
        path = Path(path_text)
        if not _source_file(path) or _skip_path(path):
            continue
        if not _api_call_occurs(text, api):
            continue
        hits.append(SearchHit(path.resolve(), int(line_text), text.strip()))
    return hits


def _fallback_search(workspace: Path, api: str) -> list[SearchHit]:
    hits: list[SearchHit] = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or not _source_file(path) or _skip_path(path):
            continue
        try:
            lines = _read_text(path).splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines, start=1):
            if _api_call_occurs(line, api):
                hits.append(SearchHit(path.resolve(), index, line.strip()))
    return hits


def search_api_usages(workspace: Path, api: str) -> list[SearchHit]:
    hits = _run_rg(workspace, api)
    if hits is None:
        hits = _fallback_search(workspace, api)
    return sorted(hits, key=lambda hit: (str(hit.path), hit.line))


def _brace_delta(line: str) -> int:
    stripped = re.sub(r"//.*", "", line)
    stripped = re.sub(r'".*?"', '""', stripped)
    return stripped.count("{") - stripped.count("}")


def _context_stack(lines: list[str], call_line: int) -> list[str]:
    stack: list[tuple[str, int]] = []
    depth = 0
    pending: str | None = None
    for index, line in enumerate(lines[: max(call_line - 1, 0)], start=1):
        stripped = line.strip()
        match = re.search(r"\b(?:namespace|class|struct)\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)", stripped)
        if match and "{" in stripped:
            stack.append((match.group(1), depth + stripped.count("{")))
            pending = None
        elif match and not stripped.endswith(";"):
            pending = match.group(1)
        elif pending and "{" in stripped:
            stack.append((pending, depth + stripped.count("{")))
            pending = None
        depth += _brace_delta(line)
        stack = [(name, start_depth) for name, start_depth in stack if depth >= start_depth]
    return [name for name, _ in stack]


def _function_name_from_signature(signature: str) -> str:
    signature = re.sub(r"//.*", "", signature)
    signature = re.sub(r"\s+", " ", signature).strip()
    matches = list(re.finditer(r"([~A-Za-z_]\w*(?:::[~A-Za-z_]\w*)*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:->\s*[^{]+)?\{?", signature))
    for match in reversed(matches):
        name = match.group(1)
        leaf = name.rsplit("::", 1)[-1].lstrip("~")
        if leaf not in CONTROL_NAMES:
            return name
    return ""


def _nearest_function(lines: list[str], call_line: int) -> str:
    window_start = max(0, call_line - 80)
    prefix_lines = lines[window_start:call_line]
    collected: list[str] = []
    for line in reversed(prefix_lines):
        collected.insert(0, line.strip())
        signature = " ".join(collected)
        name = _function_name_from_signature(signature)
        if name and "{" in signature:
            return name
        if ";" in line and "{" not in signature:
            collected = []
    return ""


def extract_symbol(path: Path, call_line: int) -> str:
    lines = _read_text(path).splitlines()
    stack = _context_stack(lines, call_line)
    function = _nearest_function(lines, call_line)
    if not function:
        return "<unknown>"
    if "::" in function:
        prefix = [name for name in stack if not function.startswith(f"{name}::")]
        if prefix and prefix[-1].split("::")[-1] not in function.split("::"):
            return _display_symbol("::".join(prefix + [function]))
        return _display_symbol(function)
    class_stack = [name for name in stack if name and name != function]
    if class_stack:
        return _display_symbol("::".join(class_stack + [function]))
    return _display_symbol(function)


def _context_excerpt(lines: list[str], line: int, radius: int = 8) -> list[str]:
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return [f"{idx}: {lines[idx - 1].rstrip()}" for idx in range(start, end + 1)]


def _relevance(path: Path, symbol: str, context_text: str) -> tuple[str, str]:
    rel_path = "/" + str(path).replace("\\", "/").lower()
    haystack = f"{rel_path}\n{symbol}\n{context_text}".lower()
    low_context = any(marker in rel_path for marker in LOW_PATH_MARKERS)
    high_hits = [term for term in HIGH_TERMS if term in haystack]
    medium_hits = [term for term in MEDIUM_TERMS if term in haystack]
    if high_hits and not low_context:
        return (
            "high",
            "Source context is security-relevant: "
            + ", ".join(high_hits[:5])
            + ".",
        )
    if high_hits or medium_hits:
        return (
            "medium" if low_context else "medium",
            "Source context shows crypto/API parsing usage"
            + (", but path appears to be test/example/benchmark code." if low_context else "."),
        )
    return (
        "low",
        "API call was found, but the local context does not show authentication, certificate, signature, key, or protocol usage.",
    )


def _caller_key(item: dict[str, Any]) -> tuple[str, str, str]:
    repository = item.get("repository") or {}
    return (
        str(repository.get("path") or ""),
        str(item.get("file") or ""),
        str(item.get("symbol") or ""),
    )


def _merge_callers(callers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for caller in callers:
        key = _caller_key(caller)
        if key not in merged:
            merged[key] = caller
            continue
        existing = merged[key]
        for item in caller.get("evidence") or []:
            _append_unique(existing["evidence"], item)
        if RELEVANCE_RANK[caller["relevance"]] < RELEVANCE_RANK[existing["relevance"]]:
            existing["relevance"] = caller["relevance"]
            existing["reason"] = caller["reason"]
    return sorted(
        merged.values(),
        key=lambda item: (
            RELEVANCE_RANK.get(str(item.get("relevance")), 9),
            item["repository"]["name"],
            item["file"],
            item["symbol"],
        ),
    )


def discover_source_callers(context_pack: dict[str, Any], workspace: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise ValueError(f"workspace is not a directory: {workspace}")
    api = str(context_pack.get("api_or_function") or "").strip()
    if not api:
        raise ValueError("context pack api_or_function is required")

    callers: list[dict[str, Any]] = []
    hits = search_api_usages(workspace, api)
    for hit in hits:
        lines = _read_text(hit.path).splitlines()
        repo_path = _repository_for_path(workspace, hit.path)
        try:
            file_relative = str(hit.path.relative_to(repo_path))
        except ValueError:
            file_relative = str(hit.path)
        symbol = extract_symbol(hit.path, hit.line)
        excerpt = _context_excerpt(lines, hit.line)
        context_text = "\n".join(excerpt)
        relevance, reason = _relevance(hit.path, symbol, context_text)
        evidence = [
            f"{hit.path}:{hit.line}: {hit.text}",
            f"{hit.path}:{hit.line}: inferred_symbol={symbol}",
        ]
        evidence.extend(f"{hit.path}:context:{line}" for line in excerpt)
        callers.append(
            {
                "repository": {
                    "name": _display_repo_name(repo_path),
                    "path": str(repo_path),
                },
                "file": file_relative,
                "symbol": symbol,
                "api_usage": f"{api} at {file_relative}:{hit.line}",
                "evidence": evidence,
                "relevance": relevance,
                "reason": reason,
            }
        )

    discovered = _merge_callers(callers)
    unknowns: list[str] = []
    if not discovered:
        unknowns.append("No source-level caller found for this candidate API in the searched workspace.")

    return {
        "schema": RESULT_SCHEMA,
        "candidate_id": context_pack["candidate_id"],
        "searched_workspace": str(workspace),
        "generated_by": GENERATED_BY,
        "timestamp": _utc_now(),
        "source_context_pack": {
            "schema": context_pack.get("schema"),
        },
        "discovered_callers": discovered,
        "unknowns": unknowns,
        "claim_policy": {
            "vulnerability": "not_assessed",
            "security_impact": "not_assessed",
        },
    }


def validate_context_pack(context_pack: dict[str, Any], schema: dict[str, Any]) -> None:
    expected = str(schema.get("context_pack_schema") or CONTEXT_PACK_SCHEMA)
    if context_pack.get("schema") != expected:
        raise ValueError(
            f"unsupported context pack schema: expected {expected}, got {context_pack.get('schema', 'missing')}"
        )
    missing = [
        str(field)
        for field in schema.get("required_context_fields") or []
        if not str(context_pack.get(str(field)) or "").strip()
    ]
    if missing:
        raise ValueError(f"context pack missing required fields: {', '.join(missing)}")


def validate_result(result: dict[str, Any], context_pack: dict[str, Any], schema: dict[str, Any]) -> None:
    required = [str(field) for field in schema.get("required_result_fields") or []]
    missing = [field for field in required if field not in result]
    if missing:
        raise ValueError(f"source discovery result missing required fields: {', '.join(missing)}")
    if result["schema"] != str(schema.get("artifact_schema") or RESULT_SCHEMA):
        raise ValueError(f"unsupported source discovery schema: {result['schema']}")
    if result["candidate_id"] != context_pack["candidate_id"]:
        raise ValueError("source discovery candidate_id does not match context pack")
    allowed = {str(item) for item in schema.get("allowed_relevance") or []}
    if not isinstance(result.get("discovered_callers"), list):
        raise ValueError("discovered_callers must be a list")
    for index, caller in enumerate(result["discovered_callers"]):
        if not isinstance(caller, dict):
            raise ValueError(f"discovered_callers[{index}] must be a mapping")
        repository = caller.get("repository")
        if not isinstance(repository, dict):
            raise ValueError(f"discovered_callers[{index}].repository must be a mapping")
        for field in ("name", "path"):
            if not isinstance(repository.get(field), str) or not repository[field].strip():
                raise ValueError(f"discovered_callers[{index}].repository.{field} must be string")
        for field in ("file", "symbol", "api_usage", "reason"):
            if not isinstance(caller.get(field), str) or not caller[field].strip():
                raise ValueError(f"discovered_callers[{index}].{field} must be string")
        if not isinstance(caller.get("evidence"), list) or not caller["evidence"]:
            raise ValueError(f"discovered_callers[{index}].evidence must be a non-empty list")
        if allowed and caller.get("relevance") not in allowed:
            raise ValueError(f"unsupported caller relevance: {caller.get('relevance')}")
    claim_policy = result.get("claim_policy")
    if not isinstance(claim_policy, dict):
        raise ValueError("claim_policy must be a mapping")
    if claim_policy.get("vulnerability") != "not_assessed":
        raise ValueError("claim_policy.vulnerability must be not_assessed")
    if claim_policy.get("security_impact") != "not_assessed":
        raise ValueError("claim_policy.security_impact must be not_assessed")


def run_source_caller_discovery(
    context_pack_path: Path,
    workspace: Path,
    output_path: Path,
    *,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
) -> dict[str, Any]:
    context_pack_path = context_pack_path.expanduser().resolve()
    schema_path = schema_path.resolve()
    context_pack = load_yaml(context_pack_path)
    schema = load_yaml(schema_path)
    validate_context_pack(context_pack, schema)
    result = discover_source_callers(context_pack, workspace)
    result["source_context_pack"] = {
        "path": str(context_pack_path),
        "schema": context_pack["schema"],
        "candidate_id": context_pack["candidate_id"],
        "sha256": _sha256(context_pack_path),
    }
    validate_result(result, context_pack, schema)
    write_yaml(output_path, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Caller Discovery v2 source-level scan over a local workspace."
    )
    parser.add_argument("--context-pack", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    result = run_source_caller_discovery(args.context_pack, args.workspace, args.out)
    print(f"[OK] Source Caller Discovery: {args.out}")
    print(f"[WORKSPACE] {result['searched_workspace']}")
    print(f"[DISCOVERED_CALLERS] {len(result['discovered_callers'])}")
    for caller in result["discovered_callers"]:
        print(
            f"[CALLER] {caller['repository']['name']} {caller['symbol']} "
            f"relevance={caller['relevance']} file={caller['file']}"
        )


if __name__ == "__main__":
    main()
