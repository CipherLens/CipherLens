"""Discover local downstream callers for one low-level crypto API candidate.

Caller Discovery is intentionally separate from the ImpactLift v1 stages.  This
runner discovers candidate repositories, call symbols, and traceable evidence; it
does not assign vulnerability, exploitability, security-impact, or CVE claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from caller_audit.external_caller_discovery import (
    CallerDiscoveryProvider,
    ExternalCodeHit,
    GitHubSourceProvider,
)
from caller_audit.impact_runner import _field_type_name, _provider_provenance
from caller_audit.io_utils import load_yaml, write_yaml
from utils.agent_provider import AgentProvider
from utils.codex_agent_provider import CodexAgentProvider, build_result_json_schema


RESULT_SCHEMA = "cipherlens_caller_discovery_v1"
CONTEXT_PACK_SCHEMA = "cipherlens_candidate_context_pack_v1"
GENERATED_BY = "caller_audit.caller_discovery_runner"
DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schemas" / "caller_discovery_v1.yaml"
DEFAULT_PROMPT_PATH = Path(__file__).parent / "prompts" / "caller_discovery_v1.md"
DEFAULT_EVIDENCE_ROOTS = (
    Path("caller_audit"),
    Path("artifacts/caller_audit"),
    Path("knowledge_raw"),
    Path("knowledge_base/api_cards"),
)
DEFAULT_WORKSPACE_SEARCH_ROOTS = (
    Path("caller_audit"),
    Path("knowledge_raw"),
    Path("knowledge_base"),
)

CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
LOCAL_SOURCE_SUFFIXES = {
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
    ".py",
    ".lua",
    ".rb",
    ".java",
    ".js",
    ".ts",
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".jsonl",
}
SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "cmake-build-debug",
    "node_modules",
}

TYPE_CHECKS = {
    "string": lambda value: isinstance(value, str),
    "array": lambda value: isinstance(value, list),
    "list": lambda value: isinstance(value, list),
    "object": lambda value: isinstance(value, dict),
    "mapping": lambda value: isinstance(value, dict),
}

RELEVANCE_RANK = {"high": 0, "medium": 1, "low": 2}
HIGH_RELEVANCE_TERMS = (
    "authentication",
    "certificate validation",
    "signature verification",
    "signature verifies",
    "x509_verify",
    "x509credential",
    "dkim",
    "credential",
    "public-key",
    "public key",
    "protocol",
    "handshake",
    "mls",
)
MEDIUM_RELEVANCE_TERMS = (
    "certificate",
    "x509",
    "key parsing",
    "publickey",
    "parsedcertificate",
    "parse",
    "spki",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _as_string_list(value: Any) -> list[str]:
    items: list[str] = []
    for item in _as_list(value):
        text = _as_text(item)
        if text and text not in items:
            items.append(text)
    return items


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "candidate"


def normalize_candidate_description(raw: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Accept a new candidate description or a legacy Candidate Context Pack."""
    if not isinstance(raw, dict):
        raise ValueError("candidate input must be a mapping")

    if isinstance(raw.get("candidate"), dict):
        source = raw["candidate"]
        library = _as_text(source.get("library") or raw.get("library"))
        apis = _as_string_list(source.get("api") or source.get("apis") or raw.get("api"))
        family = _as_text(source.get("family") or raw.get("family"))
        behavior = _as_string_list(source.get("behavior") or raw.get("behavior"))
        evidence = _as_string_list(source.get("evidence") or raw.get("evidence"))
        candidate_id = _as_text(raw.get("candidate_id") or source.get("candidate_id"))
    elif raw.get("schema") == CONTEXT_PACK_SCHEMA:
        library = _as_text(raw.get("library"))
        apis = _as_string_list(raw.get("api_or_function"))
        family = _as_text(raw.get("semantic_type"))
        behavior = _as_string_list(raw.get("trigger_condition"))
        evidence = []
        for field in ("evidence", "oracle_evidence", "source_artifacts"):
            for item in _as_list(raw.get(field)):
                if isinstance(item, dict):
                    evidence.append(json.dumps(item, sort_keys=True))
                else:
                    text = _as_text(item)
                    if text:
                        evidence.append(text)
        candidate_id = _as_text(raw.get("candidate_id"))
    else:
        library = _as_text(raw.get("library"))
        apis = _as_string_list(raw.get("api") or raw.get("api_or_function"))
        family = _as_text(raw.get("family") or raw.get("semantic_type"))
        behavior = _as_string_list(raw.get("behavior") or raw.get("trigger_condition"))
        evidence = _as_string_list(raw.get("evidence"))
        candidate_id = _as_text(raw.get("candidate_id"))

    if not candidate_id:
        candidate_id = _slugify("-".join([library, "-".join(apis), family]))

    candidate = {
        "library": library,
        "api": apis,
        "family": family,
        "behavior": behavior,
        "evidence": evidence,
    }
    return candidate_id, candidate


def _norm_api(value: Any) -> str:
    return str(value or "").strip().lower()


def _api_matches(value: Any, api: str) -> bool:
    return _norm_api(value) == _norm_api(api)


def _display_repo_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    if "/" in text:
        return text.rsplit("/", 1)[-1]
    return text


def _display_symbol(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\(.*", "", text).strip()
    parts = [part for part in text.split("::") if part]
    if len(parts) > 3:
        return "::".join(parts[-3:])
    return text


def _append_unique(items: list[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in items:
        items.append(text)


def _append_unique_mapping(items: list[dict[str, Any]], value: dict[str, Any]) -> None:
    key = json.dumps(value, sort_keys=True)
    existing = {json.dumps(item, sort_keys=True) for item in items}
    if key not in existing:
        items.append(value)


def _claim_policy() -> dict[str, Any]:
    return {
        "caller_discovery_only": True,
        "vulnerability": "not_assessed",
        "security_impact": "not_assessed",
    }


def _candidate_api_text(candidate: dict[str, Any]) -> str:
    return ", ".join(_as_string_list(candidate.get("api")))


def build_discovery_search_queries(candidate: dict[str, Any]) -> list[str]:
    """Build repository-search queries from API semantics, without caller hints."""
    apis = _as_string_list(candidate.get("api"))
    if not apis:
        raise ValueError("candidate api is required")

    queries: list[str] = []
    for api in apis:
        _append_unique(queries, f'"{api}("')
        _append_unique(queries, api)

    if len(apis) > 1:
        _append_unique(queries, " ".join(f'"{api}"' for api in apis))
        _append_unique(queries, " ".join(f'"{api}("' for api in apis))

    family = _as_text(candidate.get("family")).lower()
    behavior = " ".join(_as_string_list(candidate.get("behavior"))).lower()
    joined_api = " ".join(f'"{api}"' for api in apis)
    if "mac" in family or "mac" in behavior or any(api.startswith("EVP_MAC_") for api in apis):
        _append_unique(queries, f"{joined_api} CMAC")
        _append_unique(queries, f'{joined_api} "EVP_MAC_CTX"')
        _append_unique(queries, f"{joined_api} final update")

    return queries


def _caller_key(caller: dict[str, Any]) -> tuple[str, str, str]:
    repo = caller.get("repository") or {}
    return (
        str(repo.get("name") or "").lower(),
        str(caller.get("symbol") or "").lower(),
        "",
    )


def _relevance(symbol: str, evidence: list[str], context: dict[str, Any]) -> tuple[str, str]:
    haystack = " ".join(
        [
            symbol,
            json.dumps(evidence, ensure_ascii=False, sort_keys=True),
            json.dumps(context, ensure_ascii=False, sort_keys=True),
        ]
    ).lower()
    high_hits = [term for term in HIGH_RELEVANCE_TERMS if term in haystack]
    if high_hits:
        return (
            "high",
            "Security-relevant caller discovery: local evidence mentions "
            + ", ".join(high_hits[:4])
            + ".",
        )
    medium_hits = [term for term in MEDIUM_RELEVANCE_TERMS if term in haystack]
    if medium_hits:
        return (
            "medium",
            "Crypto parsing caller discovery: local evidence mentions "
            + ", ".join(medium_hits[:4])
            + ".",
        )
    return (
        "low",
        "Local evidence shows API usage, but no strong authentication, certificate, signature, key, or protocol context was found.",
    )


def _make_caller(
    *,
    repository_name: Any,
    repository_path: Any,
    symbol: Any,
    api_usage: str,
    evidence: Iterable[Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    evidence_list: list[str] = []
    for item in evidence:
        _append_unique(evidence_list, item)
    display_symbol = _display_symbol(symbol)
    relevance, reason = _relevance(display_symbol, evidence_list, context)
    return {
        "repository": {
            "name": _display_repo_name(repository_name),
            "path": str(repository_path or "").strip(),
        },
        "symbol": display_symbol,
        "api_usage": api_usage,
        "evidence": evidence_list,
        "relevance": relevance,
        "reason": reason,
    }


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
            item["symbol"],
        ),
    )


def _candidate_from_config(path: Path, data: dict[str, Any], api: str) -> dict[str, Any] | None:
    candidate = data.get("candidate")
    project = data.get("project")
    if not isinstance(candidate, dict) or not isinstance(project, dict):
        return None
    if not _api_matches(candidate.get("target_api"), api):
        return None
    context = {
        "candidate": candidate,
        "reachability": data.get("reachability") or {},
    }
    evidence = [
        f"{path}: candidate.target_api={candidate.get('target_api')}",
        f"{path}: candidate.component={candidate.get('component')}",
        f"{path}: project.name={project.get('name')}",
    ]
    for note in _as_list((data.get("reachability") or {}).get("notes")):
        _append_unique(evidence, f"{path}: reachability.note={str(note).strip()}")
    return _make_caller(
        repository_name=project.get("name") or project.get("repository_url"),
        repository_path=project.get("repo_path") or "",
        symbol=candidate.get("component") or "",
        api_usage=f"{candidate.get('target_api')} in {candidate.get('component')}",
        evidence=evidence,
        context=context,
    )


def _candidate_from_triage(path: Path, data: dict[str, Any], api: str) -> dict[str, Any] | None:
    candidate = data.get("candidate")
    project = data.get("project")
    repository = data.get("repository")
    if not isinstance(candidate, dict) or not _api_matches(candidate.get("target_api"), api):
        return None
    if not isinstance(project, dict):
        project = {}
    if not isinstance(repository, dict):
        repository = {}
    evidence = [
        f"{path}: candidate.target_api={candidate.get('target_api')}",
        f"{path}: candidate.component={candidate.get('component')}",
    ]
    static_checks = data.get("static_checks") or {}
    for item in _as_list(static_checks.get("items")):
        if isinstance(item, dict):
            location = f"{item.get('path')}:{item.get('line')}"
            _append_unique(
                evidence,
                f"{path}: call_site={location}, classification={item.get('classification')}, full_consumption_check_found={item.get('full_consumption_check_found')}",
            )
    for note in _as_list((data.get("reachability") or {}).get("notes")):
        _append_unique(evidence, f"{path}: reachability.note={str(note).strip()}")
    return _make_caller(
        repository_name=project.get("name") or repository.get("remote_origin"),
        repository_path=repository.get("repository_root") or project.get("repo_path") or "",
        symbol=candidate.get("component") or "",
        api_usage=f"{candidate.get('target_api')} in {candidate.get('component')}",
        evidence=evidence,
        context=data,
    )


def _candidate_from_shortlist(path: Path, data: dict[str, Any], api: str) -> list[dict[str, Any]]:
    scope = data.get("scope") if isinstance(data.get("scope"), dict) else {}
    callers: list[dict[str, Any]] = []
    for item in _as_list(data.get("candidates")):
        if not isinstance(item, dict):
            continue
        callsite = item.get("exact_callsite")
        if not isinstance(callsite, dict) or not _api_matches(callsite.get("parser_api"), api):
            continue
        evidence = [
            f"{path}: candidates[].exact_callsite.parser_api={callsite.get('parser_api')}",
            f"{path}: candidates[].exact_callsite.file={callsite.get('file')}:{callsite.get('line')}",
            f"{path}: candidates[].exact_callsite.function={callsite.get('function')}",
            f"{path}: static_quality_classification={item.get('static_quality_classification')}",
        ]
        full = item.get("full_consumption")
        if isinstance(full, dict):
            _append_unique(
                evidence,
                f"{path}: full_consumption.checked={full.get('checked')}, status={full.get('status')}",
            )
        flow = ((item.get("complete_data_flow") or {}).get("steps") or [])
        for step in flow[:4]:
            _append_unique(evidence, f"{path}: data_flow={step}")
        callers.append(
            _make_caller(
                repository_name=item.get("repository") or scope.get("repository"),
                repository_path=scope.get("local_repository") or "",
                symbol=callsite.get("function") or "",
                api_usage=f"{callsite.get('parser_api')} at {callsite.get('file')}:{callsite.get('line')}",
                evidence=evidence,
                context=item,
            )
        )
    return callers


def _candidate_from_callsite_jsonl(path: Path, api: str) -> list[dict[str, Any]]:
    callers: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or not _api_matches(row.get("parser_api"), api):
                continue
            evidence = [
                f"{path}:{line_no}: parser_api={row.get('parser_api')}",
                f"{path}:{line_no}: callsite={row.get('file')}:{row.get('line')}",
                f"{path}:{line_no}: function={row.get('function')}",
            ]
            for sink in _as_list(row.get("parsed_certificate_sink"))[:4]:
                _append_unique(evidence, f"{path}:{line_no}: parsed_sink={sink}")
            prod_path = row.get("production_path")
            if isinstance(prod_path, dict):
                for step in _as_list(prod_path.get("flow"))[:4]:
                    _append_unique(evidence, f"{path}:{line_no}: production_flow={step}")
            callers.append(
                _make_caller(
                    repository_name=row.get("repository"),
                    repository_path=row.get("local_repository") or "",
                    symbol=row.get("function") or "",
                    api_usage=f"{row.get('parser_api')} at {row.get('file')}:{row.get('line')}",
                    evidence=evidence,
                    context=row,
                )
            )
    return callers


def _api_evidence(roots: Iterable[Path], library: str, api: str) -> list[str]:
    evidence: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        candidates = [
            root / str(library).lower() / f"{api}.yaml",
            root / str(library).lower() / "3.5.5" / f"{api}.md",
            root / str(library).lower() / "3.5.5" / f"{api}.yaml",
        ]
        for path in candidates:
            if path.is_file():
                _append_unique(evidence, f"{path}: local API evidence for {library} {api}")
    return evidence


def _confidence_from_text(value: Any) -> str:
    text = _as_text(value)
    if text in CONFIDENCE_RANK:
        return text
    if text in RELEVANCE_RANK:
        return text
    return "unknown"


def _repo_url_from_path(path: str) -> str:
    text = _as_text(path)
    if text.startswith(("http://", "https://", "git@")):
        return text
    return ""


def _source_file_allowed(path: Path) -> bool:
    if path.suffix.lower() not in LOCAL_SOURCE_SUFFIXES:
        return False
    return not any(part in SKIP_DIR_NAMES for part in path.parts)


def _read_text_preview(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _infer_symbol_from_text(text: str, line_index: int, fallback: str) -> str:
    start = max(0, line_index - 80)
    prefix = "\n".join(text.splitlines()[start : line_index + 1])
    patterns = [
        r"([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\([^;{}]*\)\s*(?:const\s*)?\{",
        r"def\s+([A-Za-z_]\w*)\s*\(",
        r"function\s+([A-Za-z_]\w*)\s*\(",
    ]
    for pattern in patterns:
        matches = list(re.finditer(pattern, prefix))
        if matches:
            return _display_symbol(matches[-1].group(1))
    return fallback


def _matched_apis(line: str, apis: list[str]) -> str:
    matched = [api for api in apis if api in line]
    return ", ".join(matched)


def discover_callers_from_workspace(
    candidate: dict[str, Any],
    roots: Iterable[Path],
) -> dict[str, Any]:
    """Search local workspace files for direct candidate API usage."""
    apis = _as_string_list(candidate.get("api"))
    queries = build_discovery_search_queries(candidate)
    repositories: list[dict[str, Any]] = []
    call_sites: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    for root in roots:
        resolved = Path(root).expanduser().resolve()
        if not resolved.exists():
            continue
        search_files = [resolved] if resolved.is_file() else sorted(resolved.rglob("*"))
        for path in search_files:
            if not path.is_file() or not _source_file_allowed(path):
                continue
            text = _read_text_preview(path)
            if text is None or not any(api in text for api in apis):
                continue
            lines = text.splitlines()
            for index, line in enumerate(lines, start=1):
                matched_api = _matched_apis(line, apis)
                if not matched_api:
                    continue
                relative_file = str(path)
                symbol = _infer_symbol_from_text(text, index - 1, path.stem)
                repo_name = resolved.name if resolved.is_dir() else path.parent.name
                confidence = "medium" if any(term in relative_file.lower() for term in ("/src/", "/lib/", "/crypto/")) else "low"
                repositories.append(
                    {
                        "name": repo_name,
                        "url": "",
                        "confidence": confidence,
                    }
                )
                call_sites.append(
                    {
                        "repository": repo_name,
                        "file": f"{relative_file}:{index}",
                        "symbol": symbol,
                        "matched_api": matched_api,
                    }
                )
                _append_unique_mapping(
                    evidence,
                    {
                        "source": "local_workspace",
                        "search_query": matched_api,
                        "matched_source": f"{relative_file}:{index}: {line.strip()}",
                    },
                )

    return {
        "candidate": candidate,
        "repositories": _merge_repository_records(repositories),
        "call_sites": _merge_call_sites(call_sites),
        "evidence": evidence,
        "unknowns": [] if call_sites else ["No local workspace call site found for this candidate API."],
        "claim_policy": _claim_policy(),
        "discovered_callers": [],
    }


def _legacy_local_to_payload(
    candidate: dict[str, Any],
    legacy: dict[str, Any],
) -> dict[str, Any]:
    repositories: list[dict[str, Any]] = []
    call_sites: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for caller in legacy.get("discovered_callers") or []:
        repository = caller.get("repository") or {}
        name = _as_text(repository.get("name"))
        path = _as_text(repository.get("path"))
        confidence = _confidence_from_text(caller.get("relevance"))
        repositories.append(
            {
                "name": name,
                "url": _repo_url_from_path(path),
                "confidence": confidence,
            }
        )
        call_sites.append(
            {
                "repository": name,
                "file": path,
                "symbol": _as_text(caller.get("symbol")),
                "matched_api": _candidate_api_text(candidate),
            }
        )
        for item in caller.get("evidence") or []:
            _append_unique_mapping(
                evidence,
                {
                    "source": "local_evidence",
                    "search_query": _candidate_api_text(candidate),
                    "matched_source": _as_text(item),
                },
            )
    for item in legacy.get("evidence") or []:
        _append_unique_mapping(
            evidence,
            {
                "source": "local_evidence",
                "search_query": _candidate_api_text(candidate),
                "matched_source": _as_text(item),
            },
        )
    return {
        "candidate": candidate,
        "repositories": _merge_repository_records(repositories),
        "call_sites": _merge_call_sites(call_sites),
        "evidence": evidence,
        "unknowns": list(legacy.get("unknowns") or []),
        "claim_policy": _claim_policy(),
        "discovered_callers": list(legacy.get("discovered_callers") or []),
    }


def _legacy_context_for_api(
    candidate_id: str,
    candidate: dict[str, Any],
    api: str,
) -> dict[str, Any]:
    return {
        "schema": CONTEXT_PACK_SCHEMA,
        "candidate_id": candidate_id,
        "library": candidate["library"],
        "api_or_function": api,
        "semantic_type": candidate["family"],
        "trigger_condition": "; ".join(_as_string_list(candidate.get("behavior"))) or "caller discovery",
        "evidence": [{"source": "candidate_description", "observation": item} for item in _as_string_list(candidate.get("evidence"))],
    }


def _hit_fragments(hit: ExternalCodeHit) -> str:
    return "\n".join(_as_string_list(list(hit.fragments)))


def _external_symbol(hit: ExternalCodeHit, apis: list[str]) -> str:
    text = _hit_fragments(hit)
    fallback = Path(hit.file_path).stem or "<unknown>"
    first_match_line = 0
    for index, line in enumerate(text.splitlines()):
        if any(api in line for api in apis):
            first_match_line = index
            break
    return _infer_symbol_from_text(text, first_match_line, fallback)


def _external_confidence(hit: ExternalCodeHit, symbol: str) -> str:
    path = f"/{hit.file_path.lower()}"
    haystack = f"{hit.repository_name}\n{hit.file_path}\n{symbol}\n{_hit_fragments(hit)}".lower()
    low_path = any(term in path for term in ("/test/", "/tests/", "/example/", "/examples/", "/doc/", "/docs/", "/fuzz/"))
    security_hit = any(term in haystack for term in HIGH_RELEVANCE_TERMS + MEDIUM_RELEVANCE_TERMS + ("cmac", "mac", "crypto"))
    source_path = any(term in path for term in ("/src/", "/lib/", "/crypto/", "/ext/"))
    if security_hit and source_path and not low_path:
        return "high"
    if security_hit or source_path:
        return "medium"
    return "low"


def discover_callers_from_external_search(
    candidate: dict[str, Any],
    provider: CallerDiscoveryProvider,
    *,
    per_query: int = 10,
) -> dict[str, Any]:
    apis = _as_string_list(candidate.get("api"))
    repositories: list[dict[str, Any]] = []
    call_sites: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    for query in build_discovery_search_queries(candidate):
        for hit in provider.search(query, per_page=per_query):
            fragment_text = _hit_fragments(hit)
            matched_api = ", ".join(api for api in apis if api in fragment_text or api in hit.file_path)
            if not matched_api:
                matched_api = _candidate_api_text(candidate)
            symbol = _external_symbol(hit, apis)
            confidence = _external_confidence(hit, symbol)
            repositories.append(
                {
                    "name": hit.repository_name,
                    "url": hit.repository_url,
                    "confidence": confidence,
                }
            )
            call_sites.append(
                {
                    "repository": hit.repository_name,
                    "file": hit.file_path,
                    "symbol": symbol,
                    "matched_api": matched_api,
                }
            )
            matched_source = hit.file_url or f"{hit.repository_name}:{hit.file_path}"
            if fragment_text:
                matched_source = f"{matched_source}: {fragment_text.splitlines()[0].strip()}"
            _append_unique_mapping(
                evidence,
                {
                    "source": provider.name,
                    "search_query": query,
                    "matched_source": matched_source,
                },
            )

    return {
        "candidate": candidate,
        "repositories": _merge_repository_records(repositories),
        "call_sites": _merge_call_sites(call_sites),
        "evidence": evidence,
        "unknowns": [] if call_sites else ["No external repository candidate found for this API candidate."],
        "claim_policy": _claim_policy(),
        "discovered_callers": [],
    }


def _merge_repository_records(repositories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for repo in repositories:
        name = _as_text(repo.get("name"))
        url = _as_text(repo.get("url"))
        if not name:
            continue
        key = (name.lower(), url.lower())
        confidence = _confidence_from_text(repo.get("confidence"))
        if key not in merged:
            merged[key] = {"name": name, "url": url, "confidence": confidence}
            continue
        existing = merged[key]
        if CONFIDENCE_RANK[confidence] < CONFIDENCE_RANK[existing["confidence"]]:
            existing["confidence"] = confidence
    return sorted(
        merged.values(),
        key=lambda item: (
            CONFIDENCE_RANK.get(item["confidence"], 9),
            item["name"].lower(),
            item["url"].lower(),
        ),
    )


def _merge_call_sites(call_sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for site in call_sites:
        item = {
            "repository": _as_text(site.get("repository")),
            "file": _as_text(site.get("file")),
            "symbol": _as_text(site.get("symbol")) or "<unknown>",
            "matched_api": _as_text(site.get("matched_api")),
        }
        if not item["repository"] or not item["file"] or not item["matched_api"]:
            continue
        key = tuple(item[field].lower() for field in ("repository", "file", "symbol", "matched_api"))
        merged[key] = item
    return sorted(
        merged.values(),
        key=lambda item: (
            item["repository"].lower(),
            item["file"].lower(),
            item["symbol"].lower(),
            item["matched_api"].lower(),
        ),
    )


def _merge_payloads(
    candidate_id: str,
    candidate: dict[str, Any],
    payloads: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    repositories: list[dict[str, Any]] = []
    call_sites: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    discovered_callers: list[dict[str, Any]] = []
    unknowns: list[str] = []
    for payload in payloads:
        repositories.extend(payload.get("repositories") or [])
        call_sites.extend(payload.get("call_sites") or [])
        for item in payload.get("evidence") or []:
            if isinstance(item, dict):
                _append_unique_mapping(evidence, item)
            else:
                _append_unique_mapping(
                    evidence,
                    {
                        "source": "legacy",
                        "search_query": _candidate_api_text(candidate),
                        "matched_source": _as_text(item),
                    },
                )
        for caller in payload.get("discovered_callers") or []:
            if isinstance(caller, dict):
                discovered_callers.append(caller)
        unknowns.extend(_as_string_list(payload.get("unknowns")))

    merged_repositories = _merge_repository_records(repositories)
    merged_call_sites = _merge_call_sites(call_sites)
    if merged_repositories or merged_call_sites:
        unknowns = [
            item for item in unknowns
            if not item.startswith("No local") and not item.startswith("No external")
        ]
    if not merged_repositories and not merged_call_sites and not unknowns:
        unknowns.append("No repository candidate found for this API candidate.")
    return {
        "candidate_id": candidate_id,
        "candidate": candidate,
        "repositories": merged_repositories,
        "call_sites": merged_call_sites,
        "evidence": evidence,
        "unknowns": sorted(set(unknowns)),
        "claim_policy": _claim_policy(),
        "discovered_callers": _merge_callers(discovered_callers),
    }


def discover_candidate_callers(
    candidate_id: str,
    candidate: dict[str, Any],
    *,
    evidence_roots: Iterable[Path],
    workspace_roots: Iterable[Path],
    external_provider: CallerDiscoveryProvider | None = None,
    per_query: int = 10,
) -> dict[str, Any]:
    payloads: list[dict[str, Any]] = []
    legacy_payloads: list[dict[str, Any]] = []
    for api in _as_string_list(candidate.get("api")):
        legacy_context = _legacy_context_for_api(candidate_id, candidate, api)
        legacy = discover_callers_from_local_evidence(legacy_context, evidence_roots)
        legacy_payloads.append(_legacy_local_to_payload(candidate, legacy))
    payloads.extend(legacy_payloads)
    payloads.append(discover_callers_from_workspace(candidate, workspace_roots))
    if external_provider is not None:
        payloads.append(
            discover_callers_from_external_search(
                candidate,
                external_provider,
                per_query=per_query,
            )
        )
    return _merge_payloads(candidate_id, candidate, payloads)


def discover_callers_from_local_evidence(
    context_pack: dict[str, Any],
    evidence_roots: Iterable[Path],
) -> dict[str, Any]:
    api = str(context_pack.get("api_or_function") or "").strip()
    library = str(context_pack.get("library") or "").strip()
    roots = [Path(root).resolve() for root in evidence_roots]
    callers: list[dict[str, Any]] = []
    top_evidence = [
        f"local_evidence_root={root}" for root in roots if root.exists()
    ]
    top_evidence.extend(_api_evidence(roots, library, api))

    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.glob("examples/*.yaml")):
            data = load_yaml(path)
            caller = _candidate_from_config(path, data, api)
            if caller is not None:
                callers.append(caller)
        for path in sorted(root.glob("**/caller_triage.yaml")):
            data = load_yaml(path)
            caller = _candidate_from_triage(path, data, api)
            if caller is not None:
                callers.append(caller)
        for path in sorted(root.glob("**/discovery/candidate_shortlist.yaml")):
            callers.extend(_candidate_from_shortlist(path, load_yaml(path), api))
        for path in sorted(root.glob("**/discovery/callsite_evidence.jsonl")):
            callers.extend(_candidate_from_callsite_jsonl(path, api))

    discovered = _merge_callers(callers)
    unknowns: list[str] = []
    if not discovered:
        unknowns.append("No local downstream caller evidence found for this candidate API.")

    for caller in discovered:
        for item in caller["evidence"]:
            _append_unique(top_evidence, item)

    return {
        "candidate_id": context_pack["candidate_id"],
        "discovered_callers": discovered,
        "unknowns": unknowns,
        "evidence": top_evidence,
        "claim_policy": {
            "vulnerability": "not_assessed",
            "security_impact": "not_assessed",
        },
    }


class LocalEvidenceCallerDiscoveryProvider(AgentProvider):
    """Deterministic v1 provider over existing local caller-audit artifacts."""

    def __init__(
        self,
        evidence_roots: Iterable[Path] | None = None,
        workspace_roots: Iterable[Path] | None = None,
        external_provider: CallerDiscoveryProvider | None = None,
        *,
        per_query: int = 10,
    ) -> None:
        self.evidence_roots = tuple(DEFAULT_EVIDENCE_ROOTS if evidence_roots is None else evidence_roots)
        self.workspace_roots = tuple(DEFAULT_WORKSPACE_SEARCH_ROOTS if workspace_roots is None else workspace_roots)
        self.external_provider = external_provider
        self.per_query = per_query

    @property
    def name(self) -> str:
        return "local-evidence-caller-discovery"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "backend": "local-artifact-scan",
            "network": self.external_provider is not None,
            "external_code_search": self.external_provider.name if self.external_provider is not None else False,
            "evidence_roots": [str(path) for path in self.evidence_roots],
            "workspace_roots": [str(path) for path in self.workspace_roots],
        }

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        if "candidate" in context_pack and isinstance(context_pack["candidate"], dict):
            candidate_id = _as_text(context_pack.get("candidate_id"))
            candidate = context_pack["candidate"]
            preview_payloads = []
            if isinstance(context_pack.get("local_evidence"), dict):
                preview_payloads.append(context_pack["local_evidence"])
            if isinstance(context_pack.get("external_evidence"), dict) and context_pack["external_evidence"]:
                preview_payloads.append(context_pack["external_evidence"])
            if preview_payloads:
                return _merge_payloads(candidate_id, candidate, preview_payloads)
        else:
            candidate_id, candidate = normalize_candidate_description(context_pack)
        return discover_candidate_callers(
            candidate_id,
            candidate,
            evidence_roots=self.evidence_roots,
            workspace_roots=self.workspace_roots,
            external_provider=self.external_provider,
            per_query=self.per_query,
        )


def validate_context_pack(context_pack: dict[str, Any], schema: dict[str, Any]) -> None:
    input_schema = _as_text(context_pack.get("schema"))
    accepted = {_as_text(item) for item in schema.get("accepted_input_schemas") or []}
    if input_schema and accepted and input_schema not in accepted:
        raise ValueError(f"unsupported caller discovery input schema: {input_schema}")
    candidate_id, candidate = normalize_candidate_description(context_pack)
    del candidate_id
    missing = [
        str(field)
        for field in schema.get("required_candidate_fields") or []
        if field not in candidate or not candidate[field]
    ]
    if missing:
        raise ValueError(f"candidate description missing required fields: {', '.join(missing)}")


def validate_result(
    result: dict[str, Any],
    context_pack: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    if not isinstance(result, dict):
        raise ValueError("provider result must be a mapping")
    required = [str(field) for field in schema.get("required_result_fields") or []]
    optional = [str(field) for field in schema.get("optional_result_fields") or []]
    missing = [field for field in required if field not in result]
    if missing:
        raise ValueError(f"provider result missing required fields: {', '.join(missing)}")
    if schema.get("additional_result_fields") is False:
        unexpected = sorted(set(result) - (set(required) | set(optional)))
        if unexpected:
            raise ValueError(
                f"provider result contains unsupported fields: {', '.join(unexpected)}"
            )
    for field, field_schema in (schema.get("field_types") or {}).items():
        if field not in result:
            continue
        expected_type = _field_type_name(str(field), field_schema)
        check = TYPE_CHECKS.get(expected_type)
        if check is None:
            raise ValueError(f"unsupported schema field type: {expected_type}")
        if not check(result.get(field)):
            raise ValueError(f"provider result field {field} must be {expected_type}")
    expected_candidate_id, expected_candidate = normalize_candidate_description(context_pack)
    if "candidate_id" in result and result["candidate_id"] != expected_candidate_id:
        raise ValueError("provider result candidate_id does not match the source input")
    candidate = result.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be a mapping")
    if _as_text(candidate.get("library")) != expected_candidate["library"]:
        raise ValueError("candidate.library does not match source input")
    if _as_string_list(candidate.get("api")) != expected_candidate["api"]:
        raise ValueError("candidate.api does not match source input")
    if _as_text(candidate.get("family")) != expected_candidate["family"]:
        raise ValueError("candidate.family does not match source input")

    allowed_confidence = {str(value) for value in schema.get("allowed_confidence") or []}
    for index, repo in enumerate(result["repositories"]):
        if not isinstance(repo, dict):
            raise ValueError(f"repositories[{index}] must be a mapping")
        for field in ("name", "url", "confidence"):
            if not isinstance(repo.get(field), str):
                raise ValueError(f"repositories[{index}].{field} must be string")
        if not repo["name"].strip():
            raise ValueError(f"repositories[{index}].name must not be empty")
        if allowed_confidence and repo["confidence"] not in allowed_confidence:
            raise ValueError(f"unsupported repository confidence: {repo['confidence']}")

    for index, site in enumerate(result["call_sites"]):
        if not isinstance(site, dict):
            raise ValueError(f"call_sites[{index}] must be a mapping")
        for field in ("repository", "file", "symbol", "matched_api"):
            if not isinstance(site.get(field), str) or not site[field].strip():
                raise ValueError(f"call_sites[{index}].{field} must be string")

    for index, item in enumerate(result["evidence"]):
        if not isinstance(item, dict):
            raise ValueError(f"evidence[{index}] must be a mapping")
        for field in ("search_query", "matched_source"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"evidence[{index}].{field} must be string")
    claim_policy = result.get("claim_policy")
    if not isinstance(claim_policy, dict):
        raise ValueError("claim_policy must be a mapping")
    if claim_policy.get("caller_discovery_only") is not True:
        raise ValueError("claim_policy.caller_discovery_only must be true")
    if claim_policy.get("vulnerability") != "not_assessed":
        raise ValueError("claim_policy.vulnerability must be not_assessed")
    if claim_policy.get("security_impact") != "not_assessed":
        raise ValueError("claim_policy.security_impact must be not_assessed")


def build_caller_discovery_task(
    context_pack: dict[str, Any],
    local_evidence: dict[str, Any],
    *,
    external_evidence: dict[str, Any] | None = None,
    prompt_path: Path = DEFAULT_PROMPT_PATH,
) -> str:
    template = prompt_path.read_text(encoding="utf-8")
    candidate_id, candidate = normalize_candidate_description(context_pack)
    del candidate_id
    task = (
        template.replace(
            "{{CONTEXT_PACK_JSON}}",
            json.dumps(context_pack, indent=2, sort_keys=True),
        )
        .replace(
            "{{CANDIDATE_JSON}}",
            json.dumps(candidate, indent=2, sort_keys=True),
        )
        .replace(
            "{{LOCAL_EVIDENCE_JSON}}",
            json.dumps(local_evidence, indent=2, sort_keys=True),
        )
    )
    return task.replace(
        "{{EXTERNAL_EVIDENCE_JSON}}",
        json.dumps(external_evidence or {}, indent=2, sort_keys=True),
    )


def _provider_result(
    provider: AgentProvider,
    task: str,
    json_schema: dict[str, Any],
    provider_input: dict[str, Any],
) -> dict[str, Any]:
    analyze_structured = getattr(provider, "analyze_structured", None)
    if callable(analyze_structured):
        return analyze_structured(
            task=task,
            result_json_schema=json_schema,
            output_stem="caller_discovery",
        )
    return provider.analyze(provider_input)


def run_caller_discovery(
    context_pack_path: Path,
    output_path: Path,
    provider: AgentProvider | None = None,
    *,
    evidence_roots: Iterable[Path] | None = None,
    workspace_roots: Iterable[Path] | None = None,
    external_provider: CallerDiscoveryProvider | None = None,
    per_query: int = 10,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    prompt_path: Path = DEFAULT_PROMPT_PATH,
    timestamp_factory: Callable[[], str] = _utc_now,
) -> dict[str, Any]:
    """Run Caller Discovery v1 and write one artifact."""
    context_pack_path = context_pack_path.resolve()
    schema_path = schema_path.resolve()
    prompt_path = prompt_path.resolve()
    context_pack = load_yaml(context_pack_path)
    schema = load_yaml(schema_path)
    validate_context_pack(context_pack, schema)
    candidate_id, candidate = normalize_candidate_description(context_pack)

    roots = tuple(DEFAULT_EVIDENCE_ROOTS if evidence_roots is None else evidence_roots)
    search_roots = tuple(DEFAULT_WORKSPACE_SEARCH_ROOTS if workspace_roots is None else workspace_roots)
    local_preview = discover_candidate_callers(
        candidate_id,
        candidate,
        evidence_roots=roots,
        workspace_roots=search_roots,
    )
    external_preview = (
        discover_callers_from_external_search(candidate, external_provider, per_query=per_query)
        if external_provider is not None
        else {}
    )
    selected_provider = provider or LocalEvidenceCallerDiscoveryProvider(
        roots,
        search_roots,
        external_provider,
        per_query=per_query,
    )
    result_json_schema = build_result_json_schema(
        schema.get("field_types") or {},
        required_fields=set(schema.get("required_result_fields") or []),
    )
    task = build_caller_discovery_task(
        context_pack,
        local_preview,
        external_evidence=external_preview,
        prompt_path=prompt_path,
    )
    result = _provider_result(
        selected_provider,
        task,
        result_json_schema,
        {
            "context_pack": context_pack,
            "candidate_id": candidate_id,
            "candidate": candidate,
            "local_evidence": local_preview,
            "external_evidence": external_preview,
        },
    )
    validate_result(result, context_pack, schema)

    artifact = {
        "schema": str(schema.get("artifact_schema") or RESULT_SCHEMA),
        "source_candidate_description": {
            "path": str(context_pack_path),
            "schema": context_pack.get("schema", ""),
            "candidate_id": candidate_id,
            "sha256": _sha256(context_pack_path),
        },
        "generated_by": GENERATED_BY,
        "timestamp": timestamp_factory(),
        "provider": _provider_provenance(selected_provider),
        "candidate": result["candidate"],
        "repositories": result["repositories"],
        "call_sites": result["call_sites"],
        "evidence": result["evidence"],
        "unknowns": result["unknowns"],
        "claim_policy": result["claim_policy"],
        "result": result,
    }
    if context_pack.get("schema") == CONTEXT_PACK_SCHEMA:
        artifact["source_context_pack"] = {
            "path": str(context_pack_path),
            "schema": context_pack["schema"],
            "candidate_id": candidate_id,
            "sha256": _sha256(context_pack_path),
        }
    write_yaml(output_path, artifact)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Caller Discovery Agent v1 for repository candidate discovery."
    )
    parser.add_argument("--context-pack", type=Path, help="Legacy Candidate Context Pack input.")
    parser.add_argument("--candidate", type=Path, help="Caller Discovery candidate description input.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        action="append",
        default=None,
        help="Local evidence root to scan. May be supplied multiple times.",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        action="append",
        default=None,
        help="Local workspace root to source-search. May be supplied multiple times.",
    )
    parser.add_argument(
        "--github-search",
        action="store_true",
        help="Use GitHub Code Search via GITHUB_TOKEN or GH_TOKEN.",
    )
    parser.add_argument("--per-query", type=int, default=10)
    parser.add_argument(
        "--use-codex",
        action="store_true",
        help="Use Codex provider with the local evidence preview as bounded input.",
    )
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    input_path = args.candidate or args.context_pack
    if input_path is None:
        raise SystemExit("one of --candidate or --context-pack is required")

    roots = tuple(args.evidence_root or DEFAULT_EVIDENCE_ROOTS)
    workspace_roots = tuple(args.workspace_root or DEFAULT_WORKSPACE_SEARCH_ROOTS)
    external_provider = GitHubSourceProvider.from_environment() if args.github_search else None
    provider: AgentProvider | None = None
    if args.use_codex:
        if args.workspace is None:
            raise SystemExit("--workspace is required with --use-codex")
        provider = CodexAgentProvider(args.workspace, timeout_seconds=args.timeout_seconds)
    artifact = run_caller_discovery(
        input_path,
        args.out,
        provider,
        evidence_roots=roots,
        workspace_roots=workspace_roots,
        external_provider=external_provider,
        per_query=args.per_query,
    )
    print(f"[OK] Caller Discovery: {args.out}")
    print(f"[PROVIDER] {artifact['provider']['name']}")
    print(f"[REPOSITORIES] {len(artifact['repositories'])}")
    print(f"[CALL_SITES] {len(artifact['call_sites'])}")
    for caller in artifact["call_sites"]:
        print(
            f"[CALL_SITE] {caller['repository']} {caller['symbol']} "
            f"api={caller['matched_api']} file={caller['file']}"
        )


if __name__ == "__main__":
    main()
