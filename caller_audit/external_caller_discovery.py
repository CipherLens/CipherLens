"""External repository discovery for low-level crypto API candidates.

Caller Discovery v3 is a repository-candidate discovery prototype.  It can use
external code search providers such as GitHub Code Search, but it does not clone
repositories, modify code, build projects, run programs, or assign vulnerability,
exploitability, security impact, or CVE claims.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from caller_audit.io_utils import load_yaml, write_yaml


RESULT_SCHEMA = "cipherlens_external_caller_discovery_v1"
CONTEXT_PACK_SCHEMA = "cipherlens_candidate_context_pack_v1"
DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schemas" / "external_caller_discovery_v1.yaml"

HIGH_PATH_TERMS = (
    "/src/",
    "/lib/",
    "/protocol/",
    "/auth/",
    "/verify/",
    "/credential/",
    "/credentials/",
    "/key/",
    "/keys/",
    "/crypto/",
    "/tls/",
    "/ssh/",
    "/vpn/",
)
LOW_PATH_TERMS = (
    "/test/",
    "/tests/",
    "/benchmark/",
    "/benchmarks/",
    "/doc/",
    "/docs/",
    "/example/",
    "/examples/",
    "/demo/",
    "/demos/",
    "/fuzz/",
)
SECURITY_TERMS = (
    "authentication",
    "authenticate",
    "signature",
    "verification",
    "verify",
    "certificate",
    "private key",
    "private-key",
    "privatekey",
    "privkey",
    "public key",
    "public-key",
    "tls",
    "ssh",
    "vpn",
    "credential",
    "pkcs8",
    "pkcs#8",
    "der",
    "asn.1",
    "asn1",
    "key parsing",
)
RELEVANCE_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class ExternalCodeHit:
    repository_name: str
    repository_url: str
    file_path: str
    file_url: str
    fragments: tuple[str, ...] = field(default_factory=tuple)


class CallerDiscoveryProvider(ABC):
    """Provider-neutral interface for external caller discovery."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable provider identifier."""

    @abstractmethod
    def search(self, query: str, *, per_page: int) -> list[ExternalCodeHit]:
        """Return external code hits for one search query."""


class GitHubSourceProvider(CallerDiscoveryProvider):
    """GitHub Code Search API provider.

    A token is required for GitHub code search.  The token is read from
    ``GITHUB_TOKEN`` or ``GH_TOKEN`` by ``from_environment`` and is never written
    into artifacts.
    """

    def __init__(
        self,
        token: str,
        *,
        endpoint: str = "https://api.github.com/search/code",
        opener: Any | None = None,
    ) -> None:
        if not token.strip():
            raise ValueError("GitHub token is required for GitHub code search")
        self.token = token
        self.endpoint = endpoint
        self.opener = opener or urllib.request.urlopen

    @classmethod
    def from_environment(cls) -> "GitHubSourceProvider":
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        return cls(token)

    @property
    def name(self) -> str:
        return "github-code-search"

    def search(self, query: str, *, per_page: int) -> list[ExternalCodeHit]:
        params = urllib.parse.urlencode({"q": query, "per_page": str(per_page)})
        request = urllib.request.Request(
            f"{self.endpoint}?{params}",
            headers={
                "Accept": "application/vnd.github.text-match+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "cipherlens-caller-discovery-v3",
            },
        )
        try:
            with self.opener(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GitHub code search failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub code search failed: {exc.reason}") from exc

        hits: list[ExternalCodeHit] = []
        for item in payload.get("items") or []:
            repo = item.get("repository") or {}
            fragments = []
            for match in item.get("text_matches") or []:
                fragment = str(match.get("fragment") or "").strip()
                if fragment:
                    fragments.append(fragment)
            hits.append(
                ExternalCodeHit(
                    repository_name=str(repo.get("full_name") or repo.get("name") or ""),
                    repository_url=str(repo.get("html_url") or ""),
                    file_path=str(item.get("path") or ""),
                    file_url=str(item.get("html_url") or ""),
                    fragments=tuple(fragments),
                )
            )
        return hits


class MockExternalSearchProvider(CallerDiscoveryProvider):
    """Deterministic provider used by tests and no-token experiments."""

    def __init__(self, results_by_query: dict[str, list[ExternalCodeHit]]) -> None:
        self.results_by_query = results_by_query

    @property
    def name(self) -> str:
        return "mock-external-code-search"

    def search(self, query: str, *, per_page: int) -> list[ExternalCodeHit]:
        return list(self.results_by_query.get(query, []))[:per_page]


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _append_unique(items: list[str], value: Any) -> None:
    text = _as_text(value)
    if text and text not in items:
        items.append(text)


def build_search_queries(context_pack: dict[str, Any]) -> list[str]:
    api = _as_text(context_pack.get("api_or_function"))
    if not api:
        raise ValueError("context pack api_or_function is required")

    queries: list[str] = []
    _append_unique(queries, f'"{api}("')
    _append_unique(queries, api)
    if api.startswith("d2i_"):
        _append_unique(queries, f'"EVP_PKEY *{api}"')

    semantic_type = _as_text(context_pack.get("semantic_type")).lower()
    if "full_consumption" in semantic_type or "consumption" in semantic_type:
        for term in ("DER", "ASN.1", '"key parsing"', "PKCS8"):
            _append_unique(queries, f"{api} {term}")
    return queries


def _extract_symbol(hit: ExternalCodeHit, api: str) -> str:
    text = "\n".join(hit.fragments)
    signature_patterns = [
        r"([~A-Za-z_]\w*(?:::[~A-Za-z_]\w*)*)\s*\([^;{}]*\)\s*(?:const\s*)?\{",
        r"([~A-Za-z_]\w*(?:::[~A-Za-z_]\w*)*)\s*\([^;{}]*\)\s*const",
    ]
    for pattern in signature_patterns:
        matches = list(re.finditer(pattern, text))
        if matches:
            return _symbol_with_path_module(hit.file_path, matches[-1].group(1))

    path_parts = [part for part in hit.file_path.split("/") if part]
    context = f"{hit.file_path}\n{text}"
    for line in text.splitlines():
        if api in line:
            before = line.split(api, 1)[0]
            match = re.search(r"([~A-Za-z_]\w*(?:::[~A-Za-z_]\w*)*)\s*$", before)
            if match:
                return _symbol_with_path_module(hit.file_path, match.group(1))
    if path_parts:
        return Path(path_parts[-1]).stem
    return "<unknown>"


def _symbol_with_path_module(file_path: str, symbol: str) -> str:
    display = _display_symbol(symbol)
    parts = [part for part in file_path.split("/") if part]
    if len(parts) >= 4 and parts[0] == "lib" and parts[2] == "src":
        module = parts[1]
        if module and not display.startswith(f"{module}::"):
            return _display_symbol(f"{module}::{display}")
    return display


def _display_symbol(symbol: str) -> str:
    parts = [part for part in _as_text(symbol).split("::") if part]
    if len(parts) > 3:
        return "::".join(parts[-3:])
    return "::".join(parts) if parts else "<unknown>"


def _rank_hit(hit: ExternalCodeHit, symbol: str) -> tuple[str, str]:
    path = "/" + hit.file_path.lower()
    text = f"{hit.repository_name}\n{hit.file_path}\n{symbol}\n" + "\n".join(hit.fragments)
    haystack = text.lower()
    low_path = any(term in path for term in LOW_PATH_TERMS)
    high_path = any(term in path for term in HIGH_PATH_TERMS)
    security_hits = [term for term in SECURITY_TERMS if term in haystack]

    if security_hits and high_path and not low_path:
        return (
            "high",
            "External source context is security-relevant: "
            + ", ".join(security_hits[:5])
            + ".",
        )
    if security_hits or high_path:
        return (
            "medium",
            "External source context shows crypto/API usage"
            + (", but path appears to be test/docs/example/benchmark code." if low_path else "."),
        )
    return (
        "low",
        "External search hit mentions the API, but security context is weak in the returned snippet.",
    )


def _repository_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        _as_text(item.get("url")).lower(),
        _as_text(item.get("file")).lower(),
        _as_text(item.get("symbol")).lower(),
    )


def _merge_repositories(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = _repository_key(item)
        if key not in merged:
            merged[key] = item
            continue
        existing = merged[key]
        for evidence in item.get("evidence") or []:
            _append_unique(existing["evidence"], evidence)
        if RELEVANCE_RANK[item["relevance"]] < RELEVANCE_RANK[existing["relevance"]]:
            existing["relevance"] = item["relevance"]
            existing["reason"] = item["reason"]
    return sorted(
        merged.values(),
        key=lambda item: (
            RELEVANCE_RANK.get(item["relevance"], 9),
            item["name"],
            item["file"],
            item["symbol"],
        ),
    )


def discover_external_callers(
    context_pack: dict[str, Any],
    provider: CallerDiscoveryProvider,
    *,
    per_query: int = 10,
) -> dict[str, Any]:
    queries = build_search_queries(context_pack)
    api = _as_text(context_pack.get("api_or_function"))
    repositories: list[dict[str, Any]] = []
    unknowns: list[str] = []

    for query in queries:
        hits = provider.search(query, per_page=per_query)
        for hit in hits:
            symbol = _extract_symbol(hit, api)
            relevance, reason = _rank_hit(hit, symbol)
            evidence = [f"query={query}", f"file_url={hit.file_url}"]
            for fragment in hit.fragments:
                _append_unique(evidence, f"fragment={fragment}")
            repositories.append(
                {
                    "name": hit.repository_name,
                    "url": hit.repository_url,
                    "file": hit.file_path,
                    "symbol": symbol,
                    "api_usage": f"{api} in {hit.file_path}",
                    "evidence": evidence,
                    "relevance": relevance,
                    "reason": reason,
                }
            )

    repositories = _merge_repositories(repositories)
    if not repositories:
        unknowns.append("No external repository candidate found for this API candidate.")

    return {
        "schema": RESULT_SCHEMA,
        "candidate_id": context_pack["candidate_id"],
        "search_queries": queries,
        "repositories": repositories,
        "unknowns": unknowns,
        "claim_policy": {
            "vulnerability": "not_assessed",
            "security_impact": "not_assessed",
        },
    }


def validate_context_pack(context_pack: dict[str, Any], schema: dict[str, Any]) -> None:
    expected = _as_text(schema.get("context_pack_schema") or CONTEXT_PACK_SCHEMA)
    if context_pack.get("schema") != expected:
        raise ValueError(
            f"unsupported context pack schema: expected {expected}, got {context_pack.get('schema', 'missing')}"
        )
    missing = [
        _as_text(field)
        for field in schema.get("required_context_fields") or []
        if not _as_text(context_pack.get(_as_text(field)))
    ]
    if missing:
        raise ValueError(f"context pack missing required fields: {', '.join(missing)}")


def validate_result(result: dict[str, Any], context_pack: dict[str, Any], schema: dict[str, Any]) -> None:
    required = [_as_text(field) for field in schema.get("required_result_fields") or []]
    missing = [field for field in required if field not in result]
    if missing:
        raise ValueError(f"external discovery result missing required fields: {', '.join(missing)}")
    if result["schema"] != _as_text(schema.get("artifact_schema") or RESULT_SCHEMA):
        raise ValueError(f"unsupported external discovery schema: {result['schema']}")
    if result["candidate_id"] != context_pack["candidate_id"]:
        raise ValueError("external discovery candidate_id does not match context pack")
    if not isinstance(result.get("search_queries"), list):
        raise ValueError("search_queries must be a list")
    if not isinstance(result.get("repositories"), list):
        raise ValueError("repositories must be a list")
    allowed = {_as_text(item) for item in schema.get("allowed_relevance") or []}
    for index, repo in enumerate(result["repositories"]):
        if not isinstance(repo, dict):
            raise ValueError(f"repositories[{index}] must be a mapping")
        for field in ("name", "url", "file", "symbol", "api_usage", "reason"):
            if not _as_text(repo.get(field)):
                raise ValueError(f"repositories[{index}].{field} must be string")
        if not isinstance(repo.get("evidence"), list) or not repo["evidence"]:
            raise ValueError(f"repositories[{index}].evidence must be a non-empty list")
        if allowed and repo.get("relevance") not in allowed:
            raise ValueError(f"unsupported repository relevance: {repo.get('relevance')}")
    claim_policy = result.get("claim_policy")
    if not isinstance(claim_policy, dict):
        raise ValueError("claim_policy must be a mapping")
    if claim_policy.get("vulnerability") != "not_assessed":
        raise ValueError("claim_policy.vulnerability must be not_assessed")
    if claim_policy.get("security_impact") != "not_assessed":
        raise ValueError("claim_policy.security_impact must be not_assessed")


def run_external_caller_discovery(
    context_pack_path: Path,
    output_path: Path,
    provider: CallerDiscoveryProvider,
    *,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    per_query: int = 10,
) -> dict[str, Any]:
    context_pack = load_yaml(context_pack_path.expanduser().resolve())
    schema = load_yaml(schema_path.resolve())
    validate_context_pack(context_pack, schema)
    result = discover_external_callers(context_pack, provider, per_query=per_query)
    validate_result(result, context_pack, schema)
    write_yaml(output_path, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Caller Discovery v3 external repository discovery."
    )
    parser.add_argument("--context-pack", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--per-query", type=int, default=10)
    args = parser.parse_args()

    provider = GitHubSourceProvider.from_environment()
    result = run_external_caller_discovery(
        args.context_pack,
        args.out,
        provider,
        per_query=args.per_query,
    )
    print(f"[OK] External Caller Discovery: {args.out}")
    print(f"[PROVIDER] {provider.name}")
    print(f"[SEARCH_QUERIES] {len(result['search_queries'])}")
    print(f"[REPOSITORIES] {len(result['repositories'])}")
    for repo in result["repositories"]:
        print(
            f"[REPOSITORY] {repo['name']} {repo['symbol']} "
            f"relevance={repo['relevance']} file={repo['file']}"
        )


if __name__ == "__main__":
    main()
