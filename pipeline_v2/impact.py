"""One-way caller and advisory impact integration for a VIOLATED execution."""

from __future__ import annotations

import re
import subprocess
import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from caller_audit.scanner import scan_call_sites
from caller_audit.source_caller_discovery import discover_source_callers
from impact_bridge.caller_bridge import build_caller_impact_bridge, verified_call_site


ImpactProvider = Callable[[Mapping[str, Any], Sequence[Mapping[str, Any]]], Sequence[Mapping[str, Any]]]


def _git_rev_parse(root: Path, expression: str) -> str:
    result = subprocess.run(["git", "-C", str(root), "rev-parse", expression], text=True, capture_output=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError(f"repository identity unavailable: {expression}")
    return result.stdout.strip()


def repository_revision(root: Path) -> str:
    return _git_rev_parse(root, "HEAD")


def repository_identity(root: Path) -> dict[str, str]:
    tree_object = _git_rev_parse(root, "HEAD^{tree}")
    return {
        "repository_ref": root.resolve().name,
        "revision": _git_rev_parse(root, "HEAD"),
        "tree_digest": hashlib.sha256(tree_object.encode("ascii")).hexdigest(),
    }


def discover_verified_callers(*, repository_root: Path, callee: str, symbol: str, build_provenance_refs: Sequence[str] = ()) -> tuple[Mapping[str, Any], list[Mapping[str, Any]], Mapping[str, Any]]:
    snapshot = repository_identity(repository_root)
    # Source discovery is a local recall aid only. Scanner results are converted
    # to VERIFIED evidence only after file/revision/digest checks below.
    discovered = discover_source_callers({"candidate_id": symbol, "api_or_function": callee}, repository_root)
    sites = scan_call_sites(repository_root, [rf"\b{re.escape(callee)}\s*\("])
    verified = [verified_call_site(repository_revision=snapshot["revision"], file_path=repository_root / item["path"], repository_root=repository_root, line=int(item["line"]), symbol=symbol, callee=callee, build_provenance_refs=build_provenance_refs) for item in sites]
    discovery_record = {"schema": discovered.get("schema"), "candidate_ref": symbol, "callee": callee, "caller_count": len(discovered.get("discovered_callers", [])), "discovered_callers": discovered.get("discovered_callers", [])}
    return snapshot, verified, discovery_record


def bridge_violation(*, violation_package: Mapping[str, Any], verdict: Mapping[str, Any], repository_root: Path | None, callee: str, symbol: str, build_provenance_refs: Sequence[str] = (), impact_provider: ImpactProvider | None = None) -> tuple[Mapping[str, Any] | None, str | None, Mapping[str, Any] | None]:
    if repository_root is None:
        return None, None, None
    snapshot, callers, discovery = discover_verified_callers(repository_root=repository_root, callee=callee, symbol=symbol, build_provenance_refs=build_provenance_refs)
    advisory: Sequence[Mapping[str, Any]] = ()
    error = None
    if impact_provider is not None:
        try:
            advisory = impact_provider(violation_package, callers)
        except Exception as exc:  # advisory failure must not mutate the Verdict
            error = type(exc).__name__
    return build_caller_impact_bridge(violation_package, verdict, repository_snapshot=snapshot, verified_caller_evidence=callers, advisory_impact=advisory), error, discovery
