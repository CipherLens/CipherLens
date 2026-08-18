"""One-way wrapper around deterministic caller evidence; impact stays advisory."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from execution_model.canonical import artifact_digest, identify
from execution_model.model import REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact_or_raise


def verified_call_site(*, repository_revision: str, file_path: Path, repository_root: Path, line: int, symbol: str, callee: str, build_provenance_refs: Sequence[str] = ()) -> dict[str, Any]:
    resolved = file_path.resolve(); root = repository_root.resolve(); relative = resolved.relative_to(root).as_posix()
    return {"status": "VERIFIED", "repository_revision": repository_revision, "file": relative, "file_digest": hashlib.sha256(resolved.read_bytes()).hexdigest(), "line": line, "symbol": symbol, "callee": callee, "edge": f"{symbol}->{callee}", "build_provenance_refs": list(build_provenance_refs)}


def build_caller_impact_bridge(
    violation_package: Mapping[str, Any], execution_verdict: Mapping[str, Any], *,
    repository_snapshot: Mapping[str, Any], verified_caller_evidence: Sequence[Mapping[str, Any]],
    advisory_impact: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    if execution_verdict.get("verdict") != "VIOLATED": raise ValueError("caller bridge requires VIOLATED Verdict")
    validate_artifact_or_raise(violation_package)
    validate_artifact_or_raise(execution_verdict)
    if violation_package.get("execution_verdict_ref") != execution_verdict.get("verdict_id") or violation_package.get("execution_verdict_digest") != artifact_digest(execution_verdict):
        raise ValueError("caller bridge Verdict lineage mismatch")
    verified = [dict(x) for x in verified_caller_evidence]
    if any(x.get("status") != "VERIFIED" or not x.get("file_digest") for x in verified): raise ValueError("verified caller evidence requires deterministic file/revision provenance")
    advisory = [{**dict(x), "authority": "ADVISORY", "may_modify_execution_verdict": False, "may_create_verified_caller_fact": False} for x in advisory_impact]
    document = identify({
        "schema_version": SCHEMA_VERSIONS["caller_bridge"], "bridge_id": "pending",
        "violation_package_ref": violation_package["package_id"], "violation_package_digest": artifact_digest(violation_package),
        "execution_verdict_ref": execution_verdict["verdict_id"], "execution_verdict_digest": artifact_digest(execution_verdict),
        "repository_snapshot": dict(repository_snapshot), "verified_caller_evidence": verified, "advisory_impact": advisory,
        "claim_policy": {"one_way": True, "vulnerability_confirmed": False, "cve": False, "legacy_caller_verdict_forbidden": True},
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document); return document
