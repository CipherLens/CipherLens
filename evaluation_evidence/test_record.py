"""Persisted test-run recording; test definitions alone never call this boundary."""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from evaluation_evidence.canonical import identify, semantic_safety_errors
from evaluation_evidence.model import SCHEMA_VERSIONS
from evaluation_evidence.registry import validate_document_or_raise
from pipeline_v2.artifact_store import ArtifactRef, ArtifactStore


def _link(ref: ArtifactRef) -> dict[str, str]:
    return {"ref": ref.ref, "digest": ref.digest}


def record_test_run(
    store: ArtifactStore, *, ref_prefix: str, git_revision: str, command: Iterable[str],
    test_scope: str, test_definition_refs: Iterable[Mapping[str, str]],
    counts: Mapping[str, int], stdout: bytes, stderr: bytes,
    working_profile: Mapping[str, Any], environment_profile: Mapping[str, Any],
    result_identities: Mapping[str, Iterable[str]] | None = None,
    producer_id: str = "evaluation-test-recorder", producer_version: str = "0.1",
) -> dict[str, Any]:
    expected = {"passed", "failed", "skipped", "xfailed", "errors"}
    if set(counts) != expected or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts.values()):
        raise ValueError("counts must contain exactly five non-negative integer totals")
    profile_errors = semantic_safety_errors({"working_profile": working_profile, "environment_profile": environment_profile})
    if profile_errors:
        raise ValueError("unsafe test-run profile: " + "; ".join(profile_errors))
    stdout_ref = store.put_raw(f"{ref_prefix}/stdout.txt", stdout, media_type="text/plain")
    stderr_ref = store.put_raw(f"{ref_prefix}/stderr.txt", stderr, media_type="text/plain")
    summary: dict[str, Any]
    if result_identities is None:
        summary = dict(sorted(counts.items()))
    else:
        summary = {"counts": dict(sorted(counts.items()))}
        if set(result_identities) != expected:
            raise ValueError("result_identities must use the same five outcome keys as counts")
        identities: dict[str, list[str]] = {}
        for outcome in sorted(expected):
            values = list(result_identities[outcome])
            if any(not isinstance(item, str) or not item for item in values):
                raise ValueError("result identities must be non-empty strings")
            if len(values) != counts[outcome]:
                raise ValueError(f"result identity count does not match {outcome}")
            identities[outcome] = sorted(values)
        summary["identities"] = identities
    summary_payload = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8")
    summary_ref = store.put_raw(f"{ref_prefix}/summary.json", summary_payload, media_type="application/json")
    working_payload = json.dumps(dict(working_profile), sort_keys=True, separators=(",", ":")).encode("utf-8")
    working_ref = store.put_raw(f"{ref_prefix}/working-profile.json", working_payload, media_type="application/json")
    environment_payload = json.dumps(dict(environment_profile), sort_keys=True, separators=(",", ":")).encode("utf-8")
    environment_ref = store.put_raw(f"{ref_prefix}/environment-profile.json", environment_payload, media_type="application/json")
    value = {
        "schema_version": SCHEMA_VERSIONS["test_run_record"], "test_run_id": "pending",
        "git_revision": git_revision, "command": list(command), "test_scope": test_scope,
        "working_profile": _link(working_ref),
        "test_definition_refs": [dict(item) for item in test_definition_refs],
        "passed": counts["passed"], "failed": counts["failed"], "skipped": counts["skipped"],
        "xfailed": counts["xfailed"], "errors": counts["errors"],
        "stdout_artifact": _link(stdout_ref), "stderr_artifact": _link(stderr_ref),
        "summary_artifact": _link(summary_ref), "environment_profile": _link(environment_ref),
        "producer": {"producer_id": producer_id, "producer_version": producer_version},
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result
