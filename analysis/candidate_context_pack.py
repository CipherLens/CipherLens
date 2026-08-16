"""Build a conservative, provenance-preserving Candidate Context Pack.

This module normalizes existing CipherLens artifacts for later caller-aware
analysis.  It does not explore source repositories, classify security impact,
or invoke an LLM/agent.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

import yaml


SCHEMA = "cipherlens_candidate_context_pack_v1"
UNKNOWN = "unknown"
GENERATED_BY = "analysis.candidate_context_pack"

ID_KEYS = ("candidate_id", "logical_candidate_id", "case_id", "input_id")
COLLECTION_KEYS = ("candidates", "items", "results", "records")


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_list(value: Any) -> list[str]:
    items: list[str] = []
    for item in _as_list(value):
        text = _as_text(item)
        if text and text not in items:
            items.append(text)
    return items


def _slugify(value: str) -> str:
    import re

    slug = re.sub(r"[^A-Za-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "candidate"


def load_artifact(path: Path) -> Any:
    """Load a YAML, JSON, or JSONL artifact without changing its contents."""
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def artifact_schema(data: Any) -> str:
    if isinstance(data, dict) and data.get("schema"):
        return str(data["schema"])
    return UNKNOWN


def _record_id(record: dict[str, Any]) -> str:
    for key in ID_KEYS:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def select_candidate(data: Any, candidate_id: str | None = None) -> dict[str, Any]:
    """Select one candidate from common queue/result artifact shapes."""
    if isinstance(data, list):
        records = [item for item in data if isinstance(item, dict)]
    elif isinstance(data, dict):
        records = []
        for key in COLLECTION_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                records.extend(item for item in value if isinstance(item, dict))
        if not records:
            records = [data]
    else:
        raise ValueError("candidate artifact must contain a mapping or list")

    if candidate_id:
        matches = [record for record in records if _record_id(record) == candidate_id]
        if not matches and len(records) == 1 and not _record_id(records[0]):
            return records[0]
        if not matches:
            raise ValueError(f"candidate_id not found in artifact: {candidate_id}")
        return matches[0]
    if len(records) != 1:
        raise ValueError(
            "candidate artifact contains multiple records; pass --candidate-id"
        )
    return records[0]


def _mapping_views(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return known nested record views in deterministic priority order."""
    views = [record]
    for key in ("candidate", "dispatcher_input", "input", "dispatched", "verdict"):
        value = record.get(key)
        if isinstance(value, dict):
            views.append(value)
    return views


def _first(views: Iterable[dict[str, Any]], *keys: str) -> tuple[Any, str]:
    for view in views:
        for key in keys:
            value = view.get(key)
            if value not in (None, "", [], {}):
                return value, key
    return UNKNOWN, ""


def _status_from(data: Any) -> tuple[str, str]:
    if not isinstance(data, dict):
        return UNKNOWN, ""
    verdict = data.get("verdict")
    if isinstance(verdict, dict) and verdict.get("status"):
        return str(verdict["status"]), "verdict.status"
    for key in (
        "decision",
        "current_classification",
        "classification",
        "status",
        "validation_status",
        "external_validation_status",
        "candidate_level",
        "candidate_label",
        "label",
        "verdict",
    ):
        value = data.get(key)
        if value not in (None, "", [], {}) and not isinstance(value, dict):
            return str(value), key
    return UNKNOWN, ""


def _eligibility(classification: str) -> dict[str, str]:
    normalized = classification.lower()
    closed_markers = (
        "closed",
        "downgrade",
        "false_positive",
        "safe_negative",
        "expected_behavior",
        "expected_prefix",
        "caller_must_check",
        "not_required",
    )
    if any(marker in normalized for marker in closed_markers):
        return {
            "status": "ineligible",
            "reason": "explicit lifecycle classification is closed or downgraded",
        }
    if "candidate" in normalized or normalized in {
        "needs_triage",
        "manual_review_required",
        "external_validation_pending",
    }:
        return {
            "status": "eligible",
            "reason": "latest explicit lifecycle classification remains candidate-like",
        }
    return {
        "status": "needs_review",
        "reason": "artifacts do not provide an explicit active or closed lifecycle state",
    }


def _source_entry(path: Path, role: str, data: Any) -> dict[str, str]:
    return {
        "role": role,
        "path": str(path),
        "artifact": path.name,
        "schema": artifact_schema(data),
        "generated_by": (
            str(data.get("source_task") or data.get("task_name") or UNKNOWN)
            if isinstance(data, dict)
            else UNKNOWN
        ),
    }


def _discovery_candidate_id(discovery: dict[str, Any], candidate: dict[str, Any]) -> str:
    source = discovery.get("source_candidate_description")
    if isinstance(source, dict) and _as_text(source.get("candidate_id")):
        return _as_text(source["candidate_id"])
    result = discovery.get("result")
    if isinstance(result, dict) and _as_text(result.get("candidate_id")):
        return _as_text(result["candidate_id"])
    return _slugify(
        "-".join(
            [
                _as_text(candidate.get("library")),
                "-".join(_string_list(candidate.get("api"))),
                _as_text(candidate.get("family")),
            ]
        )
    )


def _caller_discovery_evidence(discovery: dict[str, Any]) -> dict[str, Any]:
    return {
        "repositories": list(discovery.get("repositories") or []),
        "call_sites": list(discovery.get("call_sites") or []),
        "evidence": list(discovery.get("evidence") or []),
        "unknowns": list(discovery.get("unknowns") or []),
        "claim_policy": dict(discovery.get("claim_policy") or {}),
    }


def build_context_pack_from_caller_discovery(
    caller_discovery_path: Path,
    *,
    candidate_id: str | None = None,
) -> dict[str, Any]:
    """Build a minimal ImpactLift Context Pack from Caller Discovery v1 output."""
    discovery = load_artifact(caller_discovery_path)
    if not isinstance(discovery, dict):
        raise ValueError("caller discovery artifact must be a mapping")
    if discovery.get("schema") != "cipherlens_caller_discovery_v1":
        raise ValueError(
            "unsupported caller discovery schema: "
            + _as_text(discovery.get("schema") or "missing")
        )
    candidate = discovery.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("caller discovery candidate mapping is required")

    apis = _string_list(candidate.get("api"))
    behavior = _string_list(candidate.get("behavior"))
    candidate_evidence = _string_list(candidate.get("evidence"))
    generated_candidate_id = candidate_id or _discovery_candidate_id(discovery, candidate)
    source_paths = [str(caller_discovery_path)]
    source_paths.extend(candidate_evidence)

    caller_evidence = _caller_discovery_evidence(discovery)
    observed_repository_names = [
        _as_text(repo.get("name"))
        for repo in caller_evidence["repositories"]
        if isinstance(repo, dict) and _as_text(repo.get("name"))
    ]
    observed_call_sites = [
        f"{site.get('repository')}:{site.get('file')}:{site.get('symbol')}:{site.get('matched_api')}"
        for site in caller_evidence["call_sites"]
        if isinstance(site, dict)
    ]

    return {
        "schema": SCHEMA,
        "candidate_id": generated_candidate_id,
        "library": _as_text(candidate.get("library")),
        "version": UNKNOWN,
        "family": _as_text(candidate.get("family")),
        "semantic_type": _as_text(candidate.get("family")),
        "api_or_function": ", ".join(apis),
        "trigger_condition": "; ".join(behavior),
        "observed_behavior": {
            "candidate_behavior": behavior,
            "repositories_discovered": observed_repository_names,
            "call_sites_discovered": observed_call_sites,
            "assessment_boundary": "caller_discovery_only",
        },
        "oracle_evidence": {
            "candidate_evidence": candidate_evidence,
            "caller_discovery_artifact": str(caller_discovery_path),
            "caller_discovery_evidence": caller_evidence["evidence"],
        },
        "source_artifacts": source_paths,
        "caller_discovery_evidence": caller_evidence,
        "provenance": {
            "generated_by": GENERATED_BY,
            "source": _source_entry(caller_discovery_path, "caller_discovery", discovery),
            "sources": [
                _source_entry(caller_discovery_path, "caller_discovery", discovery)
            ],
            "field_sources": {
                "candidate_id": {
                    "field": "source_candidate_description.candidate_id",
                    "source": "caller_discovery",
                },
                "library": {"field": "candidate.library", "source": "caller_discovery"},
                "family": {"field": "candidate.family", "source": "caller_discovery"},
                "api_or_function": {"field": "candidate.api", "source": "caller_discovery"},
                "caller_discovery_evidence": {
                    "field": "repositories/call_sites/evidence",
                    "source": "caller_discovery",
                },
            },
        },
        "claim_policy": {
            "vulnerability": "not_assessed",
            "security_impact": "not_assessed",
            "cve": "not_assessed",
            "propagation": "not_assessed",
        },
    }


def _questions(records: Iterable[dict[str, Any]]) -> list[Any]:
    questions: list[Any] = []
    for record in records:
        for key in ("unresolved_questions", "remaining_questions"):
            value = record.get(key)
            if isinstance(value, list):
                questions.extend(value)
            elif value not in (None, ""):
                questions.append(value)
    return questions


def build_context_pack(
    candidate_artifact: Path,
    *,
    candidate_id: str | None = None,
    logical_candidate_id: str | None = None,
    triage_artifacts: Iterable[Path] = (),
    closure_artifacts: Iterable[Path] = (),
    feedback_artifacts: Iterable[Path] = (),
    caller_audit_artifacts: Iterable[Path] = (),
) -> dict[str, Any]:
    """Build one context pack from explicit, already-existing artifacts."""
    candidate_data = load_artifact(candidate_artifact)
    candidate = select_candidate(candidate_data, candidate_id)

    sources: list[dict[str, str]] = [
        _source_entry(candidate_artifact, "candidate_emission", candidate_data)
    ]
    supporting: list[tuple[str, Path, Any]] = []
    for role, paths in (
        ("triage", triage_artifacts),
        ("closure", closure_artifacts),
        ("negative_feedback", feedback_artifacts),
        ("caller_audit", caller_audit_artifacts),
    ):
        for path in paths:
            data = load_artifact(path)
            supporting.append((role, path, data))
            sources.append(_source_entry(path, role, data))

    candidate_views = _mapping_views(candidate)
    support_maps = [
        record
        for _, _, data in supporting
        for record in (data if isinstance(data, list) else [data])
        if isinstance(record, dict)
    ]
    caller_maps = [
        data for role, _, data in supporting
        if role == "caller_audit" and isinstance(data, dict)
    ]
    all_views = candidate_views + caller_maps

    normalized: dict[str, Any] = {}
    field_sources: dict[str, dict[str, str]] = {}

    def assign(field: str, keys: tuple[str, ...], views: list[dict[str, Any]] = all_views) -> None:
        value, key = _first(views, *keys)
        normalized[field] = value
        field_sources[field] = {
            "field": key or UNKNOWN,
            "source": "existing_artifact" if key else UNKNOWN,
        }

    assign("candidate_id", ID_KEYS, candidate_views)
    if normalized["candidate_id"] == UNKNOWN and candidate_id:
        normalized["candidate_id"] = candidate_id
        field_sources["candidate_id"] = {"field": "cli.candidate_id", "source": "builder_input"}
    normalized["logical_candidate_id"] = logical_candidate_id or normalized["candidate_id"]
    field_sources["logical_candidate_id"] = {
        "field": "cli.logical_candidate_id" if logical_candidate_id else field_sources["candidate_id"]["field"],
        "source": "builder_input" if logical_candidate_id else field_sources["candidate_id"]["source"],
    }

    assign("library", ("target_library", "library", "target"))
    assign("version", ("version", "library_version", "crypto_backend"))
    assign("family", ("family", "harness_family"))
    assign(
        "semantic_type",
        ("semantic_type", "classification", "candidate_label", "label", "verdict"),
        candidate_views,
    )
    assign("api_or_function", ("api_or_function", "target_api", "api", "trigger_api", "component"))
    assign("trigger_condition", ("trigger_condition", "mutation_strategy", "state_sequence", "input_object"))
    assign("observed_behavior", ("observed_behavior", "actual_behavior", "app_replay", "dynamic_evidence"))
    assign("expected_behavior", ("expected_behavior", "expected_control"))
    assign("oracle_evidence", ("oracle_evidence", "evidence", "evidence_files", "oracle_events", "dynamic_evidence"))
    assign("testcase", ("testcase", "case_id", "input_id", "source_case"), candidate_views)
    assign("harness", ("harness", "harness_c", "source", "binary_path"))

    role_priority = {
        "candidate_emission": 0,
        "caller_audit": 1,
        "triage": 2,
        "negative_feedback": 3,
        "closure": 4,
    }
    lifecycle_rows: list[tuple[int, str, str, str]] = []
    candidate_status, candidate_status_key = _status_from(candidate)
    if candidate_status != UNKNOWN:
        lifecycle_rows.append((
            role_priority["candidate_emission"],
            candidate_status,
            str(candidate_artifact),
            candidate_status_key,
        ))
    for role, path, data in supporting:
        records = data if isinstance(data, list) else [data]
        for record in records:
            status, key = _status_from(record)
            if status != UNKNOWN:
                lifecycle_rows.append((
                    role_priority[role], status, str(path), f"{role}.{key}"
                ))
    lifecycle_rows.sort(key=lambda row: row[0])
    lifecycle_candidates = [row[1:] for row in lifecycle_rows]

    current = lifecycle_candidates[-1] if lifecycle_candidates else (UNKNOWN, UNKNOWN, UNKNOWN)
    normalized["status"] = current[0]
    normalized["current_classification"] = current[0]
    normalized["impactlift_eligibility"] = _eligibility(current[0])
    normalized["unresolved_questions"] = _questions([candidate] + support_maps)
    normalized["source_artifacts"] = [source["path"] for source in sources]

    return {
        "schema": SCHEMA,
        **normalized,
        "provenance": {
            "generated_by": GENERATED_BY,
            "source": sources[0],
            "sources": sources,
            "field_sources": field_sources,
            "lifecycle_states": [
                {"classification": status, "path": path, "field": field}
                for status, path, field in lifecycle_candidates
            ],
        },
        "claim_policy": {
            "vulnerability": "not_assessed",
            "security_impact": "not_assessed",
            "propagation": "not_assessed",
        },
    }


def write_context_pack(path: Path, pack: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(pack, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an ImpactLift Candidate Context Pack from existing artifacts."
    )
    parser.add_argument("--candidate-artifact", type=Path, required=True)
    parser.add_argument("--candidate-id")
    parser.add_argument("--logical-candidate-id")
    parser.add_argument("--triage-artifact", type=Path, action="append", default=[])
    parser.add_argument("--closure-artifact", type=Path, action="append", default=[])
    parser.add_argument("--feedback-artifact", type=Path, action="append", default=[])
    parser.add_argument("--caller-audit-artifact", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path, default=Path("candidate_context_pack.yaml"))
    args = parser.parse_args()

    pack = build_context_pack(
        args.candidate_artifact,
        candidate_id=args.candidate_id,
        logical_candidate_id=args.logical_candidate_id,
        triage_artifacts=args.triage_artifact,
        closure_artifacts=args.closure_artifact,
        feedback_artifacts=args.feedback_artifact,
        caller_audit_artifacts=args.caller_audit_artifact,
    )
    write_context_pack(args.out, pack)
    print(f"[OK] candidate context pack: {args.out}")
    print(f"[STATUS] {pack['current_classification']}")
    print(f"[ELIGIBILITY] {pack['impactlift_eligibility']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
