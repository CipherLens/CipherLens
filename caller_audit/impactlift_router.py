from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from analysis.candidate_context_pack import (
    build_context_pack,
    build_context_pack_from_caller_discovery,
    load_artifact,
    select_candidate,
    write_context_pack,
)
from caller_audit.caller_discovery_runner import run_caller_discovery
from caller_audit.exploitability_runner import run_exploitability
from caller_audit.external_caller_discovery import (
    CallerDiscoveryProvider,
    ExternalCodeHit,
    GitHubSourceProvider,
    MockExternalSearchProvider,
)
from caller_audit.impact_runner import run_impactlift
from caller_audit.io_utils import write_yaml
from caller_audit.security_impact_runner import run_security_impact
from utils.agent_provider import AgentProvider
from utils.codex_agent_provider import CodexAgentProvider


ROUTER_SCHEMA = "cipherlens_impactlift_router_run_summary_v1"
GENERATED_BY = "caller_audit.impactlift_router"
DEFAULT_BASE_OUT = Path("artifacts/caller_audit/impactlift_router")
UNKNOWN = "unknown"

ELIGIBLE_CLASSIFICATIONS = {
    "candidate_event",
    "semantic_gap_candidate",
    "robustness_candidate",
    "api_contract_gap_candidate",
    "manual_review_required",
    "high_priority_triage",
    "active",
    "unresolved",
    "needs_triage",
}
INELIGIBLE_CLASSIFICATIONS = {
    "closed",
    "downgraded",
    "contract_observation",
    "stable_safe_negative",
    "projection_limitation",
    "not_reproducible",
    "safe_reject",
    "expected_accept",
    "expected_reject",
    "expected_negative_control",
    "negative_control_support",
    "roundtrip_success",
    "unsupported",
    "missing_or_not_found",
    "invalid_contract_observation",
}


class DeterministicImpactProvider(AgentProvider):
    """Offline provider for deterministic router smoke runs.

    This provider is intentionally conservative.  It makes no vulnerability,
    CVE, or security-impact claim; it only emits schema-valid artifacts so the
    backend artifact flow can be reproduced without an LLM backend.
    """

    def __init__(self) -> None:
        self._candidate_id = ""

    @property
    def name(self) -> str:
        return "deterministic-impactlift-router-provider"

    @property
    def metadata(self) -> dict[str, Any]:
        return {"backend": "deterministic-offline-smoke"}

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        self._candidate_id = str(context_pack["candidate_id"])
        caller_evidence = context_pack.get("caller_discovery_evidence")
        caller_count = 0
        if isinstance(caller_evidence, dict):
            caller_count = len(caller_evidence.get("repositories") or [])
        return {
            "candidate_id": self._candidate_id,
            "summary": "Deterministic router smoke artifact.",
            "findings": [f"caller_repository_candidates={caller_count}"],
            "evidence": _string_list(context_pack.get("source_artifacts")),
            "confidence": "low",
            "caller_chain": [],
            "guards": ["offline provider does not assign claims"],
            "propagation": {},
            "unknowns": ["Impact details were not assessed by the deterministic provider."],
        }

    def analyze_structured(
        self,
        *,
        task: str,
        result_json_schema: dict[str, Any],
        output_stem: str,
    ) -> dict[str, Any]:
        del task, result_json_schema
        if output_stem == "exploitability":
            return {
                "candidate_id": self._candidate_id,
                "summary": "Deterministic router smoke artifact.",
                "input_sources": [],
                "attacker_control": [],
                "trust_boundaries": [],
                "security_usage": [],
                "reachable_paths": [],
                "barriers": ["offline provider does not assess reachability"],
                "unknowns": ["Not assessed by the deterministic provider."],
                "evidence": ["impact_exploration.yaml"],
                "exploitability_assessment": "unknown",
                "confidence": "low",
            }
        if output_stem == "security_impact":
            return {
                "candidate_id": self._candidate_id,
                "security_classification": "insufficient_evidence",
                "affected_security_properties": [],
                "impact_evidence": ["post-processing artifacts generated"],
                "confidence": "low",
                "unknowns": ["Not assessed by the deterministic provider."],
            }
        raise ValueError(f"unsupported deterministic output stem: {output_stem}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_id(record: dict[str, Any]) -> str:
    for key in ("candidate_id", "logical_candidate_id", "case_id", "input_id"):
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _status_value(record: dict[str, Any]) -> str:
    for key in (
        "classification",
        "status",
        "candidate_level",
        "candidate_label",
        "semantic_type",
        "label",
    ):
        value = record.get(key)
        if value not in (None, "", [], {}) and not isinstance(value, dict):
            return str(value)
    verdict = record.get("verdict")
    if isinstance(verdict, dict):
        return _as_text(verdict.get("status"))
    if verdict not in (None, "", [], {}):
        return str(verdict)
    return UNKNOWN


def _target_library(value: str) -> str:
    lowered = value.lower()
    for library in ("openssl", "mbedtls", "botan", "wolfssl"):
        if library in lowered:
            return library
    return value or UNKNOWN


def _best_api(record: dict[str, Any]) -> list[str]:
    for key in ("api", "api_or_function", "target_api", "trigger_api", "function", "component"):
        values = _string_list(record.get(key))
        if values:
            return values
    nested = record.get("dispatcher_input")
    if isinstance(nested, dict):
        observed = nested.get("observed_behavior")
        if isinstance(observed, dict):
            command = _as_text(observed.get("command"))
            if command:
                return [command]
    return []


def normalize_candidate_record(record: dict[str, Any]) -> dict[str, Any]:
    """Convert current mainline queue/candidate shapes into router input."""
    if isinstance(record.get("candidate"), dict):
        wrapped = dict(record["candidate"])
        for key in ("candidate_id", "schema", "status", "classification", "semantic_type"):
            if key in record and key not in wrapped:
                wrapped[key] = record[key]
        record = wrapped
    dispatcher_input = record.get("dispatcher_input") if isinstance(record.get("dispatcher_input"), dict) else {}
    observed = record.get(
        "observed_behavior",
        record.get("behavior", dispatcher_input.get("observed_behavior")),
    )
    evidence = record.get("evidence", dispatcher_input.get("evidence_files"))
    candidate_id = _record_id(record) or _record_id(dispatcher_input) if dispatcher_input else _record_id(record)
    api_list = _best_api(record)
    library = _target_library(_as_text(record.get("library") or record.get("target") or dispatcher_input.get("target")))
    family = _as_text(record.get("family") or dispatcher_input.get("family"))
    if not candidate_id:
        candidate_id = _slugify(
            "-".join(
                [
                    library,
                    "-".join(api_list),
                    family,
                    _as_text(record.get("classification") or record.get("candidate_level")),
                ]
            )
        )
    return {
        "candidate_id": candidate_id,
        "library": library,
        "version": _as_text(record.get("version") or record.get("library_version")),
        "family": family,
        "api": api_list,
        "semantic_type": _as_text(record.get("semantic_type") or record.get("classification")),
        "trigger_condition": _as_text(record.get("trigger_condition") or dispatcher_input.get("expected_behavior")),
        "observed_behavior": observed if observed not in (None, "", [], {}) else UNKNOWN,
        "oracle_type": _as_text(record.get("oracle_type") or dispatcher_input.get("oracle_type")),
        "oracle_evidence": _string_list(record.get("oracle_evidence") or evidence),
        "source_artifacts": _string_list(record.get("source_artifacts") or evidence),
        "status": _status_value(record),
        "repository": record.get("repository"),
        "caller": record.get("caller"),
        "caller_discovery_evidence": record.get("caller_discovery_evidence"),
        "provenance": {
            "source_campaign": record.get("source_campaign") or dispatcher_input.get("source_campaign"),
            "dispatcher_input": dispatcher_input,
        },
    }


def _has_known_caller(candidate: dict[str, Any]) -> bool:
    if candidate.get("repository") or candidate.get("caller"):
        return True
    evidence = candidate.get("caller_discovery_evidence")
    if isinstance(evidence, dict):
        if evidence.get("repositories") or evidence.get("call_sites"):
            return True
    return False


def _candidate_description(candidate: dict[str, Any]) -> dict[str, Any]:
    description = {
        "candidate_id": candidate["candidate_id"],
        "library": candidate["library"],
        "version": candidate.get("version") or UNKNOWN,
        "api": candidate.get("api") or [],
        "family": candidate.get("family") or UNKNOWN,
        "behavior": _string_list(candidate.get("observed_behavior")),
        "evidence": _string_list(candidate.get("oracle_evidence") or candidate.get("source_artifacts")),
    }
    if candidate.get("trigger_condition"):
        description["trigger_condition"] = candidate["trigger_condition"]
    if candidate.get("oracle_type"):
        description["oracle_type"] = candidate["oracle_type"]
    return description


def _eligibility(candidate: dict[str, Any]) -> dict[str, str]:
    status = _as_text(candidate.get("status")).lower()
    semantic = _as_text(candidate.get("semantic_type")).lower()
    haystack = {status, semantic}
    if any(value in INELIGIBLE_CLASSIFICATIONS for value in haystack):
        return {"status": "ineligible", "reason": "candidate classification is closed, baseline, unsupported, or observation-only"}
    if any(value in ELIGIBLE_CLASSIFICATIONS for value in haystack):
        return {"status": "eligible", "reason": "candidate classification remains triage-candidate-like"}
    if "candidate" in status or "candidate" in semantic:
        return {"status": "eligible", "reason": "candidate-like classification marker is present"}
    return {"status": "needs_review", "reason": "classification is not explicit enough for automatic post-processing"}


def _run_id(candidate_id: str, source_path: Path) -> str:
    digest = hashlib.sha256(f"{candidate_id}:{source_path}:{_utc_now()}".encode("utf-8")).hexdigest()[:12]
    return f"{_slugify(candidate_id)}-{digest}"


def default_output_root(candidate_artifact: Path, candidate_id: str) -> Path:
    return DEFAULT_BASE_OUT / _slugify(candidate_artifact.stem) / _slugify(candidate_id)


def _stage(status: str, artifact: Path | None = None) -> dict[str, Any]:
    return {"status": status, "artifact": str(artifact) if artifact else ""}


def _load_stage(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _discovered_callers(caller_discovery_path: Path | None, context_pack_path: Path) -> list[dict[str, Any]]:
    if caller_discovery_path and caller_discovery_path.exists():
        data = _load_stage(caller_discovery_path)
        return list(data.get("repositories") or [])
    if context_pack_path.exists():
        pack = _load_stage(context_pack_path)
        discovery = pack.get("caller_discovery_evidence")
        if isinstance(discovery, dict):
            return list(discovery.get("repositories") or [])
    return []


def _final_assessment(security_impact_path: Path | None) -> str:
    if security_impact_path and security_impact_path.exists():
        data = _load_stage(security_impact_path)
        result = data.get("result")
        if isinstance(result, dict):
            return _as_text(result.get("security_classification")) or "not_assessed"
    return "not_assessed"


def _confidence(*paths: Path | None) -> str:
    for path in reversed([p for p in paths if p and p.exists()]):
        data = _load_stage(path)
        result = data.get("result")
        if isinstance(result, dict) and _as_text(result.get("confidence")):
            return _as_text(result["confidence"])
    return UNKNOWN


def _unknowns(*paths: Path | None) -> list[str]:
    items: list[str] = []
    for path in paths:
        if not path or not path.exists():
            continue
        data = _load_stage(path)
        for source in (data, data.get("result") if isinstance(data.get("result"), dict) else {}):
            for item in _string_list(source.get("unknowns")):
                if item not in items:
                    items.append(item)
    return items


def write_run_summary(
    path: Path,
    *,
    run_id: str,
    candidate: dict[str, Any],
    source_candidate: Path,
    route: str,
    status: str,
    stages: dict[str, dict[str, Any]],
    caller_discovery_path: Path | None,
    context_pack_path: Path,
    impact_exploration_path: Path | None,
    exploitability_path: Path | None,
    security_impact_path: Path | None,
) -> dict[str, Any]:
    summary = {
        "schema": ROUTER_SCHEMA,
        "generated_by": GENERATED_BY,
        "run_id": run_id,
        "candidate_id": candidate["candidate_id"],
        "source_candidate": {
            "path": str(source_candidate),
            "sha256": _sha256(source_candidate),
        },
        "route": {
            "known_caller": route == "known_caller",
            "caller_discovery": route == "caller_discovery",
        },
        "status": status,
        "stages": stages,
        "discovered_callers": _discovered_callers(caller_discovery_path, context_pack_path),
        "final_assessment": _final_assessment(security_impact_path),
        "confidence": _confidence(impact_exploration_path, exploitability_path, security_impact_path),
        "unknowns": _unknowns(caller_discovery_path, impact_exploration_path, exploitability_path, security_impact_path),
        "claim_policy": {
            "vulnerability": "not_assessed_by_runner",
            "cve": "not_assessed_by_runner",
            "security_impact": "not_assessed_by_runner",
        },
    }
    write_yaml(path, summary)
    return summary


def run_impactlift_router(
    candidate_artifact: Path,
    *,
    candidate_id: str | None = None,
    output_root: Path | None = None,
    workspace: Path | None = None,
    impact_provider: AgentProvider | None = None,
    caller_discovery_provider: AgentProvider | None = None,
    external_provider: CallerDiscoveryProvider | None = None,
    evidence_roots: Iterable[Path] | None = None,
    workspace_roots: Iterable[Path] | None = None,
    timeout_seconds: int = 900,
    allow_needs_review: bool = False,
) -> dict[str, Any]:
    source_path = candidate_artifact.expanduser().resolve()
    candidate_data = load_artifact(source_path)
    raw_record = select_candidate(candidate_data, candidate_id)
    candidate = normalize_candidate_record(raw_record)
    eligibility = _eligibility(candidate)

    out_root = (
        output_root.expanduser().resolve()
        if output_root is not None
        else (Path.cwd().resolve() / default_output_root(source_path, candidate["candidate_id"]))
    )
    out_root.mkdir(parents=True, exist_ok=True)
    summary_path = out_root / "run_summary.yaml"
    run_id = _run_id(candidate["candidate_id"], source_path)

    if eligibility["status"] == "ineligible" or (eligibility["status"] == "needs_review" and not allow_needs_review):
        stages = {
            "caller_discovery": _stage("not_run"),
            "impact_exploration": _stage("not_run"),
            "exploitability": _stage("not_run"),
            "security_impact": _stage("not_run"),
        }
        summary = write_run_summary(
            summary_path,
            run_id=run_id,
            candidate=candidate,
            source_candidate=source_path,
            route="skipped",
            status=f"skipped_{eligibility['status']}",
            stages=stages,
            caller_discovery_path=None,
            context_pack_path=out_root / "candidate_context_pack.yaml",
            impact_exploration_path=None,
            exploitability_path=None,
            security_impact_path=None,
        )
        summary["eligibility"] = eligibility
        write_yaml(summary_path, summary)
        return {"summary": summary, "summary_path": summary_path, "output_root": out_root, "candidate": candidate}

    context_pack_path = out_root / "candidate_context_pack.yaml"
    impact_exploration_path = out_root / "impact_exploration.yaml"
    exploitability_path = out_root / "exploitability.yaml"
    security_impact_path = out_root / "security_impact.yaml"
    caller_discovery_path: Path | None = None

    if _has_known_caller(candidate):
        route = "known_caller"
        pack = build_context_pack(source_path, candidate_id=candidate_id)
        write_context_pack(context_pack_path, pack)
        caller_stage = _stage("not_run_known_caller")
    else:
        route = "caller_discovery"
        caller_input_path = out_root / "caller_discovery_input.yaml"
        caller_discovery_path = out_root / "caller_discovery.yaml"
        caller_input = _candidate_description(candidate)
        write_yaml(caller_input_path, caller_input)
        run_caller_discovery(
            caller_input_path,
            caller_discovery_path,
            caller_discovery_provider,
            evidence_roots=evidence_roots,
            workspace_roots=workspace_roots,
            external_provider=external_provider,
        )
        pack = build_context_pack_from_caller_discovery(caller_discovery_path)
        write_context_pack(context_pack_path, pack)
        caller_stage = _stage("completed", caller_discovery_path)

    selected_workspace = workspace.expanduser().resolve() if workspace is not None else Path.cwd().resolve()
    provider = impact_provider or CodexAgentProvider(selected_workspace, timeout_seconds=timeout_seconds)
    run_impactlift(context_pack_path, impact_exploration_path, provider)
    run_exploitability(context_pack_path, impact_exploration_path, exploitability_path, provider)
    run_security_impact(
        context_pack_path,
        impact_exploration_path,
        exploitability_path,
        security_impact_path,
        provider,
    )
    stages = {
        "caller_discovery": caller_stage,
        "impact_exploration": _stage("completed", impact_exploration_path),
        "exploitability": _stage("completed", exploitability_path),
        "security_impact": _stage("completed", security_impact_path),
    }
    summary = write_run_summary(
        summary_path,
        run_id=run_id,
        candidate=candidate,
        source_candidate=source_path,
        route=route,
        status="completed",
        stages=stages,
        caller_discovery_path=caller_discovery_path,
        context_pack_path=context_pack_path,
        impact_exploration_path=impact_exploration_path,
        exploitability_path=exploitability_path,
        security_impact_path=security_impact_path,
    )
    summary["eligibility"] = eligibility
    write_yaml(summary_path, summary)
    return {
        "summary": summary,
        "summary_path": summary_path,
        "output_root": out_root,
        "candidate": candidate,
        "candidate_context_pack": context_pack_path,
        "caller_discovery": caller_discovery_path,
        "impact_exploration": impact_exploration_path,
        "exploitability": exploitability_path,
        "security_impact": security_impact_path,
    }


def _json_preview(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def load_mock_external_provider(path: Path) -> MockExternalSearchProvider:
    data = yaml.safe_load(path.expanduser().read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("mock external search fixture must be a mapping")
    raw_results = data.get("results_by_query", data)
    if not isinstance(raw_results, dict):
        raise ValueError("mock external search fixture results_by_query must be a mapping")
    results_by_query: dict[str, list[ExternalCodeHit]] = {}
    for query, rows in raw_results.items():
        if not isinstance(rows, list):
            raise ValueError(f"mock external search query {query!r} must map to a list")
        hits: list[ExternalCodeHit] = []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError(f"mock external search hit {query!r}[{index}] must be a mapping")
            hits.append(
                ExternalCodeHit(
                    repository_name=_as_text(row.get("repository_name") or row.get("repository")),
                    repository_url=_as_text(row.get("repository_url") or row.get("url")),
                    file_path=_as_text(row.get("file_path") or row.get("file")),
                    file_url=_as_text(row.get("file_url") or row.get("url")),
                    fragments=tuple(_string_list(row.get("fragments") or row.get("fragment"))),
                )
            )
        results_by_query[str(query)] = hits
    return MockExternalSearchProvider(results_by_query)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Route a CipherLens candidate artifact into Caller Discovery and ImpactLift post-processing."
    )
    parser.add_argument("--candidate-artifact", type=Path, required=True)
    parser.add_argument("--candidate-id")
    parser.add_argument("--out-root", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--github-search", action="store_true", help="Use GitHub code search via GITHUB_TOKEN/GH_TOKEN.")
    parser.add_argument("--mock-external-search-results", type=Path, help="Use deterministic external search hits from a YAML fixture.")
    parser.add_argument("--deterministic-provider", action="store_true", help="Use an offline deterministic ImpactLift provider for smoke runs.")
    parser.add_argument("--allow-needs-review", action="store_true")
    args = parser.parse_args()

    if args.github_search and args.mock_external_search_results:
        raise SystemExit("--github-search and --mock-external-search-results are mutually exclusive")
    if args.github_search:
        external_provider = GitHubSourceProvider.from_environment()
    elif args.mock_external_search_results:
        external_provider = load_mock_external_provider(args.mock_external_search_results)
    else:
        external_provider = None
    impact_provider = DeterministicImpactProvider() if args.deterministic_provider else None
    result = run_impactlift_router(
        args.candidate_artifact,
        candidate_id=args.candidate_id,
        output_root=args.out_root,
        workspace=args.workspace,
        timeout_seconds=args.timeout_seconds,
        impact_provider=impact_provider,
        external_provider=external_provider,
        allow_needs_review=args.allow_needs_review,
    )
    print(f"[OK] ImpactLift router: {result['summary_path']}")
    print(f"[STATUS] {result['summary']['status']}")
    print(f"[ROUTE] {_json_preview(result['summary']['route'])}")


if __name__ == "__main__":
    main()
