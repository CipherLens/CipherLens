from __future__ import annotations

import argparse
import asyncio
import json
import mimetypes
import threading
import time
import uuid
from argparse import Namespace
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from starlette.responses import StreamingResponse
from pydantic import BaseModel

from analysis.card_contract_loader import TARGET_RUNTIME_STATUS, load_card_bundle, target_runtime_status
from analysis.full_mainline_glm_oracle_campaign import run_campaign
from analysis.stage_based_orchestrator import run_stage_based_orchestrator
from caller_audit.demo_replay_pipeline import run_demo_replay
from caller_audit.io_utils import write_yaml
from caller_audit.run_stage_normalizer import (
    demo_artifact_map,
    mainline_artifact_map,
    normalize_run_stages,
    read_yaml as read_stage_yaml,
    stage_based_artifact_map,
    summarize_pipeline_coverage,
)


API_SCHEMA = "cipherlens_demo_api_run_v1"
TRACE_SCHEMA = "cipherlens_demo_api_trace_v1"
SSE_SCHEMA = "cipherlens_run_event_stream_v1"
DEFAULT_RUN_ROOT = Path("artifacts/caller_audit/web_demo_runs")
DEFAULT_WORKSPACE = Path(__file__).resolve().parents[1]
LIVE_FAMILY_ALIASES = {
    "mac-lifecycle": "mac_digest_lifecycle",
    "mac lifecycle": "mac_digest_lifecycle",
    "object_state_lifecycle": "mac_digest_lifecycle",
    "mac_digest_lifecycle": "mac_digest_lifecycle",
    "der_pointer_consumption": "der_parser_full_consumption",
    "parser_full_consumption": "der_parser_full_consumption",
    "protocol_policy_semantic": "roundtrip_metamorphic",
}
LIVE_LIBRARY_TARGETS = {
    "openssl": "openssl-3.5.5-asan",
    "mbedtls": "mbedtls-4.1.0-asan",
    "mbedtls-4.1.0": "mbedtls-4.1.0-asan",
    "mbedtls-3.6.4": "mbedtls-3.6.4-asan",
    "botan": "botan-3.10.0-asan",
    "wolfssl": "wolfssl-asan",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def _write_jsonl_row(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def format_sse_event(event: dict[str, Any]) -> str:
    return "event: run_stage\ndata: " + json.dumps(event, ensure_ascii=False) + "\n\n"


def _stage(status: str, artifact: str = "", message: str = "") -> dict[str, Any]:
    return {"status": status, "artifact": artifact, "message": message}


def _initial_stages() -> dict[str, dict[str, Any]]:
    return {
        "family": _stage("pending", message="Waiting for demo selection."),
        "proposal": _stage("pending", message="Waiting to load proposal."),
        "validation": _stage("pending", message="Waiting for proposal validation."),
        "render": _stage("pending", message="Waiting for harness render."),
        "compile": _stage("pending", message="Waiting for compilation."),
        "runtime": _stage("pending", message="Waiting for runtime execution."),
        "oracle": _stage("pending", message="Waiting for oracle analysis."),
        "candidate": _stage("pending", message="Waiting for candidate generation."),
        "caller_discovery": _stage("pending", message="Waiting for caller discovery."),
        "impact_exploration": _stage("pending", message="Waiting for Impact Exploration."),
        "exploitability": _stage("pending", message="Waiting for Exploitability Analysis."),
        "security_impact": _stage("pending", message="Waiting for Security Impact Assessment."),
    }


def _stage_map_from_summary(summary: dict[str, Any] | None, impact: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    stages = _initial_stages()
    if summary:
        raw_stages = summary.get("stages") or {}
        for source, target in {
            "family": "family",
            "proposal": "proposal",
            "validation": "validation",
            "render": "render",
            "compile": "compile",
            "runtime": "runtime",
            "oracle": "oracle",
            "candidate": "candidate",
        }.items():
            if isinstance(raw_stages.get(source), dict):
                stages[target].update(raw_stages[source])
        if isinstance(raw_stages.get("impactlift"), dict):
            stages["caller_discovery"].update(raw_stages["impactlift"])
            stages["impact_exploration"].update(raw_stages["impactlift"])
            stages["exploitability"].update(raw_stages["impactlift"])
            stages["security_impact"].update(raw_stages["impactlift"])
    if impact:
        raw = impact.get("stages") or {}
        for source, target in {
            "caller_discovery": "caller_discovery",
            "impact_exploration": "impact_exploration",
            "exploitability": "exploitability",
            "security_impact": "security_impact",
        }.items():
            if isinstance(raw.get(source), dict):
                stages[target].update(raw[source])
    return stages


def _enrich_callers(callers: list[dict[str, Any]], call_sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for caller in callers:
        item = dict(caller)
        name = str(item.get("name") or item.get("repository") or "")
        sites = [dict(site) for site in call_sites if str(site.get("repository") or "") == name]
        if sites:
            item["call_sites"] = sites
            item["files"] = sorted({str(site.get("file")) for site in sites if site.get("file")})
            matched: list[str] = []
            for site in sites:
                value = site.get("matched_api")
                if isinstance(value, list):
                    matched.extend(str(part) for part in value)
                elif value:
                    matched.extend(part.strip() for part in str(value).split(","))
            item["matched_api"] = sorted({part for part in matched if part})
        enriched.append(item)
    return enriched


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _candidate_id(record: dict[str, Any], fallback: str) -> str:
    for key in ("candidate_id", "logical_candidate_id", "case_id", "input_id"):
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    dispatcher = record.get("dispatcher_input")
    if isinstance(dispatcher, dict):
        for key in ("candidate_id", "input_id"):
            value = dispatcher.get(key)
            if value not in (None, ""):
                return str(value)
    return fallback


def _candidate_library(record: dict[str, Any]) -> str:
    value = record.get("library") or record.get("target") or record.get("target_library")
    dispatcher = record.get("dispatcher_input")
    if not value and isinstance(dispatcher, dict):
        value = dispatcher.get("target")
    return str(value or "unknown")


def _candidate_api(record: dict[str, Any]) -> list[str]:
    for key in ("api", "api_or_function", "target_api", "function", "component"):
        values = [str(item) for item in _as_list(record.get(key)) if item not in (None, "")]
        if values:
            return values
    dispatcher = record.get("dispatcher_input")
    if isinstance(dispatcher, dict):
        observed = dispatcher.get("observed_behavior")
        if isinstance(observed, dict) and observed.get("command"):
            return [str(observed["command"])]
    return []


def _candidate_status(record: dict[str, Any]) -> str:
    for key in ("status", "classification", "candidate_level", "candidate_label", "semantic_type"):
        value = record.get(key)
        if value not in (None, "", [], {}) and not isinstance(value, dict):
            return str(value)
    return "needs_review"


def _candidate_bucket(status: str) -> str:
    lowered = status.lower()
    if any(part in lowered for part in ("closed", "safe", "negative", "not_reproducible", "downgraded")):
        return "closed"
    if any(part in lowered for part in ("candidate", "active", "semantic_gap", "robustness")):
        return "active"
    return "needs_review"


def _family_group(family: str) -> str:
    lowered = family.lower()
    if any(part in lowered for part in ("parser", "x509", "asn1", "der", "pkey", "pkcs")):
        return "Parser Semantics"
    if any(part in lowered for part in ("lifecycle", "mac", "heap")):
        return "Lifecycle"
    if any(part in lowered for part in ("memory", "heap", "buffer", "null")):
        return "Memory / Heap"
    if any(part in lowered for part in ("contract", "semantic")):
        return "API Contract"
    return "Other"


def _is_cross_cutting_oracle_layer(family_id: str, family: dict[str, Any], card: dict[str, Any]) -> bool:
    text = " ".join(
        str(part or "").lower()
        for part in (
            family_id,
            family.get("description"),
            card.get("description"),
            card.get("notes"),
            (card.get("oracle_contract") or {}).get("oracle_type") if isinstance(card.get("oracle_contract"), dict) else "",
        )
    )
    oracle_types = {str(item).lower() for item in family.get("oracle_types") or []}
    return (
        family_id.endswith("_oracle")
        and family_id in oracle_types
        and ("observation layer" in text or "cross-cutting oracle layer" in text)
    )


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_string_list(item))
        return [item for item in out if item]
    if isinstance(value, (str, int, float, bool)):
        text = str(value).strip()
        return [text] if text else []
    return []


def _family_behavior_contract(family_id: str, card: dict[str, Any]) -> dict[str, Any]:
    """Expose frontend-ready contract sections from existing family-card fields."""
    if not isinstance(card, dict) or not card:
        return {"source": "", "sections": []}
    harness_shape = card.get("harness_shape") if isinstance(card.get("harness_shape"), dict) else {}
    oracle_contract = card.get("oracle_contract") if isinstance(card.get("oracle_contract"), dict) else {}
    sections = [
        {
            "id": "trigger_condition",
            "title": "Trigger Condition",
            "body": _string_list(harness_shape.get("trigger")),
            "source_field": "harness_shape.trigger",
        },
        {
            "id": "vulnerability_intervention",
            "title": "Vulnerability Intervention",
            "body": _string_list(card.get("mutation_slots"))[:4],
            "source_field": "mutation_slots",
        },
        {
            "id": "critical_execution",
            "title": "Critical Execution",
            "body": _string_list(card.get("input_model")),
            "source_field": "input_model",
        },
        {
            "id": "expected_relation",
            "title": "Expected Relation",
            "body": _string_list(
                [
                    oracle_contract.get("pass_condition"),
                    oracle_contract.get("candidate_condition"),
                ]
            ),
            "source_field": "oracle_contract.pass_condition + oracle_contract.candidate_condition",
        },
        {
            "id": "observable_evidence",
            "title": "Observable Evidence",
            "body": _string_list(harness_shape.get("observables")),
            "source_field": "harness_shape.observables",
        },
    ]
    return {
        "source": f"knowledge_raw/family_cards/{family_id}.yaml",
        "sections": sections,
        "oracle_type": oracle_contract.get("oracle_type", ""),
    }


def _family_transfer_signature(family_id: str, card: dict[str, Any]) -> dict[str, Any]:
    """Derive compact migration-signature tags from real family-card constraints."""
    if not isinstance(card, dict) or not card:
        return {"source": "", "tags": []}
    harness_shape = card.get("harness_shape") if isinstance(card.get("harness_shape"), dict) else {}
    tags: list[str] = []
    tags.extend(_string_list(card.get("required_target_cards"))[:2])
    tags.extend(_string_list(harness_shape.get("observables"))[:2])
    tags.extend(_string_list(card.get("mutation_slots"))[:2])
    deduped = list(dict.fromkeys(tag.replace("_", " ") for tag in tags if tag))
    return {
        "source": f"knowledge_raw/family_cards/{family_id}.yaml",
        "derivation": "required_target_cards + harness_shape.observables + mutation_slots",
        "tags": deduped[:6],
    }


def _library_label(value: str) -> str:
    if value == "openssl":
        return "OpenSSL"
    if value == "mbedtls-3.6.4":
        return "Mbed TLS 3.6.4"
    if value == "mbedtls-4.1.0":
        return "Mbed TLS 4.1.0"
    if value == "mbedtls":
        return "Mbed TLS"
    if value == "botan-3.10.0":
        return "Botan 3.10.0"
    if value == "wolfssl":
        return "wolfSSL"
    return value


def _candidate_title(record: dict[str, Any], candidate_id: str) -> str:
    family = str(record.get("family") or "Candidate")
    api = _candidate_api(record)
    if "mac" in family.lower() and api:
        return "MAC Lifecycle"
    if api:
        return " ".join(api)[:80]
    return candidate_id.replace("_", " ").replace("-", " ")[:80]


def _candidate_from_record(record: dict[str, Any], artifact: Path, index: int) -> dict[str, Any]:
    candidate_id = _candidate_id(record, f"{artifact.stem}-{index}")
    family = str(record.get("family") or "unknown")
    status = _candidate_status(record)
    impact_summary = artifact.parent.parent / "impactlift" / "run_summary.yaml"
    impact_state = "analyzed" if impact_summary.exists() else "pending"
    final_assessment = ""
    if impact_summary.exists():
        try:
            final_assessment = str(_read_yaml(impact_summary).get("final_assessment") or "")
        except Exception:
            final_assessment = ""
    return {
        "candidate_id": candidate_id,
        "title": _candidate_title(record, candidate_id),
        "library": _candidate_library(record),
        "family": family,
        "api": _candidate_api(record),
        "status": status,
        "bucket": _candidate_bucket(status),
        "impact_state": impact_state,
        "final_assessment": final_assessment,
        "confidence": str(record.get("confidence") or ""),
        "classification": str(record.get("classification") or record.get("semantic_type") or ""),
        "observed_behavior": record.get("observed_behavior") or record.get("behavior") or {},
        "evidence": [str(item) for item in _as_list(record.get("evidence") or record.get("oracle_evidence"))],
        "artifact": str(artifact.resolve()),
    }


def _load_candidate_artifact(path: Path) -> list[dict[str, Any]]:
    data = _read_yaml(path)
    items = data.get("items")
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    candidate = data.get("candidate")
    if isinstance(candidate, dict):
        return [candidate]
    if any(key in data for key in ("candidate_id", "classification", "family", "api", "oracle_type")):
        return [data]
    return []


@dataclass(frozen=True)
class DemoConfig:
    id: str
    title: str
    family: str
    target_library: str
    mode: str
    proposal: Path
    mock_external_search_results: Path
    description: str

    def api_view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "family": self.family,
            "target_library": self.target_library,
            "mode": self.mode,
            "proposal_label": "Verified Proposal",
            "description": self.description,
            "discovery_modes": ["offline_verified_replay", "live_github_search"],
            "default_discovery_mode": "offline_verified_replay",
        }


def default_demo_registry(workspace: Path) -> dict[str, DemoConfig]:
    return {
        "mac-lifecycle": DemoConfig(
            id="mac-lifecycle",
            title="MAC Lifecycle",
            family="MAC Lifecycle",
            target_library="OpenSSL",
            mode="Regression Replay",
            proposal=workspace / "artifacts/caller_audit/cmac-demo-regression/frozen_cmac_lifecycle_proposal.yaml",
            mock_external_search_results=workspace
            / "artifacts/caller_audit/cmac-caller-discovery-v1/mock_github_search_results.yaml",
            description="Stateful cryptographic API lifecycle testing",
        )
    }


class CreateDemoRunRequest(BaseModel):
    demo_id: str = "mac-lifecycle"
    mode: str = "regression"
    discovery_mode: str = "offline_verified_replay"


class CreateRunRequest(BaseModel):
    family: str = "mac-lifecycle"
    library: str = "openssl"
    mode: str = "regression"
    execution_level: str = "syntax_only"
    discovery_mode: str = "offline_verified_replay"


class DemoApiState:
    def __init__(
        self,
        *,
        workspace: Path = DEFAULT_WORKSPACE,
        run_root: Path = DEFAULT_RUN_ROOT,
        registry: dict[str, DemoConfig] | None = None,
    ) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.run_root = (self.workspace / run_root).resolve() if not run_root.is_absolute() else run_root.resolve()
        self.registry = registry or default_demo_registry(self.workspace)
        self.runs: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    def _new_run_id(self) -> str:
        return "CL-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]

    def run_dir(self, run_id: str) -> Path:
        return self.run_root / run_id

    def trace_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "trace.jsonl"

    def state_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "api_run_state.yaml"

    def write_state(self, run_id: str) -> None:
        with self.lock:
            state = dict(self.runs[run_id])
        serializable = {k: v for k, v in state.items() if k != "thread"}
        write_yaml(self.state_path(run_id), serializable)

    def record_event(self, run_id: str, event: dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("timestamp", _utc_now())
        event.setdefault("schema", TRACE_SCHEMA)
        stage = str(event.get("stage") or "run")
        status = str(event.get("status") or "running")
        artifact = str(event.get("artifact") or "")
        with self.lock:
            run = self.runs[run_id]
            run["updated_at"] = event["timestamp"]
            if status == "failed":
                run["status"] = "failed"
            if stage != "run" and status in {"running", "completed", "failed"}:
                run["current_stage"] = stage
            if stage in run["stages"]:
                run["stages"][stage].update(
                    {
                        "status": status,
                        "artifact": artifact,
                        "message": str(event.get("message") or ""),
                        "updated_at": event["timestamp"],
                    }
                )
            if stage == "impactlift" and status in {"completed", "failed"}:
                for inner in ("caller_discovery", "impact_exploration", "exploitability", "security_impact"):
                    run["stages"][inner].update(
                        {
                            "status": status,
                            "artifact": artifact,
                            "message": str(event.get("message") or ""),
                            "updated_at": event["timestamp"],
                        }
                    )
        _write_jsonl_row(self.trace_path(run_id), event)
        self.write_state(run_id)

    def create_run(self, request: CreateDemoRunRequest) -> dict[str, Any]:
        if request.demo_id not in self.registry:
            raise HTTPException(status_code=404, detail=f"unknown demo_id: {request.demo_id}")
        if request.discovery_mode not in {"offline_verified_replay", "live_github_search"}:
            raise HTTPException(status_code=400, detail=f"unsupported discovery_mode: {request.discovery_mode}")
        demo = self.registry[request.demo_id]
        run_id = self._new_run_id()
        run_dir = self.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        now = _utc_now()
        run = {
            "schema": API_SCHEMA,
            "run_id": run_id,
            "demo_id": demo.id,
            "title": demo.title,
            "family": demo.family,
            "target_library": demo.target_library,
            "mode": demo.mode,
            "mode_key": "regression",
            "discovery_mode": request.discovery_mode,
            "status": "queued",
            "current_stage": "queued",
            "created_at": now,
            "updated_at": now,
            "run_dir": str(run_dir),
            "summary_path": str(run_dir / "demo_run_summary.yaml"),
            "trace_path": str(self.trace_path(run_id)),
            "stages": _initial_stages(),
            "error": "",
            "thread": None,
        }
        with self.lock:
            self.runs[run_id] = run
        self.record_event(run_id, {"stage": "run", "status": "queued", "message": "Demo run queued."})
        thread = threading.Thread(target=self._execute_run, args=(run_id, demo, request.discovery_mode), daemon=True)
        with self.lock:
            self.runs[run_id]["thread"] = thread
        self.write_state(run_id)
        thread.start()
        return {"run_id": run_id, "status": "queued"}

    def create_pipeline_run(self, request: CreateRunRequest) -> dict[str, Any]:
        mode = request.mode.lower().strip()
        if mode == "regression":
            demo_id = "mac-lifecycle" if request.family in {"mac-lifecycle", "MAC Lifecycle", "object_state_lifecycle"} else request.family
            return self.create_run(
                CreateDemoRunRequest(
                    demo_id=demo_id,
                    mode="regression",
                    discovery_mode=request.discovery_mode,
                )
            )
        if mode != "live":
            raise HTTPException(status_code=400, detail=f"unsupported mode: {request.mode}")
        run_id = self._new_run_id()
        run_dir = self.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        now = _utc_now()
        family = request.family
        library = request.library
        run = {
            "schema": API_SCHEMA,
            "run_id": run_id,
            "demo_id": "",
            "title": f"{family} on {library}",
            "family": family,
            "target_library": library,
            "library": library,
            "mode": "Live Model-assisted Exploration",
            "mode_key": "live",
            "discovery_mode": "",
            "status": "queued",
            "current_stage": "queued",
            "created_at": now,
            "updated_at": now,
            "run_dir": str(run_dir),
            "summary_path": str(run_dir / "run_manifest.yaml"),
            "trace_path": str(self.trace_path(run_id)),
            "stages": {},
            "error": "",
            "thread": None,
        }
        with self.lock:
            self.runs[run_id] = run
        self.record_event(run_id, {"stage": "run", "status": "queued", "message": "Live run queued."})
        execution_level = request.execution_level if request.execution_level in {"syntax_only", "runtime_smoke"} else "syntax_only"
        with self.lock:
            self.runs[run_id]["execution_level"] = execution_level
        thread = threading.Thread(target=self._execute_live_run, args=(run_id, family, library, execution_level), daemon=True)
        with self.lock:
            self.runs[run_id]["thread"] = thread
        self.write_state(run_id)
        thread.start()
        return {"run_id": run_id, "status": "queued"}

    def _execute_run(self, run_id: str, demo: DemoConfig, discovery_mode: str) -> None:
        self.record_event(run_id, {"stage": "run", "status": "running", "message": "Backend worker started."})
        with self.lock:
            self.runs[run_id]["status"] = "running"
            self.runs[run_id]["current_stage"] = "proposal"
        self.write_state(run_id)
        try:
            result = run_demo_replay(
                demo.proposal,
                output_root=self.run_dir(run_id),
                workspace=self.workspace,
                mock_external_search_results=demo.mock_external_search_results
                if discovery_mode == "offline_verified_replay"
                else None,
                github_search=discovery_mode == "live_github_search",
                stage_callback=lambda event: self.record_event(run_id, event),
            )
            self._merge_completed_summary(run_id, result)
            self.record_event(run_id, {"stage": "run", "status": "completed", "message": "Demo run completed."})
        except Exception as exc:  # pragma: no cover - exercised by failure tests through state shape
            message = f"{type(exc).__name__}: {exc}"
            with self.lock:
                self.runs[run_id]["status"] = "failed"
                self.runs[run_id]["error"] = message
            self.record_event(run_id, {"stage": "run", "status": "failed", "message": message})

    def _execute_live_run(self, run_id: str, family: str, library: str, execution_level: str = "syntax_only") -> None:
        self.record_event(run_id, {"stage": "run", "status": "running", "message": "Live mainline worker started."})
        with self.lock:
            self.runs[run_id]["status"] = "running"
            self.runs[run_id]["current_stage"] = "family_selection"
        self.write_state(run_id)
        try:
            family_key = LIVE_FAMILY_ALIASES.get(family.lower().strip(), family)
            library_key = library.lower().strip()
            target = LIVE_LIBRARY_TARGETS.get(library_key, library)
            self.record_event(
                run_id,
                {
                    "stage": "family_selection",
                    "status": "running",
                    "message": f"Starting mainline for family={family_key}, target={target}.",
                },
            )
            if execution_level == "runtime_smoke":
                self.record_event(run_id, {"stage": "runtime", "status": "running", "message": f"Preparing runtime smoke against {library}."})
                report = run_stage_based_orchestrator(
                    repo_root=self.workspace,
                    out_dir=self.run_dir(run_id),
                    targets=[library],
                    families=[family],
                    execution_mode="runtime_smoke",
                    oracle_mode="dispatch",
                    probe_mode="live",
                    max_families=1,
                    max_cases=12,
                    max_compile_jobs=12,
                    progress_callback=lambda event: self.record_event(run_id, event),
                )
            else:
                args = Namespace(
                    repo_root=str(self.workspace),
                    out_dir=str(self.run_dir(run_id)),
                    dry_run=False,
                    max_families=1,
                    max_cases=12,
                    max_compile_jobs=12,
                    targets=target,
                    families=family_key,
                    seed_source="mixed",
                    execution_mode="syntax_only",
                    oracle_mode="dispatch",
                    probe_mode="live",
                    allow_fallback=True,
                    glm_required=False,
                )
                report = run_campaign(args, progress_callback=lambda event: self.record_event(run_id, event))
            with self.lock:
                run = self.runs[run_id]
                if execution_level == "runtime_smoke" and not report.get("runtime_harness_executed"):
                    run["status"] = "blocked"
                else:
                    run["status"] = "completed" if str(report.get("quality_status", "")).startswith("pass") else "partial"
                run["current_stage"] = "completed"
                run["summary_path"] = str(self.run_dir(run_id) / "run_manifest.yaml")
                if execution_level == "runtime_smoke":
                    run["summary_path"] = str(self.run_dir(run_id) / "quality_report.yaml")
                run["quality_report_path"] = str(self.run_dir(run_id) / "quality_report.yaml")
                run["summary"] = report
                run["execution_level"] = execution_level
                run["updated_at"] = _utc_now()
            self.write_state(run_id)
            self._record_missing_normalized_stage_trace(run_id, mode="live")
            self.record_event(run_id, {"stage": "run", "status": "completed", "message": "Live mainline run completed."})
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            with self.lock:
                self.runs[run_id]["status"] = "failed"
                self.runs[run_id]["error"] = message
            self.record_event(run_id, {"stage": "run", "status": "failed", "message": message})

    def _record_missing_normalized_stage_trace(self, run_id: str, *, mode: str) -> None:
        stages = normalize_run_stages(self.run_dir(run_id), mode=mode, state_stages=None)
        existing = {
            (event.get("stage"), event.get("status"))
            for event in _read_jsonl(self.trace_path(run_id))
        }
        for stage in stages:
            status = str(stage.get("status") or "pending")
            if status == "pending":
                continue
            if (stage["id"], status) in existing:
                continue
            self.record_event(
                run_id,
                {
                    "stage": stage["id"],
                    "status": status,
                    "message": stage.get("message") or f"{stage['label']} {status}.",
                    "artifact": ",".join(stage.get("artifact_ids") or []),
                    "source": "normalized_artifact_state",
                },
            )

    def _merge_completed_summary(self, run_id: str, result: dict[str, Any]) -> None:
        summary_path = Path(result["summary_path"])
        impact_path = Path(result["impactlift_summary"])
        summary = _read_yaml(summary_path)
        impact = _read_yaml(impact_path)
        caller_discovery_path = impact_path.parent / "caller_discovery.yaml"
        caller_discovery = _read_yaml(caller_discovery_path) if caller_discovery_path.exists() else {}
        stages = _stage_map_from_summary(summary, impact)
        discovered_callers = _enrich_callers(
            impact.get("discovered_callers") or [],
            caller_discovery.get("call_sites") or [],
        )
        with self.lock:
            run = self.runs[run_id]
            run["status"] = summary.get("status", "completed")
            run["current_stage"] = "completed"
            run["summary_path"] = str(summary_path)
            run["impactlift_summary_path"] = str(impact_path)
            run["candidate_path"] = str(result["candidate"])
            run["stages"] = stages
            run["final_assessment"] = impact.get("final_assessment")
            run["confidence"] = impact.get("confidence")
            run["discovered_callers"] = discovered_callers
            run["claim_policy"] = impact.get("claim_policy") or summary.get("claim_policy") or {}
            run["updated_at"] = _utc_now()
        self.write_state(run_id)

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self.lock:
            run = self.runs.get(run_id)
            if run is None:
                path = self.state_path(run_id)
                if path.exists():
                    run = _read_yaml(path)
                    self.runs[run_id] = run
        if run is None:
            raise HTTPException(status_code=404, detail=f"unknown run_id: {run_id}")
        state = {k: v for k, v in run.items() if k != "thread"}
        mode_key = str(state.get("mode_key") or "regression")
        state["stages"] = normalize_run_stages(self.run_dir(run_id), mode=mode_key, state_stages=state.get("stages"))
        state["pipeline_coverage"] = summarize_pipeline_coverage(state["stages"])
        if state.get("status") in {"completed", "partial"}:
            state["run_status_label"] = state["pipeline_coverage"]["pipeline_coverage_label"]
        else:
            state["run_status_label"] = str(state.get("status") or "queued").replace("_", " ").title()
        state["artifacts"] = self.artifacts(run_id)["artifacts"]
        return state

    def trace(self, run_id: str) -> dict[str, Any]:
        self.get_run(run_id)
        return {"run_id": run_id, "events": _read_jsonl(self.trace_path(run_id))}

    async def event_stream(self, run_id: str):
        self.get_run(run_id)
        sent = 0
        idle_ticks = 0
        while True:
            events = _read_jsonl(self.trace_path(run_id))
            for event in events[sent:]:
                sent += 1
                yield format_sse_event({**event, "schema": SSE_SCHEMA, "run_id": run_id})
            try:
                state = self.get_run(run_id)
                terminal = state.get("status") in {"completed", "partial", "failed", "blocked", "error"}
            except HTTPException:
                terminal = True
            if terminal and sent >= len(events):
                break
            idle_ticks += 1
            if idle_ticks % 15 == 0:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.5)

    def _artifact_candidates(self, run_id: str) -> dict[str, Path]:
        with self.lock:
            run = self.runs.get(run_id)
        if run is None:
            path = self.state_path(run_id)
            if path.exists():
                run = _read_yaml(path)
            else:
                raise HTTPException(status_code=404, detail=f"unknown run_id: {run_id}")
        root = self.run_dir(run_id)
        artifacts: dict[str, Path] = {
            "trace": self.trace_path(run_id),
            "api_run_state": self.state_path(run_id),
        }
        mapping = mainline_artifact_map(root) if run.get("mode_key") == "live" else demo_artifact_map(root)
        if run.get("mode_key") == "live" and ((root / "stage_trace.yaml").exists() or (root / "campaign_plan.yaml").exists()):
            mapping = stage_based_artifact_map(root)
        artifacts.update({artifact_id: root / rel_path for artifact_id, rel_path in mapping.items()})
        return artifacts

    def artifacts(self, run_id: str) -> dict[str, Any]:
        candidates = self._artifact_candidates(run_id)
        items = []
        for artifact_id, path in candidates.items():
            resolved = path.resolve()
            if not resolved.exists():
                continue
            mime = mimetypes.guess_type(resolved.name)[0] or "text/plain"
            items.append(
                {
                    "id": artifact_id,
                    "label": artifact_id.replace("_", " ").title(),
                    "path": str(resolved),
                    "size": resolved.stat().st_size,
                    "content_type": mime,
                }
            )
        return {"run_id": run_id, "artifacts": items}

    def artifact_content(self, run_id: str, artifact_id: str) -> PlainTextResponse:
        candidates = self._artifact_candidates(run_id)
        if artifact_id not in candidates:
            raise HTTPException(status_code=404, detail=f"unknown artifact_id: {artifact_id}")
        path = candidates[artifact_id].resolve()
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"artifact not available: {artifact_id}")
        run_root = self.run_dir(run_id).resolve()
        try:
            path.relative_to(run_root)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="artifact is outside run directory") from exc
        content = path.read_text(encoding="utf-8", errors="replace")
        media_type = mimetypes.guess_type(path.name)[0] or "text/plain"
        return PlainTextResponse(content, media_type=media_type)

    def candidates(self) -> dict[str, Any]:
        source_paths = [
            self.workspace / "artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/candidate_queue.yaml",
            self.workspace / "artifacts/candidate_queue/candidate_queue.yaml",
        ]
        source_paths.extend(self.run_root.glob("CL-*/candidate/*.yaml"))
        candidates: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for path in source_paths:
            if not path.exists() or not path.is_file():
                continue
            try:
                records = _load_candidate_artifact(path)
            except Exception:
                continue
            for index, record in enumerate(records):
                item = _candidate_from_record(record, path, index)
                key = (item["candidate_id"], item["artifact"])
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(item)
        stats = {
            "total": len(candidates),
            "active": sum(1 for item in candidates if item["bucket"] == "active"),
            "needs_review": sum(1 for item in candidates if item["bucket"] == "needs_review"),
            "closed": sum(1 for item in candidates if item["bucket"] == "closed"),
            "impact_analyzed": sum(1 for item in candidates if item["impact_state"] == "analyzed"),
        }
        landscape: dict[str, int] = {}
        libraries: dict[str, int] = {}
        caller_links = 0
        for item in candidates:
            landscape[_family_group(item["family"])] = landscape.get(_family_group(item["family"]), 0) + 1
            library = str(item["library"]).upper()
            libraries[library] = libraries.get(library, 0) + 1
        with self.lock:
            for run in self.runs.values():
                caller_links += len(run.get("discovered_callers") or [])
        return {
            "schema": "cipherlens_candidate_index_v1",
            "stats": stats,
            "library_counts": libraries,
            "landscape": [{"family": key, "count": value} for key, value in sorted(landscape.items())],
            "caller_links": caller_links,
            "candidates": candidates,
        }

    def candidate_detail(self, candidate_id: str) -> dict[str, Any]:
        index = self.candidates()
        for item in index["candidates"]:
            if item["candidate_id"] != candidate_id:
                continue
            artifact = Path(item["artifact"])
            record = {}
            try:
                records = _load_candidate_artifact(artifact)
                record = records[0] if records else {}
            except Exception:
                record = {}
            run_root = artifact.parent.parent if "/web_demo_runs/" in artifact.as_posix() else artifact.parent
            context_root = run_root / "impactlift"
            return {
                "schema": "cipherlens_candidate_detail_v1",
                "candidate": item,
                "signal": {
                    "family": item["family"],
                    "library": item["library"],
                    "api": item["api"],
                    "status": item["status"],
                    "observed_behavior": item.get("observed_behavior"),
                },
                "execution_evidence": {
                    "artifact": str(artifact),
                    "record": record,
                },
                "evaluation_evidence": {
                    "classification": item.get("classification"),
                    "evidence": item.get("evidence", []),
                },
                "context_exploration": {
                    "run_summary": read_stage_yaml(context_root / "run_summary.yaml"),
                    "caller_discovery": read_stage_yaml(context_root / "caller_discovery.yaml"),
                },
                "artifacts": [
                    {"id": "candidate", "path": str(artifact.resolve())},
                    {"id": "impactlift_run_summary", "path": str((context_root / "run_summary.yaml").resolve())},
                    {"id": "caller_discovery", "path": str((context_root / "caller_discovery.yaml").resolve())},
                ],
            }
        raise HTTPException(status_code=404, detail=f"unknown candidate_id: {candidate_id}")

    def list_runs(self) -> dict[str, Any]:
        with self.lock:
            runs = [{k: v for k, v in run.items() if k != "thread"} for run in self.runs.values()]
        for state_file in sorted(self.run_root.glob("CL-*/api_run_state.yaml")):
            try:
                persisted = _read_yaml(state_file)
            except Exception:
                continue
            if not any(run.get("run_id") == persisted.get("run_id") for run in runs):
                runs.append(persisted)
        runs.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        for run in runs:
            run["stages"] = normalize_run_stages(
                self.run_dir(str(run["run_id"])),
                mode=str(run.get("mode_key") or "regression"),
                state_stages=run.get("stages"),
            )
            run["pipeline_coverage"] = summarize_pipeline_coverage(run["stages"])
            if run.get("status") in {"completed", "partial"}:
                run["run_status_label"] = run["pipeline_coverage"]["pipeline_coverage_label"]
            else:
                run["run_status_label"] = str(run.get("status") or "queued").replace("_", " ").title()
        return {"runs": runs}

    def libraries(self) -> dict[str, Any]:
        items = []
        labels = {
            "openssl": "OpenSSL",
            "mbedtls-3.6.4": "Mbed TLS 3.6.4",
            "mbedtls-4.1.0": "Mbed TLS 4.1.0",
            "botan-3.10.0": "Botan 3.10.0",
            "wolfssl": "wolfSSL",
        }
        for target in TARGET_RUNTIME_STATUS:
            items.append(
                {
                    "id": target,
                    "title": labels.get(target, target),
                    "runtime_capability": target_runtime_status(target),
                    "runtime_ready": target_runtime_status(target) == "runtime_ready",
                    "runtime_reason": None if target_runtime_status(target) == "runtime_ready" else target_runtime_status(target),
                    "status": "available" if target_runtime_status(target) != "blocked_runtime" else "blocked",
                }
            )
        return {"schema": "cipherlens_libraries_v1", "libraries": items}

    def families(self) -> dict[str, Any]:
        bundle = load_card_bundle(self.workspace)
        coverage = bundle.get("coverage_by_family", {})
        family_cards = bundle.get("family_cards", {})
        demos = {demo.family.lower(): demo for demo in self.registry.values()}
        items = []
        excluded = []
        for family_id, family in sorted(bundle.get("framework_families", {}).items()):
            card = family_cards.get(family_id, {}) if isinstance(family_cards, dict) else {}
            if _is_cross_cutting_oracle_layer(family_id, family, card if isinstance(card, dict) else {}):
                excluded.append(
                    {
                        "id": family_id,
                        "reason": "cross_cutting_oracle_observation_layer",
                        "source": "config/family_taxonomy.yaml + knowledge_raw/family_cards",
                    }
                )
                continue
            row = coverage.get(family_id, {})
            targets = []
            for target, target_row in (row.get("framework_target_cards") or {}).items():
                if isinstance(target_row, dict) and target_row.get("api_card"):
                    targets.append(target)
            targets = sorted(dict.fromkeys(targets))
            title = str(family_id).replace("_", " ").title()
            demo_ready = family_id == "object_state_lifecycle" or title.lower() in demos
            live_ready = bool(targets)
            runtime_targets = [target for target in targets if target_runtime_status(target) == "runtime_ready"]
            items.append(
                {
                    "id": family_id,
                    "title": "MAC Lifecycle" if family_id == "object_state_lifecycle" else title,
                    "description": family.get("description", ""),
                    "status": row.get("orchestrator_consumable", "available"),
                    "supported_libraries": targets,
                    "supported_library_labels": [_library_label(target) for target in targets],
                    "behavior_contract": _family_behavior_contract(family_id, card if isinstance(card, dict) else {}),
                    "transfer_signature": _family_transfer_signature(family_id, card if isinstance(card, dict) else {}),
                    "capability": {
                        "model_ready": live_ready,
                        "syntax_ready": live_ready,
                        "runtime_ready": bool(runtime_targets),
                        "runtime_reason": None if runtime_targets else "No runtime-ready target is recorded for this family.",
                    },
                    "demo_ready": demo_ready,
                    "live_ready": live_ready,
                    "priority": row.get("priority", ""),
                    "concrete_pattern_count": len(row.get("concrete_patterns") or []),
                    "needs_human_review": bool(row.get("needs_human_review")),
                }
            )
        return {
            "schema": "cipherlens_families_v1",
            "family_source": [
                "config/family_taxonomy.yaml",
                "config/card_coverage_matrix.yaml",
                "knowledge_raw/family_cards",
            ],
            "filtering_rule": "exclude framework entries that are self-typed *_oracle cross-cutting observation layers",
            "excluded_non_family_entries": excluded,
            "families": items,
        }

    def overview(self) -> dict[str, Any]:
        families = self.families()["families"]
        libraries = self.libraries()["libraries"]
        candidates = self.candidates()
        with self.lock:
            active_runs = sum(1 for run in self.runs.values() if run.get("status") in {"queued", "running"})
        pipeline_quality = read_stage_yaml(
            self.workspace / "artifacts/cross_library/mainline/full_mainline_pipeline_integration_v1/quality_report.yaml"
        )
        rag_glm = read_stage_yaml(
            self.workspace / "artifacts/cross_library/mainline/full_mainline_pipeline_integration_v1/rag_glm_integration_status.yaml"
        )
        pipeline = [
            {"id": "knowledge", "label": "Knowledge", "status": "ready" if pipeline_quality.get("ready_stage_count") else "partial", "summary": {"families": len(families)}},
            {"id": "mapping", "label": "Mapping", "status": rag_glm.get("api_mapping_status", "partial"), "summary": {"rag_available": rag_glm.get("rag_available")}},
            {"id": "generation", "label": "Generation", "status": rag_glm.get("slot_binding_status", "partial"), "summary": {"adapter_recipe_status": rag_glm.get("adapter_recipe_status")}},
            {"id": "execution", "label": "Execution", "status": "partial", "summary": {"runtime_policy": "syntax_only unless runtime_smoke is available"}},
            {"id": "evaluation", "label": "Evaluation", "status": "ready" if pipeline_quality.get("oracle_link_smoke_passed") else "partial", "summary": {"integrated_ledger_count": pipeline_quality.get("integrated_ledger_count", 0)}},
            {"id": "context_exploration", "label": "Context Exploration", "status": "ready", "summary": {"impact_analyzed": candidates["stats"]["impact_analyzed"]}},
        ]
        return {
            "schema": "cipherlens_overview_v1",
            "families": len(families),
            "libraries": len(libraries),
            "active_runs": active_runs,
            "candidates": candidates["stats"]["total"],
            "pipeline": pipeline,
        }


def create_app(state: DemoApiState | None = None) -> FastAPI:
    api_state = state or DemoApiState()
    app = FastAPI(title="CipherLens Demo API", version="0.1.0")
    app.state.demo_api_state = api_state
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/demos")
    def list_demos() -> dict[str, Any]:
        return {"demos": [demo.api_view() for demo in api_state.registry.values()]}

    @app.get("/api/overview")
    def get_overview() -> dict[str, Any]:
        return api_state.overview()

    @app.get("/api/families")
    def get_families() -> dict[str, Any]:
        return api_state.families()

    @app.get("/api/libraries")
    def get_libraries() -> dict[str, Any]:
        return api_state.libraries()

    @app.post("/api/runs")
    def create_run(request: CreateRunRequest) -> dict[str, Any]:
        return api_state.create_pipeline_run(request)

    @app.get("/api/runs")
    def list_runs() -> dict[str, Any]:
        return api_state.list_runs()

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        return api_state.get_run(run_id)

    @app.get("/api/runs/{run_id}/trace")
    def get_run_trace(run_id: str) -> dict[str, Any]:
        return api_state.trace(run_id)

    @app.get("/api/runs/{run_id}/events")
    def get_run_events(run_id: str) -> StreamingResponse:
        return StreamingResponse(api_state.event_stream(run_id), media_type="text/event-stream")

    @app.get("/api/runs/{run_id}/artifacts")
    def get_run_artifacts(run_id: str) -> dict[str, Any]:
        return api_state.artifacts(run_id)

    @app.get("/api/runs/{run_id}/artifacts/{artifact_id}")
    def get_run_artifact(run_id: str, artifact_id: str) -> PlainTextResponse:
        return api_state.artifact_content(run_id, artifact_id)

    @app.post("/api/demo-runs")
    def create_demo_run(request: CreateDemoRunRequest) -> dict[str, Any]:
        return api_state.create_run(request)

    @app.get("/api/demo-runs")
    def list_demo_runs() -> dict[str, Any]:
        return api_state.list_runs()

    @app.get("/api/demo-runs/{run_id}")
    def get_demo_run(run_id: str) -> dict[str, Any]:
        return api_state.get_run(run_id)

    @app.get("/api/demo-runs/{run_id}/trace")
    def get_trace(run_id: str) -> dict[str, Any]:
        return api_state.trace(run_id)

    @app.get("/api/demo-runs/{run_id}/artifacts")
    def get_artifacts(run_id: str) -> dict[str, Any]:
        return api_state.artifacts(run_id)

    @app.get("/api/demo-runs/{run_id}/artifacts/{artifact_id}")
    def get_artifact(run_id: str, artifact_id: str) -> PlainTextResponse:
        return api_state.artifact_content(run_id, artifact_id)

    @app.get("/api/candidates")
    def get_candidates() -> dict[str, Any]:
        return api_state.candidates()

    @app.get("/api/candidates/{candidate_id}")
    def get_candidate(candidate_id: str) -> dict[str, Any]:
        return api_state.candidate_detail(candidate_id)

    return app


app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CipherLens Demo FastAPI backend.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    import uvicorn

    uvicorn.run("caller_audit.demo_api:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
