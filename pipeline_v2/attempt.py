"""One real v2 call chain: Matcher → Merge → Handoff → execution Verdict."""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from candidate_binding.canonical import canonical_candidate_binding_bytes, canonical_validation_bytes
from contract_miner.schema import canonical_vc_bytes
from execution_model.canonical import canonical_json_bytes
from execution_trace.normalize import build_structured_trace
from execution_trace.projection import project_contract_evidence
from execution_trace.relation_eval import evaluate_contract_relations
from execution_trace.verdict import aggregate_execution_verdict
from execution_trace.witness import form_execution_witness
from impact_bridge.violation_package import build_violation_evidence_package
from matcher.orchestrate import MatcherRequest
from pipeline_v2.artifact_store import ArtifactRef, ArtifactStore
from pipeline_v2.manifest import AttemptEventLog, build_attempt_manifest, build_reproduction_manifest
from pipeline_v2.matcher_merge import match_then_merge
from pipeline_v2.merge_execution import prepare_merge_execution
from pipeline_v2.model import AttemptEventType, CampaignAttemptOutcome
from pipeline_v2.runner_backend import PipelineRunnerBackend
from pipeline_v2.impact import bridge_violation, repository_identity
from execution_trace.closure import build_unknown_closure
from template_binding_merge.canonical import canonical_bound_source_bytes, canonical_merge_bytes, canonical_merge_validation_bytes, canonical_source_map_bytes
from template_binding_merge.model import TemplateBundle
from transfer_signature.canonical import canonical_signature_bytes
from trigger_template_interface.canonical import canonical_manifest_bytes


@dataclass(frozen=True)
class PipelineAttemptResult:
    attempt_id: str
    outcome: CampaignAttemptOutcome
    artifacts: Mapping[str, ArtifactRef]
    manifest: Mapping[str, Any]
    verdict: Mapping[str, Any] | None
    closure: Mapping[str, Any] | None = None
    violation_package: Mapping[str, Any] | None = None


def _schema_bytes(value: Mapping[str, Any]) -> bytes:
    schema = value.get("schema_version")
    if schema == "cipherlens.vc.v0_3": return canonical_vc_bytes(value)
    if schema == "cipherlens.transfer_signature.v0.1": return canonical_signature_bytes(value)
    if schema == "cipherlens.trigger_template_interface.v0.1": return canonical_manifest_bytes(value)
    if schema == "cipherlens.candidate_binding.v0.1": return canonical_candidate_binding_bytes(value)
    if schema == "cipherlens.candidate_binding_validation.v0.1": return canonical_validation_bytes(value)
    if schema == "cipherlens.template_binding_merge.v0.1": return canonical_merge_bytes(value)
    if schema == "cipherlens.bound_template_source.v0.1": return canonical_bound_source_bytes(value)
    if schema == "cipherlens.bound_source_map.v0.1": return canonical_source_map_bytes(value)
    if schema == "cipherlens.template_binding_merge_validation.v0.1": return canonical_merge_validation_bytes(value)
    return canonical_json_bytes(value)


class PipelineAttempt:
    """The production integration entry point; it exposes no direct-source shortcut."""

    def __init__(self, store: ArtifactStore, runner_backend: PipelineRunnerBackend, *, workspace_root: Path | None = None, caller_repository_root: Path | None = None, impact_provider: Any = None) -> None:
        self.store, self.runner_backend = store, runner_backend
        self.workspace_root = workspace_root
        self.caller_repository_root, self.impact_provider = caller_repository_root, impact_provider

    def _put(self, artifacts: dict[str, ArtifactRef], name: str, ref: str, value: Mapping[str, Any]) -> ArtifactRef:
        artifact = self.store.put_canonical(ref, value, serializer=_schema_bytes)
        artifacts[name] = artifact
        return artifact

    def run(self, *, attempt_id: str, request: MatcherRequest, bundle: TemplateBundle, adaptation_provider: Any = None, argv: Sequence[str] = ()) -> PipelineAttemptResult:
        events, artifacts = AttemptEventLog(attempt_id), {}
        def finish(outcome: CampaignAttemptOutcome, **kwargs: Any) -> PipelineAttemptResult:
            return self._finish(attempt_id, events, artifacts, outcome, target_scope=request.target_scope.to_dict(), repo_root=Path(request.repo_root), **kwargs)
        events.append(AttemptEventType.CREATED)
        self._put(artifacts, "contract", request.contract_artifact_ref, request.contract)
        self._put(artifacts, "transfer_signature", request.transfer_signature_artifact_ref, request.transfer_signature)
        self._put(artifacts, "template", request.template_artifact_ref, request.template_manifest)
        events.append(AttemptEventType.MATCHING)
        bridge = match_then_merge(request, bundle)
        trace_artifact = self.store.put_canonical(
            bridge.matcher.trace.trace_id,
            bridge.matcher.trace.semantic_core,
            serializer=lambda _: bridge.matcher.trace.canonical_bytes(),
        )
        artifacts["matcher_trace"] = trace_artifact
        if bridge.matcher.outcome.value != "MATCH_FOUND":
            outcome = CampaignAttemptOutcome.MATCHER_NO_MATCH if bridge.matcher.outcome.value in {"NO_ELIGIBLE_CANDIDATE", "CANDIDATES_EXHAUSTED"} else CampaignAttemptOutcome.MATCHER_FAILURE
            return finish(outcome)
        events.append(AttemptEventType.MATCHED, artifacts=[trace_artifact])
        binding, binding_validation = bridge.matcher.candidate_binding, bridge.matcher.candidate_binding_validation
        assert binding is not None and binding_validation is not None and bridge.merge is not None and bridge.merge_gate is not None
        self._put(artifacts, "candidate_binding", binding["binding_id"], binding)
        self._put(artifacts, "candidate_binding_validation", binding_validation["validation_id"], binding_validation)
        events.append(AttemptEventType.MERGING)
        try:
            prepared = prepare_merge_execution(contract=request.contract, gate=bridge.merge_gate, merge=bridge.merge, repo_root=request.repo_root, adaptation_provider=adaptation_provider, phase_callback=lambda phase: events.append(AttemptEventType[phase]))
        except Exception:
            return finish(CampaignAttemptOutcome.MERGE_FAILURE)
        self._put(artifacts, "merge", prepared.merge["merge_id"], prepared.merge)
        self._put(artifacts, "bound_source", prepared.bound_source["bound_source_id"], prepared.bound_source)
        self._put(artifacts, "source_map", prepared.source_map["source_map_id"], prepared.source_map)
        self._put(artifacts, "merge_validation", prepared.validation["validation_id"], prepared.validation)
        source = self.store.put_raw(prepared.bound_source["source_artifact_ref"], prepared.source_bytes, media_type="text/x-c")
        artifacts["source"] = source
        if prepared.handoff is None:
            return finish(CampaignAttemptOutcome.ADAPTATION_FAILURE)
        self._put(artifacts, "handoff", prepared.handoff["handoff_id"], prepared.handoff)
        events.append(AttemptEventType.HANDOFF_ACCEPTED, artifacts=[artifacts["handoff"]])
        workspace_context = tempfile.TemporaryDirectory(dir=self.workspace_root) if self.workspace_root else tempfile.TemporaryDirectory()
        with workspace_context as directory:
            events.append(AttemptEventType.BUILDING)
            try:
                executed = self.runner_backend.execute(
                    prepared.handoff, source_bytes=prepared.source_bytes, workspace=Path(directory), artifact_namespace=attempt_id, argv=argv,
                    phase_callback=lambda phase: events.append(AttemptEventType[phase]),
                )
            except Exception:
                return finish(CampaignAttemptOutcome.BUILD_FAILURE)
        self._put(artifacts, "build_spec", executed.build_spec["build_spec_id"], executed.build_spec)
        self._put(artifacts, "build_record", executed.build_record["build_record_id"], executed.build_record)
        for index, raw in enumerate(executed.raw_artifacts): artifacts[f"raw_{index}"] = raw
        raw_by_ref = {item.ref: item.digest for item in executed.raw_artifacts}
        for phase in executed.build_record.get("phases", []):
            for key in ("stdout", "stderr"):
                ref, digest = phase[f"{key}_ref"], phase[f"{key}_digest"]
                if raw_by_ref.get(ref) != digest or not self.store.verify(ref, digest):
                    return finish(CampaignAttemptOutcome.BUILD_FAILURE)
        if executed.run_spec is None or executed.run_record is None:
            return finish(CampaignAttemptOutcome.BUILD_FAILURE)
        self._put(artifacts, "run_spec", executed.run_spec["run_spec_id"], executed.run_spec)
        self._put(artifacts, "run_record", executed.run_record["run_record_id"], executed.run_record)
        for raw_record in executed.run_record.get("raw_artifacts", []):
            if raw_by_ref.get(raw_record["artifact_ref"]) != raw_record["artifact_digest"] or not self.store.verify(raw_record["artifact_ref"], raw_record["artifact_digest"]):
                return finish(CampaignAttemptOutcome.RUN_LAUNCH_FAILURE)
        events.append(AttemptEventType.RAN, artifacts=[artifacts["run_record"]])
        witness_outcome, witness = form_execution_witness(contract_ref=prepared.handoff["contract_ref"], contract_digest=prepared.handoff["contract_digest"], candidate_binding_ref=prepared.handoff["candidate_binding_ref"], candidate_binding_digest=prepared.handoff["candidate_binding_digest"], merge_ref=prepared.merge["merge_id"], merge_digest=prepared.handoff["merge_digest"], merge_validation_ref=prepared.validation["validation_id"], merge_validation_digest=prepared.handoff["merge_validation_digest"], bound_source_ref=prepared.bound_source["bound_source_id"], bound_source_digest=prepared.handoff["bound_source_digest"], source_map_ref=prepared.source_map["source_map_id"], source_map_digest=prepared.handoff["source_map_digest"], build_spec=executed.build_spec, build_record=executed.build_record, run_spec=executed.run_spec, run_record=executed.run_record, source_artifact_digest=prepared.handoff["source_artifact_digest"])
        if witness is None:
            outcome = CampaignAttemptOutcome.RUN_LAUNCH_FAILURE if executed.run_record.get("process_start") != "STARTED" else CampaignAttemptOutcome.WITNESS_INVALID
            return finish(outcome)
        self._put(artifacts, "witness", witness["witness_id"], witness); events.append(AttemptEventType.WITNESS_FORMED)
        trace = build_structured_trace(witness, executed.run_record, prepared.merge, binding, request.contract, prepared.source_map, executed.acquisitions, [*executed.run_record.get("process_events", []), *executed.process_evidence])
        self._put(artifacts, "trace", trace["trace_id"], trace); events.append(AttemptEventType.TRACE_NORMALIZED)
        projection = project_contract_evidence(request.contract, binding, prepared.merge, prepared.source_map, trace)
        self._put(artifacts, "projection", projection["projection_id"], projection); events.append(AttemptEventType.PROJECTED)
        evaluations = evaluate_contract_relations(request.contract, witness, trace, projection)
        for index, evaluation in enumerate(evaluations): self._put(artifacts, f"evaluation_{index}", evaluation["evaluation_id"], evaluation)
        events.append(AttemptEventType.EVALUATED)
        verdict = aggregate_execution_verdict(request.contract, binding, prepared.merge, witness, trace, evaluations)
        if verdict is None: return finish(CampaignAttemptOutcome.WITNESS_INVALID)
        self._put(artifacts, "execution_verdict", verdict["verdict_id"], verdict); events.append(AttemptEventType.VERDICTED)
        closure = None
        if verdict["verdict"] == "SATISFIED": outcome = CampaignAttemptOutcome.SATISFIED_WITNESS
        elif verdict["verdict"] == "UNKNOWN":
            outcome = CampaignAttemptOutcome.EXECUTION_UNKNOWN
            missing = [entry["contract_observable_ref"] for entry in projection.get("entries", []) if entry.get("sufficiency") != "SUFFICIENT"]
            closure = build_unknown_closure(verdict, reason_codes=["MISSING_REQUIRED_OBSERVABLE"], missing_evidence=missing)
            self._put(artifacts, "closure", closure["closure_id"], closure)
        else:
            outcome = CampaignAttemptOutcome.VIOLATED_WITNESS
            package = build_violation_evidence_package(contract=request.contract, candidate_binding=binding, merge=prepared.merge, merge_validation=prepared.validation, bound_source=prepared.bound_source, source_map=prepared.source_map, build_spec=executed.build_spec, build_record=executed.build_record, run_spec=executed.run_spec, run_record=executed.run_record, witness=witness, trace=trace, evaluations=evaluations, verdict=verdict, supporting_raw_artifacts=[{"artifact_ref": x.ref, "artifact_digest": x.digest} for x in executed.raw_artifacts])
            self._put(artifacts, "violation_package", package["package_id"], package)
            callee = str((binding.get("operation_bindings") or [{}])[0].get("target_symbol_ref") or "unknown")
            provenance_refs = [executed.build_spec["build_spec_id"], executed.build_record["build_record_id"]]
            bridge_doc, impact_error, discovery = bridge_violation(violation_package=package, verdict=verdict, repository_root=self.caller_repository_root, callee=callee, symbol=binding["binding_id"], build_provenance_refs=provenance_refs, impact_provider=self.impact_provider)
            if discovery is not None:
                self._put(artifacts, "caller_discovery", f"caller-discovery:{attempt_id}", discovery)
            if bridge_doc is not None:
                self._put(artifacts, "caller_bridge", bridge_doc["bridge_id"], bridge_doc)
            if impact_error is not None:
                events.append(AttemptEventType.ROUTED, reason_code=f"IMPACT_ANALYSIS_FAILURE:{impact_error}")
        return finish(outcome, verdict=verdict, closure=closure, violation_package=package if verdict["verdict"] == "VIOLATED" else None)

    def _finish(self, attempt_id: str, events: AttemptEventLog, artifacts: Mapping[str, ArtifactRef], outcome: CampaignAttemptOutcome, *, verdict: Mapping[str, Any] | None = None, closure: Mapping[str, Any] | None = None, violation_package: Mapping[str, Any] | None = None, target_scope: Mapping[str, Any] | None = None, repo_root: Path | None = None) -> PipelineAttemptResult:
        events.append(AttemptEventType.ROUTED, reason_code=outcome.value)
        events.append(AttemptEventType.CLOSED); events.close()
        try:
            identity = repository_identity(repo_root) if repo_root is not None else {"revision": "unavailable", "tree_digest": "unavailable"}
        except Exception:
            identity = {"revision": "unavailable", "tree_digest": "unavailable"}
        reproduction = build_reproduction_manifest(attempt_id=attempt_id, artifacts=artifacts, target_scope=target_scope or {}, repo_revision=identity["revision"], repo_tree_digest=identity["tree_digest"], toolchain_profile=dict(self.runner_backend.configuration.toolchain), execution_config={"timeout_seconds": self.runner_backend.configuration.timeout_seconds})
        reproduction_ref = self.store.put_canonical(f"attempts/{attempt_id}/reproduction.json", reproduction)
        manifest = build_attempt_manifest(attempt_id=attempt_id, events=events.events, artifact_refs=artifacts, outcome=outcome.value, reproduction_ref=reproduction_ref)
        self.store.put_canonical(f"attempts/{attempt_id}/manifest.json", manifest)
        return PipelineAttemptResult(attempt_id, outcome, dict(artifacts), manifest, verdict, closure=closure, violation_package=violation_package)
