"""Controlled, single-unit C1 Retry v0.4 executor.

The executor accepts only the fixed 0020 unit.  It uses the C1-fix10 source
and C1-fix4 archived libraries, emits create-only evidence, and never creates
a Verdict or a violation package.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping

from execution_model.canonical import artifact_digest, canonical_json_bytes as execution_bytes, identify, semantic_digest
from execution_pipeline.build_adapter import build_spec_from_handoff, execute_build
from execution_pipeline.capture_protocol import PREFIX, parse_target_capture_line, target_capture_to_runtime_event
from execution_pipeline.runner_adapter import build_run_spec, execute_run
from execution_trace.normalize import build_structured_trace
from execution_trace.projection import project_contract_evidence
from execution_trace.relation_eval import evaluate_contract_relations
from execution_trace.witness import form_execution_witness
from target_knowledge.canonical import canonical_json_bytes, identified


UNIT = "unit:track-a:0020:fixed"
OUTPUT = Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.4")
FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage")
FIX4 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1")
FIX7 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix7-v0.1")
FIX8 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix8-v0.1")
FIX9 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix9-v0.1")
FIX10 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix10-v0.1")


def _load(root: Path, ref: Path | str) -> dict[str, Any]:
    return json.loads((root / ref).read_text(encoding="utf-8"))


def _edge(root: Path, ref: Path | str) -> dict[str, str]:
    text = str(ref)
    return {"ref": text, "digest": hashlib.sha256((root / text).read_bytes()).hexdigest()}


def _write(path: Path, document: Mapping[str, Any], *, execution: bool = False) -> dict[str, str]:
    payload = execution_bytes(document) if execution else canonical_json_bytes(document)
    path.write_bytes(payload)
    return {"ref": str(path.relative_to(path.parents[len(OUTPUT.parts) - 1])), "digest": hashlib.sha256(payload).hexdigest()}


def _parent_edges(root: Path) -> dict[str, dict[str, str]]:
    return {name: _edge(root, ref / "artifact_index.json") for name, ref in {
        "c1_fix10": FIX10, "c1_fix9": FIX9, "c1_fix8": FIX8, "c1_fix7": FIX7, "c1_fix4": FIX4,
    }.items()}


def _preflight(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root = Path(root).resolve()
    executable = _load(root, FIX10 / "executable_bound_source.json")
    source_map = _load(root, FIX10 / "source_map_finalization.json")
    capture = _load(root, FIX10 / "capture_protocol_materialization.json")
    handoff_ready = _load(root, FIX10 / "execution_handoff_readiness.json")
    gate = _load(root, FIX10 / "c1_pre_run_gate_decision.json")
    provenance = _load(root, FIX4 / "library_build_provenance_record.json")
    plan = _load(root, FIX4 / "controlled_rebuild_plan.json")
    source_identity = _load(root, "artifacts/pipeline_v2/real_campaign_preflight/source_identities/mbedtls-0020-fixed.json")
    source_dir = Path(plan["telemetry"]["source_directory"])
    source_ref = executable["source_artifact"]
    source_ok = (root / source_ref["ref"]).is_file() and _edge(root, source_ref["ref"])["digest"] == source_ref["digest"]
    libs_ok = all((root / item["ref"]).is_file() and _edge(root, item["ref"])["digest"] == item["digest"] for item in provenance["generated_library_artifacts"])
    source_tree_ok = source_dir.is_dir() and (source_dir / "include/mbedtls/pk.h").is_file()
    if source_tree_ok:
        completed = subprocess.run(["git", "-C", str(source_dir), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
        source_tree_ok = completed.returncode == 0 and completed.stdout.strip() == source_identity["identity"]["revision"]
    roles = {item["semantic_role"] for item in capture.get("capture_realizations", [])}
    checks = [
        ("UNIT", UNIT == "unit:track-a:0020:fixed", "APPROVED_TRACK_A_0020_FIXED_UNIT"),
        ("FIX10_GATE", gate.get("status") == "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY", "FIX10_GATE_NOT_READY"),
        ("EXECUTABLE_BOUNDSOURCE", executable.get("status") == "READY" and source_ok, "EXECUTABLE_BOUNDSOURCE_INVALID"),
        ("SOURCEMAP", source_map.get("status") == "READY", "SOURCEMAP_NOT_READY"),
        ("CAPTURE_PROTOCOL", capture.get("status") == "READY" and roles == {"operation_outcome", "consumed_length", "input_length"}, "CAPTURE_PROTOCOL_NOT_READY"),
        ("HANDOFF_READINESS", handoff_ready.get("status") == "READY", "EXECUTION_HANDOFF_NOT_READY"),
        ("FIXED_LIBRARY_PROVENANCE", provenance.get("validation_status") == "REPRODUCIBLE_PROVENANCE_READY" and libs_ok, "FIXED_LIBRARY_PROVENANCE_INVALID"),
        ("FIXED_HEADER_IDENTITY", source_tree_ok, "FIXED_HEADER_IDENTITY_INVALID"),
    ]
    blockers = [reason for _, passed, reason in checks if not passed]
    gate_doc = identified({
        "schema_version": "cipherlens.c1_retry_pre_run_gate.v0.4", "attempt_version": "v0.4", "unit_id": UNIT,
        "scope": "SINGLE_UNIT_DRY_RUN", "campaign_scope": "NOT_FULL_CAMPAIGN", "report_real_number_allowed": False,
        "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if not blockers else "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "checks": [{"check": name, "status": "PASS" if passed else "BLOCKED", "reason_code": reason} for name, passed, reason in checks],
        "blocking_reasons": blockers, "build_run_authorized": not blockers, "build_attempted": False, "run_attempted": False,
        "parent_artifacts": _parent_edges(root), "authority": "C1_RETRY_V04_FIXED_UNIT_PRE_RUN_GATE",
    }, "c1-retry-v04-pre-run-gate", "gate_id")
    return gate_doc, {"executable": executable, "source_map": source_map, "capture": capture, "handoff_ready": handoff_ready, "provenance": provenance, "plan": plan, "source_dir": source_dir}


def run_c1_retry_v04(repo_root: str | Path) -> dict[str, Path]:
    """Execute the sole approved unit after a strict local pre-run gate."""
    root = Path(repo_root).resolve(); output = root / OUTPUT
    if output.exists(): raise FileExistsError("C1 retry v0.4 root is create-only")
    gate, ctx = _preflight(root)
    output.mkdir(parents=True)
    results: dict[str, Path] = {}
    def put(name: str, doc: Mapping[str, Any], execution: bool = False) -> dict[str, str]:
        path = output / name; path.parent.mkdir(parents=True, exist_ok=True); payload = execution_bytes(doc) if execution else canonical_json_bytes(doc); path.write_bytes(payload); results[name] = path
        return {"ref": str(OUTPUT / name), "digest": hashlib.sha256(payload).hexdigest()}
    gate_edge = put("pre_run_gate.json", gate)
    common = {"attempt_version": "v0.4", "unit_id": UNIT, "scope": "SINGLE_UNIT_DRY_RUN", "campaign_scope": "NOT_FULL_CAMPAIGN", "report_real_number_allowed": False, "parent_artifacts": _parent_edges(root)}
    if gate["status"] != "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY":
        claim = identified({"schema_version":"cipherlens.c1_retry_claim_gate.v0.4", **common, "status":"C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "pre_run_gate":gate_edge, "blocking_reasons":gate["blocking_reasons"], "security_finding_generated":False, "authority":"C1_RETRY_V04_BLOCKED_CLAIM_GATE"}, "c1-retry-v04-claim-gate", "decision_id")
        claim_edge = put("claim_gate.json", claim)
        attempt = identified({"schema_version":"cipherlens.c1_retry_attempt_manifest.v0.4", **common, "status":"C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "pre_run_gate":gate_edge, "claim_gate":claim_edge, "failed_stage":"PRE_RUN_GATE", "missing_artifacts":[], "build_attempted":False, "run_attempted":False, "runtime_event_generated":False, "witness_generated":False, "trace_generated":False, "execution_verdict_generated":False}, "c1-retry-v04-attempt", "attempt_id")
        put("c1_attempt_manifest.json", attempt); return results

    executable, source_map, capture = ctx["executable"], ctx["source_map"], ctx["capture"]
    merge, candidate, contract, base_handoff, base_map = (_load(root, FIX2 / name) for name in ("merge.json", "candidate_binding.json", "contract.json", "execution_handoff.json", "source_map.json"))
    bridge = {"schema_version":"cipherlens.c1_retry_trace_source_map_bridge.v0.1", "source_artifact":dict(executable["source_artifact"]), "fix10_source_map":_edge(root, FIX10 / "source_map_finalization.json"), "observation_capture_records":list(base_map["observation_capture_records"]), "authority":"FIX10_CAPTURE_MAP_COMPATIBILITY_BRIDGE_ONLY"}
    bridge["source_map_id"] = "source-map:" + semantic_digest(bridge)
    bridge_edge = put("trace_source_map_bridge.json", bridge)
    handoff = dict(base_handoff); handoff.update({"bound_source_ref":executable["bound_source_id"], "bound_source_digest":_edge(root, FIX10 / "executable_bound_source.json")["digest"], "source_map_ref":bridge["source_map_id"], "source_map_digest":bridge_edge["digest"], "source_artifact_ref":executable["source_artifact"]["ref"], "source_artifact_digest":executable["source_artifact"]["digest"]}); handoff = identify(handoff)
    handoff_edge = put("execution_handoff.json", handoff, execution=True)
    provenance = ctx["provenance"]; libs = provenance["generated_library_artifacts"]; libdir = root / FIX4 / "raw/libraries"; source_dir = ctx["source_dir"]
    build_spec = build_spec_from_handoff(handoff, toolchain={"compiler":"cc", "version_profile_digest":provenance["compiler_version_evidence"]["digest"]}, compile_units=[{"artifact_ref":handoff["source_artifact_ref"], "artifact_digest":handoff["source_artifact_digest"], "language":"c"}], include_configs=[{"artifact_ref":"source:mbedtls:0020:fixed/include", "artifact_digest":source_identity_digest(root)}], compile_flags=["-O0"], library_inputs=[{"artifact_ref":item["ref"],"artifact_digest":item["digest"]} for item in libs], link_flags=["-lmbedtls","-lmbedx509","-lmbedcrypto"], expected_output={"artifact_ref":str(OUTPUT / "raw/build/c1_0020_fixed"),"kind":"EXECUTABLE"}, instrumentation_profile={"name":"none"}, environment_profile={"kind":"controlled-local"})
    build_spec_edge = put("build_spec.json", build_spec, execution=True)
    raw_dir = output / "raw"; build_dir = raw_dir / "build"; build_dir.mkdir(parents=True)
    calls=[]
    def runner(command, **kwargs):
        result=subprocess.run(command, **kwargs); calls.append(result); return result
    build_record, _ = execute_build(build_spec, source_paths=[root / executable["source_artifact"]["ref"]], object_paths=[build_dir / "c1_0020_fixed.o"], binary_path=build_dir / "c1_0020_fixed", compiler_path="/usr/bin/cc", resolved_include_paths=[source_dir / "include", source_dir / "library"], resolved_library_paths=[libdir], controlled_env={"PATH":os.environ.get("PATH", ""),"LANG":"C","LC_ALL":"C"}, timeout_seconds=120, runner=runner)
    for name, result in (("compile.stdout", calls[0].stdout if calls else ""),("compile.stderr", calls[0].stderr if calls else ""),("link.stdout", calls[1].stdout if len(calls)>1 else ""),("link.stderr", calls[1].stderr if len(calls)>1 else "")):
        (raw_dir/name).write_bytes((result or "").encode())
    build_record_edge=put("build_record.json",build_record,execution=True)
    if build_record["result"] != "BUILT":
        claim=identified({"schema_version":"cipherlens.c1_retry_claim_gate.v0.4",**common,"status":"BUILD_FAILURE","pre_run_gate":gate_edge,"build_record":build_record_edge,"security_finding_generated":False,"authority":"C1_RETRY_V04_BUILD_FAILURE_CLAIM_GATE"},"c1-retry-v04-claim-gate","decision_id"); claim_edge=put("claim_gate.json",claim)
        attempt=identified({"schema_version":"cipherlens.c1_retry_attempt_manifest.v0.4",**common,"status":"BUILD_FAILURE","pre_run_gate":gate_edge,"build_record":build_record_edge,"claim_gate":claim_edge,"failed_stage":"BUILD","missing_artifacts":["run_record","runtime_events","execution_witness","structured_execution_trace","contract_projection","relation_evaluation"],"build_attempted":True,"run_attempted":False,"runtime_event_generated":False,"witness_generated":False,"trace_generated":False,"execution_verdict_generated":False},"c1-retry-v04-attempt","attempt_id"); put("c1_attempt_manifest.json",attempt); return results
    run_spec=build_run_spec(build_spec,build_record,environment_profile={"kind":"controlled-local"},working_directory_profile={"kind":"artifact-root"},timeout_policy={"seconds":30},instrumentation_profile={"name":"none"},required_capture_refs=[item["capture_binding_ref"] for item in capture["capture_realizations"]],expected_phases=["TARGET_OPERATION","PROCESS_END"])
    put("run_spec.json",run_spec,execution=True)
    run_calls=[]
    def run_runner(command, **kwargs):
        result=subprocess.run(command, **kwargs); run_calls.append(result); return result
    run_record,_=execute_run(run_spec,binary_path=build_dir / "c1_0020_fixed",controlled_env={"PATH":os.environ.get("PATH", ""),"LANG":"C","LC_ALL":"C"},working_directory=build_dir,timeout_seconds=30,runner=run_runner)
    completed=run_calls[-1] if run_calls else None
    stdout=(getattr(completed,"stdout","") or "").encode(); stderr=(getattr(completed,"stderr","") or "").encode()
    (raw_dir/"run.stdout").write_bytes(stdout); (raw_dir/"run.stderr").write_bytes(stderr)
    run_record_edge=put("run_record.json",run_record,execution=True)
    attempt_ref="c1-retry-v04-attempt:"+hashlib.sha256((handoff["handoff_id"]+build_record["build_record_id"]+run_record["run_record_id"]).encode()).hexdigest()
    events=[]; acquisitions=[]
    for line in stdout.decode("utf-8",errors="strict").splitlines():
        if not line.startswith(PREFIX): continue
        payload=parse_target_capture_line(line)
        event=target_capture_to_runtime_event(payload,execution_attempt_ref=attempt_ref,evidence_ref=str(OUTPUT/"raw/run.stdout"))
        events.append(event)
        acquisitions.append({"capture_binding_ref":event["merge_capture_ref"],"status":event["status"],"value_presence":"VALUE" if event["status"]=="PRESENT" else "NONE","value":event["value"],"sequence_index":payload["sequence_index"],"correlation_group_ref":event["correlation_group_ref"],"channel_active":True,"phase_reached":True,"evidence_refs":[str(OUTPUT/"raw/run.stdout")]})
    event_edges=[]
    for index,event in enumerate(events):
        event_edges.append(put(f"runtime_events/{index:04d}.json",event))
    event_index=identified({"schema_version":"cipherlens.c1_retry_runtime_event_index.v0.4",**common,"status":"COMPLETE" if len(events)==3 else "INCOMPLETE","execution_attempt_ref":attempt_ref,"events":event_edges,"required_roles":["operation_outcome","consumed_length","input_length"],"authority":"TARGET_EMITTED_STRICT_JSON_TO_RUNTIME_EVENT"},"c1-retry-v04-runtime-events","index_id")
    event_index_edge=put("runtime_event_index.json",event_index)
    merge_validation=_load(root,FIX2/"merge_validation.json")
    outcome,witness=form_execution_witness(contract_ref=handoff["contract_ref"],contract_digest=handoff["contract_digest"],candidate_binding_ref=handoff["candidate_binding_ref"],candidate_binding_digest=handoff["candidate_binding_digest"],merge_ref=handoff["merge_ref"],merge_digest=handoff["merge_digest"],merge_validation_ref=merge_validation["validation_id"],merge_validation_digest=_edge(root,FIX2/"merge_validation.json")["digest"],bound_source_ref=handoff["bound_source_ref"],bound_source_digest=handoff["bound_source_digest"],source_map_ref=bridge["source_map_id"],source_map_digest=bridge_edge["digest"],build_spec=build_spec,build_record=build_record,run_spec=run_spec,run_record=run_record,source_artifact_digest=handoff["source_artifact_digest"],acquisition_integrity={"framework_complete":run_record["collection"]=="COMPLETE","artifact_integrity":True,"lineage_integrity":True,"required_channels_complete":run_record["collection"]=="COMPLETE"})
    witness_edge=put("execution_witness.json",witness,execution=True) if witness else None
    trace=projection=relation=None
    if witness and len(events)==3:
        trace=build_structured_trace(witness,run_record,merge,candidate,contract,bridge,acquisitions)
        trace_edge=put("structured_execution_trace.json",trace,execution=True)
        projection=project_contract_evidence(contract,candidate,merge,bridge,trace)
        projection_edge=put("contract_projection.json",projection,execution=True)
        evaluations=evaluate_contract_relations(contract,witness,trace,projection)
        relation=evaluations[0] if evaluations else None
        if relation: relation_edge=put("relation_evaluation.json",relation,execution=True)
    status="C1_SINGLE_UNIT_DRY_RUN_PASSED" if witness and trace and projection and relation else "C1_SINGLE_UNIT_DRY_RUN_INCOMPLETE"
    claim=identified({"schema_version":"cipherlens.c1_retry_claim_gate.v0.4",**common,"status":status,"pre_run_gate":gate_edge,"build_record":build_record_edge,"run_record":run_record_edge,"runtime_event_index":event_index_edge,"relation_evaluation":relation_edge if relation else None,"allowed_claims":["SINGLE_UNIT_EXECUTION_ENGINEERING_EVIDENCE"],"forbidden_claims":["CURRENT_V2_CAMPAIGN_RESULT","SECURITY_FINDING","VULNERABILITY_CONFIRMED","LIBRARY_SAFE"],"security_finding_generated":False,"authority":"C1_RETRY_V04_SINGLE_UNIT_CLAIM_GATE"},"c1-retry-v04-claim-gate","decision_id")
    claim_edge=put("claim_gate.json",claim)
    attempt=identified({"schema_version":"cipherlens.c1_retry_attempt_manifest.v0.4",**common,"attempt_id":attempt_ref,"status":status,"pre_run_gate":gate_edge,"build_record":build_record_edge,"run_record":run_record_edge,"runtime_event_index":event_index_edge,"execution_witness":witness_edge,"structured_execution_trace":trace_edge if trace else None,"contract_projection":projection_edge if projection else None,"relation_evaluation":relation_edge if relation else None,"claim_gate":claim_edge,"build_attempted":True,"run_attempted":True,"runtime_event_generated":bool(events),"witness_generated":witness is not None,"trace_generated":trace is not None,"execution_verdict_generated":False,"violation_evidence_package_generated":False,"failed_stage":None if status.endswith("PASSED") else "RUNTIME_EVENT_OR_TRACE","missing_artifacts":[] if status.endswith("PASSED") else ["structured_execution_trace_or_relation"]},"c1-retry-v04-attempt","attempt_id")
    put("c1_attempt_manifest.json",attempt)
    index=identified({"schema_version":"cipherlens.c1_retry_artifact_index.v0.4",**common,"status":status,"artifacts":[{"artifact_type":p.stem,"ref":str(p.relative_to(root)),"digest":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(results.values())],"create_only":True,"authority":"C1_RETRY_V04_CREATE_ONLY_ARTIFACT_INDEX"},"c1-retry-v04-index","index_id")
    put("artifact_index.json",index)
    return results


def source_identity_digest(root: Path) -> str:
    return _edge(root, "artifacts/pipeline_v2/real_campaign_preflight/source_identities/mbedtls-0020-fixed.json")["digest"]


def record_v04_materialization_failure(repo_root: str | Path, reason_code: str) -> dict[str, Path]:
    """Append only failure records to an interrupted create-only v0.4 root."""
    root = Path(repo_root).resolve(); output = root / OUTPUT
    pre_run = output / "pre_run_gate.json"
    if not pre_run.is_file():
        raise FileNotFoundError("v0.4 pre-run gate is required")
    names = ("claim_gate.json", "c1_attempt_manifest.json", "artifact_index.json")
    if any((output / name).exists() for name in names):
        raise FileExistsError("v0.4 failure records are create-only")
    common={"attempt_version":"v0.4","unit_id":UNIT,"scope":"SINGLE_UNIT_DRY_RUN","campaign_scope":"NOT_FULL_CAMPAIGN","report_real_number_allowed":False,"parent_artifacts":_parent_edges(root)}
    pre_edge=_edge(root, OUTPUT / "pre_run_gate.json")
    claim=identified({"schema_version":"cipherlens.c1_retry_claim_gate.v0.4",**common,"status":"C1_SINGLE_UNIT_DRY_RUN_BLOCKED","pre_run_gate":pre_edge,"blocking_reasons":[reason_code],"allowed_claims":["ENGINEERING_BLOCKER_CLAIM"],"security_finding_generated":False,"authority":"C1_RETRY_V04_POST_GATE_MATERIALIZATION_FAILURE"},"c1-retry-v04-claim-gate","decision_id")
    claim_path=output/"claim_gate.json"; claim_path.write_bytes(canonical_json_bytes(claim)); claim_edge=_edge(root,OUTPUT/"claim_gate.json")
    attempt=identified({"schema_version":"cipherlens.c1_retry_attempt_manifest.v0.4",**common,"status":"C1_SINGLE_UNIT_DRY_RUN_BLOCKED","pre_run_gate":pre_edge,"claim_gate":claim_edge,"failed_stage":"BUILD_SPEC_MATERIALIZATION","reason_code":reason_code,"missing_artifacts":["build_spec","build_record","run_record","runtime_event_index","execution_witness","structured_execution_trace","contract_projection","relation_evaluation"],"build_attempted":False,"run_attempted":False,"runtime_event_generated":False,"witness_generated":False,"trace_generated":False,"execution_verdict_generated":False,"violation_evidence_package_generated":False},"c1-retry-v04-attempt","attempt_id")
    attempt_path=output/"c1_attempt_manifest.json"; attempt_path.write_bytes(canonical_json_bytes(attempt))
    files=[pre_run,claim_path,attempt_path]
    index=identified({"schema_version":"cipherlens.c1_retry_artifact_index.v0.4",**common,"status":"C1_SINGLE_UNIT_DRY_RUN_BLOCKED","artifacts":[{"artifact_type":path.stem,"ref":str(path.relative_to(root)),"digest":hashlib.sha256(path.read_bytes()).hexdigest()} for path in files],"create_only":True,"authority":"C1_RETRY_V04_INTERRUPTED_ROOT_INDEX"},"c1-retry-v04-index","index_id")
    index_path=output/"artifact_index.json"; index_path.write_bytes(canonical_json_bytes(index))
    return {path.name:path for path in (*files,index_path)}
