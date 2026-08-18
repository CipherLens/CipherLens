from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any, Mapping

import yaml

from execution_model.canonical import artifact_digest, identify
from execution_model.model import REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_pipeline.build_adapter import build_spec_from_handoff
from execution_pipeline.handoff import create_execution_handoff
from execution_pipeline.runner_adapter import build_run_spec
from execution_trace.normalize import build_structured_trace
from execution_trace.projection import project_contract_evidence
from execution_trace.relation_eval import evaluate_contract_relations
from execution_trace.verdict import aggregate_execution_verdict
from execution_trace.witness import form_execution_witness
from template_binding_merge.canonical import bound_source_digest, merge_digest, merge_validation_digest, source_map_digest
from template_binding_merge.completion import programmatic_complete
from template_binding_merge.registry import validate_merged_source
from tests.template_binding_merge.common import ROOT, built, context, inputs


SHA_EMPTY = hashlib.sha256(b"").hexdigest()
SHA_BINARY = hashlib.sha256(b"synthetic-binary").hexdigest()


def load_contract(family: str) -> dict[str, Any]:
    path = ROOT / "tests" / "contract_miner" / "fixtures" / "golden" / family / "expected.vc.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def upstream(family: str = "mbedtls_poc_0020") -> dict[str, Any]:
    _, _, binding, _ = inputs(family)
    gated, merge, base = built(family)
    rendered = programmatic_complete(merge, base.source_bytes, base.source_map, base.bound_source, ROOT)
    validation = validate_merged_source(context(gated, merge, rendered))
    contract = load_contract(family)
    handoff = create_execution_handoff(
        contract, binding, merge, validation, rendered.bound_source, rendered.source_map,
        rendered.source_bytes,
    )
    return {
        "contract": contract, "binding": binding, "merge": merge, "validation": validation,
        "bound_source": rendered.bound_source, "source_map": rendered.source_map,
        "source_bytes": rendered.source_bytes, "handoff": handoff,
    }


def build_spec(data: Mapping[str, Any]) -> dict[str, Any]:
    handoff = data["handoff"]
    return build_spec_from_handoff(
        handoff,
        toolchain={"compiler": "cc", "version_profile_digest": "1" * 64},
        compile_units=[{"artifact_ref": handoff["source_artifact_ref"], "artifact_digest": handoff["source_artifact_digest"], "language": "c"}],
        include_configs=[], compile_flags=["-std=c11"], library_inputs=[], link_flags=[],
        expected_output={"artifact_ref": "build:synthetic-binary", "kind": "EXECUTABLE"},
        instrumentation_profile={"profile_ref": "instrumentation:none", "profile_digest": "2" * 64},
        environment_profile={"profile_ref": "environment:controlled", "profile_digest": "3" * 64},
    )


def phase(name: str, result: str = "SUCCEEDED", *, output: bool = True) -> dict[str, Any]:
    return {
        "phase": name, "result": result, "exit_status": 0 if result == "SUCCEEDED" else 1,
        "stdout_ref": f"raw:{name.lower()}.stdout", "stdout_digest": SHA_EMPTY,
        "stderr_ref": f"raw:{name.lower()}.stderr", "stderr_digest": SHA_EMPTY,
        "output_ref": f"build-output:{name.lower()}" if output else None,
        "output_digest": ("4" * 64) if output else None,
        "reason_codes": [],
    }


def built_record(spec: Mapping[str, Any], *, result: str = "BUILT") -> dict[str, Any]:
    compile_result = "SUCCEEDED" if result not in {"COMPILE_FAILED", "TOOLCHAIN_LAUNCH_FAILED", "BUILD_TIMED_OUT"} else ("FAILED" if result == "COMPILE_FAILED" else "LAUNCH_FAILED")
    link_result = "SUCCEEDED" if result == "BUILT" else ("FAILED" if result == "LINK_FAILED" else "NOT_RUN")
    return identify({
        "schema_version": SCHEMA_VERSIONS["build_record"], "build_record_id": "pending",
        "build_spec_ref": spec["build_spec_id"], "build_spec_digest": artifact_digest(spec),
        "result": result,
        "phases": [phase("COMPILE", compile_result, output=compile_result == "SUCCEEDED"), phase("LINK", link_result, output=link_result == "SUCCEEDED")],
        "diagnostic_artifacts": ["raw:compile.stdout", "raw:compile.stderr", "raw:link.stdout", "raw:link.stderr"],
        "binary_ref": "build:synthetic-binary" if result == "BUILT" else None,
        "binary_digest": SHA_BINARY if result == "BUILT" else None,
        "reason_codes": [] if result == "BUILT" else [result], "registry_version": REGISTRY_VERSION,
    })


def run_spec(spec: Mapping[str, Any], record: Mapping[str, Any], required_capture_refs: list[str]) -> dict[str, Any]:
    return build_run_spec(
        spec, record, input_artifacts=[], argv=[],
        environment_profile={"profile_ref": "environment:controlled", "profile_digest": "3" * 64},
        working_directory_profile={"profile_ref": "cwd:isolated", "logical_directory": "run"},
        timeout_policy={"policy_ref": "timeout:short", "limit_seconds": 10},
        instrumentation_profile={"profile_ref": "instrumentation:none", "profile_digest": "2" * 64},
        required_capture_refs=required_capture_refs, expected_phases=["TARGET_OPERATION", "PROCESS_END"],
        expected_markers=["ORACLE_EVENT"], required_channels=["stdout", "stderr"],
    )


def run_record(spec: Mapping[str, Any], *, collection: str = "COMPLETE", started: bool = True) -> dict[str, Any]:
    return identify({
        "schema_version": SCHEMA_VERSIONS["run_record"], "run_record_id": "pending",
        "run_spec_ref": spec["run_spec_id"], "run_spec_digest": artifact_digest(spec),
        "binary_ref": spec["binary_ref"], "binary_digest": spec["binary_digest"],
        "process_start": "STARTED" if started else "LAUNCH_FAILED",
        "termination": "EXITED" if started else "NOT_STARTED", "collection": collection,
        "exit_status": 0 if started else None, "signal": None, "timeout": False,
        "raw_artifacts": [
            {"artifact_ref": "raw:run.stdout", "artifact_digest": SHA_EMPTY, "media_type": "text/plain"},
            {"artifact_ref": "raw:run.stderr", "artifact_digest": SHA_EMPTY, "media_type": "text/plain"},
        ],
        "process_events": ([{"evidence_id": "process:event:exit", "evidence_type": "process_exit", "artifact_refs": ["raw:run.stdout", "raw:run.stderr"]}] if started else []),
        "raw_observations": [], "integrity_reasons": [], "telemetry_ref": "telemetry:run",
        "registry_version": REGISTRY_VERSION,
    })


DEFAULT_VALUES = {
    "PARSE_OUTCOME": "success", "CONSUMED_LENGTH": 10, "INPUT_LENGTH": 10,
    "FINAL_OUTCOME": "reject", "OUTPUT_LENGTH_BEFORE": 0, "OUTPUT_LENGTH_AFTER": 0,
    "BUFFER_PRESENT_AFTER_ZERO": False, "STORED_LENGTH_AFTER_ZERO": 0,
    "REUSE_FATAL_EVENT": None,
}


def chain(
    family: str = "mbedtls_poc_0020", *, values: Mapping[str, Any] | None = None,
    statuses: Mapping[str, str] | None = None, partial: bool = False,
) -> dict[str, Any]:
    data = upstream(family)
    spec = build_spec(data); build = built_record(spec)
    run = run_spec(spec, build, data["handoff"]["observation_capture_refs"])
    record = run_record(run, collection="PARTIAL" if partial else "COMPLETE")
    _, witness = form_execution_witness(
        contract_ref=data["handoff"]["contract_ref"], contract_digest=data["handoff"]["contract_digest"],
        candidate_binding_ref=data["handoff"]["candidate_binding_ref"], candidate_binding_digest=data["handoff"]["candidate_binding_digest"],
        merge_ref=data["merge"]["merge_id"], merge_digest=merge_digest(data["merge"]),
        merge_validation_ref=data["validation"]["validation_id"], merge_validation_digest=merge_validation_digest(data["validation"]),
        bound_source_ref=data["bound_source"]["bound_source_id"], bound_source_digest=bound_source_digest(data["bound_source"]),
        source_map_ref=data["source_map"]["source_map_id"], source_map_digest=source_map_digest(data["source_map"]),
        build_spec=spec, build_record=build, run_spec=run, run_record=record,
        source_artifact_digest=data["handoff"]["source_artifact_digest"],
        acquisition_integrity={"framework_complete": not partial, "artifact_integrity": True, "lineage_integrity": True, "required_channels_complete": not partial},
    )
    assert witness is not None
    value_map = {**DEFAULT_VALUES, **dict(values or {})}; status_map = dict(statuses or {})
    acquisitions = []
    for index, capture in enumerate(data["merge"]["observation_capture_bindings"]):
        ref = capture["contract_observable_ref"]; status = status_map.get(ref, "PRESENT")
        value = value_map.get(ref)
        presence = "NONE" if status in {"OBSERVED_ABSENCE", "NOT_REACHED", "CHANNEL_UNAVAILABLE", "ACQUISITION_FAILED", "INVALID_VALUE", "CONFLICTING_EVIDENCE"} else ("EXPLICIT_NULL" if value is None else "VALUE")
        acquisitions.append({
            "capture_binding_ref": capture["capture_binding_id"], "status": status,
            "value_presence": presence, "value": value if presence in {"VALUE", "EXPLICIT_NULL"} else None,
            "channel_active": status != "CHANNEL_UNAVAILABLE", "phase_reached": status != "NOT_REACHED",
            "evidence_refs": [f"raw-observation:{index}"], "sequence_index": index,
        })
    trace = build_structured_trace(witness, record, data["merge"], data["binding"], data["contract"], data["source_map"], acquisitions, record["process_events"])
    projection = project_contract_evidence(data["contract"], data["binding"], data["merge"], data["source_map"], trace)
    evaluations = evaluate_contract_relations(data["contract"], witness, trace, projection)
    verdict = aggregate_execution_verdict(data["contract"], data["binding"], data["merge"], witness, trace, evaluations)
    data.update({"build_spec": spec, "build_record": build, "run_spec": run, "run_record": record, "witness": witness, "trace": trace, "projection": projection, "evaluations": evaluations, "verdict": verdict})
    return data


def reidentify(document: Mapping[str, Any]) -> dict[str, Any]:
    changed = deepcopy(dict(document))
    return identify(changed)
