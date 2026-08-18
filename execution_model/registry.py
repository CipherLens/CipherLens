"""Closed validators and reason/evidence registries for execution artifacts."""

from __future__ import annotations

import re
from typing import Any, Mapping

from execution_model.canonical import ID_FIELDS, artifact_id
from execution_model.model import (
    BUILD_EVIDENCE_TYPES, PROCESS_EVIDENCE_TYPES, SEMANTIC_EVIDENCE_TYPES,
    BuildResult, ClosureRoute, CollectionStatus, CorrelationState,
    ExecutionModelError, ExecutionVerdict, ObservationStatus, PhaseResult,
    RelationResult, SCHEMA_VERSIONS, Sufficiency, Termination, ValuePresence,
    WitnessStatus, ProcessStart,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_SEMANTIC_KEYS = {
    "timestamp", "timestamps", "pid", "hostname", "absolute_path", "workspace_path",
    "temporary_path", "temp_path", "duration", "cpu", "cpu_load", "host_environment",
}

TOP_FIELDS: dict[str, set[str]] = {
    SCHEMA_VERSIONS["handoff"]: {"schema_version", "handoff_id", "contract_ref", "contract_digest", "candidate_binding_ref", "candidate_binding_digest", "merge_ref", "merge_digest", "merge_validation_ref", "merge_validation_digest", "bound_source_ref", "bound_source_digest", "source_map_ref", "source_map_digest", "source_artifact_ref", "source_artifact_digest", "build_intent_seed", "observation_capture_refs", "identity_refs", "operation_refs", "registry_version"},
    SCHEMA_VERSIONS["build_spec"]: {"schema_version", "build_spec_id", "execution_handoff_ref", "execution_handoff_digest", "merge_ref", "merge_digest", "bound_source_ref", "bound_source_digest", "source_map_ref", "source_map_digest", "source_artifact_ref", "source_artifact_digest", "build_intent_seed_ref", "build_intent_seed_digest", "language", "toolchain", "compile_units", "include_configs", "compile_flags", "library_inputs", "link_flags", "expected_output", "instrumentation_profile", "environment_profile", "registry_version"},
    SCHEMA_VERSIONS["build_record"]: {"schema_version", "build_record_id", "build_spec_ref", "build_spec_digest", "result", "phases", "diagnostic_artifacts", "binary_ref", "binary_digest", "reason_codes", "registry_version"},
    SCHEMA_VERSIONS["run_spec"]: {"schema_version", "run_spec_id", "build_spec_ref", "build_spec_digest", "build_record_ref", "build_record_digest", "binary_ref", "binary_digest", "input_artifacts", "argv", "environment_profile", "working_directory_profile", "timeout_policy", "instrumentation_profile", "required_capture_refs", "expected_phases", "expected_markers", "required_channels", "registry_version"},
    SCHEMA_VERSIONS["run_record"]: {"schema_version", "run_record_id", "run_spec_ref", "run_spec_digest", "binary_ref", "binary_digest", "process_start", "termination", "collection", "exit_status", "signal", "timeout", "raw_artifacts", "process_events", "raw_observations", "integrity_reasons", "telemetry_ref", "registry_version"},
    SCHEMA_VERSIONS["witness"]: {"schema_version", "witness_id", "status", "attempt_outcome", "contract_ref", "contract_digest", "candidate_binding_ref", "candidate_binding_digest", "merge_ref", "merge_digest", "merge_validation_ref", "merge_validation_digest", "bound_source_ref", "bound_source_digest", "source_map_ref", "source_map_digest", "build_spec_ref", "build_spec_digest", "build_record_ref", "build_record_digest", "run_spec_ref", "run_spec_digest", "run_record_ref", "run_record_digest", "source_artifact_digest", "binary_digest", "input_artifact_digests", "raw_artifact_manifest", "acquisition_integrity", "reason_codes", "registry_version"},
    SCHEMA_VERSIONS["trace"]: {"schema_version", "trace_id", "witness_ref", "witness_digest", "run_record_ref", "run_record_digest", "merge_ref", "merge_digest", "candidate_binding_ref", "candidate_binding_digest", "contract_ref", "contract_digest", "semantic_observations", "process_evidence", "execution_sequence", "correlation_groups", "ordering_edges", "integrity_summary", "registry_version"},
    SCHEMA_VERSIONS["projection"]: {"schema_version", "projection_id", "trace_ref", "trace_digest", "contract_ref", "contract_digest", "candidate_binding_ref", "candidate_binding_digest", "merge_ref", "merge_digest", "entries", "registry_version"},
    SCHEMA_VERSIONS["relation_evaluation"]: {"schema_version", "evaluation_id", "relation_instance_ref", "relation_type", "criticality", "contract_ref", "contract_digest", "witness_ref", "witness_digest", "trace_ref", "trace_digest", "projection_refs", "correlation_refs", "evaluator_version", "result", "reason_code", "missing_requirements", "invalid_requirements", "evidence_bindings", "admissibility"},
    SCHEMA_VERSIONS["verdict"]: {"schema_version", "verdict_id", "contract_ref", "contract_digest", "candidate_binding_ref", "candidate_binding_digest", "merge_ref", "merge_digest", "witness_ref", "witness_digest", "trace_ref", "trace_digest", "relation_evaluations", "verdict", "supporting_broken_relation_refs", "non_evaluable_relation_refs", "reason_codes", "evidence_sufficiency_summary", "producer", "registry_version"},
    SCHEMA_VERSIONS["closure"]: {"schema_version", "closure_id", "verdict_ref", "verdict_digest", "analysis", "plan", "record", "registry_version"},
    SCHEMA_VERSIONS["violation_package"]: {"schema_version", "package_id", "contract_ref", "contract_digest", "candidate_binding_ref", "candidate_binding_digest", "merge_ref", "merge_digest", "merge_validation_ref", "merge_validation_digest", "bound_source_ref", "bound_source_digest", "source_map_ref", "source_map_digest", "build_spec_ref", "build_spec_digest", "build_record_ref", "build_record_digest", "run_spec_ref", "run_spec_digest", "run_record_ref", "run_record_digest", "witness_ref", "witness_digest", "trace_ref", "trace_digest", "broken_relation_evaluations", "execution_verdict_ref", "execution_verdict_digest", "supporting_raw_artifacts", "reproduction_metadata_refs", "claim_policy", "registry_version"},
    SCHEMA_VERSIONS["caller_bridge"]: {"schema_version", "bridge_id", "violation_package_ref", "violation_package_digest", "execution_verdict_ref", "execution_verdict_digest", "repository_snapshot", "verified_caller_evidence", "advisory_impact", "claim_policy", "registry_version"},
}


def _exact(value: Any, fields: set[str], path: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return False
    missing = fields - set(value)
    extra = set(value) - fields
    errors.extend(f"{path}.{key}: required field missing" for key in sorted(missing))
    errors.extend(f"{path}.{key}: unknown field" for key in sorted(extra))
    return not missing and not extra


def _ref_digest_pairs(value: Any, errors: list[str], path: str = "$") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _ref_digest_pairs(item, errors, f"{path}[{index}]")
        return
    if not isinstance(value, Mapping):
        return
    for key, item in value.items():
        if key.endswith("_digest") and item is not None and (not isinstance(item, str) or not SHA256_RE.fullmatch(item)):
            errors.append(f"{path}.{key}: expected sha256")
        _ref_digest_pairs(item, errors, f"{path}.{key}")


def _forbidden_recursive(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key) in FORBIDDEN_SEMANTIC_KEYS:
                errors.append(f"{path}.{key}: operational telemetry forbidden in semantic artifact")
            _forbidden_recursive(item, f"{path}.{key}", errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _forbidden_recursive(item, f"{path}[{index}]", errors)


def _objects(items: Any, fields: set[str], path: str, errors: list[str]) -> None:
    if not isinstance(items, list):
        errors.append(f"{path}: expected array")
        return
    for index, item in enumerate(items):
        _exact(item, fields, f"{path}[{index}]", errors)


def _validate_nested(schema: str, value: Mapping[str, Any], errors: list[str]) -> None:
    if schema == SCHEMA_VERSIONS["handoff"]:
        seed = value.get("build_intent_seed")
        if _exact(seed, {"seed_ref", "seed_digest", "hints"}, "build_intent_seed", errors):
            hints = seed["hints"]
            if _exact(hints, {"target_scope", "language", "renderer_id", "renderer_version"}, "build_intent_seed.hints", errors):
                _exact(hints["target_scope"], {"library", "version", "surface_ref"}, "build_intent_seed.hints.target_scope", errors)
    elif schema == SCHEMA_VERSIONS["build_spec"]:
        _exact(value.get("toolchain"), {"compiler", "version_profile_digest"}, "toolchain", errors)
        compiler = (value.get("toolchain") or {}).get("compiler")
        if isinstance(compiler, str) and compiler.startswith("/"):
            errors.append("toolchain.compiler: absolute path forbidden")
        _objects(value.get("compile_units"), {"artifact_ref", "artifact_digest", "language"}, "compile_units", errors)
        _objects(value.get("include_configs"), {"artifact_ref", "artifact_digest"}, "include_configs", errors)
        _objects(value.get("library_inputs"), {"artifact_ref", "artifact_digest"}, "library_inputs", errors)
        _exact(value.get("expected_output"), {"artifact_ref", "kind"}, "expected_output", errors)
        _exact(value.get("instrumentation_profile"), {"profile_ref", "profile_digest"}, "instrumentation_profile", errors)
        _exact(value.get("environment_profile"), {"profile_ref", "profile_digest"}, "environment_profile", errors)
    elif schema == SCHEMA_VERSIONS["build_record"]:
        for index, phase in enumerate(value.get("phases", [])):
            if _exact(phase, {"phase", "result", "exit_status", "stdout_ref", "stdout_digest", "stderr_ref", "stderr_digest", "output_ref", "output_digest", "reason_codes"}, f"phases[{index}]", errors):
                if phase["result"] not in {x.value for x in PhaseResult}:
                    errors.append(f"phases[{index}].result: unknown value")
        if value.get("result") not in {x.value for x in BuildResult}:
            errors.append("result: unknown value")
        if value.get("result") == BuildResult.BUILT.value and not value.get("binary_ref"):
            errors.append("binary_ref: required when BUILT")
        if value.get("result") != BuildResult.BUILT.value and (value.get("binary_ref") is not None or value.get("binary_digest") is not None):
            errors.append("binary: forbidden unless BUILT")
        phases = value.get("phases") or []
        if [x.get("phase") for x in phases if isinstance(x, dict)] != ["COMPILE", "LINK"]:
            errors.append("phases: expected ordered COMPILE then LINK")
        if value.get("result") == "BUILT" and any(x.get("result") != "SUCCEEDED" for x in phases if isinstance(x, dict)):
            errors.append("phases: BUILT requires both phases SUCCEEDED")
    elif schema == SCHEMA_VERSIONS["run_record"]:
        if value.get("process_start") not in {x.value for x in ProcessStart}:
            errors.append("process_start: unknown value")
        if value.get("termination") not in {x.value for x in Termination}:
            errors.append("termination: unknown value")
        if value.get("collection") not in {x.value for x in CollectionStatus}:
            errors.append("collection: unknown value")
        _objects(value.get("raw_artifacts"), {"artifact_ref", "artifact_digest", "media_type"}, "raw_artifacts", errors)
        _objects(value.get("process_events"), {"evidence_id", "evidence_type", "artifact_refs"}, "process_events", errors)
        _objects(value.get("raw_observations"), {"observation_ref", "artifact_ref", "artifact_digest"}, "raw_observations", errors)
        for index, event in enumerate(value.get("process_events", [])):
            if isinstance(event, dict) and event.get("evidence_type") not in PROCESS_EVIDENCE_TYPES:
                errors.append(f"process_events[{index}].evidence_type: unknown process evidence")
        if value.get("process_start") == "LAUNCH_FAILED" and (value.get("termination") != "NOT_STARTED" or value.get("collection") != "FAILED"):
            errors.append("run state: LAUNCH_FAILED requires NOT_STARTED/FAILED")
        if value.get("process_start") == "STARTED" and value.get("termination") == "NOT_STARTED":
            errors.append("run state: STARTED cannot terminate NOT_STARTED")
    elif schema == SCHEMA_VERSIONS["run_spec"]:
        _objects(value.get("input_artifacts"), {"artifact_ref", "artifact_digest"}, "input_artifacts", errors)
        _exact(value.get("environment_profile"), {"profile_ref", "profile_digest"}, "environment_profile", errors)
        _exact(value.get("working_directory_profile"), {"profile_ref", "logical_directory"}, "working_directory_profile", errors)
        _exact(value.get("timeout_policy"), {"policy_ref", "limit_seconds"}, "timeout_policy", errors)
        _exact(value.get("instrumentation_profile"), {"profile_ref", "profile_digest"}, "instrumentation_profile", errors)
    elif schema == SCHEMA_VERSIONS["witness"]:
        if value.get("status") not in {x.value for x in WitnessStatus}:
            errors.append("status: unknown value")
        _objects(value.get("raw_artifact_manifest"), {"artifact_ref", "artifact_digest"}, "raw_artifact_manifest", errors)
        _exact(value.get("acquisition_integrity"), {"framework_complete", "artifact_integrity", "lineage_integrity", "required_channels_complete"}, "acquisition_integrity", errors)
        if value.get("status") in {"VALID_WITNESS", "PARTIAL_WITNESS"} and value.get("attempt_outcome") != "WITNESS_FORMED":
            errors.append("attempt_outcome: admissible witness requires WITNESS_FORMED")
        if value.get("status") == "INVALID_WITNESS" and value.get("attempt_outcome") != "LINEAGE_INTEGRITY_FAILED":
            errors.append("attempt_outcome: invalid witness requires LINEAGE_INTEGRITY_FAILED")
    elif schema == SCHEMA_VERSIONS["trace"]:
        for index, obs in enumerate(value.get("semantic_observations", [])):
            fields = {"observation_id", "contract_observable_ref", "observation_binding_ref", "capture_binding_ref", "source_map_record_ref", "semantic_role", "subject_ref", "identity_group_ref", "operation_ref", "phase", "correlation_group_ref", "status", "value_presence", "value", "value_artifact_ref", "value_artifact_digest", "evidence_refs", "sequence_index"}
            if _exact(obs, fields, f"semantic_observations[{index}]", errors):
                if obs["status"] not in {x.value for x in ObservationStatus}:
                    errors.append(f"semantic_observations[{index}].status: unknown value")
                if obs["value_presence"] not in {x.value for x in ValuePresence}:
                    errors.append(f"semantic_observations[{index}].value_presence: unknown value")
                if obs["status"] == "OBSERVED_ABSENCE" and obs["value_presence"] != "NONE":
                    errors.append(f"semantic_observations[{index}]: absence must use NONE")
        _objects(value.get("process_evidence"), {"evidence_id", "evidence_type", "artifact_refs"}, "process_evidence", errors)
        for index, event in enumerate(value.get("process_evidence", [])):
            if isinstance(event, dict) and event.get("evidence_type") not in PROCESS_EVIDENCE_TYPES:
                errors.append(f"process_evidence[{index}].evidence_type: unknown process evidence")
        _exact(value.get("integrity_summary"), {"status", "reason_codes", "conflicting_observation_refs"}, "integrity_summary", errors)
    elif schema == SCHEMA_VERSIONS["projection"]:
        for index, entry in enumerate(value.get("entries", [])):
            fields = {"contract_observable_ref", "semantic_role", "observation_binding_ref", "merge_capture_ref", "source_map_capture_ref", "trace_evidence_refs", "trace_evidence_digests", "observation_status", "value_presence", "value", "sufficiency", "correlation_state", "missing_requirements", "reason_code"}
            if _exact(entry, fields, f"entries[{index}]", errors):
                if entry["sufficiency"] not in {x.value for x in Sufficiency}:
                    errors.append(f"entries[{index}].sufficiency: unknown value")
                if entry["correlation_state"] not in {x.value for x in CorrelationState}:
                    errors.append(f"entries[{index}].correlation_state: unknown value")
    elif schema == SCHEMA_VERSIONS["relation_evaluation"]:
        if value.get("result") not in {x.value for x in RelationResult}:
            errors.append("result: unknown value")
        _objects(value.get("projection_refs"), {"ref", "digest"}, "projection_refs", errors)
        _objects(value.get("evidence_bindings"), {"contract_observable_ref", "trace_evidence_refs"}, "evidence_bindings", errors)
        _exact(value.get("admissibility"), {"witness_status", "evidence_complete", "phase_reached", "channel_valid", "subject_valid", "identity_valid", "correlation_valid", "provenance_valid", "broken_admissible"}, "admissibility", errors)
    elif schema == SCHEMA_VERSIONS["verdict"]:
        if value.get("verdict") not in {x.value for x in ExecutionVerdict}:
            errors.append("verdict: unknown value")
        _objects(value.get("relation_evaluations"), {"ref", "digest"}, "relation_evaluations", errors)
        _exact(value.get("evidence_sufficiency_summary"), {"total", "holds", "broken", "not_evaluable", "witness_status"}, "evidence_sufficiency_summary", errors)
    elif schema == SCHEMA_VERSIONS["closure"]:
        _exact(value.get("analysis"), {"reason_codes", "missing_evidence"}, "analysis", errors)
        _exact(value.get("plan"), {"route", "candidate_binding_mutation_allowed", "merge_mutation_allowed", "matcher_reentry_required"}, "plan", errors)
        _exact(value.get("record"), {"status", "result_artifact_refs"}, "record", errors)
        plan = value.get("plan") or {}
        if plan.get("route") not in {x.value for x in ClosureRoute}:
            errors.append("plan.route: unknown value")
    elif schema == SCHEMA_VERSIONS["violation_package"]:
        _objects(value.get("broken_relation_evaluations"), {"ref", "digest"}, "broken_relation_evaluations", errors)
        _objects(value.get("supporting_raw_artifacts"), {"artifact_ref", "artifact_digest"}, "supporting_raw_artifacts", errors)
        _exact(value.get("claim_policy"), {"execution_relation_violation", "confirmed_vulnerability", "cve", "exploitability"}, "claim_policy", errors)
    elif schema == SCHEMA_VERSIONS["caller_bridge"]:
        _exact(value.get("repository_snapshot"), {"repository_ref", "revision", "tree_digest"}, "repository_snapshot", errors)
        _objects(value.get("verified_caller_evidence"), {"status", "repository_revision", "file", "file_digest", "line", "symbol", "callee", "edge", "build_provenance_refs"}, "verified_caller_evidence", errors)
        _objects(value.get("advisory_impact"), {"provider", "interpretation", "authority", "may_modify_execution_verdict", "may_create_verified_caller_fact"}, "advisory_impact", errors)
        _exact(value.get("claim_policy"), {"one_way", "vulnerability_confirmed", "cve", "legacy_caller_verdict_forbidden"}, "claim_policy", errors)


def validate_artifact(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    schema = value.get("schema_version")
    fields = TOP_FIELDS.get(str(schema))
    if fields is None:
        return ["schema_version: unsupported"]
    _exact(value, fields, "$", errors)
    _forbidden_recursive(value, "$", errors)
    _ref_digest_pairs(value, errors)
    _validate_nested(str(schema), value, errors)
    id_field = ID_FIELDS[str(schema)]
    if isinstance(value.get(id_field), str):
        try:
            if value[id_field] != artifact_id(value):
                errors.append(f"{id_field}: canonical identity mismatch")
        except (TypeError, ValueError) as exc:
            errors.append(f"{id_field}: {exc}")
    return sorted(dict.fromkeys(errors))


def validate_artifact_or_raise(value: Any) -> None:
    errors = validate_artifact(value)
    if errors:
        schema = value.get("schema_version", "artifact") if isinstance(value, dict) else "artifact"
        raise ExecutionModelError(str(schema), errors)


def evidence_type_allowed(value: str) -> bool:
    return value in SEMANTIC_EVIDENCE_TYPES | PROCESS_EVIDENCE_TYPES | BUILD_EVIDENCE_TYPES
