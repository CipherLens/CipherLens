"""Thin build/run integration which preserves raw evidence before normalization."""

from __future__ import annotations

import hashlib
import subprocess
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from execution_model.model import BuildResult
from execution_model.canonical import identify
from execution_model.registry import validate_artifact_or_raise
from execution_pipeline.build_adapter import build_spec_from_handoff, execute_build
from execution_pipeline.collect_adapter import oracle_event_acquisitions, sanitizer_evidence
from execution_pipeline.runner_adapter import build_run_spec, execute_run
from pipeline_v2.artifact_store import ArtifactRef, ArtifactStore


Runner = Callable[..., Any]


def _as_bytes(value: Any) -> bytes:
    return value if isinstance(value, bytes) else str(value or "").encode("utf-8", errors="replace")


@dataclass
class CapturingRunner:
    """Records subprocess-compatible results; it is not a second executor."""
    delegate: Runner = subprocess.run
    calls: list[tuple[list[str], Any]] = field(default_factory=list)

    def __call__(self, command: Sequence[str], **kwargs: Any) -> Any:
        try:
            result = self.delegate(command, **kwargs)
        except Exception as exc:
            self.calls.append((list(command), exc))
            raise
        self.calls.append((list(command), result))
        return result


@dataclass(frozen=True)
class RunnerConfiguration:
    toolchain: Mapping[str, Any]
    compile_flags: tuple[str, ...]
    link_flags: tuple[str, ...]
    expected_output: Mapping[str, Any]
    instrumentation_profile: Mapping[str, Any]
    environment_profile: Mapping[str, Any]
    working_directory_profile: Mapping[str, Any]
    timeout_policy: Mapping[str, Any]
    compiler_path: str
    timeout_seconds: int = 10
    include_configs: tuple[Mapping[str, Any], ...] = ()
    library_inputs: tuple[Mapping[str, Any], ...] = ()


def configuration_from_build_profile_mapping(
    mapping: Mapping[str, Any], *, expected_output: Mapping[str, Any],
    instrumentation_profile: Mapping[str, Any], environment_profile: Mapping[str, Any],
    working_directory_profile: Mapping[str, Any], timeout_policy: Mapping[str, Any],
    compiler_path: str, timeout_seconds: int = 10,
) -> RunnerConfiguration:
    """Create runner configuration from a C0 mapping without resolving paths.

    The mapping owns semantic compile/link inputs.  ``compiler_path`` remains
    local runtime telemetry and is deliberately not added to BuildSpec.
    """

    if mapping.get("status") != "READY_FOR_BUILDSPEC_FIXTURE":
        raise ValueError("runner configuration requires complete C0 profile mapping")
    if mapping.get("authority") != "C0_PREPARATION_ONLY_NO_BUILD_EXECUTION":
        raise ValueError("runner configuration requires C0 profile mapping authority")
    return RunnerConfiguration(
        toolchain=dict(mapping["toolchain"]), compile_flags=tuple(mapping["compile_flags"]),
        link_flags=tuple(mapping["link_flags"]), expected_output=dict(expected_output),
        instrumentation_profile=dict(instrumentation_profile), environment_profile=dict(environment_profile),
        working_directory_profile=dict(working_directory_profile), timeout_policy=dict(timeout_policy),
        compiler_path=compiler_path, timeout_seconds=timeout_seconds,
        include_configs=tuple(dict(item) for item in mapping["include_configs"]),
        library_inputs=tuple(dict(item) for item in mapping["library_inputs"]),
    )


@dataclass(frozen=True)
class RunnerResult:
    build_spec: Mapping[str, Any]
    build_record: Mapping[str, Any]
    run_spec: Mapping[str, Any] | None
    run_record: Mapping[str, Any] | None
    raw_artifacts: tuple[ArtifactRef, ...]
    acquisitions: tuple[Mapping[str, Any], ...]
    process_evidence: tuple[Mapping[str, Any], ...]


class PipelineRunnerBackend:
    """Only accepts a validated handoff and delegates process execution to Batch 6B."""

    def __init__(self, store: ArtifactStore, configuration: RunnerConfiguration, *, runner: Runner = subprocess.run) -> None:
        self.store, self.configuration, self.runner = store, configuration, runner

    def _persist(self, ref: str, data: bytes) -> ArtifactRef:
        return self.store.put_raw(ref, data, media_type="text/plain")

    @staticmethod
    def _raw_ref(namespace: str, ref: str) -> str:
        return f"attempts/{namespace}/{ref}"

    @classmethod
    def _namespace_build_record(cls, record: Mapping[str, Any], namespace: str) -> dict[str, Any]:
        changed = deepcopy(dict(record))
        remapped: dict[str, str] = {}
        for phase in changed["phases"]:
            for key in ("stdout_ref", "stderr_ref"):
                old = phase[key]; phase[key] = cls._raw_ref(namespace, old); remapped[old] = phase[key]
        changed["diagnostic_artifacts"] = [remapped.get(ref, ref) for ref in changed["diagnostic_artifacts"]]
        changed = identify(changed); validate_artifact_or_raise(changed)
        return changed

    @classmethod
    def _namespace_run_record(cls, record: Mapping[str, Any], namespace: str) -> dict[str, Any]:
        changed = deepcopy(dict(record)); remapped: dict[str, str] = {}
        for raw in changed["raw_artifacts"]:
            old = raw["artifact_ref"]; raw["artifact_ref"] = cls._raw_ref(namespace, old); remapped[old] = raw["artifact_ref"]
        for event in changed["process_events"]:
            event["artifact_refs"] = [remapped.get(ref, ref) for ref in event["artifact_refs"]]
        changed = identify(changed); validate_artifact_or_raise(changed)
        return changed

    def execute(self, handoff: Mapping[str, Any], *, source_bytes: bytes, workspace: Path, artifact_namespace: str, input_artifacts: Sequence[Mapping[str, Any]] = (), argv: Sequence[str] = (), phase_callback: Callable[[str], None] | None = None) -> RunnerResult:
        validate_artifact_or_raise(handoff)
        if handoff.get("schema_version") != "cipherlens.execution_handoff.v0.1" or "handoff_id" not in handoff or "bound_source_ref" not in handoff:
            raise ValueError("PipelineRunnerBackend requires canonical ExecutionHandoff")
        ArtifactStore._validate_ref(artifact_namespace)
        workspace = workspace.resolve(); workspace.mkdir(parents=True, exist_ok=True)
        source = workspace / "bound_source.c"; source.write_bytes(source_bytes)
        obj = workspace / "bound_source.o"; binary = workspace / "bound_binary"
        config = self.configuration
        build_spec = build_spec_from_handoff(
            handoff, toolchain=config.toolchain,
            compile_units=[{"artifact_ref": handoff["source_artifact_ref"], "artifact_digest": handoff["source_artifact_digest"], "language": handoff["build_intent_seed"]["hints"]["language"]}],
            include_configs=config.include_configs, compile_flags=config.compile_flags,
            library_inputs=config.library_inputs, link_flags=config.link_flags,
            expected_output=config.expected_output, instrumentation_profile=config.instrumentation_profile, environment_profile=config.environment_profile,
        )
        captured = CapturingRunner(self.runner)
        build_record, _ = execute_build(build_spec, source_paths=[source], object_paths=[obj], binary_path=binary, compiler_path=config.compiler_path, controlled_env={}, timeout_seconds=config.timeout_seconds, runner=captured)
        build_record = self._namespace_build_record(build_record, artifact_namespace)
        raw: list[ArtifactRef] = []
        compile_calls = captured.calls[:-1] if len(captured.calls) > 1 else captured.calls
        link_calls = captured.calls[-1:] if len(captured.calls) > 1 else []
        if compile_calls:
            result = compile_calls[-1][1]; raw.extend([self._persist(self._raw_ref(artifact_namespace, "raw:compile.stdout"), _as_bytes(getattr(result, "stdout", ""))), self._persist(self._raw_ref(artifact_namespace, "raw:compile.stderr"), _as_bytes(getattr(result, "stderr", "")))])
        else:
            raw.extend([self._persist(self._raw_ref(artifact_namespace, "raw:compile.stdout"), b""), self._persist(self._raw_ref(artifact_namespace, "raw:compile.stderr"), b"")])
        if link_calls:
            result = link_calls[-1][1]; raw.extend([self._persist(self._raw_ref(artifact_namespace, "raw:link.stdout"), _as_bytes(getattr(result, "stdout", ""))), self._persist(self._raw_ref(artifact_namespace, "raw:link.stderr"), _as_bytes(getattr(result, "stderr", "")))])
        else:
            raw.extend([self._persist(self._raw_ref(artifact_namespace, "raw:link.stdout"), b""), self._persist(self._raw_ref(artifact_namespace, "raw:link.stderr"), b"")])
        if build_record["result"] != BuildResult.BUILT.value:
            return RunnerResult(build_spec, build_record, None, None, tuple(raw), (), ())
        if phase_callback is not None:
            phase_callback("BUILT")
        run_spec = build_run_spec(
            build_spec, build_record, input_artifacts=input_artifacts, argv=argv,
            environment_profile=config.environment_profile, working_directory_profile=config.working_directory_profile,
            timeout_policy=config.timeout_policy, instrumentation_profile=config.instrumentation_profile,
            required_capture_refs=handoff["observation_capture_refs"], expected_phases=["TARGET_OPERATION", "PROCESS_END"], expected_markers=["ORACLE_EVENT"], required_channels=["stdout", "stderr"],
        )
        if phase_callback is not None:
            phase_callback("RUNNING")
        run_capture = CapturingRunner(self.runner)
        run_record, _ = execute_run(run_spec, binary_path=binary, controlled_env={}, working_directory=workspace, timeout_seconds=config.timeout_seconds, runner=run_capture)
        run_record = self._namespace_run_record(run_record, artifact_namespace)
        completed = run_capture.calls[-1][1] if run_capture.calls else None
        stdout, stderr = _as_bytes(getattr(completed, "stdout", "")), _as_bytes(getattr(completed, "stderr", ""))
        stdout_ref = self._raw_ref(artifact_namespace, "raw:run.stdout")
        stderr_ref = self._raw_ref(artifact_namespace, "raw:run.stderr")
        sanitizer_ref = self._raw_ref(artifact_namespace, "raw:run.sanitizer")
        raw.extend([self._persist(stdout_ref, stdout), self._persist(stderr_ref, stderr)])
        sanitizer_raw, sanitizer_events = sanitizer_evidence(sanitizer_ref, stderr)
        if sanitizer_events:
            raw.append(self._persist(sanitizer_raw["artifact_ref"], stderr))
        _, stdout_acquisitions = oracle_event_acquisitions(stdout_ref, stdout, allowed_capture_refs=handoff["observation_capture_refs"])
        _, stderr_acquisitions = oracle_event_acquisitions(stderr_ref, stderr, allowed_capture_refs=handoff["observation_capture_refs"])
        return RunnerResult(build_spec, build_record, run_spec, run_record, tuple(raw), tuple(stdout_acquisitions + stderr_acquisitions), tuple(sanitizer_events))
