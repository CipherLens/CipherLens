"""Canonical two-stage compile/link adapter over subprocess-compatible runners."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from execution_model.canonical import artifact_digest, identify
from execution_model.model import BuildResult, PhaseResult, REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact_or_raise


Runner = Callable[..., Any]


def build_spec_from_handoff(
    handoff: Mapping[str, Any],
    *,
    toolchain: Mapping[str, Any],
    compile_units: Sequence[Mapping[str, Any]],
    include_configs: Sequence[Mapping[str, Any]] = (),
    compile_flags: Sequence[str] = (),
    library_inputs: Sequence[Mapping[str, Any]] = (),
    link_flags: Sequence[str] = (),
    expected_output: Mapping[str, Any],
    instrumentation_profile: Mapping[str, Any],
    environment_profile: Mapping[str, Any],
) -> dict[str, Any]:
    seed = handoff["build_intent_seed"]
    document = identify({
        "schema_version": SCHEMA_VERSIONS["build_spec"],
        "build_spec_id": "pending",
        "execution_handoff_ref": handoff["handoff_id"],
        "execution_handoff_digest": artifact_digest(handoff),
        "merge_ref": handoff["merge_ref"], "merge_digest": handoff["merge_digest"],
        "bound_source_ref": handoff["bound_source_ref"], "bound_source_digest": handoff["bound_source_digest"],
        "source_map_ref": handoff["source_map_ref"], "source_map_digest": handoff["source_map_digest"],
        "source_artifact_ref": handoff["source_artifact_ref"], "source_artifact_digest": handoff["source_artifact_digest"],
        "build_intent_seed_ref": seed["seed_ref"], "build_intent_seed_digest": seed["seed_digest"],
        "language": seed["hints"]["language"],
        "toolchain": dict(toolchain),
        "compile_units": [dict(item) for item in compile_units],
        "include_configs": [dict(item) for item in include_configs],
        "compile_flags": list(compile_flags),
        "library_inputs": [dict(item) for item in library_inputs],
        "link_flags": list(link_flags),
        "expected_output": dict(expected_output),
        "instrumentation_profile": dict(instrumentation_profile),
        "environment_profile": dict(environment_profile),
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document)
    return document


def _phase(phase: str, result: str, completed: Any | None, prefix: str, output: Path | None, reason: str = "") -> dict[str, Any]:
    def encoded(value: Any) -> bytes:
        return value if isinstance(value, bytes) else str(value or "").encode("utf-8", errors="replace")

    stdout = encoded(getattr(completed, "stdout", ""))
    stderr = encoded(getattr(completed, "stderr", ""))
    output_digest = hashlib.sha256(output.read_bytes()).hexdigest() if output is not None and output.is_file() else None
    return {
        "phase": phase, "result": result,
        "exit_status": getattr(completed, "returncode", None),
        "stdout_ref": f"raw:{prefix}.stdout", "stdout_digest": hashlib.sha256(stdout).hexdigest(),
        "stderr_ref": f"raw:{prefix}.stderr", "stderr_digest": hashlib.sha256(stderr).hexdigest(),
        "output_ref": f"build-output:{output.name}" if output_digest and output else None,
        "output_digest": output_digest,
        "reason_codes": [reason] if reason else [],
    }


def execute_build(
    build_spec: Mapping[str, Any],
    *,
    source_paths: Sequence[Path],
    object_paths: Sequence[Path],
    binary_path: Path,
    compiler_path: str,
    resolved_include_paths: Sequence[Path] = (),
    resolved_library_paths: Sequence[Path] = (),
    controlled_env: Mapping[str, str] | None = None,
    timeout_seconds: int = 60,
    runner: Runner = subprocess.run,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compile with -c, then link; stage identity never relies on stderr text."""

    validate_artifact_or_raise(build_spec)
    if len(source_paths) != len(object_paths) or not source_paths:
        raise ValueError("source_paths/object_paths must be non-empty and aligned")
    if len(source_paths) != len(build_spec["compile_units"]):
        raise ValueError("resolved sources must align with BuildSpec compile units")
    for source, unit in zip(source_paths, build_spec["compile_units"]):
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != unit["artifact_digest"]:
            raise ValueError("compile unit bytes do not match BuildSpec")
    compile_commands: list[list[str]] = []
    compile_completed = None
    compile_result = PhaseResult.SUCCEEDED.value
    compile_reason = ""
    try:
        for source, obj in zip(source_paths, object_paths):
            obj.parent.mkdir(parents=True, exist_ok=True)
            command = [compiler_path, *build_spec["compile_flags"]]
            command.extend(f"-I{path}" for path in resolved_include_paths)
            command.extend(["-c", str(source), "-o", str(obj)])
            compile_commands.append(command)
            compile_completed = runner(command, text=True, capture_output=True, timeout=timeout_seconds, env=dict(controlled_env or {}), check=False)
            if compile_completed.returncode != 0:
                compile_result = PhaseResult.FAILED.value
                compile_reason = "COMPILE_EXIT_NONZERO"
                break
    except FileNotFoundError:
        compile_result = PhaseResult.LAUNCH_FAILED.value
        compile_reason = "TOOLCHAIN_LAUNCH_FAILED"
    except subprocess.TimeoutExpired as exc:
        compile_completed = exc
        compile_result = PhaseResult.TIMED_OUT.value
        compile_reason = "COMPILE_TIMED_OUT"

    compile_phase = _phase("COMPILE", compile_result, compile_completed, "compile", object_paths[-1], compile_reason)
    link_completed = None
    link_result = PhaseResult.NOT_RUN.value
    link_reason = "COMPILE_NOT_SUCCEEDED" if compile_result != PhaseResult.SUCCEEDED.value else ""
    link_command: list[str] = []
    if compile_result == PhaseResult.SUCCEEDED.value:
        binary_path.parent.mkdir(parents=True, exist_ok=True)
        link_command = [compiler_path, *(str(path) for path in object_paths)]
        link_command.extend(f"-L{path}" for path in resolved_library_paths)
        link_command.extend(build_spec["link_flags"])
        link_command.extend(["-o", str(binary_path)])
        try:
            link_completed = runner(link_command, text=True, capture_output=True, timeout=timeout_seconds, env=dict(controlled_env or {}), check=False)
            link_result = PhaseResult.SUCCEEDED.value if link_completed.returncode == 0 else PhaseResult.FAILED.value
            link_reason = "" if link_result == PhaseResult.SUCCEEDED.value else "LINK_EXIT_NONZERO"
        except FileNotFoundError:
            link_result = PhaseResult.LAUNCH_FAILED.value
            link_reason = "TOOLCHAIN_LAUNCH_FAILED"
        except subprocess.TimeoutExpired as exc:
            link_completed = exc
            link_result = PhaseResult.TIMED_OUT.value
            link_reason = "LINK_TIMED_OUT"
    link_phase = _phase("LINK", link_result, link_completed, "link", binary_path, link_reason)

    if compile_result == PhaseResult.LAUNCH_FAILED.value or link_result == PhaseResult.LAUNCH_FAILED.value:
        top = BuildResult.TOOLCHAIN_LAUNCH_FAILED.value
    elif compile_result == PhaseResult.TIMED_OUT.value or link_result == PhaseResult.TIMED_OUT.value:
        top = BuildResult.BUILD_TIMED_OUT.value
    elif compile_result != PhaseResult.SUCCEEDED.value:
        top = BuildResult.COMPILE_FAILED.value
    elif link_result != PhaseResult.SUCCEEDED.value:
        top = BuildResult.LINK_FAILED.value
    elif not binary_path.is_file():
        top = BuildResult.OUTPUT_MISSING.value
    else:
        top = BuildResult.BUILT.value
    binary_digest = hashlib.sha256(binary_path.read_bytes()).hexdigest() if top == BuildResult.BUILT.value else None
    record = identify({
        "schema_version": SCHEMA_VERSIONS["build_record"], "build_record_id": "pending",
        "build_spec_ref": build_spec["build_spec_id"], "build_spec_digest": artifact_digest(build_spec),
        "result": top, "phases": [compile_phase, link_phase],
        "diagnostic_artifacts": [compile_phase["stdout_ref"], compile_phase["stderr_ref"], link_phase["stdout_ref"], link_phase["stderr_ref"]],
        "binary_ref": build_spec["expected_output"].get("artifact_ref") if binary_digest else None,
        "binary_digest": binary_digest,
        "reason_codes": [x for x in (compile_reason, link_reason) if x],
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(record)
    telemetry = {"compiler_path": compiler_path, "compile_commands": compile_commands, "link_command": link_command, "source_paths": [str(x) for x in source_paths], "object_paths": [str(x) for x in object_paths], "binary_path": str(binary_path)}
    return record, telemetry
