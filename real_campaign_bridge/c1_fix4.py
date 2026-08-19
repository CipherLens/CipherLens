"""Controlled library-rebuild provenance records for the approved C1 unit.

All functions here are pure record construction: the controlled build is
performed separately and its byte-addressed evidence is passed in.  Nothing in
this module executes a compiler, a target, a provider, or a network request.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from target_knowledge.canonical import canonical_json_bytes, identified, semantic_safety_errors

from .c1_gate import APPROVED_UNIT_ID


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
CAMPAIGN_SCOPE = "NOT_FULL_CAMPAIGN"
_HEX = set("0123456789abcdef")


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _HEX for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _edge(value: Mapping[str, Any], label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not isinstance(value.get("ref"), str) or not value["ref"]:
        raise ValueError(f"{label} requires ref + digest")
    if value["ref"].startswith("/"):
        raise ValueError(f"{label} ref must be logical, not absolute")
    return {"ref": value["ref"], "digest": _sha(value.get("digest"), f"{label} digest")}


def _common() -> dict[str, Any]:
    return {
        "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE,
        "campaign_scope": CAMPAIGN_SCOPE,
        "execution_status": "BUILD_PROVENANCE_ONLY",
        "report_real_number_allowed": False,
    }


def _identified(document: Mapping[str, Any], prefix: str, field: str) -> dict[str, Any]:
    errors = semantic_safety_errors(document)
    if errors:
        raise ValueError("; ".join(errors))
    return identified(document, prefix, field)


def make_controlled_rebuild_plan(
    *, source_identity: Mapping[str, Any], source_tree_digest: str,
    include_evidence: Mapping[str, Any], selected_headers: Sequence[Mapping[str, Any]],
    build_profile: Mapping[str, Any], compiler_logical_identity: str,
    architecture: str, expected_libraries: Sequence[str], telemetry: Mapping[str, Any],
) -> dict[str, Any]:
    if compiler_logical_identity != "cc" or architecture != "x86_64":
        raise ValueError("controlled rebuild plan is frozen for the approved local toolchain")
    if not expected_libraries or any(not name.startswith("libmbed") or not name.endswith(".a") for name in expected_libraries):
        raise ValueError("controlled rebuild plan requires only expected static libraries")
    return _identified({
        "schema_version": "cipherlens.c1_controlled_rebuild_plan.v0.1",
        **_common(),
        "authority": "C1_FIXED_LIBRARY_REBUILD_PROVENANCE_ONLY",
        "source_identity": _edge(source_identity, "fixed SourceIdentity"),
        "fixed_source_tree_digest": _sha(source_tree_digest, "fixed source tree digest"),
        "include_evidence": _edge(include_evidence, "fixed include evidence"),
        "selected_headers": [_edge(item, f"selected header {index}") for index, item in enumerate(selected_headers)],
        "preparation_build_profile": _edge(build_profile, "preparation BuildProfile"),
        "compiler_logical_identity": compiler_logical_identity,
        "architecture": architecture,
        "build_system": "cmake-unix-makefiles",
        "commands": [
            {"operation": "CONFIGURE", "argv": ["cmake", "-S", "source:mbedtls:0020:fixed", "-B", "build-dir:c1fix4:0020:fixed", "-DENABLE_TESTING=OFF", "-DENABLE_PROGRAMS=OFF", "-DUSE_STATIC_MBEDTLS_LIBRARY=ON", "-DUSE_SHARED_MBEDTLS_LIBRARY=OFF", "-DGEN_FILES=OFF", "-DDISABLE_PACKAGE_CONFIG_AND_INSTALL=ON", "-DMBEDTLS_FATAL_WARNINGS=OFF", "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]},
            {"operation": "BUILD_LIBRARY_ONLY", "argv": ["cmake", "--build", "build-dir:c1fix4:0020:fixed", "--target", "lib", "--parallel", "1"]},
        ],
        "forbidden_operations": ["RUN_TARGET_BINARY", "RUN_TEST", "RUN_POC", "RUN_HARNESS", "RUN_CAMPAIGN", "NETWORK", "PROVIDER"],
        "environment_allowlist": ["LANG", "LC_ALL", "PATH"],
        "timeout_policy_seconds": 120,
        "expected_library_outputs": list(expected_libraries),
        "expected_object_input_closure": "COMPILE_COMMANDS_AND_OBJECT_DIGESTS_REQUIRED",
        "telemetry": dict(telemetry),
    }, "c1-controlled-rebuild-plan", "plan_id")


def make_compiler_version_evidence(*, compiler_version: Mapping[str, Any], cmake_version: Mapping[str, Any], archive_version: Mapping[str, Any]) -> dict[str, Any]:
    return _identified({
        "schema_version": "cipherlens.c1_compiler_version_evidence.v0.1",
        **_common(),
        "status": "COMPLETE",
        "compiler_version_output": _edge(compiler_version, "compiler version output"),
        "build_system_version_output": _edge(cmake_version, "CMake version output"),
        "archive_tool_version_output": _edge(archive_version, "archive tool version output"),
        "authority": "C1_LOCAL_TOOL_VERSION_BYTES",
    }, "c1-compiler-version-evidence", "evidence_id")


def make_build_config_evidence(*, plan: Mapping[str, Any], cache: Mapping[str, Any], configure_stdout: Mapping[str, Any], configure_stderr: Mapping[str, Any], compile_database: Mapping[str, Any]) -> dict[str, Any]:
    return _identified({
        "schema_version": "cipherlens.c1_build_config_evidence.v0.1",
        **_common(),
        "status": "COMPLETE",
        "plan": _edge({"ref": plan["plan_id"], "digest": hashlib.sha256(canonical_json_bytes(plan)).hexdigest()}, "controlled rebuild plan"),
        "cmake_cache": _edge(cache, "CMake cache"),
        "configure_stdout": _edge(configure_stdout, "configure stdout"),
        "configure_stderr": _edge(configure_stderr, "configure stderr"),
        "compile_database": _edge(compile_database, "compile database"),
        "tests_enabled": False,
        "programs_enabled": False,
        "authority": "C1_CMAKE_CONFIG_BYTES",
    }, "c1-build-config-evidence", "evidence_id")


def make_compile_invocation_manifest(*, config: Mapping[str, Any], units: Sequence[Mapping[str, Any]], build_stdout: Mapping[str, Any], build_stderr: Mapping[str, Any]) -> dict[str, Any]:
    normalized = []
    for index, item in enumerate(units):
        normalized.append({
            "object": _edge(item["object"], f"compile object {index}"),
        })
    if not normalized:
        raise ValueError("compile invocation manifest requires object closure")
    return _identified({
        "schema_version": "cipherlens.c1_compile_invocation_manifest.v0.1",
        **_common(),
        "status": "COMPLETE",
        "build_config": _edge({"ref": config["evidence_id"], "digest": hashlib.sha256(canonical_json_bytes(config)).hexdigest()}, "build config evidence"),
        "compiled_object_outputs": normalized,
        "compile_command_count": len(normalized),
        "build_stdout": _edge(build_stdout, "build stdout"),
        "build_stderr": _edge(build_stderr, "build stderr"),
        "authority": "C1_COMPILE_DATABASE_AND_OBJECT_CLOSURE",
    }, "c1-compile-invocation-manifest", "manifest_id")


def make_object_inventory(*, compile_manifest: Mapping[str, Any]) -> dict[str, Any]:
    units = compile_manifest.get("compiled_object_outputs", [])
    objects = [dict(item["object"]) for item in units]
    return _identified({
        "schema_version": "cipherlens.c1_rebuilt_object_inventory.v0.1",
        **_common(),
        "status": "COMPLETE" if objects else "MISSING",
        "compile_manifest": _edge({"ref": compile_manifest["manifest_id"], "digest": hashlib.sha256(canonical_json_bytes(compile_manifest)).hexdigest()}, "compile manifest"),
        "object_inputs": objects,
        "missing_provenance": [] if objects else ["OBJECT_INPUT_PROVENANCE_MISSING"],
        "authority": "C1_REBUILT_OBJECT_BYTES",
    }, "c1-rebuilt-object-inventory", "inventory_id")


def make_archive_command_evidence(*, archive_commands: Sequence[Mapping[str, Any]], libraries: Sequence[Mapping[str, Any]], build_stdout: Mapping[str, Any]) -> dict[str, Any]:
    commands = [_edge(item, f"archive command {index}") for index, item in enumerate(archive_commands)]
    outputs = [_edge(item, f"rebuilt library {index}") for index, item in enumerate(libraries)]
    if len(commands) != 3 or len(outputs) != 3:
        raise ValueError("controlled rebuild requires three archive commands and libraries")
    return _identified({
        "schema_version": "cipherlens.c1_archive_command_evidence.v0.1",
        **_common(),
        "status": "COMPLETE",
        "archive_command_files": commands,
        "generated_library_artifacts": outputs,
        "build_stdout": _edge(build_stdout, "build stdout"),
        "authority": "C1_CMAKE_ARCHIVE_COMMAND_AND_OUTPUT_BYTES",
    }, "c1-archive-command-evidence", "evidence_id")


def make_library_build_provenance_record(*, plan: Mapping[str, Any], compiler: Mapping[str, Any], config: Mapping[str, Any], compile_manifest: Mapping[str, Any], objects: Mapping[str, Any], archive: Mapping[str, Any], environment: Mapping[str, Any]) -> dict[str, Any]:
    components = (plan, compiler, config, compile_manifest, objects, archive, environment)
    if any(item.get("status") != "COMPLETE" for item in components[1:6]) or objects.get("status") != "COMPLETE":
        missing = ["CONTROLLED_REBUILD_EVIDENCE_INCOMPLETE"]
    else:
        missing = []
    complete = not missing
    return _identified({
        "schema_version": "cipherlens.library_build_provenance_record.v0.1",
        **_common(),
        "provenance_completeness_status": "COMPLETE" if complete else "PARTIAL",
        "validation_status": "REPRODUCIBLE_PROVENANCE_READY" if complete else "PROVENANCE_PARTIAL",
        "controlled_rebuild_plan": _edge({"ref": plan["plan_id"], "digest": hashlib.sha256(canonical_json_bytes(plan)).hexdigest()}, "plan"),
        "compiler_version_evidence": _edge({"ref": compiler["evidence_id"], "digest": hashlib.sha256(canonical_json_bytes(compiler)).hexdigest()}, "compiler"),
        "build_system_config_evidence": _edge({"ref": config["evidence_id"], "digest": hashlib.sha256(canonical_json_bytes(config)).hexdigest()}, "config"),
        "compile_invocation_manifest": _edge({"ref": compile_manifest["manifest_id"], "digest": hashlib.sha256(canonical_json_bytes(compile_manifest)).hexdigest()}, "compile manifest"),
        "object_input_evidence": _edge({"ref": objects["inventory_id"], "digest": hashlib.sha256(canonical_json_bytes(objects)).hexdigest()}, "objects"),
        "archive_command_evidence": _edge({"ref": archive["evidence_id"], "digest": hashlib.sha256(canonical_json_bytes(archive)).hexdigest()}, "archive"),
        "environment_profile": _edge({"ref": environment["profile_id"], "digest": hashlib.sha256(canonical_json_bytes(environment)).hexdigest()}, "environment"),
        "generated_library_artifacts": list(archive["generated_library_artifacts"]),
        "stdout_stderr_logs": [dict(config["configure_stdout"]), dict(config["configure_stderr"]), dict(compile_manifest["build_stdout"]), dict(compile_manifest["build_stderr"])],
        "missing_provenance": missing,
        "authority": "C1_CONTROLLED_REBUILD_LIBRARY_PROVENANCE",
    }, "c1-library-build-provenance", "provenance_id")


def make_existing_vs_rebuilt_alignment(*, existing: Sequence[Mapping[str, Any]], rebuilt: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    old = [_edge(item, f"existing library {index}") for index, item in enumerate(existing)]
    new = [_edge(item, f"rebuilt library {index}") for index, item in enumerate(rebuilt)]
    if len(old) != 3 or len(new) != 3:
        raise ValueError("library alignment requires three existing and rebuilt artifacts")
    old_by_name = {item["ref"].rsplit(":", 1)[-1]: item["digest"] for item in old}
    new_by_name = {item["ref"].rsplit("/", 1)[-1]: item["digest"] for item in new}
    matches = all(old_by_name.get(name) == digest for name, digest in new_by_name.items())
    return _identified({
        "schema_version": "cipherlens.c1_existing_rebuilt_library_alignment.v0.1",
        **_common(),
        "status": "MATCHES_EXISTING" if matches else "DIFFERS_FROM_EXISTING",
        "old_library_artifacts": old,
        "rebuilt_library_artifacts": new,
        "c1_must_use_rebuilt_provenance_complete_libraries": not matches,
        "authority": "C1_LIBRARY_IDENTITY_ALIGNMENT",
    }, "c1-existing-rebuilt-library-alignment", "alignment_id")


def make_build_profile_alignment(*, plan: Mapping[str, Any], provenance: Mapping[str, Any], existing_profile: Mapping[str, Any]) -> dict[str, Any]:
    complete = provenance.get("validation_status") == "REPRODUCIBLE_PROVENANCE_READY"
    return _identified({
        "schema_version": "cipherlens.c1_rebuilt_build_profile_alignment.v0.1",
        **_common(),
        "status": "COMPLETE" if complete else "INCOMPLETE",
        "controlled_rebuild_plan": _edge({"ref": plan["plan_id"], "digest": hashlib.sha256(canonical_json_bytes(plan)).hexdigest()}, "plan"),
        "rebuilt_library_provenance": _edge({"ref": provenance["provenance_id"], "digest": hashlib.sha256(canonical_json_bytes(provenance)).hexdigest()}, "provenance"),
        "prior_preparation_profile": _edge(existing_profile, "prior preparation profile"),
        "authority": "C1_REBUILT_PROFILE_SUPERSEDES_PREPARATION_ONLY_FOR_LIBRARY_INPUTS",
        "missing_provenance": [] if complete else ["LIBRARY_BUILD_PROVENANCE_MISSING"],
    }, "c1-rebuilt-build-profile-alignment", "alignment_id")


def make_c1_pre_run_gate(*, source: Mapping[str, Any], include: Mapping[str, Any], provenance: Mapping[str, Any], profile_alignment: Mapping[str, Any], local_mapping: Mapping[str, Any], lineage: Mapping[str, Any], build_readiness: Mapping[str, Any], parent_gate: Mapping[str, Any]) -> dict[str, Any]:
    checks = {
        "FIXED_SOURCE": source.get("status") == "VERIFIED",
        "FIXED_INCLUDE": include.get("status") == "VERIFIED",
        "LIBRARY_PROVENANCE": provenance.get("validation_status") == "REPRODUCIBLE_PROVENANCE_READY",
        "BUILD_PROFILE_ALIGNMENT": profile_alignment.get("status") == "COMPLETE",
        "LOCAL_MAPPING": local_mapping.get("status") == "COMPLETE",
        "C1_LINEAGE": lineage.get("status") == "COMPLETE_NOT_EXECUTED",
        "BUILDSPEC": build_readiness.get("status") == "BUILDSPEC_MATERIALIZED_NOT_EXECUTED",
    }
    blockers = [f"{name}_MISSING" for name, value in checks.items() if not value]
    ready = not blockers
    return _identified({
        "schema_version": "cipherlens.c1_pre_run_gate.v0.3",
        **_common(),
        "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if ready else "C1_PRE_RUN_GATE_STILL_BLOCKED",
        "parent_gate": _edge(parent_gate, "C1-fix3 claim gate"),
        "checks": [{"check": key, "status": "PASS" if value else "BLOCKED"} for key, value in checks.items()],
        "blocking_reasons": blockers,
        "allowed_next_stage": "C1_RETRY_ONLY" if ready else "C1_FIX_CONTINUE",
        "run_spec_readiness": "AWAITING_BUILT_BINARY_UNDER_SEPARATELY_AUTHORIZED_C1_RETRY",
        "full_campaign_allowed": False,
        "current_campaign_result": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED",
        "witness_generated": False,
        "structured_trace_generated": False,
        "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
        "authority": "C1_FIX4_PRE_RUN_GATE_ONLY",
    }, "c1-fix4-pre-run-gate", "decision_id")


def make_artifact_index(*, parent_index: Mapping[str, Any], artifacts: Mapping[str, Mapping[str, Any]], status: str) -> dict[str, Any]:
    return _identified({
        "schema_version": "cipherlens.c1_repair_artifact_index.v0.4",
        **_common(),
        "status": status,
        "parent_artifact_index": _edge(parent_index, "C1-fix3 artifact index"),
        "repair_lineage": "CREATE_ONLY_FIX4_SUCCESSOR_DO_NOT_REWRITE_PARENT",
        "artifacts": [{"artifact_type": name, **_edge(value, f"artifact {name}")} for name, value in sorted(artifacts.items())],
        "authority": "C1_FIX4_CREATE_ONLY_ARTIFACT_INDEX",
    }, "c1-fix4-artifact-index", "index_id")
