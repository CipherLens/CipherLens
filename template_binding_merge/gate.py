"""Fail-closed input gate for Template--CandidateBinding Merge."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from candidate_binding.canonical import candidate_binding_digest, validation_digest
from candidate_binding.model import VALIDATOR_REGISTRY_VERSION as BINDING_VALIDATOR_REGISTRY_VERSION
from candidate_binding.validate import (
    validate_candidate_binding_or_raise,
    validate_validation_artifact_or_raise,
)
from trigger_template_interface.canonical import manifest_digest
from trigger_template_interface.validate import validate_manifest_or_raise

from template_binding_merge.model import MergeGateError, MergeGateResult, TemplateBundle


def validate_merge_gate(
    bundle: TemplateBundle,
    template_manifest: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    candidate_binding_validation: Mapping[str, Any],
    repo_root: str | Path,
    *,
    expected_target_scope: Mapping[str, Any] | None = None,
) -> MergeGateResult:
    """Validate all frozen upstream inputs without repairing or substituting them."""

    errors: list[str] = []
    try:
        validate_manifest_or_raise(template_manifest)
    except ValueError as exc:
        errors.append(f"template_interface: {exc}")
    try:
        validate_candidate_binding_or_raise(candidate_binding)
    except ValueError as exc:
        errors.append(f"candidate_binding: {exc}")
    try:
        validate_validation_artifact_or_raise(candidate_binding_validation)
    except ValueError as exc:
        errors.append(f"candidate_binding_validation: {exc}")

    root = Path(repo_root).resolve()
    _check_repo_artifact(
        root, bundle.source_artifact_ref, bundle.source_artifact_digest,
        "template_bundle.source_artifact", errors,
    )
    for index, artifact_ref in enumerate(
        template_manifest.get("provenance", {}).get("source_artifact_refs", [])
    ):
        _check_repo_artifact(root, artifact_ref, None, f"template_interface.provenance[{index}]", errors)
    for index, slot in enumerate(template_manifest.get("slots", [])):
        artifact_ref = slot.get("source_locator", {}).get("artifact_ref")
        _check_repo_artifact(root, artifact_ref, None, f"template_interface.slots[{index}].source_locator", errors)
    for index, input_binding in enumerate(candidate_binding.get("input_bindings", [])):
        artifact_ref = input_binding.get("artifact_ref")
        if artifact_ref is not None:
            _check_repo_artifact(root, artifact_ref, None, f"candidate_binding.input_bindings[{index}]", errors)

    manifest_ref = template_manifest.get("manifest_id")
    manifest_template_ref = template_manifest.get("trigger_template_ref")
    manifest_template_digest = template_manifest.get("trigger_template_digest")
    binding_ref = candidate_binding.get("binding_id")
    binding_template_ref = candidate_binding.get("trigger_template_ref")
    binding_template_digest = candidate_binding.get("trigger_template_digest")

    if not (
        bundle.trigger_template_ref
        == manifest_template_ref
        == binding_template_ref
    ):
        errors.append("template_ref: bundle, interface, and CandidateBinding must match exactly")
    if not (
        bundle.trigger_template_digest
        == manifest_template_digest
        == binding_template_digest
    ):
        errors.append("template_digest: bundle, interface, and CandidateBinding must match exactly")

    actual_binding_digest = _safe_digest(candidate_binding_digest, candidate_binding, "candidate_binding", errors)
    actual_validation_digest = _safe_digest(validation_digest, candidate_binding_validation, "candidate_binding_validation", errors)
    actual_manifest_digest = _safe_digest(manifest_digest, template_manifest, "template_interface", errors)

    if candidate_binding_validation.get("candidate_binding_ref") != binding_ref:
        errors.append("candidate_binding_validation.candidate_binding_ref: current binding mismatch")
    if actual_binding_digest is not None and candidate_binding_validation.get("candidate_binding_digest") != actual_binding_digest:
        errors.append("candidate_binding_validation.candidate_binding_digest: current binding mismatch")
    if candidate_binding_validation.get("validator_registry_version") != BINDING_VALIDATOR_REGISTRY_VERSION:
        errors.append("candidate_binding_validation.validator_registry_version: unsupported registry")
    if candidate_binding_validation.get("status") != "VALID":
        errors.append("candidate_binding_validation.status: only VALID may enter Merge")

    reference_checks = [
        check for check in candidate_binding_validation.get("check_results", [])
        if check.get("validator_type") == "REFERENCE_INTEGRITY"
    ]
    if len(reference_checks) != 1 or reference_checks[0].get("result") != "PASS":
        errors.append("candidate_binding_validation: REFERENCE_INTEGRITY must be uniquely PASS")
    elif manifest_ref not in reference_checks[0].get("binding_refs", []):
        errors.append("candidate_binding_validation: current interface ref is not integrity-bound")
    elif actual_manifest_digest not in reference_checks[0].get("evidence_refs", []):
        errors.append("candidate_binding_validation: current interface digest is not integrity-bound")

    target_checks = [
        check for check in candidate_binding_validation.get("check_results", [])
        if check.get("validator_type") == "TARGET_SCOPE"
    ]
    if len(target_checks) != 1 or target_checks[0].get("result") != "PASS":
        errors.append("candidate_binding_validation: TARGET_SCOPE must be uniquely PASS")
    if expected_target_scope is not None and dict(candidate_binding.get("target_scope", {})) != dict(expected_target_scope):
        errors.append("target_scope: expected scope does not exactly match CandidateBinding")

    if errors:
        raise MergeGateError("Merge input gate", errors)
    assert actual_manifest_digest is not None
    assert actual_binding_digest is not None
    assert actual_validation_digest is not None
    return MergeGateResult(
        template_bundle=bundle,
        template_manifest=template_manifest,
        candidate_binding=candidate_binding,
        candidate_binding_validation=candidate_binding_validation,
        template_interface_digest=actual_manifest_digest,
        candidate_binding_digest=actual_binding_digest,
        candidate_binding_validation_digest=actual_validation_digest,
    )


def _safe_digest(function: Any, value: Mapping[str, Any], label: str, errors: list[str]) -> str | None:
    try:
        return str(function(value))
    except (TypeError, ValueError, KeyError) as exc:
        errors.append(f"{label}: canonical digest unavailable ({exc})")
        return None


def _check_repo_artifact(
    root: Path,
    artifact_ref: Any,
    expected_digest: str | None,
    label: str,
    errors: list[str],
) -> None:
    if not isinstance(artifact_ref, str) or not artifact_ref:
        errors.append(f"{label}: invalid artifact ref")
        return
    pure = PurePosixPath(artifact_ref)
    if pure.is_absolute() or ".." in pure.parts:
        errors.append(f"{label}: artifact ref must be repo-relative")
        return
    path = (root / pure).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        errors.append(f"{label}: artifact resolves outside repository")
        return
    if not path.is_file():
        errors.append(f"{label}: artifact is not resolvable")
        return
    if expected_digest is not None:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_digest:
            errors.append(f"{label}: content digest mismatch")
