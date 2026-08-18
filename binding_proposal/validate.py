"""Strict payload and trusted-envelope validation."""

from __future__ import annotations

from collections import Counter
import re
from pathlib import PurePosixPath
from typing import Any, Mapping

from binding_proposal.model import AuthClass, BindingProposalError, PAYLOAD_SCHEMA_VERSION, PROPOSAL_SCHEMA_VERSION, ProviderKind, UsagePlane


PROPOSAL_LISTS = (
    "role_proposals", "subject_proposals", "operation_proposals", "input_proposals",
    "intervention_proposals", "state_continuity_proposals", "observation_proposals",
)
_PAYLOAD_REQUIRED = {"schema_version", *PROPOSAL_LISTS}
_PAYLOAD_OPTIONAL = {"advisory_rationale"}
_ITEM = {"proposal_ref", "source_ref", "target_ref", "semantic_role", "related_refs", "evidence_hints"}
_TOP_REQUIRED = {"schema_version", "proposal_id", "source_references", "target_references", "provider_provenance", "epistemic_status", "evidence", *PROPOSAL_LISTS}
_TOP_OPTIONAL = {"advisory_rationale", "raw_output_artifact_ref", "raw_output_digest"}
_REFERENCE = {"artifact_ref", "artifact_digest"}
_EVIDENCE = {"evidence_ref", "kind", "artifact_ref", "artifact_digest"}
_PROVENANCE = {"provider_kind", "usage_plane", "auth_class", "model_ref", "provider_instance_ref", "invocation_ref", "prompt_template_version", "structured_output_schema_version", "sandbox_profile", "generation_metadata", "credential_env"}
_SANDBOX = {"sandbox_mode", "working_root", "tool_network_policy", "ephemeral", "ignore_user_config", "ignore_rules"}
_GENERATION = {"transport", "exit_code"}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_TRUTH = {"verified", "eligible", "eligibility", "verdict", "satisfied", "violated", "vulnerability_confirmed", "cve_status", "security_truth"}
_SECRET_KEYS = {"api_key", "apikey", "token", "bearer_token", "session_secret", "cookie", "authorization", "authorization_header", "credential_value", "password", "secret"}


def validate_payload(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _PAYLOAD_REQUIRED, _PAYLOAD_OPTIONAL, errors)
    if value.get("schema_version") != PAYLOAD_SCHEMA_VERSION:
        errors.append(f"schema_version: expected {PAYLOAD_SCHEMA_VERSION!r}")
    _forbidden_recursive(value, "$", errors)
    for name in PROPOSAL_LISTS:
        _proposal_list(value.get(name), name, errors)
    if "advisory_rationale" in value:
        _text(value.get("advisory_rationale"), "advisory_rationale", errors)
    return sorted(dict.fromkeys(errors))


def validate_payload_or_raise(value: Any) -> None:
    errors = validate_payload(value)
    if errors:
        raise BindingProposalError("BindingProposalPayload", errors)


def validate_binding_proposal(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _TOP_REQUIRED, _TOP_OPTIONAL, errors)
    if value.get("schema_version") != PROPOSAL_SCHEMA_VERSION:
        errors.append(f"schema_version: expected {PROPOSAL_SCHEMA_VERSION!r}")
    if value.get("epistemic_status") != "PROPOSED":
        errors.append("epistemic_status: only PROPOSED is permitted")
    _text(value.get("proposal_id"), "proposal_id", errors)
    _forbidden_recursive(value, "$", errors, ignore_allowed={"epistemic_status"})
    for name in ("source_references", "target_references"):
        refs = _list(value.get(name), name, 1, errors)
        for index, item in enumerate(refs):
            record = _object(item, f"{name}[{index}]", _REFERENCE, set(), errors)
            if record:
                _repo_path(record.get("artifact_ref"), f"{name}[{index}].artifact_ref", errors)
                _sha(record.get("artifact_digest"), f"{name}[{index}].artifact_digest", errors)
    evidence = _list(value.get("evidence"), "evidence", 0, errors)
    for index, item in enumerate(evidence):
        record = _object(item, f"evidence[{index}]", _EVIDENCE, set(), errors)
        if record:
            _text(record.get("evidence_ref"), f"evidence[{index}].evidence_ref", errors)
            _text(record.get("kind"), f"evidence[{index}].kind", errors)
            _repo_path(record.get("artifact_ref"), f"evidence[{index}].artifact_ref", errors)
            _sha(record.get("artifact_digest"), f"evidence[{index}].artifact_digest", errors)
    provenance = _object(value.get("provider_provenance"), "provider_provenance", _PROVENANCE, set(), errors)
    if provenance:
        _enum(provenance.get("provider_kind"), "provider_provenance.provider_kind", {x.value for x in ProviderKind}, errors)
        _enum(provenance.get("usage_plane"), "provider_provenance.usage_plane", {x.value for x in UsagePlane}, errors)
        _enum(provenance.get("auth_class"), "provider_provenance.auth_class", {x.value for x in AuthClass}, errors)
        for key in ("model_ref", "provider_instance_ref", "invocation_ref", "prompt_template_version", "structured_output_schema_version"):
            _text(provenance.get(key), f"provider_provenance.{key}", errors)
        credential_env = provenance.get("credential_env")
        if credential_env is not None and (not isinstance(credential_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", credential_env)):
            errors.append("provider_provenance.credential_env: expected environment variable name or null")
        sandbox = _object(provenance.get("sandbox_profile"), "provider_provenance.sandbox_profile", _SANDBOX, set(), errors)
        if sandbox:
            _enum(sandbox.get("sandbox_mode"), "provider_provenance.sandbox_profile.sandbox_mode", {"READ_ONLY", "NONE"}, errors)
            _repo_path(sandbox.get("working_root"), "provider_provenance.sandbox_profile.working_root", errors, allow_dot=True)
            _enum(sandbox.get("tool_network_policy"), "provider_provenance.sandbox_profile.tool_network_policy", {"DISABLED_REQUIRED", "NOT_APPLICABLE"}, errors)
            for key in ("ephemeral", "ignore_user_config", "ignore_rules"):
                if not isinstance(sandbox.get(key), bool):
                    errors.append(f"provider_provenance.sandbox_profile.{key}: expected boolean")
        generation = _object(provenance.get("generation_metadata"), "provider_provenance.generation_metadata", _GENERATION, set(), errors)
        if generation:
            _text(generation.get("transport"), "provider_provenance.generation_metadata.transport", errors)
            if generation.get("exit_code") is not None and not isinstance(generation.get("exit_code"), int):
                errors.append("provider_provenance.generation_metadata.exit_code: expected integer or null")
    for name in PROPOSAL_LISTS:
        _proposal_list(value.get(name), name, errors)
    if "advisory_rationale" in value:
        _text(value.get("advisory_rationale"), "advisory_rationale", errors)
    for key in ("raw_output_artifact_ref",):
        if key in value:
            _repo_path(value.get(key), key, errors)
    if "raw_output_digest" in value:
        _sha(value.get("raw_output_digest"), "raw_output_digest", errors)
    return sorted(dict.fromkeys(errors))


def validate_binding_proposal_or_raise(value: Any) -> None:
    errors = validate_binding_proposal(value)
    if errors:
        raise BindingProposalError("BindingProposal", errors)


def _proposal_list(value: Any, path: str, errors: list[str]) -> None:
    items = _list(value, path, 0, errors)
    ids: list[str] = []
    for index, item in enumerate(items):
        item_path = f"{path}[{index}]"
        proposal = _object(item, item_path, _ITEM, set(), errors)
        if not proposal:
            continue
        for key in ("proposal_ref", "source_ref", "target_ref", "semantic_role"):
            _text(proposal.get(key), f"{item_path}.{key}", errors)
        _strings(proposal.get("related_refs"), f"{item_path}.related_refs", 0, errors)
        _strings(proposal.get("evidence_hints"), f"{item_path}.evidence_hints", 0, errors)
        if isinstance(proposal.get("proposal_ref"), str):
            ids.append(proposal["proposal_ref"])
    for item, count in Counter(ids).items():
        if count > 1:
            errors.append(f"{path}: duplicate proposal_ref {item!r}")


def _forbidden_recursive(value: Any, path: str, errors: list[str], ignore_allowed: set[str] | None = None) -> None:
    ignored = ignore_allowed or set()
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            child_path = f"{path}.{key}"
            if lowered in _FORBIDDEN_TRUTH and lowered not in ignored:
                errors.append(f"{child_path}: trusted truth field is forbidden")
            if lowered in _SECRET_KEYS or any(part in lowered for part in ("api_key_value", "access_token", "private_key")):
                errors.append(f"{child_path}: secret-like field is forbidden")
            _forbidden_recursive(child, child_path, errors, ignored)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _forbidden_recursive(child, f"{path}[{index}]", errors, ignored)


def _keys(value: Mapping[str, Any], path: str, required: set[str], optional: set[str], errors: list[str]) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{path}.{key}: required field missing")
    for key in sorted(set(value) - required - optional, key=str):
        errors.append(f"{path}.{key}: unknown field")


def _object(value: Any, path: str, required: set[str], optional: set[str], errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return None
    _keys(value, path, required, optional, errors)
    return value


def _list(value: Any, path: str, minimum: int, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path}: expected list")
        return []
    if len(value) < minimum:
        errors.append(f"{path}: expected at least {minimum} item(s)")
    return value


def _strings(value: Any, path: str, minimum: int, errors: list[str]) -> list[str]:
    items = _list(value, path, minimum, errors)
    for index, item in enumerate(items):
        _text(item, f"{path}[{index}]", errors)
    return [item for item in items if isinstance(item, str)]


def _text(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")


def _enum(value: Any, path: str, allowed: set[str], errors: list[str]) -> None:
    if value not in allowed:
        errors.append(f"{path}: unknown value {value!r}")


def _sha(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        errors.append(f"{path}: expected lowercase SHA-256")


def _repo_path(value: Any, path: str, errors: list[str], allow_dot: bool = False) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected repo-relative path")
        return
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or (value == "." and not allow_dot):
        errors.append(f"{path}: expected repo-relative path")
