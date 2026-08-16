"""Orchestrate ImpactLift analysis through an injected AgentProvider.

The runner loads a Candidate Context Pack, delegates analysis, validates the
provider's structured result, and writes an artifact.  It contains no source
exploration, model integration, prompt, or impact-classification logic.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from caller_audit.io_utils import load_yaml, write_yaml
from utils.agent_provider import AgentProvider


RESULT_SCHEMA = "cipherlens_impact_exploration_v1"
CONTEXT_PACK_SCHEMA = "cipherlens_candidate_context_pack_v1"
GENERATED_BY = "caller_audit.impact_runner"
DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schemas" / "impact_exploration_v1.yaml"

TYPE_CHECKS = {
    "string": lambda value: isinstance(value, str),
    "list": lambda value: isinstance(value, list),
    "mapping": lambda value: isinstance(value, dict),
    "array": lambda value: isinstance(value, list),
    "object": lambda value: isinstance(value, dict),
}


def _field_type_name(field: str, field_schema: Any) -> str:
    """Return a validation type name from old scalar or new structured schema."""
    if isinstance(field_schema, str):
        return field_schema
    if isinstance(field_schema, dict):
        type_name = str(field_schema.get("type") or "").strip()
        if type_name:
            return type_name
    raise ValueError(f"unsupported schema field type for {field}: {field_schema}")


def validate_context_pack(context_pack: dict[str, Any], schema: dict[str, Any]) -> None:
    expected = str(schema.get("context_pack_schema") or CONTEXT_PACK_SCHEMA)
    if context_pack.get("schema") != expected:
        raise ValueError(
            f"unsupported context pack schema: expected {expected}, "
            f"got {context_pack.get('schema', 'missing')}"
        )
    if not str(context_pack.get("candidate_id") or "").strip():
        raise ValueError("context pack candidate_id is required")
    if not isinstance(context_pack.get("provenance"), dict):
        raise ValueError("context pack provenance mapping is required")


def validate_result(
    result: dict[str, Any],
    context_pack: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    if not isinstance(result, dict):
        raise ValueError("provider result must be a mapping")

    required = [str(field) for field in schema.get("required_result_fields") or []]
    optional = [str(field) for field in schema.get("optional_result_fields") or []]
    missing = [field for field in required if field not in result]
    if missing:
        raise ValueError(f"provider result missing required fields: {', '.join(missing)}")

    if schema.get("additional_result_fields") is False:
        allowed = set(required) | set(optional)
        unexpected = sorted(set(result) - allowed)
        if unexpected:
            raise ValueError(
                f"provider result contains unsupported fields: {', '.join(unexpected)}"
            )

    for field, field_schema in (schema.get("field_types") or {}).items():
        if field not in result:
            continue
        expected_type = _field_type_name(str(field), field_schema)
        check = TYPE_CHECKS.get(str(expected_type))
        if check is None:
            raise ValueError(f"unsupported schema field type: {expected_type}")
        if not check(result.get(field)):
            raise ValueError(f"provider result field {field} must be {expected_type}")

    allowed_status = {str(value) for value in schema.get("allowed_status") or []}
    if "status" in result and allowed_status and result["status"] not in allowed_status:
        raise ValueError(f"unsupported ImpactLift status: {result['status']}")

    allowed_confidence = {
        str(value) for value in schema.get("allowed_confidence") or []
    }
    if (
        "confidence" in result
        and allowed_confidence
        and result["confidence"] not in allowed_confidence
    ):
        raise ValueError(f"unsupported ImpactLift confidence: {result['confidence']}")

    if result["candidate_id"] != context_pack["candidate_id"]:
        raise ValueError(
            "provider result candidate_id does not match the source context pack"
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _provider_provenance(provider: AgentProvider) -> dict[str, Any]:
    metadata = getattr(provider, "metadata", None)
    provider_info = {
        "name": provider.name,
        "interface": "utils.agent_provider.AgentProvider",
    }
    if isinstance(metadata, dict):
        provider_info.update(metadata)
    return provider_info


def run_impactlift(
    context_pack_path: Path,
    output_path: Path,
    provider: AgentProvider,
    *,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    timestamp_factory: Callable[[], str] = _utc_now,
) -> dict[str, Any]:
    """Run provider-neutral ImpactLift orchestration and write one artifact."""
    context_pack_path = context_pack_path.resolve()
    schema_path = schema_path.resolve()
    context_pack = load_yaml(context_pack_path)
    schema = load_yaml(schema_path)
    validate_context_pack(context_pack, schema)

    result = provider.analyze(context_pack)
    validate_result(result, context_pack, schema)

    source_bytes = context_pack_path.read_bytes()
    artifact = {
        "schema": str(schema.get("artifact_schema") or RESULT_SCHEMA),
        "source_context_pack": {
            "path": str(context_pack_path),
            "schema": context_pack["schema"],
            "candidate_id": context_pack["candidate_id"],
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
        },
        "generated_by": GENERATED_BY,
        "timestamp": timestamp_factory(),
        "provider": _provider_provenance(provider),
        "result": result,
        "claim_policy": {
            "runner_assigned_status": False,
            "vulnerability": "not_assessed_by_runner",
            "security_impact": "not_assessed_by_runner",
        },
    }
    write_yaml(output_path, artifact)
    return artifact
