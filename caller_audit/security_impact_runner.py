"""Run ImpactLift security impact assessment from prior stage artifacts.

This stage consumes a Candidate Context Pack, an Impact Exploration artifact,
and an Exploitability Assessment artifact.  It records a bounded security
impact assessment without assigning a vulnerability verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from caller_audit.impact_runner import (
    _field_type_name,
    _provider_provenance,
    validate_context_pack,
)
from caller_audit.io_utils import load_yaml, write_yaml
from utils.agent_provider import AgentProvider
from utils.codex_agent_provider import CodexAgentProvider, build_result_json_schema


RESULT_SCHEMA = "cipherlens_security_impact_v1"
GENERATED_BY = "caller_audit.security_impact_runner"
DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schemas" / "security_impact_v1.yaml"
DEFAULT_PROMPT_PATH = Path(__file__).parent / "prompts" / "security_impact_v1.md"

TYPE_CHECKS = {
    "string": lambda value: isinstance(value, str),
    "array": lambda value: isinstance(value, list),
    "list": lambda value: isinstance(value, list),
    "object": lambda value: isinstance(value, dict),
    "mapping": lambda value: isinstance(value, dict),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_stage_artifact(
    artifact: dict[str, Any],
    context_pack: dict[str, Any],
    *,
    expected_schema: str,
    stage_name: str,
) -> None:
    if artifact.get("schema") != expected_schema:
        raise ValueError(
            f"unsupported {stage_name} schema: expected {expected_schema}, "
            f"got {artifact.get('schema', 'missing')}"
        )
    result = artifact.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"{stage_name} result mapping is required")
    if result.get("candidate_id") != context_pack["candidate_id"]:
        raise ValueError(f"{stage_name} candidate_id does not match the context pack")


def validate_security_impact_result(
    result: dict[str, Any],
    context_pack: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    if not isinstance(result, dict):
        raise ValueError("provider result must be a mapping")

    required = [str(field) for field in schema.get("required_result_fields") or []]
    missing = [field for field in required if field not in result]
    if missing:
        raise ValueError(f"provider result missing required fields: {', '.join(missing)}")

    if schema.get("additional_result_fields") is False:
        unexpected = sorted(set(result) - set(required))
        if unexpected:
            raise ValueError(
                f"provider result contains unsupported fields: {', '.join(unexpected)}"
            )

    for field, field_schema in (schema.get("field_types") or {}).items():
        if field not in result:
            continue
        expected_type = _field_type_name(str(field), field_schema)
        check = TYPE_CHECKS.get(expected_type)
        if check is None:
            raise ValueError(f"unsupported schema field type: {expected_type}")
        if not check(result.get(field)):
            raise ValueError(f"provider result field {field} must be {expected_type}")

        if isinstance(field_schema, dict) and "enum" in field_schema:
            allowed = {str(item) for item in field_schema["enum"]}
            if result[field] not in allowed:
                raise ValueError(
                    f"unsupported security impact field {field}: {result[field]}"
                )

    if result["candidate_id"] != context_pack["candidate_id"]:
        raise ValueError(
            "provider result candidate_id does not match the source context pack"
        )


def build_security_impact_task(
    context_pack: dict[str, Any],
    exploration_artifact: dict[str, Any],
    exploitability_artifact: dict[str, Any],
    *,
    prompt_path: Path = DEFAULT_PROMPT_PATH,
) -> str:
    template = prompt_path.read_text(encoding="utf-8")
    return (
        template.replace("{{CANDIDATE_ID}}", str(context_pack["candidate_id"]))
        .replace(
            "{{CONTEXT_PACK_JSON}}",
            json.dumps(context_pack, indent=2, sort_keys=True),
        )
        .replace(
            "{{IMPACT_EXPLORATION_JSON}}",
            json.dumps(exploration_artifact, indent=2, sort_keys=True),
        )
        .replace(
            "{{EXPLOITABILITY_JSON}}",
            json.dumps(exploitability_artifact, indent=2, sort_keys=True),
        )
    )


def _provider_result(
    provider: AgentProvider,
    task: str,
    json_schema: dict[str, Any],
    provider_input: dict[str, Any],
) -> dict[str, Any]:
    analyze_structured = getattr(provider, "analyze_structured", None)
    if callable(analyze_structured):
        return analyze_structured(
            task=task,
            result_json_schema=json_schema,
            output_stem="security_impact",
        )
    return provider.analyze(provider_input)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_security_impact(
    context_pack_path: Path,
    impact_exploration_path: Path,
    exploitability_path: Path,
    output_path: Path,
    provider: AgentProvider,
    *,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    prompt_path: Path = DEFAULT_PROMPT_PATH,
    timestamp_factory: Callable[[], str] = _utc_now,
) -> dict[str, Any]:
    """Run provider-neutral security impact assessment and write one artifact."""
    context_pack_path = context_pack_path.resolve()
    impact_exploration_path = impact_exploration_path.resolve()
    exploitability_path = exploitability_path.resolve()
    schema_path = schema_path.resolve()
    prompt_path = prompt_path.resolve()

    context_pack = load_yaml(context_pack_path)
    exploration_artifact = load_yaml(impact_exploration_path)
    exploitability_artifact = load_yaml(exploitability_path)
    schema = load_yaml(schema_path)

    validate_context_pack(context_pack, schema)
    _validate_stage_artifact(
        exploration_artifact,
        context_pack,
        expected_schema=str(schema.get("impact_exploration_schema") or ""),
        stage_name="impact exploration",
    )
    _validate_stage_artifact(
        exploitability_artifact,
        context_pack,
        expected_schema=str(schema.get("exploitability_schema") or ""),
        stage_name="exploitability",
    )

    task = build_security_impact_task(
        context_pack,
        exploration_artifact,
        exploitability_artifact,
        prompt_path=prompt_path,
    )
    result_json_schema = build_result_json_schema(
        schema.get("field_types") or {},
        required_fields=set(schema.get("required_result_fields") or []),
    )
    provider_input = {
        "context_pack": context_pack,
        "impact_exploration": exploration_artifact,
        "exploitability": exploitability_artifact,
    }
    result = _provider_result(provider, task, result_json_schema, provider_input)
    validate_security_impact_result(result, context_pack, schema)

    artifact = {
        "schema": str(schema.get("artifact_schema") or RESULT_SCHEMA),
        "source_context_pack": {
            "path": str(context_pack_path),
            "schema": context_pack["schema"],
            "candidate_id": context_pack["candidate_id"],
            "sha256": _sha256(context_pack_path),
        },
        "source_impact_exploration": {
            "path": str(impact_exploration_path),
            "schema": exploration_artifact["schema"],
            "candidate_id": context_pack["candidate_id"],
            "sha256": _sha256(impact_exploration_path),
        },
        "source_exploitability": {
            "path": str(exploitability_path),
            "schema": exploitability_artifact["schema"],
            "candidate_id": context_pack["candidate_id"],
            "sha256": _sha256(exploitability_path),
        },
        "generated_by": GENERATED_BY,
        "timestamp": timestamp_factory(),
        "provider": _provider_provenance(provider),
        "result": result,
        "claim_policy": {
            "runner_assigned_vulnerability": False,
            "vulnerability": "not_assessed_by_runner",
            "cve": "not_assessed_by_runner",
            "security_impact": "assessment_only",
        },
    }
    write_yaml(output_path, artifact)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run ImpactLift security impact assessment v1 with the Codex backend."
    )
    parser.add_argument("--context-pack", type=Path, required=True)
    parser.add_argument("--exploration", type=Path, required=True)
    parser.add_argument("--exploitability", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    provider = CodexAgentProvider(
        args.workspace,
        timeout_seconds=args.timeout_seconds,
    )
    artifact = run_security_impact(
        args.context_pack,
        args.exploration,
        args.exploitability,
        args.out,
        provider,
    )
    result = artifact["result"]
    print(f"[OK] ImpactLift security impact: {args.out}")
    print(f"[PROVIDER] {artifact['provider']['name']}")
    print(f"[MODEL] {artifact['provider']['model']}")
    print(f"[REASONING] {artifact['provider']['reasoning_effort']}")
    print(f"[CLASSIFICATION] {result['security_classification']}")
    print(f"[CONFIDENCE] {result['confidence']}")


if __name__ == "__main__":
    main()
