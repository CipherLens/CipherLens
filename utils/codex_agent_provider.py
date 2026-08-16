"""Read-only Codex CLI provider for ImpactLift repository exploration.

This module adapts the locally installed ``codex exec`` interface to the
provider-neutral :class:`AgentProvider` contract.  Process execution is
injectable so tests never need credentials or a live model call.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from utils.agent_provider import AgentProvider


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]

DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_REASONING_EFFORT = "high"
SANDBOX_MODE = "read-only"
EPHEMERAL_EXECUTION = True

ALLOWED_CONFIDENCE = {"low", "medium", "high", "unknown"}
REQUIRED_FIELDS = {
    "candidate_id",
    "summary",
    "findings",
    "evidence",
    "confidence",
    "caller_chain",
    "guards",
    "propagation",
    "unknowns",
}

RESULT_FIELD_TYPES: dict[str, Any] = {
    "candidate_id": {"type": "string", "minLength": 1},
    "summary": {"type": "string", "minLength": 1},
    "findings": {"type": "array", "items": {"type": "string"}},
    "evidence": {"type": "array", "items": {"type": "string"}},
    "confidence": {"type": "string", "enum": sorted(ALLOWED_CONFIDENCE)},
    "caller_chain": {"type": "array", "items": {"type": "string"}},
    "guards": {"type": "array", "items": {"type": "string"}},
    "propagation": {"type": "object", "additionalProperties": False},
    "unknowns": {"type": "array", "items": {"type": "string"}},
}


def _json_schema_property(field: str, field_schema: Any) -> dict[str, Any]:
    """Convert old or structured ImpactLift field specs to strict JSON Schema."""
    if isinstance(field_schema, str):
        aliases = {"list": "array", "mapping": "object"}
        schema_type = aliases.get(field_schema, field_schema)
        schema: dict[str, Any] = {"type": schema_type}
    elif isinstance(field_schema, dict):
        schema = dict(field_schema)
        schema_type = str(schema.get("type") or "").strip()
    else:
        raise ValueError(f"unsupported schema field type for {field}: {field_schema}")

    if schema_type == "array":
        schema.setdefault("items", {"type": "string"})
    elif schema_type == "object":
        schema.setdefault("properties", {})
        schema.setdefault("required", sorted(schema["properties"]))
        schema.setdefault("additionalProperties", False)
    elif schema_type != "string":
        raise ValueError(f"unsupported JSON Schema type for {field}: {schema_type}")
    return schema


def build_result_json_schema(
    field_types: dict[str, Any],
    *,
    required_fields: set[str] | None = None,
) -> dict[str, Any]:
    """Build the strict schema passed to ``codex exec --output-schema``."""
    required = required_fields or REQUIRED_FIELDS
    properties = {
        field: _json_schema_property(field, field_types[field])
        for field in sorted(required)
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(required),
        "properties": properties,
    }


RESULT_JSON_SCHEMA: dict[str, Any] = build_result_json_schema(RESULT_FIELD_TYPES)


class CodexAgentProvider(AgentProvider):
    """Invoke ``codex exec`` as the fixed ImpactLift v1 Codex backend."""

    def __init__(
        self,
        workspace: Path | str,
        *,
        timeout_seconds: int = 900,
        executable: str = "codex",
        command_runner: CommandRunner | None = None,
    ) -> None:
        self.workspace = Path(workspace).expanduser().resolve()
        if not self.workspace.is_dir():
            raise ValueError(f"Codex workspace is not a directory: {self.workspace}")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not executable.strip():
            raise ValueError("Codex executable must not be empty")

        self.timeout_seconds = timeout_seconds
        self.executable = executable
        self.model = DEFAULT_MODEL
        self.reasoning_effort = DEFAULT_REASONING_EFFORT
        self.sandbox_mode = SANDBOX_MODE
        self.ephemeral = EPHEMERAL_EXECUTION
        self._command_runner = command_runner or subprocess.run
        self._uses_default_runner = command_runner is None

    @property
    def name(self) -> str:
        return "codex"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "backend": "codex-cli",
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "sandbox": self.sandbox_mode,
            "ephemeral": self.ephemeral,
            "workspace": str(self.workspace),
            "timeout_seconds": self.timeout_seconds,
        }

    def build_agent_task(self, context_pack: dict[str, Any]) -> str:
        """Build a fixed, auditable exploration task from one Context Pack."""
        if not isinstance(context_pack, dict):
            raise ValueError("context pack must be a mapping")
        candidate_id = str(context_pack.get("candidate_id") or "").strip()
        if not candidate_id:
            raise ValueError("context pack candidate_id is required")

        serialized = json.dumps(context_pack, indent=2, sort_keys=True)
        return f"""You are the read-only repository exploration agent for CipherLens ImpactLift.

Analyze only candidate {candidate_id!r}, using the supplied Candidate Context Pack as the
starting evidence. Produce an exploration report, not a final vulnerability verdict.

Exploration goals:
- Locate the named API or function and summarize its low-level behavior.
- Search for relevant callers in the current workspace.
- Inspect defensive guards, especially checks that consume or validate the full input.
- Record observed call paths and evidence.
- If this is a library-only workspace and no upper-level caller exists, report that as an unknown.
- Do not decide that the candidate is exploitable, safe, vulnerable, or not vulnerable.

Safety and scope constraints:
- Treat the repository as read-only. Do not create, edit, delete, or rename files.
- Do not run git commit, checkout, reset, merge, rebase, clean, or push.
- Do not run destructive commands, install dependencies, or contact external services.
- Keep exploration bounded to this candidate; do not perform a whole-repository security scan.
- Report uncertainty when evidence is incomplete.
- Cite repository evidence with paths and symbols (and line numbers when available).

Return JSON only. Required fields:
- candidate_id: string, unchanged from the Context Pack
- summary: string describing what was explored and what was observed
- findings: array of strings with exploration findings, including API behavior and caller observations
- evidence: array of strings with repository evidence, including paths, symbols, and line numbers when available
- confidence: one of low, medium, high, unknown
- caller_chain: array of strings
- guards: array of strings
- propagation: object
- unknowns: array of strings

If no caller is found in the current workspace, return:
- caller_chain: []
- guards: []
- propagation: {{}}
- unknowns: ["No upper-level caller found in current workspace"]

Do not include status, security_semantics, vulnerability verdicts, or final impact claims.

Candidate Context Pack:
{serialized}
"""

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        """Run one non-interactive Codex session and parse its final JSON result."""
        task = self.build_agent_task(context_pack)
        result = self.analyze_structured(
            task=task,
            result_json_schema=RESULT_JSON_SCHEMA,
            output_stem="impact_exploration",
        )
        self._validate_result(result, str(context_pack["candidate_id"]))
        return result

    def analyze_structured(
        self,
        *,
        task: str,
        result_json_schema: dict[str, Any],
        output_stem: str,
    ) -> dict[str, Any]:
        """Run one non-interactive Codex session for a supplied structured task."""
        if self._uses_default_runner and shutil.which(self.executable) is None:
            raise RuntimeError(f"Codex CLI executable not found: {self.executable}")

        with tempfile.TemporaryDirectory(prefix="cipherlens-impactlift-") as tmp:
            temp_root = Path(tmp)
            schema_path = temp_root / f"{output_stem}.schema.json"
            output_path = temp_root / f"{output_stem}.json"
            schema_path.write_text(
                json.dumps(result_json_schema, indent=2, sort_keys=True),
                encoding="utf-8",
            )

            command = [
                self.executable,
                "exec",
                "--skip-git-repo-check",
                "-m",
                self.model,
                "-c",
                f'model_reasoning_effort="{self.reasoning_effort}"',
                "--sandbox",
                self.sandbox_mode,
                "--ephemeral",
                "--ignore-user-config",
                "--color",
                "never",
                "--output-schema",
                str(schema_path),
                "--output-last-message",
                str(output_path),
                "-C",
                str(self.workspace),
                "-",
            ]
            try:
                completed = self._command_runner(
                    command,
                    input=task,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"Codex Agent timed out after {self.timeout_seconds} seconds"
                ) from exc

            if completed.returncode != 0:
                detail = (
                    "\nSTDERR:\n"
                    + (completed.stderr or "")
                    + "\nSTDOUT:\n"
                    + (completed.stdout or "")
                )
                raise RuntimeError(
                    f"Codex Agent failed with exit code {completed.returncode}:{detail}"
                )
            if not output_path.is_file():
                raise RuntimeError("Codex Agent did not write its final response")

            result = self.parse_agent_response(output_path.read_text(encoding="utf-8"))
        return result

    @staticmethod
    def parse_agent_response(response: str) -> dict[str, Any]:
        """Parse a strict JSON final response; prose and fenced JSON are rejected."""
        try:
            parsed = json.loads(response)
        except json.JSONDecodeError as exc:
            raise ValueError("Codex Agent final response is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Codex Agent final response must be a JSON object")
        return parsed

    @staticmethod
    def _validate_result(result: dict[str, Any], candidate_id: str) -> None:
        missing = sorted(REQUIRED_FIELDS - set(result))
        unexpected = sorted(set(result) - REQUIRED_FIELDS)
        if missing:
            raise ValueError(f"Codex Agent result missing fields: {', '.join(missing)}")
        if unexpected:
            raise ValueError(
                f"Codex Agent result contains unsupported fields: {', '.join(unexpected)}"
            )
        if result["candidate_id"] != candidate_id:
            raise ValueError("Codex Agent result candidate_id does not match Context Pack")
        if not isinstance(result["summary"], str):
            raise ValueError("Codex Agent result field summary must be a string")
        for field in ("findings", "evidence", "caller_chain", "guards", "unknowns"):
            if field not in result:
                continue
            if not isinstance(result[field], list):
                raise ValueError(f"Codex Agent result field {field} must be a list")
        if "propagation" in result and not isinstance(result["propagation"], dict):
            raise ValueError("Codex Agent result field propagation must be an object")
        if result["confidence"] not in ALLOWED_CONFIDENCE:
            raise ValueError(f"unsupported ImpactLift confidence: {result['confidence']}")
