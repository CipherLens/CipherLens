from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from utils.codex_agent_provider import (
    DEFAULT_MODEL,
    DEFAULT_REASONING_EFFORT,
    CodexAgentProvider,
    RESULT_JSON_SCHEMA,
    build_result_json_schema,
)


def context_pack() -> dict[str, Any]:
    return {
        "schema": "cipherlens_candidate_context_pack_v1",
        "candidate_id": "candidate-001",
        "logical_candidate_id": "logical-001",
        "api_or_function": "d2i_PUBKEY",
        "trigger_condition": "DER input with trailing bytes",
        "oracle_evidence": [{"consumed_len": 12, "input_len": 16}],
        "provenance": {"sources": [{"path": "results/candidate.yaml"}]},
    }


def exploration_result() -> dict[str, Any]:
    return {
        "candidate_id": "candidate-001",
        "summary": "d2i_PUBKEY consumes one DER object and no upper caller was found.",
        "findings": [
            "api_behavior: The input pointer advances after successful parsing."
        ],
        "evidence": ["crypto/x509/x_pubkey.c: d2i_PUBKEY"],
        "confidence": "high",
        "caller_chain": [],
        "guards": [],
        "propagation": {},
        "unknowns": ["No application-level caller exists in this library workspace."],
    }


def exploration_result_with_caller_fields() -> dict[str, Any]:
    result = exploration_result()
    result.update(
        {
            "caller_chain": ["parse_key", "d2i_PUBKEY"],
            "guards": ["parse_key: checks full consumption"],
            "propagation": {},
        }
    )
    return result


class RecordingRunner:
    def __init__(self, response: str, returncode: int = 0) -> None:
        self.response = response
        self.returncode = returncode
        self.command: list[str] | None = None
        self.input: str | None = None
        self.output_schema: dict[str, Any] | None = None

    def __call__(
        self, command: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        self.command = command
        self.input = kwargs["input"]
        schema_path = Path(command[command.index("--output-schema") + 1])
        self.output_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text(self.response, encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            self.returncode,
            stdout="",
            stderr="mock failure" if self.returncode else "",
        )


def _strict_schema_errors(schema: dict[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    schema_type = schema.get("type")
    if schema_type == "array" and "items" not in schema:
        errors.append(f"{path}: array schema missing items")
    if schema_type == "object":
        if not isinstance(schema.get("properties"), dict):
            errors.append(f"{path}: object schema missing properties")
        if schema.get("additionalProperties") is not False:
            errors.append(f"{path}: object schema missing additionalProperties=false")
        if set(schema.get("required") or []) != set(schema.get("properties") or {}):
            errors.append(f"{path}: object required keys do not match properties")
    for name, child in (schema.get("properties") or {}).items():
        if isinstance(child, dict):
            errors.extend(_strict_schema_errors(child, f"{path}.properties.{name}"))
    items = schema.get("items")
    if isinstance(items, dict):
        errors.extend(_strict_schema_errors(items, f"{path}.items"))
    return errors


class CodexAgentProviderTest(unittest.TestCase):
    def test_structured_output_schema_is_codex_compatible(self):
        self.assertEqual(RESULT_JSON_SCHEMA["type"], "object")
        self.assertIs(RESULT_JSON_SCHEMA["additionalProperties"], False)

        properties = RESULT_JSON_SCHEMA["properties"]
        self.assertEqual(set(properties), set(RESULT_JSON_SCHEMA["required"]))
        self.assertEqual(
            properties["findings"], {"type": "array", "items": {"type": "string"}}
        )
        self.assertEqual(
            properties["propagation"],
            {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
        )
        self.assertEqual(_strict_schema_errors(RESULT_JSON_SCHEMA), [])

    def test_schema_builder_adds_required_codex_keywords(self):
        schema = build_result_json_schema(
            {
                "candidate_id": {"type": "string"},
                "summary": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "string"}},
                "evidence": "list",
                "confidence": {"type": "string"},
                "caller_chain": "list",
                "guards": {"type": "array"},
                "propagation": {"type": "object"},
                "unknowns": "list",
            }
        )

        self.assertEqual(
            schema["properties"]["findings"],
            {"type": "array", "items": {"type": "string"}},
        )
        self.assertEqual(
            schema["properties"]["propagation"],
            {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
        )
        self.assertEqual(set(schema["properties"]), set(schema["required"]))
        self.assertEqual(_strict_schema_errors(schema), [])

    def test_provider_can_be_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = CodexAgentProvider(tmp, command_runner=RecordingRunner("{}"))
        self.assertEqual(provider.name, "codex")
        self.assertEqual(provider.timeout_seconds, 900)
        self.assertEqual(provider.model, DEFAULT_MODEL)
        self.assertEqual(provider.reasoning_effort, DEFAULT_REASONING_EFFORT)
        self.assertEqual(provider.metadata["model"], "gpt-5.6-luna")
        self.assertEqual(provider.metadata["reasoning_effort"], "high")

    def test_context_pack_is_converted_to_bounded_read_only_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = CodexAgentProvider(tmp, command_runner=RecordingRunner("{}"))
            task = provider.build_agent_task(context_pack())

        self.assertIn("d2i_PUBKEY", task)
        self.assertIn("candidate-001", task)
        self.assertIn("repository as read-only", task)
        self.assertIn("do not perform a whole-repository security scan", task)

    def test_mock_cli_response_is_parsed_as_impactlift_exploration(self):
        runner = RecordingRunner(json.dumps(exploration_result_with_caller_fields()))
        with tempfile.TemporaryDirectory() as tmp:
            provider = CodexAgentProvider(tmp, command_runner=runner)
            result = provider.analyze(context_pack())

        self.assertEqual(
            result["summary"],
            "d2i_PUBKEY consumes one DER object and no upper caller was found.",
        )
        self.assertEqual(result["confidence"], "high")
        self.assertIsNotNone(runner.command)
        assert runner.command is not None
        self.assertEqual(runner.command[:2], ["codex", "exec"])
        self.assertEqual(
            runner.command[runner.command.index("-m") + 1], "gpt-5.6-luna"
        )
        self.assertIn("-c", runner.command)
        self.assertIn('model_reasoning_effort="high"', runner.command)
        self.assertIn("--ignore-user-config", runner.command)
        self.assertEqual(
            runner.command[runner.command.index("--sandbox") + 1], "read-only"
        )
        self.assertIn("--ephemeral", runner.command)
        self.assertIn("--output-schema", runner.command)
        self.assertEqual(runner.command[-1], "-")
        self.assertEqual(_strict_schema_errors(runner.output_schema or {}), [])

    def test_library_only_workspace_unknown_caller_is_valid(self):
        result = exploration_result()
        runner = RecordingRunner(json.dumps(result))
        with tempfile.TemporaryDirectory() as tmp:
            provider = CodexAgentProvider(tmp, command_runner=runner)
            parsed = provider.analyze(context_pack())

        self.assertEqual(parsed["caller_chain"], [])
        self.assertEqual(parsed["guards"], [])
        self.assertEqual(parsed["propagation"], {})
        self.assertIn("No application-level caller", parsed["unknowns"][0])

    def test_invalid_response_is_rejected(self):
        runner = RecordingRunner("not JSON")
        with tempfile.TemporaryDirectory() as tmp:
            provider = CodexAgentProvider(tmp, command_runner=runner)
            with self.assertRaisesRegex(ValueError, "not valid JSON"):
                provider.analyze(context_pack())

    def test_schema_invalid_response_is_rejected(self):
        invalid = exploration_result()
        invalid["status"] = "VULNERABLE"
        runner = RecordingRunner(json.dumps(invalid))
        with tempfile.TemporaryDirectory() as tmp:
            provider = CodexAgentProvider(tmp, command_runner=runner)
            with self.assertRaisesRegex(ValueError, "unsupported fields: status"):
                provider.analyze(context_pack())


if __name__ == "__main__":
    unittest.main()
