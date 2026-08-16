from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from caller_audit import security_impact_runner as cli
from caller_audit.security_impact_runner import (
    build_security_impact_task,
    run_security_impact,
)
from utils.agent_provider import AgentProvider
from utils.codex_agent_provider import build_result_json_schema


def context_pack() -> dict[str, Any]:
    return {
        "schema": "cipherlens_candidate_context_pack_v1",
        "candidate_id": "candidate-001",
        "api_or_function": "d2i_X509",
        "provenance": {"sources": [{"path": "candidate.yaml"}]},
    }


def impact_exploration() -> dict[str, Any]:
    return {
        "schema": "cipherlens_impact_exploration_v1",
        "result": {
            "candidate_id": "candidate-001",
            "summary": "Explored d2i_X509 behavior.",
            "findings": ["d2i_X509 advances the DER input pointer on success."],
            "evidence": ["crypto/x509/x_x509.c: d2i_X509"],
            "confidence": "medium",
            "caller_chain": ["parse_cert", "d2i_X509"],
            "guards": [],
            "propagation": {},
            "unknowns": [],
        },
    }


def exploitability() -> dict[str, Any]:
    return {
        "schema": "cipherlens_exploitability_v1",
        "result": {
            "candidate_id": "candidate-001",
            "summary": "A caller path exists but security use remains unclear.",
            "input_sources": ["network certificate bytes"],
            "attacker_control": ["DER certificate bytes"],
            "trust_boundaries": ["network to certificate parser"],
            "security_usage": [],
            "reachable_paths": ["parse_cert -> d2i_X509"],
            "barriers": [],
            "unknowns": ["Whether parsed certificate reaches authentication is unknown."],
            "evidence": ["src/tls.cc: parse_cert"],
            "exploitability_assessment": "reachable_path_observed",
            "confidence": "medium",
        },
    }


def security_impact_result(candidate_id: str = "candidate-001") -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "security_classification": "insufficient_evidence",
        "affected_security_properties": ["unknown"],
        "impact_evidence": [
            "Reachable parser path observed, but no security decision was confirmed."
        ],
        "confidence": "low",
        "unknowns": ["Whether parsed certificate affects authentication is unknown."],
    }


class MockSecurityImpactProvider(AgentProvider):
    @property
    def name(self) -> str:
        return "mock-security-impact"

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        return security_impact_result(context_pack["context_pack"]["candidate_id"])


class InvalidClassificationProvider(MockSecurityImpactProvider):
    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        result = super().analyze(context_pack)
        result["security_classification"] = "confirmed_vulnerability"
        return result


class VulnerabilityClaimProvider(MockSecurityImpactProvider):
    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        result = super().analyze(context_pack)
        result["vulnerability"] = True
        return result


class RecordingStructuredProvider(AgentProvider):
    def __init__(self) -> None:
        self.task = ""
        self.result_json_schema: dict[str, Any] = {}
        self.output_stem = ""

    @property
    def name(self) -> str:
        return "recording-codex"

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("structured provider should use analyze_structured")

    def analyze_structured(
        self,
        *,
        task: str,
        result_json_schema: dict[str, Any],
        output_stem: str,
    ) -> dict[str, Any]:
        self.task = task
        self.result_json_schema = result_json_schema
        self.output_stem = output_stem
        return security_impact_result()


class FakeCodexProvider(AgentProvider):
    def __init__(self, workspace: Path, *, timeout_seconds: int = 900) -> None:
        self.workspace = Path(workspace)
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return "codex"

    @property
    def metadata(self) -> dict[str, object]:
        return {
            "backend": "codex-cli",
            "model": "gpt-5.6-luna",
            "reasoning_effort": "high",
            "sandbox": "read-only",
            "ephemeral": True,
            "workspace": str(self.workspace),
            "timeout_seconds": self.timeout_seconds,
        }

    def analyze_structured(
        self,
        *,
        task: str,
        result_json_schema: dict[str, Any],
        output_stem: str,
    ) -> dict[str, Any]:
        return security_impact_result()

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("CLI should use structured Codex analysis")


class SecurityImpactRunnerTest(unittest.TestCase):
    def _write_inputs(self, root: Path) -> tuple[Path, Path, Path]:
        context_path = root / "candidate_context_pack.yaml"
        exploration_path = root / "impact_exploration.yaml"
        exploitability_path = root / "exploitability.yaml"
        context_path.write_text(
            yaml.safe_dump(context_pack(), sort_keys=False),
            encoding="utf-8",
        )
        exploration_path.write_text(
            yaml.safe_dump(impact_exploration(), sort_keys=False),
            encoding="utf-8",
        )
        exploitability_path.write_text(
            yaml.safe_dump(exploitability(), sort_keys=False),
            encoding="utf-8",
        )
        return context_path, exploration_path, exploitability_path

    def test_mock_provider_writes_security_impact_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path, exploration_path, exploitability_path = self._write_inputs(root)
            output_path = root / "security_impact.yaml"
            artifact = run_security_impact(
                context_path,
                exploration_path,
                exploitability_path,
                output_path,
                MockSecurityImpactProvider(),
                timestamp_factory=lambda: "2026-08-13T00:00:00+00:00",
            )
            loaded = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertEqual(artifact, loaded)
        self.assertEqual(loaded["schema"], "cipherlens_security_impact_v1")
        self.assertEqual(
            loaded["result"]["security_classification"], "insufficient_evidence"
        )
        self.assertEqual(loaded["result"]["affected_security_properties"], ["unknown"])
        self.assertFalse(loaded["claim_policy"]["runner_assigned_vulnerability"])
        self.assertEqual(loaded["claim_policy"]["vulnerability"], "not_assessed_by_runner")

    def test_structured_provider_receives_prompt_and_strict_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path, exploration_path, exploitability_path = self._write_inputs(root)
            provider = RecordingStructuredProvider()
            run_security_impact(
                context_path,
                exploration_path,
                exploitability_path,
                root / "security_impact.yaml",
                provider,
                timestamp_factory=lambda: "2026-08-13T00:00:00+00:00",
            )

        self.assertEqual(provider.output_stem, "security_impact")
        self.assertIn("Security Impact Assessment Agent", provider.task)
        self.assertIn("Exploitability Assessment Artifact", provider.task)
        schema = provider.result_json_schema
        self.assertEqual(set(schema["properties"]), set(schema["required"]))
        for name, prop in schema["properties"].items():
            if prop["type"] == "array":
                self.assertIn("items", prop, name)

    def test_invalid_security_classification_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path, exploration_path, exploitability_path = self._write_inputs(root)
            with self.assertRaisesRegex(
                ValueError, "unsupported security impact field"
            ):
                run_security_impact(
                    context_path,
                    exploration_path,
                    exploitability_path,
                    root / "security_impact.yaml",
                    InvalidClassificationProvider(),
                )

    def test_vulnerability_claim_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path, exploration_path, exploitability_path = self._write_inputs(root)
            with self.assertRaisesRegex(ValueError, "unsupported fields: vulnerability"):
                run_security_impact(
                    context_path,
                    exploration_path,
                    exploitability_path,
                    root / "security_impact.yaml",
                    VulnerabilityClaimProvider(),
                )

    def test_prompt_includes_all_inputs_and_no_vulnerability_claim_policy(self):
        task = build_security_impact_task(
            context_pack(),
            impact_exploration(),
            exploitability(),
        )
        self.assertIn("candidate-001", task)
        self.assertIn("Do not generate a CVE judgment", task)
        self.assertIn("Exploitability Assessment Artifact", task)

    def test_schema_builder_requires_all_security_impact_fields(self):
        field_types = yaml.safe_load(
            Path("caller_audit/schemas/security_impact_v1.yaml").read_text(
                encoding="utf-8"
            )
        )["field_types"]
        schema = build_result_json_schema(
            field_types,
            required_fields=set(field_types),
        )
        self.assertEqual(set(schema["properties"]), set(schema["required"]))

    def test_cli_wires_all_inputs_workspace_provider_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "repo"
            workspace.mkdir()
            context_path, exploration_path, exploitability_path = self._write_inputs(root)
            output_path = root / "security_impact.yaml"

            with patch.object(cli, "CodexAgentProvider", FakeCodexProvider):
                with patch(
                    "sys.argv",
                    [
                        "security_impact_runner",
                        "--context-pack",
                        str(context_path),
                        "--exploration",
                        str(exploration_path),
                        "--exploitability",
                        str(exploitability_path),
                        "--workspace",
                        str(workspace),
                        "--out",
                        str(output_path),
                        "--timeout-seconds",
                        "123",
                    ],
                ):
                    cli.main()

            loaded = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertEqual(loaded["schema"], "cipherlens_security_impact_v1")
        self.assertEqual(loaded["provider"]["name"], "codex")
        self.assertEqual(loaded["provider"]["workspace"], str(workspace))
        self.assertEqual(loaded["provider"]["timeout_seconds"], 123)
        self.assertEqual(
            loaded["result"]["security_classification"], "insufficient_evidence"
        )


if __name__ == "__main__":
    unittest.main()
