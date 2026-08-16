from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

from caller_audit.impact_runner import run_impactlift
from utils.agent_provider import AgentProvider


class MockExplorationProvider(AgentProvider):
    @property
    def name(self) -> str:
        return "mock-exploration"

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        return {
            "candidate_id": context_pack["candidate_id"],
            "summary": "Mock exploration found API behavior evidence.",
            "findings": ["api_behavior: mock finding"],
            "evidence": ["mock: observed"],
            "confidence": "high",
            "caller_chain": [],
            "guards": [],
            "propagation": {},
            "unknowns": ["No upper-level caller was present in the mock workspace."],
        }


class InvalidOutputProvider(MockExplorationProvider):
    @property
    def name(self) -> str:
        return "mock-invalid-output"

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        result = super().analyze(context_pack)
        result.pop("evidence")
        return result


class MetadataProvider(MockExplorationProvider):
    @property
    def name(self) -> str:
        return "codex"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "model": "gpt-5.6-luna",
            "reasoning_effort": "high",
            "sandbox": "read-only",
        }


class ImpactRunnerTest(unittest.TestCase):
    def _write_context_pack(self, root: Path) -> Path:
        path = root / "candidate_context_pack.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "schema": "cipherlens_candidate_context_pack_v1",
                    "candidate_id": "candidate-001",
                    "logical_candidate_id": "logical-001",
                    "current_classification": "semantic_gap_candidate",
                    "oracle_evidence": ["evidence.yaml"],
                    "provenance": {
                        "generated_by": "analysis.candidate_context_pack",
                        "sources": [{"path": "evidence.yaml"}],
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return path

    def test_mock_provider_writes_valid_exploration_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = self._write_context_pack(root)
            output_path = root / "impact_exploration.yaml"
            artifact = run_impactlift(
                context_path,
                output_path,
                MockExplorationProvider(),
                timestamp_factory=lambda: "2026-08-10T00:00:00+00:00",
            )
            loaded = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertEqual(artifact, loaded)
        self.assertEqual(loaded["schema"], "cipherlens_impact_exploration_v1")
        self.assertEqual(loaded["result"]["confidence"], "high")
        self.assertIn("No upper-level caller", loaded["result"]["unknowns"][0])
        self.assertEqual(loaded["provider"]["name"], "mock-exploration")
        self.assertEqual(
            loaded["source_context_pack"]["candidate_id"], "candidate-001"
        )
        self.assertEqual(len(loaded["source_context_pack"]["sha256"]), 64)
        self.assertFalse(loaded["claim_policy"]["runner_assigned_status"])

    def test_provider_metadata_is_recorded_in_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_path = root / "impact_exploration.yaml"
            loaded = run_impactlift(
                self._write_context_pack(root),
                output_path,
                MetadataProvider(),
                timestamp_factory=lambda: "2026-08-10T00:00:00+00:00",
            )

        self.assertEqual(loaded["provider"]["name"], "codex")
        self.assertEqual(loaded["provider"]["model"], "gpt-5.6-luna")
        self.assertEqual(loaded["provider"]["reasoning_effort"], "high")
        self.assertEqual(loaded["provider"]["sandbox"], "read-only")

    def test_invalid_provider_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(
                ValueError, "missing required fields: evidence"
            ):
                run_impactlift(
                    self._write_context_pack(root),
                    root / "impact_exploration.yaml",
                    InvalidOutputProvider(),
                )


if __name__ == "__main__":
    unittest.main()
