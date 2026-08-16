from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from caller_audit import run_impactlift as cli
from utils.agent_provider import AgentProvider


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

    def analyze(self, context_pack: dict[str, object]) -> dict[str, object]:
        return {
            "candidate_id": str(context_pack["candidate_id"]),
            "summary": "Mock Codex exploration completed.",
            "findings": ["caller_search: mock finding"],
            "evidence": ["mock"],
            "confidence": "medium",
            "caller_chain": [],
            "guards": [],
            "propagation": {},
            "unknowns": ["No upper caller found."],
        }


class RunImpactLiftCliTest(unittest.TestCase):
    def test_cli_wires_context_pack_workspace_provider_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "repo"
            workspace.mkdir()
            context_pack = root / "candidate_context_pack.yaml"
            output = root / "impact_exploration.yaml"
            context_pack.write_text(
                yaml.safe_dump(
                    {
                        "schema": "cipherlens_candidate_context_pack_v1",
                        "candidate_id": "candidate-001",
                        "provenance": {"sources": [{"path": "candidate.yaml"}]},
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )

            with patch.object(cli, "CodexAgentProvider", FakeCodexProvider):
                with patch(
                    "sys.argv",
                    [
                        "run_impactlift",
                        "--context-pack",
                        str(context_pack),
                        "--workspace",
                        str(workspace),
                        "--out",
                        str(output),
                        "--timeout-seconds",
                        "123",
                    ],
                ):
                    cli.main()

            loaded = yaml.safe_load(output.read_text(encoding="utf-8"))

        self.assertEqual(loaded["schema"], "cipherlens_impact_exploration_v1")
        self.assertEqual(loaded["result"]["confidence"], "medium")
        self.assertIn("No upper caller", loaded["result"]["unknowns"][0])
        self.assertEqual(loaded["provider"]["name"], "codex")
        self.assertEqual(loaded["provider"]["model"], "gpt-5.6-luna")
        self.assertEqual(loaded["provider"]["reasoning_effort"], "high")
        self.assertEqual(loaded["provider"]["sandbox"], "read-only")
        self.assertTrue(loaded["provider"]["ephemeral"])
        self.assertEqual(loaded["provider"]["timeout_seconds"], 123)


if __name__ == "__main__":
    unittest.main()
