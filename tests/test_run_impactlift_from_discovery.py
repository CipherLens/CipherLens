from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from caller_audit import run_impactlift_from_discovery as cli
from utils.agent_provider import AgentProvider


ROOT = Path(__file__).resolve().parents[1]
CMAC_CANDIDATE = ROOT / "artifacts/caller_audit/cmac-caller-discovery-v1/cmac_candidate.yaml"
CMAC_DISCOVERY = ROOT / "artifacts/caller_audit/cmac-caller-discovery-v1/caller_discovery.yaml"


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

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        candidate_id = str(context_pack["candidate_id"])
        return {
            "candidate_id": candidate_id,
            "summary": "Mock exploration of caller discovery evidence.",
            "findings": ["lua-openssl src/mac.c calls EVP_MAC_update and EVP_MAC_final."],
            "evidence": ["caller_discovery_evidence.call_sites: zhaozg/lua-openssl src/mac.c"],
            "confidence": "medium",
            "caller_chain": ["openssl_mac_ctx_update", "EVP_MAC_update/EVP_MAC_final"],
            "guards": [],
            "propagation": {},
            "unknowns": ["Caller discovery does not assess vulnerability or security impact."],
        }

    def analyze_structured(
        self,
        *,
        task: str,
        result_json_schema: dict[str, Any],
        output_stem: str,
    ) -> dict[str, Any]:
        del task, result_json_schema
        candidate_id = "openssl-evp-mac-update-evp-mac-final-mac-lifecycle-semantic-divergence"
        if output_stem == "exploitability":
            return {
                "candidate_id": candidate_id,
                "summary": "Mock exploitability assessment remains unknown.",
                "input_sources": [],
                "attacker_control": [],
                "trust_boundaries": [],
                "security_usage": [],
                "reachable_paths": ["caller discovery candidate: zhaozg/lua-openssl src/mac.c"],
                "barriers": [],
                "unknowns": ["No vulnerability or exploitability claim was made."],
                "evidence": ["candidate_context_pack.caller_discovery_evidence"],
                "exploitability_assessment": "unknown",
                "confidence": "low",
            }
        if output_stem == "security_impact":
            return {
                "candidate_id": candidate_id,
                "security_classification": "insufficient_evidence",
                "affected_security_properties": ["unknown"],
                "impact_evidence": [
                    "Caller discovery found a repository candidate but did not establish security impact."
                ],
                "confidence": "low",
                "unknowns": ["No CVE or vulnerability claim was made."],
            }
        raise AssertionError(f"unexpected output_stem: {output_stem}")


class RunImpactLiftFromDiscoveryTest(unittest.TestCase):
    def test_bridge_builds_context_pack_and_runs_impactlift_chain(self):
        candidate_text = CMAC_CANDIDATE.read_text(encoding="utf-8")
        discovery = yaml.safe_load(CMAC_DISCOVERY.read_text(encoding="utf-8"))

        self.assertNotIn("lua-openssl", candidate_text)
        self.assertTrue(
            any(repo["name"] == "zhaozg/lua-openssl" for repo in discovery["repositories"])
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            out_root = root / "impactlift"
            with patch.object(cli, "CodexAgentProvider", FakeCodexProvider):
                outputs = cli.run_impactlift_from_discovery(
                    CMAC_DISCOVERY,
                    output_root=out_root,
                    workspace=workspace,
                    timeout_seconds=123,
                )

            context_pack = yaml.safe_load(
                outputs["candidate_context_pack"].read_text(encoding="utf-8")
            )
            impact_exploration = yaml.safe_load(
                outputs["impact_exploration"].read_text(encoding="utf-8")
            )
            exploitability = yaml.safe_load(
                outputs["exploitability"].read_text(encoding="utf-8")
            )
            security_impact = yaml.safe_load(
                outputs["security_impact"].read_text(encoding="utf-8")
            )

        self.assertEqual(context_pack["schema"], "cipherlens_candidate_context_pack_v1")
        self.assertEqual(context_pack["library"], "OpenSSL")
        self.assertEqual(context_pack["family"], "mac_lifecycle_semantic_divergence")
        self.assertEqual(context_pack["api_or_function"], "EVP_MAC_update, EVP_MAC_final")
        self.assertIn("caller_discovery_evidence", context_pack)
        self.assertTrue(
            any(
                repo["name"] == "zhaozg/lua-openssl"
                for repo in context_pack["caller_discovery_evidence"]["repositories"]
            )
        )
        self.assertTrue(
            any(
                "lua-openssl" in site["repository"] and site["file"] == "src/mac.c"
                for site in context_pack["caller_discovery_evidence"]["call_sites"]
            )
        )
        self.assertEqual(context_pack["claim_policy"]["vulnerability"], "not_assessed")
        self.assertEqual(context_pack["claim_policy"]["security_impact"], "not_assessed")
        self.assertEqual(context_pack["claim_policy"]["cve"], "not_assessed")
        self.assertNotIn("vulnerability: true", yaml.safe_dump(context_pack).lower())
        self.assertNotIn("cve-", yaml.safe_dump(context_pack).lower())

        self.assertEqual(impact_exploration["schema"], "cipherlens_impact_exploration_v1")
        self.assertEqual(exploitability["schema"], "cipherlens_exploitability_v1")
        self.assertEqual(security_impact["schema"], "cipherlens_security_impact_v1")
        self.assertEqual(
            security_impact["result"]["security_classification"],
            "insufficient_evidence",
        )
        self.assertEqual(
            security_impact["claim_policy"]["vulnerability"],
            "not_assessed_by_runner",
        )
        self.assertEqual(security_impact["claim_policy"]["cve"], "not_assessed_by_runner")


if __name__ == "__main__":
    unittest.main()
