from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from caller_audit.demo_replay_pipeline import load_yaml, run_demo_replay, validate_frozen_proposal


ROOT = Path(__file__).resolve().parents[1]
PROPOSAL = ROOT / "artifacts/caller_audit/cmac-demo-regression/frozen_cmac_lifecycle_proposal.yaml"
MOCK_SEARCH = ROOT / "artifacts/caller_audit/cmac-caller-discovery-v1/mock_github_search_results.yaml"


class DemoReplayPipelineTest(unittest.TestCase):
    def test_frozen_proposal_validates_and_has_no_downstream_caller_hint(self):
        proposal = load_yaml(PROPOSAL)
        validate_frozen_proposal(proposal)

        text = PROPOSAL.read_text(encoding="utf-8").lower()
        self.assertNotIn("lua-openssl", text)
        self.assertNotIn("zhaozg", text)
        self.assertNotIn("issue #410", text)

    def test_cmac_demo_replay_regenerates_candidate_and_runs_impactlift(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp) / "demo"
            result = run_demo_replay(
                PROPOSAL,
                output_root=out_root,
                workspace=ROOT,
                mock_external_search_results=MOCK_SEARCH,
            )
            summary = yaml.safe_load(result["summary_path"].read_text(encoding="utf-8"))
            validation = yaml.safe_load((out_root / "proposal_validation.yaml").read_text(encoding="utf-8"))
            render_report = yaml.safe_load((out_root / "render/render_report.yaml").read_text(encoding="utf-8"))
            compile_report = yaml.safe_load((out_root / "compile/compile_report.yaml").read_text(encoding="utf-8"))
            runtime_report = yaml.safe_load((out_root / "runtime/runtime_report.yaml").read_text(encoding="utf-8"))
            oracle_result = yaml.safe_load((out_root / "oracle/oracle_result.yaml").read_text(encoding="utf-8"))
            candidate = yaml.safe_load(result["candidate"].read_text(encoding="utf-8"))
            impactlift = yaml.safe_load(result["impactlift_summary"].read_text(encoding="utf-8"))
            rendered_harness_exists = Path(render_report["rendered_harness"]).exists()

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["mode"], "regression_replay")
        self.assertFalse(validation["llm_called"])
        self.assertTrue(rendered_harness_exists)
        self.assertEqual(compile_report["status"], "completed")
        self.assertEqual(runtime_report["status"], "completed")
        self.assertEqual(oracle_result["status"], "completed")
        self.assertEqual(oracle_result["classification"], "semantic_gap_candidate")
        self.assertIn("update_after_final_allowed", candidate["behavior"])
        self.assertIn("repeated_final_allowed", candidate["behavior"])
        self.assertTrue(any(str(out_root) in item for item in candidate["source_artifacts"]))
        self.assertEqual(impactlift["status"], "completed")
        self.assertTrue(impactlift["route"]["caller_discovery"])
        self.assertTrue(
            any(repo["name"] == "zhaozg/lua-openssl" for repo in impactlift["discovered_callers"])
        )
        dumped = yaml.safe_dump(candidate).lower() + yaml.safe_dump(summary).lower()
        self.assertNotIn("vulnerability: true", dumped)
        self.assertNotIn("cve-", dumped)


if __name__ == "__main__":
    unittest.main()
