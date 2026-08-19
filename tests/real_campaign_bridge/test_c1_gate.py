from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from real_campaign_bridge.c1_gate import (
    APPROVED_UNIT_ID,
    evaluate_c1_pre_run_gate,
    make_c1_artifact_index,
    make_c1_blocked_claim_gate,
    make_c1_blocked_manifests,
)
from target_knowledge.canonical import canonical_json_bytes


ROOT = Path(__file__).parents[2]
C1_ROOT = ROOT / "artifacts" / "pipeline_v2" / "single_unit_dry_run"


def _load(relative: str) -> dict:
    return json.loads((C1_ROOT / relative).read_text())


class C1SingleUnitGateTests(unittest.TestCase):
    def _generated(self):
        gate = evaluate_c1_pre_run_gate(ROOT)
        gate_edge = {"ref": "pre_run_gate/gate.json", "digest": hashlib.sha256(canonical_json_bytes(gate)).hexdigest()}
        claim = make_c1_blocked_claim_gate(gate, gate_ref=gate_edge["ref"], gate_digest=gate_edge["digest"])
        claim_edge = {"ref": "claim_gate/decision.json", "digest": hashlib.sha256(canonical_json_bytes(claim)).hexdigest()}
        attempt, raw, reproduction = make_c1_blocked_manifests(gate, claim, gate_edge=gate_edge, claim_edge=claim_edge)
        return gate, claim, attempt, raw, reproduction

    def test_gate_is_fixed_unit_only_and_blocks_before_execution(self) -> None:
        with patch.object(subprocess, "run") as runner:
            gate = evaluate_c1_pre_run_gate(ROOT)
        runner.assert_not_called()
        self.assertEqual(APPROVED_UNIT_ID, gate["unit_id"])
        self.assertEqual("C1_SINGLE_UNIT_DRY_RUN_BLOCKED", gate["status"])
        self.assertFalse(gate["build_run_authorized"])
        self.assertFalse(gate["build_run_attempted"])
        self.assertEqual([
            "REPRODUCIBLE_TARGET_LIBRARY_MISSING",
            "FIXED_INCLUDE_EVIDENCE_POINTS_TO_BUGGY_SOURCE",
            "FIXED_SOURCE_ROOT_HAS_NO_LOCAL_EXECUTION_MAPPING",
            "ONLY_C0_REPLAY_FIXTURE_LINEAGE_AVAILABLE",
            "CANONICAL_C1_BUILDSPEC_RUNSPEC_NOT_MATERIALIZABLE",
        ], gate["blocking_reasons"])

    def test_digest_valid_inputs_pass_before_engineering_blockers(self) -> None:
        gate = evaluate_c1_pre_run_gate(ROOT)
        by_name = {item["check"]: item for item in gate["checks"]}
        for name in ("FROZEN_POPULATION", "APPROVED_UNIT", "SOURCE_IDENTITY", "BUILD_PROFILE", "DIFFERENTIAL_PAIR", "CONTRACT", "TRANSFER_SIGNATURE", "TRIGGER_TEMPLATE", "CAPTURE_SPEC"):
            self.assertEqual("PASS", by_name[name]["status"])
        self.assertEqual("BLOCKED", by_name["FIXED_INCLUDE_EVIDENCE"]["status"])
        self.assertEqual("BLOCKED", by_name["CANONICAL_C1_LINEAGE"]["status"])

    def test_blocked_claim_gate_forbids_result_and_security_claims(self) -> None:
        _, claim, attempt, raw, reproduction = self._generated()
        self.assertEqual("C1_SINGLE_UNIT_DRY_RUN_BLOCKED", claim["status"])
        self.assertEqual("NOT_GENERATED", claim["current_campaign_result"])
        self.assertFalse(claim["real_execution_completed"])
        self.assertFalse(claim["report_real_number_allowed"])
        self.assertIn("SECURITY_FINDING_CLAIM", claim["forbidden_claim_levels"])
        self.assertFalse(attempt["build_attempted"])
        self.assertFalse(attempt["run_attempted"])
        self.assertFalse(attempt["execution_verdict_generated"])
        self.assertFalse(attempt["violation_evidence_package_generated"])
        self.assertEqual([], raw["raw_artifacts"])
        self.assertEqual("NOT_AVAILABLE_PRE_RUN_GATE_BLOCKED", reproduction["reproduction_command"])

    def test_create_only_artifacts_match_deterministic_generation(self) -> None:
        gate, claim, attempt, raw, reproduction = self._generated()
        self.assertEqual(gate, _load("pre_run_gate/gate.json"))
        self.assertEqual(claim, _load("claim_gate/decision.json"))
        self.assertEqual(attempt, _load("attempts/track-a-0020-fixed/attempt_manifest.json"))
        self.assertEqual(raw, _load("raw_artifacts/manifest.json"))
        self.assertEqual(reproduction, _load("reproduction/readiness.json"))

    def test_every_c1_file_edge_has_sha256_provenance(self) -> None:
        documents = [_load("pre_run_gate/gate.json"), _load("claim_gate/decision.json"), _load("attempts/track-a-0020-fixed/attempt_manifest.json"), _load("raw_artifacts/manifest.json"), _load("reproduction/readiness.json")]

        def visit(value):
            if isinstance(value, dict):
                if set(("ref", "digest")).issubset(value):
                    ref, digest = value["ref"], value["digest"]
                    self.assertRegex(digest, r"^[0-9a-f]{64}$")
                    path = ROOT / ref if ref.startswith(("artifacts/", "tests/", "normalized_templates/")) else C1_ROOT / ref
                    self.assertTrue(path.is_file(), ref)
                    self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest(), ref)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        for document in documents:
            visit(document)

        edges = {
            "pre_run_gate": {"ref": "pre_run_gate/gate.json", "digest": hashlib.sha256((C1_ROOT / "pre_run_gate/gate.json").read_bytes()).hexdigest()},
            "claim_gate": {"ref": "claim_gate/decision.json", "digest": hashlib.sha256((C1_ROOT / "claim_gate/decision.json").read_bytes()).hexdigest()},
            "attempt_manifest": {"ref": "attempts/track-a-0020-fixed/attempt_manifest.json", "digest": hashlib.sha256((C1_ROOT / "attempts/track-a-0020-fixed/attempt_manifest.json").read_bytes()).hexdigest()},
            "raw_artifact_manifest": {"ref": "raw_artifacts/manifest.json", "digest": hashlib.sha256((C1_ROOT / "raw_artifacts/manifest.json").read_bytes()).hexdigest()},
            "reproduction_readiness": {"ref": "reproduction/readiness.json", "digest": hashlib.sha256((C1_ROOT / "reproduction/readiness.json").read_bytes()).hexdigest()},
        }
        index = make_c1_artifact_index(edges)
        self.assertEqual(index, _load("artifact_index.json"))
        visit(index)


if __name__ == "__main__":
    unittest.main()
