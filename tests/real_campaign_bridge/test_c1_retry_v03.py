import hashlib
import unittest
from pathlib import Path

from real_campaign_bridge.c1_retry import (
    c1_retry_v03_blocked_documents,
    evaluate_c1_retry_v03_gate,
)
from target_knowledge.canonical import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[2]
V01 = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.1/artifact_index.json"
V02 = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.2/artifact_index.json"


class C1RetryV03Tests(unittest.TestCase):
    def test_gate_stops_before_build_on_specification_only_bound_source(self):
        before = (hashlib.sha256(V01.read_bytes()).hexdigest(), hashlib.sha256(V02.read_bytes()).hexdigest())
        gate = evaluate_c1_retry_v03_gate(ROOT)
        after = (hashlib.sha256(V01.read_bytes()).hexdigest(), hashlib.sha256(V02.read_bytes()).hexdigest())
        self.assertEqual(before, after)
        self.assertEqual("C1_SINGLE_UNIT_DRY_RUN_BLOCKED", gate["status"])
        self.assertEqual(
            [
                "EXECUTABLE_BOUND_SOURCE_NOT_MATERIALIZED",
                "DECLARED_CAPTURE_PROTOCOL_NOT_MATERIALIZED",
            ],
            gate["blocking_reasons"],
        )
        self.assertFalse(gate["build_attempted"])
        self.assertFalse(gate["run_attempted"])

    def test_first_five_lineage_checks_pass_and_execution_checks_block(self):
        checks = evaluate_c1_retry_v03_gate(ROOT)["checks"]
        self.assertEqual(["PASS"] * 5, [item["status"] for item in checks[:5]])
        self.assertEqual(["BLOCKED", "BLOCKED"], [item["status"] for item in checks[5:]])
        source = evaluate_c1_retry_v03_gate(ROOT)["source_materialization"]
        self.assertFalse(source["executable_source_generated"])
        self.assertTrue(source["unresolved_template_masks_present"])
        self.assertFalse(source["declared_capture_protocol_present"])
        self.assertFalse(source["older_c0_source_reuse_allowed"])

    def test_blocked_documents_are_digest_closed_without_execution_outputs(self):
        documents = c1_retry_v03_blocked_documents(evaluate_c1_retry_v03_gate(ROOT))
        index = documents["artifact_index.json"]
        self.assertEqual(3, len(index["artifacts"]))
        for entry in index["artifacts"]:
            name = entry["artifact_type"] + ".json"
            self.assertEqual(
                entry["digest"],
                hashlib.sha256(canonical_json_bytes(documents[name])).hexdigest(),
            )
        attempt = documents["attempt_manifest.json"]
        for key in (
            "build_attempted",
            "run_attempted",
            "target_binary_started",
            "runtime_event_generated",
            "witness_generated",
            "trace_generated",
            "projection_generated",
            "relation_evaluation_generated",
            "execution_verdict_generated",
            "violation_evidence_package_generated",
        ):
            self.assertFalse(attempt[key])


if __name__ == "__main__":
    unittest.main()
