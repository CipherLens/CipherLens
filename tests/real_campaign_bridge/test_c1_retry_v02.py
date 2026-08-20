import hashlib
import unittest
from pathlib import Path

from real_campaign_bridge.c1_retry import (
    c1_retry_v02_blocked_documents,
    evaluate_c1_retry_v02_gate,
)
from target_knowledge.canonical import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[2]
OLD_INDEX = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.1/artifact_index.json"


class C1RetryV02Tests(unittest.TestCase):
    def test_gate_fails_before_build_on_unmaterialized_source(self):
        before = hashlib.sha256(OLD_INDEX.read_bytes()).hexdigest()
        gate = evaluate_c1_retry_v02_gate(ROOT)
        after = hashlib.sha256(OLD_INDEX.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertEqual("C1_SINGLE_UNIT_DRY_RUN_BLOCKED", gate["status"])
        self.assertEqual(
            [
                "BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED",
                "DECLARED_CAPTURE_REGION_NOT_MATERIALIZED_IN_BOUND_SOURCE",
            ],
            gate["blocking_reasons"],
        )
        self.assertFalse(gate["build_attempted"])
        self.assertFalse(gate["run_attempted"])

    def test_blocked_artifact_index_is_closed(self):
        documents = c1_retry_v02_blocked_documents(evaluate_c1_retry_v02_gate(ROOT))
        index = documents["artifact_index.json"]
        self.assertEqual(3, len(index["artifacts"]))
        for entry in index["artifacts"]:
            name = entry["artifact_type"] + ".json"
            self.assertEqual(
                entry["digest"],
                hashlib.sha256(canonical_json_bytes(documents[name])).hexdigest(),
            )
        attempt = documents["attempt_manifest.json"]
        self.assertFalse(attempt["runtime_event_generated"])
        self.assertFalse(attempt["witness_generated"])
        self.assertFalse(attempt["trace_generated"])
        self.assertFalse(attempt["execution_verdict_generated"])
