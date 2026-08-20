import hashlib
import unittest
from pathlib import Path

from real_campaign_bridge.c1_fix7 import c1_fix7_documents
from real_campaign_bridge.capture_emitter import capture_emitter_binding
from target_knowledge.canonical import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[2]


class C1Fix7Tests(unittest.TestCase):
    def test_missing_declared_region_blocks_capture(self):
        result = capture_emitter_binding(
            {
                "capture_binding_id": "capture:test",
                "observation_binding_ref": "observation:test",
                "semantic_role": "input_length",
                "acquisition_kind": "BOUND_VALUE",
                "phase": "AFTER_STEP",
            },
            [{"region_id": "region:protected", "protected": True}],
        )
        self.assertEqual("MISSING_DECLARED_CAPTURE_REGION", result["status"])

    def test_artifacts_are_preparation_only_and_closed(self):
        documents = c1_fix7_documents(ROOT)
        gate = documents["c1_pre_run_gate_decision.json"]
        self.assertEqual("C1_PRE_RUN_GATE_STILL_BLOCKED", gate["status"])
        self.assertEqual(["MISSING_DECLARED_CAPTURE_REGION"], gate["blocking_reasons"])
        self.assertIn("CAPTURE_HOOK_PROTOCOL_UNMATERIALIZABLE", gate["cleared_blocking_reasons"])
        self.assertFalse(gate["build_run_authorized"])
        self.assertFalse(documents["c1_fix7_capture_spec.json"]["runtime_events_generated"])
        index = documents["artifact_index.json"]
        for entry in index["artifacts"]:
            name = entry["artifact_type"] + ".json"
            self.assertEqual(entry["digest"], hashlib.sha256(canonical_json_bytes(documents[name])).hexdigest())
