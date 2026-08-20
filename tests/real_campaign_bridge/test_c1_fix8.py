import hashlib
import json
import unittest
from pathlib import Path

from real_campaign_bridge.c1_fix8 import c1_fix8_documents
from target_knowledge.canonical import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[2]
BASE_MANIFEST = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage/merge.json"


class C1Fix8Tests(unittest.TestCase):
    def test_gate_is_ready_only_after_complete_capture_chain(self):
        before = hashlib.sha256(BASE_MANIFEST.read_bytes()).hexdigest()
        documents = c1_fix8_documents(ROOT)
        after = hashlib.sha256(BASE_MANIFEST.read_bytes()).hexdigest()
        gate = documents["c1_pre_run_gate_decision.json"]
        self.assertEqual(before, after)
        self.assertEqual("C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY", gate["status"])
        self.assertEqual([], gate["blocking_reasons"])
        self.assertIn("MISSING_DECLARED_CAPTURE_REGION", gate["cleared_blocking_reasons"])
        self.assertEqual("C1_RETRY_ONLY", gate["allowed_next_stage"])

    def test_no_execution_or_security_outputs(self):
        documents = c1_fix8_documents(ROOT)
        gate = documents["c1_pre_run_gate_decision.json"]
        self.assertFalse(gate["build_run_attempted"])
        for key in (
            "runtime_event_generated", "witness_generated", "structured_trace_generated",
            "projection_generated", "relation_evaluation_generated",
            "execution_verdict_generated", "violation_evidence_package_generated",
        ):
            self.assertFalse(gate[key])
        readiness = documents["bound_source_readiness.json"]
        self.assertEqual("READY", readiness["status"])
        self.assertFalse(readiness["executable_source_generated"])

    def test_artifact_index_digest_closure(self):
        documents = c1_fix8_documents(ROOT)
        index = documents["artifact_index.json"]
        self.assertEqual(6, len(index["artifacts"]))
        for entry in index["artifacts"]:
            name = entry["artifact_type"] + ".json"
            actual = hashlib.sha256(canonical_json_bytes(documents[name])).hexdigest()
            self.assertEqual(entry["digest"], actual)
        payload = json.dumps(documents, sort_keys=True)
        self.assertNotIn("adapter_filler", payload)
