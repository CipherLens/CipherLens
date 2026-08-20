import ast
import hashlib
import unittest
from pathlib import Path

from real_campaign_bridge.c1_fix10 import FIX2, OUTPUT, c1_fix10_documents
from target_knowledge.canonical import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[2]


class C1Fix10Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents, cls.source = c1_fix10_documents(ROOT)

    def test_executable_bound_source_and_handoff_are_ready(self):
        executable = self.documents["executable_bound_source.json"]
        handoff = self.documents["execution_handoff_readiness.json"]
        self.assertEqual("READY", executable["status"])
        self.assertTrue(executable["executable_source_generated"])
        self.assertEqual("DETERMINISTIC_DECLARED_REGION_RENDER", executable["source_generation_mode"])
        self.assertEqual("READY", handoff["status"])
        self.assertEqual("C1_RETRY_ONLY", handoff["claim_boundary"]["allowed_next_stage"])

    def test_c0_source_is_not_replayed(self):
        source_ref = self.documents["executable_bound_source.json"]["source_artifact"]["ref"]
        self.assertNotEqual(str(FIX2 / "bound_source.c"), source_ref)
        self.assertEqual(str(OUTPUT / "executable_bound_source.c"), source_ref)

    def test_gate_clears_only_the_materialization_blockers(self):
        gate = self.documents["c1_pre_run_gate_decision.json"]
        self.assertEqual("C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY", gate["status"])
        self.assertEqual(
            {
                "EXECUTABLE_BOUND_SOURCE_NOT_MATERIALIZED",
                "DECLARED_CAPTURE_PROTOCOL_NOT_MATERIALIZED",
            },
            set(gate["cleared_blocking_reasons"]),
        )
        self.assertTrue(gate["c1_retry_allowed"])
        self.assertFalse(gate["full_campaign_allowed"])

    def test_no_execution_outputs_exist_in_fix_documents(self):
        gate = self.documents["c1_pre_run_gate_decision.json"]
        for key in (
            "build_attempted", "run_attempted", "target_binary_started", "runtime_event_generated",
            "witness_generated", "trace_generated", "projection_generated", "relation_evaluation_generated",
            "execution_verdict_generated", "violation_evidence_package_generated",
        ):
            self.assertFalse(gate[key])

    def test_artifact_index_and_source_digest_close(self):
        index = self.documents["artifact_index.json"]
        self.assertEqual({"c1_fix9", "c1_fix8", "c1_fix7"}, set(index["parent_artifacts"]))
        entries = {entry["artifact_type"]: entry for entry in index["artifacts"]}
        self.assertEqual(hashlib.sha256(self.source).hexdigest(), entries["executable_source"]["digest"])
        for name, document in self.documents.items():
            if name == "artifact_index.json":
                continue
            entry = entries[name[:-5]]
            self.assertEqual(hashlib.sha256(canonical_json_bytes(document)).hexdigest(), entry["digest"])

    def test_fix_module_has_no_provider_network_or_legacy_filler_import(self):
        source = (ROOT / "real_campaign_bridge/c1_fix10.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        forbidden = {"requests", "socket", "subprocess"}
        self.assertTrue(modules.isdisjoint(forbidden))
        self.assertNotIn("adapter_filler", source)


if __name__ == "__main__":
    unittest.main()
