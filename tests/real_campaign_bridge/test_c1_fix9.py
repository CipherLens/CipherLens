import ast
import copy
import hashlib
import json
import unittest
from pathlib import Path

from real_campaign_bridge.c1_fix9 import (
    FIX2,
    FIX4,
    OUTPUT,
    c1_fix9_documents,
    execution_handoff_readiness,
    finalize_source_map,
    materialize_bound_source,
)
from target_knowledge.canonical import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[2]


def _load(ref):
    return json.loads((ROOT / ref).read_text(encoding="utf-8"))


def _edge(ref):
    return {
        "ref": str(ref),
        "digest": hashlib.sha256((ROOT / ref).read_bytes()).hexdigest(),
    }


def _document_edge(name, document):
    return {
        "ref": str(OUTPUT / name),
        "digest": hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
    }


class C1Fix9Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = c1_fix9_documents(ROOT)
        cls.merge = _load(FIX2 / "merge.json")
        cls.candidate = _load(FIX2 / "candidate_binding.json")
        cls.source_map_capture = _load(
            "artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix8-v0.1/source_map_capture_update.json"
        )
        cls.parents = cls.documents["artifact_index.json"]["parent_artifacts"]

    def _materialize(self, values=None, captures=None, protected=False):
        return materialize_bound_source(
            values or self.documents["resolved_template_values.json"],
            captures or self.documents["capture_binding_materialization.json"],
            self.source_map_capture,
            self.merge,
            self.candidate,
            base_source_edge=_edge(FIX2 / "bound_source.c"),
            protected_region_modified=protected,
            parent_artifacts=self.parents,
        )

    def _handoff(self, bound_source, source_map):
        return execution_handoff_readiness(
            bound_source,
            source_map,
            self.merge,
            self.candidate,
            bound_source_edge=_document_edge("bound_source_materialization.json", bound_source),
            source_map_edge=_document_edge("source_map_finalization.json", source_map),
            merge_edge=_edge(FIX2 / "merge.json"),
            candidate_binding_edge=_edge(FIX2 / "candidate_binding.json"),
            build_profile_edge=_edge(FIX4 / "build_profile_alignment.json"),
            parent_artifacts=self.parents,
        )

    def test_all_declared_holes_are_resolved_correctly(self):
        values = self.documents["resolved_template_values.json"]
        self.assertEqual("READY", values["status"])
        self.assertEqual([], values["missing_requirements"])
        actual = {
            item["hole_ref"]: item["resolved_value"]
            for item in values["resolved_values"]
        }
        self.assertEqual(
            {
                "hole:DER_KIND": "private",
                "hole:EXPECT_RET": "MBEDTLS_ERR_RSA_BAD_INPUT_DATA",
                "hole:PARSE_API_KIND": "rsa_private",
                "hole:TRAILING_GARBAGE_BYTES": "020100",
                "hole:TRAILING_GARBAGE_LEN": 3,
            },
            actual,
        )
        for item in values["resolved_values"]:
            self.assertEqual(len(item["source_refs"]), len(item["source_digests"]))
            self.assertRegex(item["digest"], r"^[0-9a-f]{64}$")

    def test_unresolved_hole_blocks_bound_source(self):
        values = copy.deepcopy(self.documents["resolved_template_values.json"])
        values["status"] = "BLOCKED"
        values["resolved_values"] = [
            item for item in values["resolved_values"]
            if item["hole_ref"] != "hole:EXPECT_RET"
        ]
        bound_source = self._materialize(values=values)
        self.assertEqual("BLOCKED", bound_source["status"])
        self.assertIn("BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED", bound_source["missing_requirements"])

    def test_capture_region_and_all_bindings_appear_in_bound_source(self):
        captures = self.documents["capture_binding_materialization.json"]
        bound_source = self.documents["bound_source_materialization.json"]
        self.assertEqual("READY", captures["status"])
        self.assertEqual(
            {"operation_outcome", "consumed_length", "input_length"},
            {item["semantic_role"] for item in captures["capture_bindings"]},
        )
        self.assertEqual(3, len(bound_source["capture_bindings"]))
        for item in captures["capture_bindings"]:
            self.assertEqual(
                "region:c1-overlay:oracle-event-capture",
                item["capture_region_ref"],
            )

    def test_missing_capture_binding_blocks_readiness(self):
        captures = copy.deepcopy(self.documents["capture_binding_materialization.json"])
        captures["status"] = "BLOCKED"
        captures["capture_bindings"] = captures["capture_bindings"][1:]
        bound_source = self._materialize(captures=captures)
        self.assertEqual("BLOCKED", bound_source["status"])
        self.assertIn(
            "DECLARED_CAPTURE_REGION_NOT_MATERIALIZED_IN_BOUND_SOURCE",
            bound_source["missing_requirements"],
        )

    def test_protected_region_modification_is_rejected(self):
        bound_source = self._materialize(protected=True)
        self.assertEqual("BLOCKED", bound_source["status"])
        self.assertIn("PROTECTED_REGION_MODIFICATION_REJECTED", bound_source["missing_requirements"])

    def test_source_map_identity_changes_when_mapping_changes(self):
        original = self.documents["source_map_finalization.json"]
        captures = copy.deepcopy(self.documents["capture_binding_materialization.json"])
        captures["capture_bindings"][0]["observation_binding_digest"] = "0" * 64
        changed = finalize_source_map(
            self.documents["bound_source_materialization.json"],
            self.documents["resolved_template_values.json"],
            captures,
            self.merge,
            self.candidate,
            bound_source_edge=_document_edge(
                "bound_source_materialization.json",
                self.documents["bound_source_materialization.json"],
            ),
            merge_edge=_edge(FIX2 / "merge.json"),
            base_source_map_edge=_edge(FIX2 / "source_map.json"),
            parent_artifacts=self.parents,
        )
        self.assertNotEqual(original["source_map_id"], changed["source_map_id"])

    def test_handoff_requires_new_ready_bound_source_and_rejects_c0_replay(self):
        ready = self.documents["bound_source_materialization.json"]
        final_map = self.documents["source_map_finalization.json"]
        self.assertEqual("READY", self._handoff(ready, final_map)["status"])

        blocked = copy.deepcopy(ready)
        blocked["status"] = "BLOCKED"
        self.assertIn(
            "MATERIALIZED_BOUND_SOURCE_NOT_READY",
            self._handoff(blocked, final_map)["missing_requirements"],
        )

        c0_replay = _load(FIX2 / "bound_source.json")
        replay_handoff = self._handoff(c0_replay, final_map)
        self.assertEqual("BLOCKED", replay_handoff["status"])
        self.assertIn("C0_REPLAY_BOUND_SOURCE_REJECTED", replay_handoff["missing_requirements"])

    def test_source_generation_bypass_is_rejected(self):
        values = copy.deepcopy(self.documents["resolved_template_values.json"])
        values["source_code"] = "int main(void) { return 0; }"
        bound_source = self._materialize(values=values)
        self.assertEqual("BLOCKED", bound_source["status"])
        self.assertIn("SOURCE_GENERATION_BYPASS_REJECTED", bound_source["missing_requirements"])

    def test_no_legacy_filler_or_external_provider_import(self):
        source = (ROOT / "real_campaign_bridge/c1_fix9.py").read_text(encoding="utf-8")
        imports = {
            alias.name
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module or ""
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom)
        )
        forbidden = {
            "migration." + "adapter_" + "filler",
            "re" + "quests",
            "sock" + "et",
            "sub" + "process",
        }
        self.assertTrue(imports.isdisjoint(forbidden))

    def test_gate_allows_retry_only_without_execution_outputs(self):
        gate = self.documents["c1_pre_run_gate_decision.json"]
        self.assertEqual("C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY", gate["status"])
        self.assertEqual("C1_RETRY_ONLY", gate["allowed_next_stage"])
        self.assertFalse(gate["full_campaign_allowed"])
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
            self.assertFalse(gate[key])

    def test_artifact_index_digest_closure_and_parent_lineage(self):
        index = self.documents["artifact_index.json"]
        self.assertEqual(6, len(index["artifacts"]))
        self.assertEqual(
            {"c1_retry_v0_2", "c1_fix8", "c1_fix7"},
            set(index["parent_artifacts"]),
        )
        for entry in index["artifacts"]:
            name = entry["artifact_type"] + ".json"
            self.assertEqual(
                entry["digest"],
                hashlib.sha256(canonical_json_bytes(self.documents[name])).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
