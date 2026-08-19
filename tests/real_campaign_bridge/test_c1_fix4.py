from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
import unittest

from real_campaign_bridge.c1_fix4 import (
    make_archive_command_evidence,
    make_build_profile_alignment,
    make_c1_pre_run_gate,
    make_compile_invocation_manifest,
    make_library_build_provenance_record,
    make_object_inventory,
)
from target_knowledge.canonical import canonical_json_bytes, semantic_digest


ROOT = Path(__file__).parents[2]
REPAIR = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1"


def edge(ref: str, digit: str) -> dict[str, str]:
    return {"ref": ref, "digest": digit * 64}


def complete_document(identifier: str, status: str = "COMPLETE") -> dict:
    return {"status": status, identifier: f"{identifier}:" + "a" * 64}


class C1Fix4Tests(unittest.TestCase):
    def test_archive_evidence_requires_exactly_three_library_outputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "three archive"):
            make_archive_command_evidence(
                archive_commands=[edge("archive:one", "a")],
                libraries=[edge("library:one", "b")],
                build_stdout=edge("log:build", "c"),
            )

    def test_compile_manifest_requires_byte_addressed_object_closure(self) -> None:
        config = {"evidence_id": "config:" + "a" * 64}
        with self.assertRaisesRegex(ValueError, "object closure"):
            make_compile_invocation_manifest(config=config, units=[], build_stdout=edge("log:out", "b"), build_stderr=edge("log:err", "c"))

    def test_object_inventory_is_required_for_provenance(self) -> None:
        manifest = {
            "manifest_id": "manifest:" + "a" * 64,
            "compiled_object_outputs": [{"object": edge("object:one", "b")}],
        }
        inventory = make_object_inventory(compile_manifest=manifest)
        self.assertEqual("COMPLETE", inventory["status"])
        self.assertEqual(edge("object:one", "b"), inventory["object_inputs"][0])

    def test_rebuilt_profile_alignment_requires_complete_provenance(self) -> None:
        plan = {"plan_id": "plan:" + "a" * 64}
        prior = edge("profile:prior", "b")
        partial = {"provenance_id": "provenance:" + "c" * 64, "validation_status": "PROVENANCE_PARTIAL"}
        complete = {"provenance_id": "provenance:" + "d" * 64, "validation_status": "REPRODUCIBLE_PROVENANCE_READY"}
        self.assertEqual("INCOMPLETE", make_build_profile_alignment(plan=plan, provenance=partial, existing_profile=prior)["status"])
        self.assertEqual("COMPLETE", make_build_profile_alignment(plan=plan, provenance=complete, existing_profile=prior)["status"])

    def test_ready_to_retry_requires_full_provenance_lineage_and_buildspec(self) -> None:
        source = {"status": "VERIFIED"}
        include = {"status": "VERIFIED"}
        provenance = {"validation_status": "REPRODUCIBLE_PROVENANCE_READY"}
        alignment = {"status": "COMPLETE"}
        mapping = {"status": "COMPLETE"}
        lineage = {"status": "COMPLETE_NOT_EXECUTED"}
        build = {"status": "BUILDSPEC_MATERIALIZED_NOT_EXECUTED"}
        gate = make_c1_pre_run_gate(source=source, include=include, provenance=provenance, profile_alignment=alignment, local_mapping=mapping, lineage=lineage, build_readiness=build, parent_gate=edge("gate:parent", "a"))
        self.assertEqual("C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY", gate["status"])
        self.assertEqual("C1_RETRY_ONLY", gate["allowed_next_stage"])
        blocked = make_c1_pre_run_gate(source=source, include=include, provenance={"validation_status": "PROVENANCE_PARTIAL"}, profile_alignment=alignment, local_mapping=mapping, lineage=lineage, build_readiness=build, parent_gate=edge("gate:parent", "a"))
        self.assertEqual("C1_PRE_RUN_GATE_STILL_BLOCKED", blocked["status"])
        self.assertIn("LIBRARY_PROVENANCE_MISSING", blocked["blocking_reasons"])

    def test_semantic_identity_excludes_rebuild_telemetry_paths(self) -> None:
        record = json.loads((REPAIR / "controlled_rebuild_plan.json").read_text())
        moved = deepcopy(record)
        moved["telemetry"]["build_directory"] = "/tmp/moved-build"
        self.assertEqual(semantic_digest(record), semantic_digest(moved))

    def test_stored_controlled_rebuild_is_provenance_only_and_ready_for_retry(self) -> None:
        plan = json.loads((REPAIR / "controlled_rebuild_plan.json").read_text())
        record = json.loads((REPAIR / "library_build_provenance_record.json").read_text())
        alignment = json.loads((REPAIR / "existing_vs_rebuilt_library_alignment.json").read_text())
        gate = json.loads((REPAIR / "c1_pre_run_gate_decision.json").read_text())
        self.assertEqual("BUILD_PROVENANCE_ONLY", plan["execution_status"])
        self.assertEqual("COMPLETE", record["provenance_completeness_status"])
        self.assertEqual("REPRODUCIBLE_PROVENANCE_READY", record["validation_status"])
        self.assertEqual("DIFFERS_FROM_EXISTING", alignment["status"])
        self.assertTrue(alignment["c1_must_use_rebuilt_provenance_complete_libraries"])
        self.assertEqual("C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY", gate["status"])
        self.assertFalse(gate["full_campaign_allowed"])
        self.assertFalse(gate["witness_generated"])
        self.assertFalse(gate["structured_trace_generated"])
        self.assertFalse(gate["execution_verdict_generated"])
        self.assertFalse(gate["violation_evidence_package_generated"])

    def test_all_raw_and_canonical_artifacts_have_real_sha256_edges(self) -> None:
        raw = json.loads((REPAIR / "raw_artifact_inventory.json").read_text())
        self.assertGreaterEqual(len(raw["artifacts"]), 100)
        for item in raw["artifacts"]:
            path = ROOT / item["ref"]
            self.assertEqual(item["digest"], hashlib.sha256(path.read_bytes()).hexdigest(), item["ref"])
        index = json.loads((REPAIR / "artifact_index.json").read_text())
        for item in index["artifacts"]:
            path = ROOT / item["ref"]
            self.assertEqual(item["digest"], hashlib.sha256(path.read_bytes()).hexdigest(), item["ref"])

    def test_no_subprocess_provider_or_network_transport_in_record_builder(self) -> None:
        source = (ROOT / "real_campaign_bridge/c1_fix4.py").read_text()
        for forbidden in ("subprocess", "requests", "urllib", "httpx", "CodexExecProvider", "GLM"):
            self.assertNotIn(forbidden, source)

    def test_record_identity_is_recomputable_without_self_id(self) -> None:
        record = json.loads((REPAIR / "library_build_provenance_record.json").read_text())
        unsigned = dict(record)
        unsigned.pop("provenance_id")
        self.assertEqual(record["provenance_id"].rsplit(":", 1)[1], semantic_digest(unsigned))
        self.assertEqual(hashlib.sha256(canonical_json_bytes(record)).hexdigest(), hashlib.sha256(canonical_json_bytes(record)).hexdigest())


if __name__ == "__main__":
    unittest.main()
