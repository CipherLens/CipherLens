from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from real_campaign_bridge.c1_fix3 import (
    fixed_object_inventory,
    make_build_profile_alignment,
    make_fix3_claim_gate,
    make_library_build_provenance_record,
    make_provenance_discovery,
)
from target_knowledge.canonical import canonical_json_bytes, semantic_digest


ROOT = Path(__file__).parents[2]
REPAIR = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix3-v0.1"


def edge(ref: str, digit: str) -> dict[str, str]:
    return {"ref": ref, "digest": digit * 64}


def inputs(*, complete: bool = False) -> dict:
    return {
        "source_identity": edge("source:fixed", "a"),
        "source_tree_digest": "b" * 64,
        "build_profile": edge("build:profile", "c"),
        "libraries": [edge("library:one", "d"), edge("library:two", "e"), edge("library:three", "f")],
        "compiler_identity": edge("compiler:identity", "1"),
        "compiler_version": edge("compiler:version", "2"),
        "makefile_evidence": [edge("evidence:Makefile", "3")],
        "include_evidence": [edge("evidence:config", "4")],
        "object_inventory": {**edge("evidence:objects", "5"), "status": "AVAILABLE"},
        "actual_compiler_invocation": edge("evidence:compile-log", "6") if complete else None,
        "actual_build_log": edge("evidence:build-log", "7") if complete else None,
    }


class C1Fix3Tests(unittest.TestCase):
    def test_existing_object_bytes_are_inventory_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "library").mkdir()
            (root / "library/a.o").write_bytes(b"object-a")
            inventory = fixed_object_inventory(fixed_root=root)
        self.assertEqual("AVAILABLE", inventory["status"])
        self.assertEqual(hashlib.sha256(b"object-a").hexdigest(), inventory["object_inputs"][0]["digest"])
        moved = deepcopy(inventory)
        moved["telemetry"]["fixed_library_directory"] = "/tmp/moved/library"
        self.assertEqual(semantic_digest(inventory), semantic_digest(moved))

    def test_library_presence_and_recipe_template_do_not_prove_reproducibility(self) -> None:
        discovery = make_provenance_discovery(**inputs())
        record = make_library_build_provenance_record(discovery)
        self.assertEqual("PARTIAL", discovery["status"])
        self.assertEqual("PARTIAL", record["provenance_completeness_status"])
        self.assertEqual("PROVENANCE_PARTIAL", record["validation_status"])
        self.assertEqual([
            "COMPILER_PROVENANCE_MISSING",
            "LINK_COMMAND_PROVENANCE_MISSING",
            "BUILD_LOG_MISSING",
            "REBUILD_REQUIRED_FOR_PROVENANCE",
        ], record["missing_provenance"])

    def test_complete_provenance_is_the_only_ready_to_retry_case(self) -> None:
        discovery = make_provenance_discovery(**inputs(complete=True))
        record = make_library_build_provenance_record(discovery)
        alignment = make_build_profile_alignment(build_profile=inputs()["build_profile"], provenance=record)
        gate = make_fix3_claim_gate(provenance=record, alignment=alignment, parent_claim_gate=edge("gate:parent", "8"))
        self.assertEqual("COMPLETE", record["provenance_completeness_status"])
        self.assertEqual("REPRODUCIBLE_PROVENANCE_READY", record["validation_status"])
        self.assertEqual("ALIGNED_FOR_REPRODUCIBILITY", alignment["status"])
        self.assertEqual("C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY", gate["status"])
        self.assertEqual("C1_RETRY_ONLY", gate["allowed_next_stage"])

    def test_partial_provenance_requires_controlled_rebuild(self) -> None:
        record = make_library_build_provenance_record(make_provenance_discovery(**inputs()))
        alignment = make_build_profile_alignment(build_profile=inputs()["build_profile"], provenance=record)
        gate = make_fix3_claim_gate(provenance=record, alignment=alignment, parent_claim_gate=edge("gate:parent", "8"))
        self.assertEqual("C1_REQUIRES_CONTROLLED_LIBRARY_REBUILD_PROVENANCE", gate["status"])
        self.assertEqual("C1_FIX4_CONTROLLED_REBUILD_PROVENANCE", gate["allowed_next_stage"])
        self.assertFalse(gate["full_campaign_allowed"])
        self.assertEqual("NOT_GENERATED", gate["vulnerability_result"])

    def test_missing_object_and_actual_link_evidence_yield_precise_blockers(self) -> None:
        data = inputs()
        data["object_inventory"] = {**edge("evidence:objects", "5"), "status": "MISSING"}
        discovery = make_provenance_discovery(**data)
        self.assertIn("OBJECT_INPUT_PROVENANCE_MISSING", discovery["missing_provenance"])
        self.assertIn("LINK_COMMAND_PROVENANCE_MISSING", discovery["missing_provenance"])
        self.assertIn("REBUILD_REQUIRED_FOR_PROVENANCE", discovery["missing_provenance"])

    def test_semantic_identity_excludes_absolute_telemetry_path_and_rejects_raw_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "library").mkdir()
            (root / "library/a.o").write_bytes(b"object-a")
            first = fixed_object_inventory(fixed_root=root)
        moved = deepcopy(first)
        moved["telemetry"]["fixed_library_directory"] = "/tmp/other/library"
        self.assertEqual(semantic_digest(first), semantic_digest(moved))
        bad = inputs(); bad["libraries"] = [edge("/tmp/lib.a", "d")]
        with self.assertRaisesRegex(ValueError, "logical"):
            make_provenance_discovery(**bad)

    def test_discovery_digest_is_recomputable_and_no_subprocess_is_used(self) -> None:
        discovery = make_provenance_discovery(**inputs())
        record = make_library_build_provenance_record(discovery)
        unsigned = dict(record)
        unsigned.pop("provenance_id")
        self.assertEqual(record["provenance_id"].rsplit(":", 1)[1], semantic_digest(unsigned))
        source = (ROOT / "real_campaign_bridge/c1_fix3.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("requests", source)

    def test_stored_fix3_records_are_fail_closed_and_digest_addressed(self) -> None:
        record = json.loads((REPAIR / "library_build_provenance_record.json").read_text())
        alignment = json.loads((REPAIR / "build_profile_alignment.json").read_text())
        gate = json.loads((REPAIR / "claim_gate_decision.json").read_text())
        index = json.loads((REPAIR / "artifact_index.json").read_text())
        self.assertEqual("PARTIAL", record["provenance_completeness_status"])
        self.assertEqual("PREPARATION_PROFILE_ONLY", alignment["status"])
        self.assertEqual("C1_REQUIRES_CONTROLLED_LIBRARY_REBUILD_PROVENANCE", gate["status"])
        self.assertEqual("C1_FIX4_CONTROLLED_REBUILD_PROVENANCE", gate["allowed_next_stage"])
        self.assertEqual("CREATE_ONLY_FIX3_SUCCESSOR_DO_NOT_REWRITE_PARENT", index["repair_lineage"])
        for item in index["artifacts"]:
            path = ROOT / item["ref"]
            self.assertEqual(item["digest"], hashlib.sha256(path.read_bytes()).hexdigest())
        for path in REPAIR.rglob("*"):
            if path.is_file():
                text = path.read_text(errors="ignore")
                self.assertNotIn("preflight:pending", text)
                self.assertNotIn("TODO_DIGEST", text)
                self.assertNotIn("Witness", text)
                self.assertNotIn("ViolationEvidencePackage", text)


if __name__ == "__main__":
    unittest.main()
