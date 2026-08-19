from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from real_campaign_bridge.c1_repair import (
    check_build_run_materialization,
    fixed_include_readiness,
    inspect_fixed_library,
    make_c1_lineage_readiness,
    make_local_execution_mapping,
    make_repair_artifact_index,
    make_repair_claim_gate,
    validate_fixed_profile_include,
)
from target_knowledge.canonical import canonical_json_bytes
from tests.execution_support import upstream


ROOT = Path(__file__).parents[2]
PREP = ROOT / "artifacts/pipeline_v2/real_campaign_preflight"
C1 = ROOT / "artifacts/pipeline_v2/single_unit_dry_run"
REPAIR = C1 / "repairs/c1-fix-v0.1"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _file_edge(path: Path) -> dict[str, str]:
    return {"ref": str(path.relative_to(ROOT)), "digest": hashlib.sha256(path.read_bytes()).hexdigest()}


class C1RepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile_path = PREP / "build_profiles/0020.fixed.json"
        cls.profile = _load(cls.profile_path)
        cls.profile_edge = _file_edge(cls.profile_path)
        cls.source_path = PREP / cls.profile["source_root"]["ref"]
        cls.source = _load(cls.source_path)
        cls.fixed_source_edge = _file_edge(cls.source_path)
        cls.buggy_source_path = PREP / "source_identities/mbedtls-0020-buggy.json"
        cls.buggy_source_edge = _file_edge(cls.buggy_source_path)
        cls.include_path = PREP / cls.profile["include_path_evidence"][0]["ref"]
        cls.include = _load(cls.include_path)
        cls.include_edge = _file_edge(cls.include_path)
        cls.pair = _load(PREP / "differential_pairs/0020.json")

    def test_fixed_include_rejects_buggy_and_swapped_evidence(self) -> None:
        readiness = fixed_include_readiness(
            fixed_source_identity=self.fixed_source_edge,
            buggy_source_identity=self.buggy_source_edge,
            rejected_include_evidence=self.include_edge,
        )
        self.assertEqual("MISSING", readiness["status"])
        self.assertEqual(self.fixed_source_edge, readiness["fixed_source_identity"])
        self.assertEqual([], readiness["fixed_include_roots"])
        with self.assertRaisesRegex(ValueError, "non-fixed source"):
            validate_fixed_profile_include(
                profile=self.profile,
                profile_edge=self.profile_edge,
                pair=self.pair,
                fixed_source_identity=self.profile["source_root"],
                include_evidence=self.include,
            )
        swapped = deepcopy(self.pair)
        swapped["fixed_profile_digest"] = swapped["buggy_profile_digest"]
        with self.assertRaisesRegex(ValueError, "fixed profile digest"):
            validate_fixed_profile_include(
                profile=self.profile,
                profile_edge=self.profile_edge,
                pair=swapped,
                fixed_source_identity=self.profile["source_root"],
                include_evidence={
                    "source_identity_ref": self.profile["source_root"]["ref"],
                    "source_identity_digest": self.profile["source_root"]["digest"],
                    "header_roots": [{"tree_digest": self.profile["source_tree_digest"]["fixed"]}],
                },
            )

    def test_missing_library_stays_blocked_and_existing_bytes_get_sha256(self) -> None:
        missing = inspect_fixed_library(None)
        self.assertEqual("MISSING", missing["status"])
        self.assertEqual(3, len(missing["missing_artifacts"]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "libmbedtls.a"
            path.write_bytes(b"synthetic-library-inventory-only")
            existing = inspect_fixed_library(path, artifact_ref="test:c1:libmbedtls.a", producer_evidence=[self.fixed_source_edge])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), existing["library_artifact"]["digest"])
            self.assertEqual("AVAILABLE", existing["status"])

    def test_local_mapping_is_path_safe_and_fails_closed(self) -> None:
        mapping = make_local_execution_mapping(
            source_identity_document=self.source,
            source_identity=self.fixed_source_edge,
            source_root_ref="source-root:mbedtls:0020:fixed",
            build_profile=self.profile_edge,
            local_source_root=Path("/tmp/location-one"),
        )
        moved = make_local_execution_mapping(
            source_identity_document=self.source,
            source_identity=self.fixed_source_edge,
            source_root_ref="source-root:mbedtls:0020:fixed",
            build_profile=self.profile_edge,
            local_source_root=Path("/tmp/location-two"),
        )
        self.assertEqual(mapping["mapping_id"], moved["mapping_id"])
        self.assertEqual("INCOMPLETE", mapping["status"])
        self.assertIn("fixed compile unit refs", mapping["missing_artifacts"])
        wrong_source = dict(self.fixed_source_edge, digest="0" * 64)
        with self.assertRaisesRegex(ValueError, "source identity digest mismatch"):
            make_local_execution_mapping(
                source_identity_document=self.source,
                source_identity=wrong_source,
                source_root_ref="source-root:mbedtls:0020:fixed",
                build_profile=self.profile_edge,
            )

    def test_c1_lineage_is_explicit_and_c0_is_never_accepted(self) -> None:
        lineage = make_c1_lineage_readiness({})
        self.assertEqual("INCOMPLETE", lineage["status"])
        self.assertEqual(6, len(lineage["missing_artifacts"]))
        self.assertFalse(lineage["c0_replay_accepted"])
        with self.assertRaisesRegex(ValueError, "C0 replay fixture"):
            make_c1_lineage_readiness({
                "execution_handoff": {"ref": "c0:handoff", "digest": "a" * 64, "classification": "C0_REPLAY_FIXTURE_NOT_REAL_CAMPAIGN"},
            })

    def test_materialization_blocks_without_handoff_or_library(self) -> None:
        mapping = make_local_execution_mapping(
            source_identity_document=self.source,
            source_identity=self.fixed_source_edge,
            source_root_ref="source-root:mbedtls:0020:fixed",
            build_profile=self.profile_edge,
        )
        with patch.object(subprocess, "run") as runner:
            result = check_build_run_materialization(
                execution_handoff=None,
                build_profile_document=self.profile,
                build_profile=self.profile_edge,
                local_mapping=mapping,
            )
        runner.assert_not_called()
        self.assertEqual("BLOCKED", result["status"])
        self.assertIsNone(result["build_spec"])
        self.assertIsNone(result["run_spec"])
        self.assertIn("C1 execution handoff", result["missing_artifacts"])
        self.assertIn("fixed library input refs", result["missing_artifacts"])

    def test_complete_synthetic_inputs_materialize_buildspec_without_execution(self) -> None:
        data = upstream("mbedtls_poc_0020")
        compile_unit = {"ref": data["handoff"]["source_artifact_ref"], "digest": data["handoff"]["source_artifact_digest"]}
        include = {"ref": "synthetic:c1:fixed-include", "digest": "3" * 64}
        library = {"ref": "synthetic:c1:fixed-library", "digest": "4" * 64}
        mapping = make_local_execution_mapping(
            source_identity_document=self.source,
            source_identity=self.fixed_source_edge,
            source_root_ref="source-root:mbedtls:0020:fixed",
            build_profile=self.profile_edge,
            compile_units=[compile_unit], include_roots=[include], library_inputs=[library],
            local_source_root=Path("/tmp/synthetic-c1-source"),
        )
        build_units = [{"artifact_ref": compile_unit["ref"], "artifact_digest": compile_unit["digest"], "language": "c"}]
        with patch.object(subprocess, "run") as runner:
            result = check_build_run_materialization(
                execution_handoff=data["handoff"],
                build_profile_document=self.profile,
                build_profile=self.profile_edge,
                local_mapping=mapping,
                compile_units=build_units,
            )
        runner.assert_not_called()
        self.assertEqual("BUILDSPEC_MATERIALIZED_NOT_EXECUTED", result["status"])
        self.assertIsNotNone(result["build_spec"])
        self.assertIsNone(result["run_spec"])
        self.assertFalse(result["build_attempted"])
        self.assertFalse(result["run_attempted"])
        tampered = deepcopy(mapping)
        tampered["build_profile"]["digest"] = "9" * 64
        with self.assertRaisesRegex(ValueError, "build profile mismatch"):
            check_build_run_materialization(
                execution_handoff=data["handoff"], build_profile_document=self.profile,
                build_profile=self.profile_edge, local_mapping=tampered, compile_units=build_units,
            )

    def test_raw_path_shortcut_and_unit_mismatch_are_rejected(self) -> None:
        mapping = make_local_execution_mapping(
            source_identity_document=self.source, source_identity=self.fixed_source_edge,
            source_root_ref="source-root:mbedtls:0020:fixed", build_profile=self.profile_edge,
        )
        raw = deepcopy(mapping); raw["raw_source_path"] = "/tmp/shortcut.c"
        with self.assertRaisesRegex(ValueError, "raw path shortcut"):
            check_build_run_materialization(execution_handoff=None, build_profile_document=self.profile, build_profile=self.profile_edge, local_mapping=raw)
        wrong = deepcopy(mapping); wrong["unit_id"] = "unit:track-a:0020:buggy"
        with self.assertRaisesRegex(ValueError, "unit mismatch"):
            check_build_run_materialization(execution_handoff=None, build_profile_document=self.profile, build_profile=self.profile_edge, local_mapping=wrong)

    def test_stored_repair_artifacts_are_create_only_blocked_lineage(self) -> None:
        old_gate = _load(C1 / "pre_run_gate/gate.json")
        old_index = _load(C1 / "artifact_index.json")
        parent_gate = _file_edge(C1 / "pre_run_gate/gate.json")
        parent_index = _file_edge(C1 / "artifact_index.json")
        self.assertEqual("C1_SINGLE_UNIT_DRY_RUN_BLOCKED", old_gate["status"])
        self.assertEqual("C1_SINGLE_UNIT_DRY_RUN_BLOCKED", old_index["status"])

        docs = {
            "library": _load(REPAIR / "fixed_library_readiness.json"),
            "fixed_include": _load(REPAIR / "fixed_include_readiness.json"),
            "local_mapping": _load(REPAIR / "local_execution_mapping.json"),
            "canonical_lineage": _load(REPAIR / "canonical_lineage_readiness.json"),
            "build_run": _load(REPAIR / "build_run_readiness.json"),
        }
        expected_library = inspect_fixed_library(None)
        expected_include = fixed_include_readiness(
            fixed_source_identity=self.fixed_source_edge,
            buggy_source_identity=self.buggy_source_edge,
            rejected_include_evidence=self.include_edge,
        )
        expected_mapping = make_local_execution_mapping(
            source_identity_document=self.source,
            source_identity=self.fixed_source_edge,
            source_root_ref="source-root:mbedtls:0020:fixed",
            build_profile=self.profile_edge,
        )
        expected_lineage = make_c1_lineage_readiness({})
        expected_build_run = check_build_run_materialization(
            execution_handoff=None,
            build_profile_document=self.profile,
            build_profile=self.profile_edge,
            local_mapping=expected_mapping,
        )
        self.assertEqual({
            "library": expected_library,
            "fixed_include": expected_include,
            "local_mapping": expected_mapping,
            "canonical_lineage": expected_lineage,
            "build_run": expected_build_run,
        }, docs)
        edges = {name: _file_edge(REPAIR / filename) for name, filename in {
            "library": "fixed_library_readiness.json",
            "fixed_include": "fixed_include_readiness.json",
            "local_mapping": "local_execution_mapping.json",
            "canonical_lineage": "canonical_lineage_readiness.json",
            "build_run": "build_run_readiness.json",
        }.items()}
        claim = make_repair_claim_gate(repair_documents=docs, repair_artifacts=edges, parent_gate=parent_gate)
        self.assertEqual(claim, _load(REPAIR / "claim_gate_decision.json"))
        self.assertEqual("C1_PRE_RUN_GATE_STILL_BLOCKED", claim["status"])
        self.assertEqual("C1_FIX_CONTINUE", claim["allowed_next_stage"])
        self.assertFalse(claim["witness_generated"])
        self.assertFalse(claim["structured_trace_generated"])
        self.assertFalse(claim["execution_verdict_generated"])
        self.assertFalse(claim["violation_evidence_package_generated"])
        edges["claim_gate"] = _file_edge(REPAIR / "claim_gate_decision.json")
        index = make_repair_artifact_index(parent_index=parent_index, artifacts=edges)
        self.assertEqual(index, _load(REPAIR / "artifact_index.json"))
        self.assertEqual(parent_index, index["parent_artifact_index"])
        self.assertEqual("CREATE_ONLY_SUCCESSOR_DO_NOT_REWRITE_PARENT", index["repair_lineage"])
        self.assertNotIn("PASSED", json.dumps(claim))

    def test_artifacts_have_real_edges_and_no_execution_outputs(self) -> None:
        for path in sorted(REPAIR.glob("*.json")):
            raw = path.read_bytes()
            text = raw.decode()
            self.assertNotIn("preflight:pending", text)
            self.assertNotIn("TODO_DIGEST", text)
            self.assertNotIn("Witness", text)
            self.assertNotIn("ViolationEvidencePackage", text)
            document = json.loads(raw)
            self.assertEqual("SINGLE_UNIT_DRY_RUN_PREP", document["scope"])
            self.assertEqual("NOT_FULL_CAMPAIGN", document["campaign_scope"])
            self.assertFalse(document["report_real_number_allowed"])


if __name__ == "__main__":
    unittest.main()
