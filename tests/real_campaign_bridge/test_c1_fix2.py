from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from execution_model.registry import validate_artifact_or_raise
from real_campaign_bridge.c1_fix2 import (
    discover_fixed_source,
    make_c1_prep_lineage,
    make_fix2_build_run_readiness,
    make_fix2_claim_gate,
    make_fix2_local_execution_mapping,
    make_fixed_include_readiness,
    make_fixed_library_readiness,
)
from target_knowledge.canonical import canonical_json_bytes, identified, semantic_digest
from target_knowledge.source_index import file_digest, tree_digest
from template_binding_merge.validate import (
    validate_bound_source_or_raise,
    validate_merge_or_raise,
    validate_merge_validation_or_raise,
    validate_source_map_or_raise,
)
from candidate_binding.validate import validate_candidate_binding_or_raise, validate_validation_artifact_or_raise


ROOT = Path(__file__).parents[2]
PREP = ROOT / "artifacts/pipeline_v2/real_campaign_preflight"
REPAIR = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _edge(path: Path) -> dict[str, str]:
    return {"ref": str(path.relative_to(ROOT)), "digest": hashlib.sha256(path.read_bytes()).hexdigest()}


def _linked_worktree(root: Path, head: str) -> None:
    metadata = root.parent / (root.name + "-gitdir")
    metadata.mkdir()
    (metadata / "HEAD").write_text(head + "\n")
    (root / ".git").write_text(f"gitdir: {metadata}\n")


class C1Fix2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_path = PREP / "source_identities/mbedtls-0020-fixed.json"
        cls.source_identity = _load(cls.source_path)
        cls.source_edge = _edge(cls.source_path)
        cls.profile_path = PREP / "build_profiles/0020.fixed.json"
        cls.profile = _load(cls.profile_path)
        cls.profile_edge = _edge(cls.profile_path)
        cls.pair_path = PREP / "differential_pairs/0020.json"
        cls.pair_edge = _edge(cls.pair_path)

    def test_source_discovery_rejects_buggy_or_mismatched_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fixed, buggy = base / "fixed", base / "buggy"
            for root, text, head in ((fixed, "fixed", "a" * 40), (buggy, "buggy", "b" * 40)):
                (root / "include/mbedtls").mkdir(parents=True)
                (root / "include/mbedtls/rsa.h").write_text(text)
                _linked_worktree(root, head)
            digest, count = tree_digest(fixed)
            identity = identified({
                "schema_version": "cipherlens.source_identity_record.v0.1",
                "source_root_ref": "source:mbedtls:0020:fixed", "source_tree_digest": digest,
                "file_count": count, "identity": {"kind": "git", "revision": "a" * 40},
                "preparation_status": "PREPARED_FOR_7D_B",
            }, "source-identity", "source_identity_id")
            edge = {"ref": "synthetic:fixed-identity", "digest": hashlib.sha256(canonical_json_bytes(identity)).hexdigest()}
            with patch.object(subprocess, "run") as runner:
                found = discover_fixed_source(
                    fixed_root=fixed, buggy_root=buggy,
                    fixed_source_identity_document=identity, fixed_source_identity=edge,
                )
            runner.assert_not_called()
            self.assertEqual("VERIFIED", found["status"])
            self.assertTrue(found["fixed_distinct_from_buggy"])
            wrong = deepcopy(identity); wrong["identity"]["revision"] = "b" * 40
            rejected = discover_fixed_source(
                fixed_root=fixed, buggy_root=buggy,
                fixed_source_identity_document=wrong,
                fixed_source_identity={"ref": "synthetic:wrong", "digest": hashlib.sha256(canonical_json_bytes(wrong)).hexdigest()},
            )
            self.assertEqual("CANDIDATE", rejected["status"])

    def test_include_and_library_evidence_are_byte_addressed_and_not_reproducible_without_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); fixed, buggy = base / "fixed", base / "buggy"
            for root, text, head in ((fixed, "fixed", "a" * 40), (buggy, "buggy", "b" * 40)):
                (root / "include/mbedtls").mkdir(parents=True)
                (root / "library").mkdir()
                (root / "include/mbedtls/rsa.h").write_text(text)
                (root / "library/libmbedcrypto.a").write_bytes((text + " archive").encode())
                _linked_worktree(root, head)
            digest, count = tree_digest(fixed)
            identity = {"identity": {"revision": "a" * 40}, "source_tree_digest": digest, "file_count": count, "source_root_ref": "source:mbedtls:0020:fixed"}
            edge = {"ref": "synthetic:source", "digest": hashlib.sha256(canonical_json_bytes(identity)).hexdigest()}
            discovery = discover_fixed_source(fixed_root=fixed, buggy_root=buggy, fixed_source_identity_document=identity, fixed_source_identity=edge)
            include = make_fixed_include_readiness(fixed_root=fixed, source_discovery=discovery, selected_headers=("include/mbedtls/rsa.h",))
            self.assertEqual("VERIFIED", include["status"])
            self.assertEqual(file_digest(fixed / "include/mbedtls/rsa.h"), include["selected_headers"][0]["digest"])
            library = make_fixed_library_readiness(
                fixed_root=fixed, source_discovery=discovery,
                libraries=(("library/libmbedcrypto.a", "static_library"),),
            )
            self.assertEqual("ARTIFACT_PRESENT_PROVENANCE_INCOMPLETE", library["status"])
            self.assertFalse(library["reproducible_target_library"])
            self.assertEqual(file_digest(fixed / "library/libmbedcrypto.a"), library["library_artifacts"][0]["digest"])
            self.assertIn("library build provenance", library["missing_artifacts"])
            self.assertNotIn(str(fixed), semantic_digest(library))

    def test_stored_fix2_discovery_mapping_and_include_are_complete_and_path_safe(self) -> None:
        source = _load(REPAIR / "fixed_source_discovery.json")
        include = _load(REPAIR / "fixed_include_readiness.json")
        library = _load(REPAIR / "fixed_library_readiness.json")
        mapping = _load(REPAIR / "local_execution_mapping.json")
        self.assertEqual("VERIFIED", source["status"])
        self.assertEqual(self.source_identity["identity"]["revision"], source["observed_revision"])
        self.assertEqual(self.source_identity["source_tree_digest"], source["observed_source_tree_digest"])
        self.assertEqual("VERIFIED", include["status"])
        self.assertNotEqual("e639fd696d5b74d4597af715cb5c6cc87e593239ba3bc6bc71b29e3c706cc5c3", _edge(REPAIR / "fixed_include_readiness.json")["digest"])
        self.assertEqual("ARTIFACT_PRESENT_PROVENANCE_INCOMPLETE", library["status"])
        self.assertEqual("COMPLETE", mapping["validation_status"])
        moved_source = deepcopy(source); moved_source["telemetry"]["fixed_source_root"] = "/tmp/moved-source-root"
        moved = make_fix2_local_execution_mapping(
            source_discovery=moved_source, include_readiness=include, library_readiness=library,
            build_profile=self.profile_edge, differential_pair=self.pair_edge,
            compile_units=mapping["compile_units"],
        )
        self.assertEqual(mapping["mapping_id"], moved["mapping_id"])
        raw = deepcopy(mapping); raw["compile_units"][0]["ref"] = "/tmp/shortcut.c"
        with self.assertRaisesRegex(ValueError, "logical, not absolute"):
            make_fix2_local_execution_mapping(
                source_discovery=source, include_readiness=include, library_readiness=library,
                build_profile=self.profile_edge, differential_pair=self.pair_edge,
                compile_units=raw["compile_units"],
            )

    def test_stored_c1_lineage_is_canonical_not_c0_and_has_no_execution_outputs(self) -> None:
        documents = {
            "candidate_binding": _load(REPAIR / "lineage/candidate_binding.json"),
            "candidate_binding_validation": _load(REPAIR / "lineage/candidate_binding_validation.json"),
            "merge": _load(REPAIR / "lineage/merge.json"),
            "merge_validation": _load(REPAIR / "lineage/merge_validation.json"),
            "bound_source": _load(REPAIR / "lineage/bound_source.json"),
            "source_map": _load(REPAIR / "lineage/source_map.json"),
            "execution_handoff": _load(REPAIR / "lineage/execution_handoff.json"),
        }
        validate_candidate_binding_or_raise(documents["candidate_binding"])
        validate_validation_artifact_or_raise(documents["candidate_binding_validation"])
        validate_merge_or_raise(documents["merge"])
        validate_merge_validation_or_raise(documents["merge_validation"])
        validate_bound_source_or_raise(documents["bound_source"])
        validate_source_map_or_raise(documents["source_map"])
        validate_artifact_or_raise(documents["execution_handoff"])
        lineage = _load(REPAIR / "c1_lineage_readiness.json")
        self.assertEqual("COMPLETE_NOT_EXECUTED", lineage["status"])
        self.assertFalse(lineage["c0_replay_accepted"])
        self.assertNotIn("C0_REPLAY", lineage["classification"])
        self.assertFalse(lineage["witness_generated"])
        self.assertFalse(lineage["structured_trace_generated"])
        self.assertFalse(lineage["execution_verdict_generated"])
        self.assertFalse(lineage["violation_evidence_package_generated"])
        c0 = deepcopy(documents); c0["merge"]["classification"] = "C0_REPLAY_FIXTURE_NOT_REAL_CAMPAIGN"
        edges = dict(lineage["lineage_artifacts"])
        with self.assertRaisesRegex(ValueError, "C0 replay fixture"):
            make_c1_prep_lineage(documents=c0, artifacts=edges)

    def test_buildspec_is_materialized_not_executed_and_claim_gate_remains_provenance_blocked(self) -> None:
        build_spec = _load(REPAIR / "build_spec.json")
        validate_artifact_or_raise(build_spec)
        readiness = _load(REPAIR / "build_run_readiness.json")
        self.assertEqual("BUILDSPEC_MATERIALIZED_NOT_EXECUTED", readiness["status"])
        self.assertFalse(readiness["build_attempted"])
        self.assertFalse(readiness["run_attempted"])
        self.assertIsNone(readiness["run_spec"])
        self.assertIn("BUILT BuildRecord", readiness["missing_future_outputs"])
        claim = _load(REPAIR / "claim_gate_decision.json")
        self.assertEqual("C1_PRE_RUN_GATE_STILL_BLOCKED", claim["status"])
        self.assertEqual(["LIBRARY_BUILD_PROVENANCE_MISSING"], claim["blocking_reasons"])
        self.assertEqual("C1_FIX_CONTINUE", claim["allowed_next_stage"])
        self.assertFalse(claim["full_campaign_allowed"])
        self.assertEqual("NOT_GENERATED", claim["current_campaign_result"])
        self.assertEqual("NOT_GENERATED", claim["vulnerability_result"])

    def test_fix2_artifacts_are_digest_addressed_create_only_successors(self) -> None:
        index = _load(REPAIR / "artifact_index.json")
        self.assertEqual("CREATE_ONLY_FIX2_SUCCESSOR_DO_NOT_REWRITE_PARENT", index["repair_lineage"])
        self.assertEqual("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix-v0.1/artifact_index.json", index["parent_artifact_index"]["ref"])
        for item in index["artifacts"]:
            path = ROOT / item["ref"]
            self.assertTrue(path.is_file(), item["ref"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["digest"])
        for path in REPAIR.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(errors="ignore")
            self.assertNotIn("preflight:pending", text)
            self.assertNotIn("TODO_DIGEST", text)


if __name__ == "__main__":
    unittest.main()
