from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

import yaml

from evaluation_evidence.canonical import canonical_bytes, canonical_json_bytes, identify, persist_canonical
from evaluation_evidence.inventory import observe_repository_file, recount_legacy_candidate_population
from evaluation_evidence.model import EvidenceOrigin
from evaluation_evidence.registry import INITIAL_METRIC_REGISTRY, validate_document
from pipeline_v2.artifact_store import ArtifactStore
from tests.evaluation_evidence.common import HEAD, ROOT, artifact_record


class CanonicalInventoryTests(unittest.TestCase):
    def test_artifact_record_canonical_stability_and_identity(self) -> None:
        record = artifact_record("fixture:source", b"source")
        shuffled = dict(reversed(list(record.items())))
        self.assertEqual(canonical_bytes(record), canonical_bytes(shuffled))
        self.assertEqual(record["artifact_record_id"], identify(shuffled)["artifact_record_id"])

    def test_validated_document_persists_immutably(self) -> None:
        record = artifact_record("fixture:persisted", b"source")
        with tempfile.TemporaryDirectory() as directory:
            store = ArtifactStore(directory)
            link = persist_canonical(store, "evaluation/artifact-record.json", record)
            self.assertEqual(canonical_bytes(record), store.get(link.ref, link.digest))

    def test_recursive_unknown_field_and_bad_digest_rejected(self) -> None:
        record = artifact_record("fixture:source", b"source")
        unknown = deepcopy(record); unknown["producer"]["surprise"] = True; unknown = identify(unknown)
        self.assertTrue(any("producer.surprise" in item for item in validate_document(unknown)))
        bad = deepcopy(record); bad["artifact_digest"] = "G" * 64; bad = identify(bad)
        self.assertTrue(any("artifact_digest" in item for item in validate_document(bad)))

    def test_secret_and_absolute_path_rejected(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json_bytes({"api_key": "not-a-real-secret"})
        with self.assertRaises(ValueError):
            canonical_json_bytes({"command": ["tool", "--token"]})
        with self.assertRaises(ValueError):
            canonical_json_bytes({"source_location": "/tmp/evidence"})

    def test_current_v2_and_legacy_origins_are_distinct(self) -> None:
        current = artifact_record("fixture:current", b"same")
        legacy = artifact_record("fixture:legacy", b"same", origin=EvidenceOrigin.LEGACY)
        self.assertNotEqual(current["artifact_record_id"], legacy["artifact_record_id"])
        self.assertEqual(("CURRENT_V2", "LEGACY"), (current["origin"], legacy["origin"]))

    def test_missing_file_is_observation_not_artifact_truth(self) -> None:
        record = observe_repository_file(
            ROOT, "does-not-exist.batch7b", artifact_type="expected",
            git_revision=HEAD, origin=EvidenceOrigin.CURRENT_V2,
        )
        self.assertEqual("NOT_FOUND", record["inventory_state"])
        self.assertIsNone(record["artifact_digest"])
        self.assertEqual([], record["validation_maturity"])

    def test_all_schemas_are_closed_and_metric_registry_complete(self) -> None:
        schemas = sorted((ROOT / "evaluation_evidence/schemas").glob("*.yaml"))
        self.assertEqual(10, len(schemas))
        for path in schemas:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertFalse(value["additionalProperties"], path.name)
        self.assertEqual(44, len(INITIAL_METRIC_REGISTRY))

    def test_legacy_42_recount_has_exact_population_and_real_composition(self) -> None:
        actual = recount_legacy_candidate_population(ROOT)
        expected = yaml.safe_load((ROOT / "tests/evaluation_evidence/fixtures/legacy_candidate_queue_recount.expected.yaml").read_text())
        for key in ("schema_version", "population_unit", "duplicate_policy", "actual_count", "declared_count", "source_type_counts", "item_identities"):
            self.assertEqual(expected[key], actual[key])
        self.assertEqual(42, len(set(actual["item_identities"])))
        self.assertTrue(actual["identity_set_equal"] and actual["declared_count_matches"])

    def test_legacy_recount_duplicate_policy_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifacts/candidate_queue").mkdir(parents=True)
            (root / "artifacts/pattern_bank").mkdir(parents=True)
            bank = {"patterns": [{"pattern_id": "P1", "source_type": "feedback_sprint"}, {"pattern_id": "P1", "source_type": "feedback_sprint"}]}
            queue = {"sources": {"pattern_bank": "artifacts/pattern_bank/unified.yaml"}, "summary": {"total_candidates": 2}, "candidates": [{"pattern_id": "P1"}, {"pattern_id": "P1"}]}
            (root / "artifacts/pattern_bank/unified.yaml").write_text(yaml.safe_dump(bank))
            (root / "artifacts/candidate_queue/candidate_queue.yaml").write_text(yaml.safe_dump(queue))
            with self.assertRaisesRegex(ValueError, "duplicate pattern_id"):
                recount_legacy_candidate_population(root)


if __name__ == "__main__":
    unittest.main()
