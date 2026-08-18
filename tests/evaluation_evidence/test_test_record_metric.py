from __future__ import annotations

from copy import deepcopy
import tempfile
import unittest

from evaluation_evidence.canonical import canonical_bytes, identify
from evaluation_evidence.metric import (
    MetricEvaluationError, build_population_manifest, evaluate_metric,
    is_formal_current_v2_metric, population_manifest_link,
)
from evaluation_evidence.model import EvidenceOrigin, RecomputeStatus, ValidationMaturity
from evaluation_evidence.registry import INITIAL_METRIC_REGISTRY, validate_document
from evaluation_evidence.test_record import record_test_run
from pipeline_v2.artifact_store import ArtifactStore
from tests.evaluation_evidence.common import HEAD, artifact_record, raw_link, resolver_for


class TestRunAndMetricTests(unittest.TestCase):
    def test_test_defined_is_not_test_run_recorded(self) -> None:
        definition = artifact_record(
            "test-definition:one", b"def test_one", artifact_type="test_definition",
            origin=EvidenceOrigin.SYNTHETIC, synthetic=True,
            maturity=(ValidationMaturity.TEST_DEFINED,),
        )
        self.assertIn("TEST_DEFINED", definition["validation_maturity"])
        self.assertNotIn("TEST_RUN_RECORDED", definition["validation_maturity"])
        self.assertNotEqual("cipherlens.test_run_record.v0.1", definition["schema_version"])

    def test_fake_test_run_is_persisted_before_record_formation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ArtifactStore(directory)
            test_ref = raw_link("test-definition:one", b"def test_one")
            record = record_test_run(
                store, ref_prefix="test-runs/fake-one", git_revision=HEAD,
                command=["python3", "-m", "unittest", "fake"], test_scope="synthetic-recorder-test",
                test_definition_refs=[test_ref],
                counts={"passed": 1, "failed": 0, "skipped": 0, "xfailed": 0, "errors": 0},
                stdout=b"OK\n", stderr=b"", working_profile={"profile": "repository-root"},
                environment_profile={"python": "fixture", "network": "disabled"},
            )
            self.assertEqual((1, 0, 0), (record["passed"], record["failed"], record["errors"]))
            for key in ("stdout_artifact", "stderr_artifact", "summary_artifact", "environment_profile", "working_profile"):
                self.assertTrue(store.verify(record[key]["ref"], record[key]["digest"]))

    def _population(self):
        items = [
            {**raw_link("schema:one", b"one"), "artifact_type": "schema_document", "origin": "CURRENT_V2", "attributes": {"status": "PRESENT"}},
            {**raw_link("schema:two", b"two"), "artifact_type": "schema_document", "origin": "CURRENT_V2", "attributes": {"status": "PRESENT"}},
        ]
        manifest = build_population_manifest(INITIAL_METRIC_REGISTRY["schema_count"], items,
                                             origin=EvidenceOrigin.CURRENT_V2, complete=True)
        resolver = resolver_for([population_manifest_link(manifest)] + [{"ref": item["ref"], "digest": item["digest"]} for item in items])
        return manifest, items, resolver

    def test_metric_definition_is_not_metric_record_and_is_canonical(self) -> None:
        definition = INITIAL_METRIC_REGISTRY["schema_count"]
        self.assertEqual("cipherlens.metric_definition.v0.1", definition["schema_version"])
        self.assertNotIn("derived_value", definition)
        self.assertEqual(canonical_bytes(definition), canonical_bytes(dict(reversed(list(definition.items())))))

    def test_count_metric_is_recomputed_from_digest_verified_population(self) -> None:
        manifest, items, resolver = self._population()
        record = evaluate_metric(INITIAL_METRIC_REGISTRY["schema_count"], manifest, resolver=resolver, git_revision=HEAD)
        self.assertEqual((2, 0, {"kind": "COUNT", "numerator": 2, "denominator": 0}),
                         (record["numerator_value"], record["denominator_value"], record["derived_value"]))
        self.assertTrue(is_formal_current_v2_metric(record))

    def test_ratio_preserves_exact_numerator_and_denominator(self) -> None:
        definition = INITIAL_METRIC_REGISTRY["required_slot_coverage"]
        one = raw_link("slot:one", b"one"); two = raw_link("slot:two", b"two")
        items = [
            {**one, "artifact_type": "merge_validation", "origin": "CURRENT_V2", "attributes": {"status": "FILLED"}},
            {**two, "artifact_type": "merge_validation", "origin": "CURRENT_V2", "attributes": {"status": "MISSING"}},
        ]
        manifest = build_population_manifest(definition, items, origin=EvidenceOrigin.CURRENT_V2, complete=True)
        record = evaluate_metric(definition, manifest,
                                 resolver=resolver_for([population_manifest_link(manifest), one, two]), git_revision=HEAD)
        self.assertEqual({"kind": "RATIO", "numerator": 1, "denominator": 2}, record["derived_value"])

    def test_bad_digest_and_missing_denominator_produce_no_metric(self) -> None:
        manifest, items, _ = self._population()
        with self.assertRaisesRegex(MetricEvaluationError, "digest"):
            evaluate_metric(INITIAL_METRIC_REGISTRY["schema_count"], manifest, resolver=lambda _r, _d: False, git_revision=HEAD)
        empty = build_population_manifest(INITIAL_METRIC_REGISTRY["required_slot_coverage"], [],
                                          origin=EvidenceOrigin.CURRENT_V2, complete=True)
        with self.assertRaisesRegex(MetricEvaluationError, "denominator"):
            evaluate_metric(INITIAL_METRIC_REGISTRY["required_slot_coverage"], empty,
                            resolver=resolver_for([population_manifest_link(empty)]), git_revision=HEAD)

    def test_numerator_must_be_subset_of_denominator(self) -> None:
        definition = deepcopy(INITIAL_METRIC_REGISTRY["required_slot_coverage"])
        definition["denominator_rule"] = {"kind": "FILTER", "predicates": [{"field": "attributes.status", "comparator": "EQ", "value": "MISSING"}]}
        definition = identify(definition)
        one = raw_link("slot:one", b"one"); two = raw_link("slot:two", b"two")
        items = [
            {**one, "artifact_type": "merge_validation", "origin": "CURRENT_V2", "attributes": {"status": "FILLED"}},
            {**two, "artifact_type": "merge_validation", "origin": "CURRENT_V2", "attributes": {"status": "MISSING"}},
        ]
        manifest = build_population_manifest(definition, items, origin=EvidenceOrigin.CURRENT_V2, complete=True)
        with self.assertRaisesRegex(MetricEvaluationError, "subset"):
            evaluate_metric(definition, manifest,
                            resolver=resolver_for([population_manifest_link(manifest), one, two]), git_revision=HEAD)

    def test_manual_percentage_cannot_override_exact_authority(self) -> None:
        manifest, items, resolver = self._population()
        record = evaluate_metric(INITIAL_METRIC_REGISTRY["schema_count"], manifest, resolver=resolver, git_revision=HEAD)
        forged = deepcopy(record); forged["derived_value"]["numerator"] = 98; forged = identify(forged)
        self.assertTrue(any("derived_value" in item for item in validate_document(forged)))
        with self.assertRaises(TypeError):
            evaluate_metric(INITIAL_METRIC_REGISTRY["schema_count"], manifest,
                            resolver=resolver, git_revision=HEAD, derived_value="98.81%")  # type: ignore[call-arg]

    def test_incomplete_population_is_not_formal_current_v2_metric(self) -> None:
        manifest, items, resolver = self._population()
        manifest = build_population_manifest(INITIAL_METRIC_REGISTRY["schema_count"], items,
                                             origin=EvidenceOrigin.CURRENT_V2, complete=False)
        resolver = resolver_for([population_manifest_link(manifest)] + [{"ref": item["ref"], "digest": item["digest"]} for item in items])
        record = evaluate_metric(INITIAL_METRIC_REGISTRY["schema_count"], manifest, resolver=resolver, git_revision=HEAD)
        self.assertEqual(RecomputeStatus.PARTIALLY_RECOMPUTABLE.value, record["recompute_status"])
        self.assertFalse(is_formal_current_v2_metric(record))

    def test_legacy_origin_cannot_enter_current_only_definition(self) -> None:
        item = raw_link("legacy:one", b"one")
        population = [{**item, "artifact_type": "schema_document", "origin": "LEGACY", "attributes": {}}]
        manifest = build_population_manifest(INITIAL_METRIC_REGISTRY["schema_count"], population,
                                             origin=EvidenceOrigin.LEGACY, complete=True)
        with self.assertRaisesRegex(MetricEvaluationError, "does not allow"):
            evaluate_metric(INITIAL_METRIC_REGISTRY["schema_count"], manifest,
                            resolver=resolver_for([population_manifest_link(manifest), item]), git_revision=HEAD)


if __name__ == "__main__":
    unittest.main()
