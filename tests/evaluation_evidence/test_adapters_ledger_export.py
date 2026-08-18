from __future__ import annotations

from unittest.mock import patch
import unittest

from evaluation_evidence.adapters.external import import_external_snapshot
from evaluation_evidence.adapters.legacy import import_legacy_artifact
from evaluation_evidence.adapters.pipeline_v2 import observe_pipeline_artifact
from evaluation_evidence.claim_gate import build_claim_record, evaluate_claim
from evaluation_evidence.export import structured_evidence_export
from evaluation_evidence.ledger import build_evidence_ledger
from evaluation_evidence.model import ClaimTaxonomy, EvidenceOrigin, ValidationMaturity
from evaluation_evidence.registry import metric_registry_snapshot
from tests.evaluation_evidence.common import HEAD, ROOT, artifact_record, resolver_for, scope


class AdapterLedgerExportTests(unittest.TestCase):
    def test_legacy_import_is_read_only_and_preserves_untrusted_label(self) -> None:
        record = import_legacy_artifact(
            ROOT, "artifacts/candidate_queue/candidate_queue.yaml",
            artifact_type="legacy_candidate_queue", legacy_semantic_label="bug_candidate",
            git_revision=HEAD,
        )
        self.assertEqual("LEGACY", record["origin"])
        self.assertEqual("legacy-unmodified", record["artifact_schema_version"])
        self.assertTrue(any("legacy_semantic_label=bug_candidate" == item for item in record["notes"]))
        self.assertNotIn("verdict", record)
        self.assertNotIn("finding_status", record)
        with self.assertRaises(ValueError):
            import_legacy_artifact(ROOT, "artifacts/candidate_queue/candidate_queue.yaml",
                                   artifact_type="legacy", legacy_semantic_label="VIOLATED", git_revision=HEAD)

    def test_external_adapter_requires_local_snapshot_for_digest_maturity(self) -> None:
        reference = import_external_snapshot(
            ROOT, url="https://example.invalid/upstream/1", snapshot_location=None,
            publisher_identity="fixture-upstream", evidence_type="upstream_response",
            authority_classification="PROJECT_MAINTAINER", git_revision=HEAD,
            retrieved_at_telemetry="telemetry-only",
        )
        self.assertEqual("PRESENT_UNVERIFIED", reference.record["inventory_state"])
        self.assertIsNone(reference.record["artifact_digest"])
        self.assertNotIn("retrieved_at", repr(reference.record))
        self.assertEqual("telemetry-only", reference.telemetry["retrieved_at"])
        snapshot = import_external_snapshot(
            ROOT, url="https://example.invalid/upstream/1",
            snapshot_location="tests/evaluation_evidence/fixtures/legacy_candidate_queue_recount.expected.yaml",
            publisher_identity="fixture-upstream", evidence_type="upstream_response",
            authority_classification="PROJECT_MAINTAINER", git_revision=HEAD,
        )
        self.assertEqual("VERIFIED_PRESENT", snapshot.record["inventory_state"])
        self.assertIn("DIGEST_VERIFIED", snapshot.record["validation_maturity"])

    def test_pipeline_adapter_does_not_mutate_frozen_artifact(self) -> None:
        digest = "a" * 64
        record = observe_pipeline_artifact(
            artifact_ref="pipeline:verdict", artifact_digest=digest,
            artifact_type="execution_verdict", artifact_schema_version="cipherlens.execution_verdict.v0.1",
            git_revision=HEAD, resolver=lambda ref, actual: ref == "pipeline:verdict" and actual == digest,
            synthetic=True,
        )
        self.assertEqual(("CURRENT_V2", "SYNTHETIC"), (record["origin"], record["synthetic_or_real"]))
        self.assertNotIn("verdict", record)

    def test_ledger_is_provenance_index_and_structured_export_is_gate_driven(self) -> None:
        source = artifact_record("source:evaluation", b"source")
        link = {"ref": source["artifact_ref"], "digest": source["artifact_digest"]}
        claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.IMPLEMENTATION_CLAIM,
            statement="Evaluation ledger foundation exists", scope=scope(current_v2=True),
            evidence_refs=[link], requested_report_sections=["3"], requested_ppt_usage=["Engineering Validation"],
            git_revision=HEAD,
        )
        ledger = build_evidence_ledger(git_revision=HEAD, artifact_records=[source], claim_records=[claim])
        report = evaluate_claim(claim, artifact_records=[source], resolver=resolver_for([link]))
        view = structured_evidence_export(ledger, [report])
        self.assertEqual(1, len(view["report_evidence_view"]))
        self.assertEqual(1, len(view["ppt_evidence_view"]))
        self.assertNotIn("execution_verdict", ledger)
        self.assertNotIn("vulnerability_confirmed", ledger)

    def test_metric_registry_contains_definitions_without_values(self) -> None:
        snapshot = metric_registry_snapshot()
        self.assertEqual("cipherlens.metric_registry.v0.1", snapshot["registry_version"])
        self.assertEqual(44, len(snapshot["definitions"]))
        self.assertTrue(all("derived_value" not in item for item in snapshot["definitions"]))

    def test_default_foundation_path_has_no_network_provider_or_campaign_calls(self) -> None:
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")), \
             patch("subprocess.run", side_effect=AssertionError("provider/campaign forbidden")):
            snapshot = metric_registry_snapshot()
            record = import_legacy_artifact(
                ROOT, "artifacts/candidate_queue/candidate_queue.yaml",
                artifact_type="legacy_candidate_queue", legacy_semantic_label="candidate_queue",
                git_revision=HEAD,
            )
        self.assertEqual(44, len(snapshot["definitions"]))
        self.assertEqual(EvidenceOrigin.LEGACY.value, record["origin"])


if __name__ == "__main__":
    unittest.main()
