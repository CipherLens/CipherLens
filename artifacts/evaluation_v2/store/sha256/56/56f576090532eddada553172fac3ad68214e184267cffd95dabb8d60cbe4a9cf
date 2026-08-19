from __future__ import annotations

from copy import deepcopy
import unittest

from evaluation_evidence.claim_gate import build_claim_record, evaluate_claim, metric_link
from evaluation_evidence.findings import (
    FindingGateError, build_finding, build_security_finding_ledger, finding_link,
)
from evaluation_evidence.metric import build_population_manifest, evaluate_metric, population_manifest_link
from evaluation_evidence.model import ClaimGateResult, ClaimTaxonomy, EvidenceOrigin, FindingStatus, ValidationMaturity
from evaluation_evidence.registry import INITIAL_METRIC_REGISTRY
from execution_model.canonical import artifact_digest
from impact_bridge.violation_package import build_violation_evidence_package
from tests.evaluation_evidence.common import HEAD, artifact_record, raw_link, resolver_for, scope
from tests.execution_support import chain


def _violation_package(data):
    return build_violation_evidence_package(
        contract=data["contract"], candidate_binding=data["binding"], merge=data["merge"],
        merge_validation=data["validation"], bound_source=data["bound_source"], source_map=data["source_map"],
        build_spec=data["build_spec"], build_record=data["build_record"], run_spec=data["run_spec"],
        run_record=data["run_record"], witness=data["witness"], trace=data["trace"],
        evaluations=data["evaluations"], verdict=data["verdict"],
        supporting_raw_artifacts=[{
            "artifact_ref": data["run_record"]["raw_artifacts"][0]["artifact_ref"],
            "artifact_digest": data["run_record"]["raw_artifacts"][0]["artifact_digest"],
        }],
        reproduction_metadata_refs=["reproduction:synthetic-fixture"],
    )


class FindingAndClaimGateTests(unittest.TestCase):
    def test_v2_violated_witness_requires_real_canonical_verdict_and_package(self) -> None:
        invalid = build_finding(
            finding_status=FindingStatus.V2_VIOLATED_WITNESS,
            target_scope={"library": "fixture", "version": "1", "build_profile": "local"},
            affected_component="parser", family="der", origin=EvidenceOrigin.CURRENT_V2,
            public_disclosure_state="LOCAL_ONLY", allowed_claim_boundary="witness-level only",
        )
        with self.assertRaises(FindingGateError):
            build_security_finding_ledger(findings=[invalid], git_revision=HEAD,
                                          artifact_records=[], resolver=lambda _r, _d: False)

        data = chain(values={"CONSUMED_LENGTH": 7})
        package = _violation_package(data)
        verdict_link = {"ref": data["verdict"]["verdict_id"], "digest": artifact_digest(data["verdict"])}
        package_link = {"ref": package["package_id"], "digest": artifact_digest(package)}
        maturity = (ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.REAL_EXECUTION_REPRODUCED)
        records = [
            artifact_record(verdict_link["ref"], b"ignored", artifact_type="execution_verdict", maturity=maturity),
            artifact_record(package_link["ref"], b"ignored", artifact_type="violation_package", maturity=maturity),
        ]
        records[0] = _with_digest(records[0], verdict_link["digest"])
        records[1] = _with_digest(records[1], package_link["digest"])
        finding = build_finding(
            finding_status=FindingStatus.V2_VIOLATED_WITNESS,
            target_scope={"library": "fixture", "version": "1", "build_profile": "local"},
            affected_component="parser", family="der", execution_verdict=verdict_link,
            violation_package=package_link, origin=EvidenceOrigin.CURRENT_V2,
            public_disclosure_state="LOCAL_ONLY", allowed_claim_boundary="witness-level relation violation",
        )
        before = artifact_digest(data["verdict"])
        documents = {(verdict_link["ref"], verdict_link["digest"]): data["verdict"], (package_link["ref"], package_link["digest"]): package}
        ledger = build_security_finding_ledger(
            findings=[finding], git_revision=HEAD, artifact_records=records,
            resolver=resolver_for([verdict_link, package_link]),
            document_resolver=lambda ref, digest: documents.get((ref, digest)),
        )
        self.assertEqual(FindingStatus.V2_VIOLATED_WITNESS.value, ledger["findings"][0]["finding_status"])
        self.assertEqual(before, artifact_digest(data["verdict"]))

    def test_finding_upgrade_gates_are_evidence_specific(self) -> None:
        target = {"library": "fixture", "version": "1", "build_profile": "local"}
        cases = [
            (FindingStatus.REPRODUCED_RELATION_BEHAVIOR, {}, "reproduction"),
            (FindingStatus.IMPACT_ANALYZED, {}, "impact"),
            (FindingStatus.REPORTED_UPSTREAM, {}, "submission"),
            (FindingStatus.UPSTREAM_ACKNOWLEDGED, {}, "external response"),
            (FindingStatus.FIX_CONFIRMED, {}, "fix revision"),
            (FindingStatus.CVE_OR_ADVISORY_CONFIRMED, {}, "advisory"),
        ]
        for status, refs, expected in cases:
            with self.subTest(status=status.value):
                finding = build_finding(
                    finding_status=status, target_scope=target, affected_component="component",
                    family="family", origin=EvidenceOrigin.CURRENT_NON_V2,
                    public_disclosure_state="LOCAL_ONLY", allowed_claim_boundary="bounded",
                    **refs,
                )
                with self.assertRaisesRegex(FindingGateError, expected):
                    build_security_finding_ledger(findings=[finding], git_revision=HEAD,
                                                  artifact_records=[], resolver=lambda _r, _d: False)

    def test_claim_gate_all_frozen_results(self) -> None:
        source = artifact_record("source:implementation", b"source")
        source_link = {"ref": source["artifact_ref"], "digest": source["artifact_digest"]}
        allow_claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.IMPLEMENTATION_CLAIM,
            statement="The evaluation package is implemented", scope=scope(current_v2=True),
            evidence_refs=[source_link], requested_report_sections=["3"],
            git_revision=HEAD,
        )
        report = evaluate_claim(allow_claim, artifact_records=[source], resolver=resolver_for([source_link]))
        self.assertEqual(ClaimGateResult.ALLOW.value, report["gate_result"])

        synthetic = artifact_record("synthetic:e2e", b"synthetic", artifact_type="synthetic_e2e_record",
                                    origin=EvidenceOrigin.SYNTHETIC, synthetic=True)
        synthetic_link = {"ref": synthetic["artifact_ref"], "digest": synthetic["artifact_digest"]}
        caveat_claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.PIPELINE_VALIDATION_CLAIM,
            statement="Synthetic E2E completed", scope=scope(), evidence_refs=[synthetic_link],
            git_revision=HEAD,
        )
        self.assertEqual("ALLOW_WITH_CAVEAT", evaluate_claim(caveat_claim, artifact_records=[synthetic], resolver=resolver_for([synthetic_link]))["gate_result"])

        blocked = build_claim_record(claim_taxonomy=ClaimTaxonomy.ENGINEERING_VALIDATION_CLAIM,
                                     statement="A number without evidence", scope=scope(), git_revision=HEAD)
        self.assertEqual("BLOCK", evaluate_claim(blocked, artifact_records=[], resolver=lambda _r, _d: False)["gate_result"])

        not_run = artifact_record("attempt:manifest", b"not-run", artifact_type="campaign_attempt")
        not_run_link = {"ref": not_run["artifact_ref"], "digest": not_run["artifact_digest"]}
        campaign = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.CURRENT_CAMPAIGN_RESULT_CLAIM,
            statement="Current campaign result", scope=scope(current_v2=True, real_campaign=True),
            evidence_refs=[not_run_link],
            git_revision=HEAD,
        )
        self.assertEqual("NEEDS_RERUN", evaluate_claim(campaign, artifact_records=[not_run], resolver=resolver_for([not_run_link]))["gate_result"])

        item = raw_link("schema:one", b"one")
        manifest = build_population_manifest(
            INITIAL_METRIC_REGISTRY["schema_count"],
            [{**item, "artifact_type": "schema_document", "origin": "CURRENT_V2", "attributes": {}}],
            origin=EvidenceOrigin.CURRENT_V2, complete=False,
        )
        metric = evaluate_metric(INITIAL_METRIC_REGISTRY["schema_count"], manifest,
                                 resolver=resolver_for([population_manifest_link(manifest), item]), git_revision=HEAD)
        mlink = metric_link(metric)
        metric_claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.ENGINEERING_VALIDATION_CLAIM,
            statement="Incomplete metric", scope=scope(current_v2=True), metric_refs=[mlink],
            git_revision=HEAD,
        )
        self.assertEqual("NEEDS_RECOMPUTATION", evaluate_claim(metric_claim, artifact_records=[], metric_records=[metric], resolver=resolver_for([mlink]))["gate_result"])

        hypothesis = build_finding(
            finding_status=FindingStatus.HYPOTHESIS,
            target_scope={"library": "fixture", "version": "1", "build_profile": "local"},
            affected_component="component", family="family", origin=EvidenceOrigin.CURRENT_NON_V2,
            public_disclosure_state="LOCAL_ONLY", allowed_claim_boundary="hypothesis",
        )
        flink = finding_link(hypothesis)
        upstream_claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.UPSTREAM_CONFIRMED_CLAIM,
            statement="Upstream acknowledged", scope=scope(upstream_acknowledged=True),
            evidence_refs=[source_link], finding_refs=[flink],
            git_revision=HEAD,
        )
        self.assertEqual("NEEDS_EXTERNAL_CONFIRMATION", evaluate_claim(
            upstream_claim, artifact_records=[source], findings=[hypothesis],
            resolver=resolver_for([source_link, flink]))["gate_result"])

        legacy = artifact_record("legacy:baseline", b"legacy", origin=EvidenceOrigin.LEGACY)
        legacy_link = {"ref": legacy["artifact_ref"], "digest": legacy["artifact_digest"]}
        legacy_claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.LEGACY_BASELINE_CLAIM,
            statement="Historical baseline", scope=scope(), evidence_refs=[legacy_link],
            git_revision=HEAD,
        )
        self.assertEqual("LEGACY_ONLY", evaluate_claim(legacy_claim, artifact_records=[legacy], resolver=resolver_for([legacy_link]))["gate_result"])

    def test_violated_is_not_confirmed_vulnerability_and_satisfied_is_not_global_safe(self) -> None:
        finding = build_finding(
            finding_status=FindingStatus.V2_VIOLATED_WITNESS,
            target_scope={"library": "fixture", "version": "1", "build_profile": "local"},
            affected_component="component", family="family", origin=EvidenceOrigin.CURRENT_V2,
            public_disclosure_state="LOCAL_ONLY", allowed_claim_boundary="witness only",
        )
        flink = finding_link(finding)
        evidence = artifact_record("verdict:violated", b"violated", artifact_type="execution_verdict")
        elink = {"ref": evidence["artifact_ref"], "digest": evidence["artifact_digest"]}
        claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.SECURITY_FINDING_CLAIM,
            statement="Confirmed vulnerability", scope=scope(current_v2=True, confirmed_vulnerability=True),
            evidence_refs=[elink], finding_refs=[flink],
            git_revision=HEAD,
        )
        self.assertEqual("BLOCK", evaluate_claim(claim, artifact_records=[evidence], findings=[finding], resolver=resolver_for([elink, flink]))["gate_result"])
        safe = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.SECURITY_FINDING_CLAIM,
            statement="Library is globally safe", scope=scope(current_v2=True, global_security=True),
            evidence_refs=[elink],
            git_revision=HEAD,
        )
        self.assertEqual("BLOCK", evaluate_claim(safe, artifact_records=[evidence], resolver=resolver_for([elink]))["gate_result"])

    def test_recomputable_legacy_metric_cannot_masquerade_as_current_v2(self) -> None:
        definition = deepcopy(INITIAL_METRIC_REGISTRY["schema_count"])
        definition["allowed_origins"] = ["CURRENT_V2", "LEGACY"]
        from evaluation_evidence.canonical import identify
        definition = identify(definition)
        item = raw_link("legacy:schema", b"legacy")
        manifest = build_population_manifest(
            definition,
            [{**item, "artifact_type": "schema_document", "origin": "LEGACY", "attributes": {}}],
            origin=EvidenceOrigin.LEGACY, complete=True,
        )
        metric = evaluate_metric(definition, manifest,
                                 resolver=resolver_for([population_manifest_link(manifest), item]),
                                 git_revision=HEAD)
        link = metric_link(metric)
        claim = build_claim_record(
            claim_taxonomy=ClaimTaxonomy.ENGINEERING_VALIDATION_CLAIM,
            statement="Legacy count as current", scope=scope(current_v2=True),
            metric_refs=[link], git_revision=HEAD,
        )
        report = evaluate_claim(claim, artifact_records=[], metric_records=[metric], resolver=resolver_for([link]))
        self.assertEqual("BLOCK", report["gate_result"])
        self.assertIn("LEGACY_OR_NON_V2_MASQUERADES_AS_CURRENT_V2", report["reason_codes"])


def _with_digest(record, digest):
    changed = deepcopy(record)
    changed["artifact_digest"] = digest
    return identify_artifact(changed)


def identify_artifact(record):
    from evaluation_evidence.canonical import identify
    from evaluation_evidence.registry import validate_document_or_raise
    result = identify(record); validate_document_or_raise(result); return result


if __name__ == "__main__":
    unittest.main()
