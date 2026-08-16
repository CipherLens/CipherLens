from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from analysis.candidate_context_pack import (
    SCHEMA,
    build_context_pack,
    write_context_pack,
)


ROOT = Path(__file__).resolve().parents[1]


class CandidateContextPackTest(unittest.TestCase):
    def test_x509_candidate_preserves_oracle_and_provenance(self):
        triage = ROOT / "artifacts/sprints/x509_candidate_triage_v1/triage/x509_candidate_triage.yaml"
        candidate_id = "x509_parsing__generic_mut_001__der_valid_plus_trailing_garbage"

        pack = build_context_pack(
            triage,
            candidate_id=candidate_id,
            logical_candidate_id="openssl-x509-full-consumption-gap",
        )

        self.assertEqual(pack["schema"], SCHEMA)
        self.assertEqual(pack["candidate_id"], candidate_id)
        self.assertEqual(pack["family"], "unknown")
        self.assertEqual(
            pack["current_classification"],
            "app_level_validation_gap_candidate",
        )
        self.assertTrue(pack["oracle_evidence"]["full_consumption_gap"])
        self.assertEqual(pack["impactlift_eligibility"]["status"], "eligible")
        self.assertEqual(pack["provenance"]["source"]["path"], str(triage))
        self.assertIn(str(triage), pack["source_artifacts"])

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "candidate_context_pack.yaml"
            write_context_pack(output, pack)
            loaded = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual(loaded["candidate_id"], candidate_id)
            self.assertEqual(loaded["oracle_evidence"], pack["oracle_evidence"])

    def test_public_key_caller_audit_fields_are_expressed(self):
        audit = ROOT / "artifacts/caller_audit/libdkimpp-public-key-v1/v0.1/caller_triage.yaml"
        pack = build_context_pack(
            audit,
            candidate_id="libdkimpp-public-key",
            logical_candidate_id="openssl-d2i-pubkey-full-consumption-gap",
        )

        self.assertEqual(pack["library"], "openssl")
        self.assertEqual(pack["version"], "OpenSSL 3.5.5")
        self.assertEqual(pack["api_or_function"], "d2i_PUBKEY")
        self.assertEqual(
            pack["current_classification"],
            "production_reachable_candidate",
        )
        self.assertEqual(pack["impactlift_eligibility"]["status"], "eligible")
        self.assertEqual(pack["claim_policy"]["security_impact"], "not_assessed")


    def test_explicit_closure_overrides_caller_candidate_status(self):
        audit = ROOT / "artifacts/caller_audit/libdkimpp-public-key-v1/v0.1/caller_triage.yaml"
        with tempfile.TemporaryDirectory() as tmp:
            closure = Path(tmp) / "closure.yaml"
            closure.write_text(
                "schema: candidate_closure_v1\nstatus: closed_negative_feedback\n",
                encoding="utf-8",
            )
            pack = build_context_pack(
                audit,
                candidate_id="libdkimpp-public-key",
                closure_artifacts=[closure],
            )
        self.assertEqual(pack["current_classification"], "closed_negative_feedback")
        self.assertEqual(pack["impactlift_eligibility"]["status"], "ineligible")
        self.assertEqual(pack["provenance"]["sources"][-1]["role"], "closure")


if __name__ == "__main__":
    unittest.main()
