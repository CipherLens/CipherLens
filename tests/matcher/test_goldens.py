from __future__ import annotations

import unittest

from matcher.model import MatcherRunOutcome
from matcher.orchestrate import run_matcher
from tests.matcher.common import CASES, case_request


class ThreeFamilyMatcherGoldenTests(unittest.TestCase):
    def test_three_families_reach_valid_candidate_binding(self) -> None:
        for name in CASES:
            with self.subTest(name=name):
                request, replay, backend = case_request(name)
                result = run_matcher(request)
                self.assertEqual(MatcherRunOutcome.MATCH_FOUND, result.outcome)
                self.assertIsNotNone(result.candidate_binding)
                self.assertEqual("VALID", result.candidate_binding_validation["status"])
                self.assertEqual(2, replay.invocation_count)
                self.assertEqual(0, backend.network_call_count)
                self.assertEqual("MATCH_FOUND", result.trace.semantic_core["run_outcome"])

    def test_replay_trace_is_semantically_stable(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020")
        first = run_matcher(request)
        second = run_matcher(request)
        self.assertEqual(first.trace.digest(), second.trace.digest())
        self.assertEqual(
            first.candidate_binding["binding_id"], second.candidate_binding["binding_id"]
        )

    def test_trace_keeps_all_stage_lineage(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0005")
        core = run_matcher(request).trace.semantic_core
        for field in (
            "retrieval_records", "assembly_records", "provider_attempts",
            "proposal_records", "fact_resolution_records", "profile_records",
            "eligibility_records", "observability_records", "ranking_records",
            "binding_attempts", "validation_records",
        ):
            self.assertTrue(core[field], field)
        self.assertIsNotNone(core["selected_binding_ref"])
        self.assertIsNotNone(core["selected_validation_ref"])


if __name__ == "__main__":
    unittest.main()
