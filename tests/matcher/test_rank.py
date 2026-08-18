from __future__ import annotations

import unittest

from matcher.model import MatcherCandidate, ObservabilityRecord, ObservabilityStatus, TargetScope
from matcher.rank import RankingInput, rank_attempts


def candidate(surface_ref: str) -> MatcherCandidate:
    scope = TargetScope("synthetic-target", "1.0", surface_ref)
    return MatcherCandidate.create(
        target_scope=scope,
        subject_refs=[surface_ref + ":subject"],
        symbol_refs=[surface_ref + ":symbol"],
        surface_composition={"kind": "API_GROUP"},
    )


def observability(item: MatcherCandidate, status: ObservabilityStatus) -> ObservabilityRecord:
    return ObservabilityRecord(
        record_id="observability:test:" + item.candidate_id[-8:],
        candidate_ref=item.candidate_id,
        proposal_ref="proposal:" + "a" * 64,
        profile_ref="target-profile:TEST",
        eligibility_ref="eligibility-evaluation:TEST:TEST",
        status=status,
        observable_assignments=(),
        verified_fact_refs=(),
        evidence_refs=(),
        missing_requirements=(),
        reason_codes=("TEST",),
    )


def ranking_input(item: MatcherCandidate, eligibility: str = "ELIGIBLE", status: ObservabilityStatus = ObservabilityStatus.RESOLVABLE) -> RankingInput:
    return RankingInput(
        candidate=item,
        proposal_ref="proposal:" + "a" * 64,
        profile={"facts": [], "evidence": []},
        eligibility_evaluation={"eligibility": eligibility, "constraint_results": []},
        observability=observability(item, status),
        template_manifest={"slots": []},
    )


class RankingBoundaryTests(unittest.TestCase):
    def test_tie_break_is_canonical_candidate_id(self) -> None:
        left = candidate("surface:left")
        right = candidate("surface:right")
        result = rank_attempts([ranking_input(right), ranking_input(left)])
        self.assertEqual(
            sorted([left.candidate_id, right.candidate_id]),
            [item.candidate_ref for item in result],
        )

    def test_ineligible_cannot_enter_ranking(self) -> None:
        with self.assertRaisesRegex(ValueError, "RANKING_REQUIRES_ELIGIBLE"):
            rank_attempts([ranking_input(candidate("surface:no"), "INELIGIBLE")])

    def test_unresolvable_cannot_enter_ranking(self) -> None:
        with self.assertRaisesRegex(ValueError, "RANKING_REQUIRES_RESOLVABLE"):
            rank_attempts([
                ranking_input(
                    candidate("surface:no-observation"),
                    status=ObservabilityStatus.UNRESOLVABLE,
                )
            ])


if __name__ == "__main__":
    unittest.main()
