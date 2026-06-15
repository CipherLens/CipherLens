"""Candidate labels used by family-level analyzers."""

from __future__ import annotations


NORMAL_REJECT = "normal_reject"
NORMAL_ACCEPT = "normal_accept"
NO_CRASH_OBSERVED = "no_crash_observed"
FULL_CONSUMPTION_GAP_CANDIDATE = "full_consumption_gap_candidate"
SEMANTIC_DIVERGENCE_CANDIDATE = "semantic_divergence_candidate"
NEEDS_TRIAGE = "needs_triage"
ORACLE_INCOMPLETE = "oracle_incomplete"


ORACLE_AWARE_LABELS = {
    NORMAL_REJECT,
    NORMAL_ACCEPT,
    FULL_CONSUMPTION_GAP_CANDIDATE,
    SEMANTIC_DIVERGENCE_CANDIDATE,
    NEEDS_TRIAGE,
    ORACLE_INCOMPLETE,
}


RAW_RESULT_LABELS = {
    NO_CRASH_OBSERVED,
    SEMANTIC_DIVERGENCE_CANDIDATE,
    NEEDS_TRIAGE,
}
