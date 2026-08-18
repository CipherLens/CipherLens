"""Contract-guided Matcher v0.1 foundation."""

from matcher.model import *
from matcher.query import RecallQuery, build_recall_query
from matcher.knowledge import EvidenceItem, KnowledgeSeed, SyntheticKnowledgeBackend, TargetKnowledgeBase
from matcher.recall import RecallResult, assemble_candidate_surfaces, wide_recall
from matcher.proposal import ProposalAttempt, ProposalOrchestrator
from matcher.resolve import DeterministicResolver, ProfileRound, VerifierRegistry
from matcher.observability import evaluate_concrete_observability
from matcher.rank import RankingInput, rank_attempts
from matcher.trace import MatcherTrace, MatcherTraceBuilder, matcher_trace_digest
from matcher.orchestrate import MatcherRequest, MatcherResult, run_matcher

__all__ = [name for name in globals() if not name.startswith("_")]
