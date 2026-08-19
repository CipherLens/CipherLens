"""Fail-closed bridge foundations for eventual real CipherLens campaigns."""

from .capture_bridge import OracleEventStatus, make_oracle_event, parse_oracle_event
from .claim_gate_adapter import evaluate_preflight
from .target_adaptation import adapt_target_source

__all__ = ["OracleEventStatus", "adapt_target_source", "evaluate_preflight", "make_oracle_event", "parse_oracle_event"]
