"""Fail-closed bridge foundations for eventual real CipherLens campaigns."""

from .build_mapping import build_spec_from_profile_mapping, map_build_environment_profile
from .capture_bridge import OracleEventStatus, make_oracle_event, parse_oracle_event
from .claim_gate_adapter import evaluate_c0_bridge, evaluate_preflight
from .replay_lineage import make_c0_replay_lineage
from .target_adaptation import adapt_target_source

__all__ = ["OracleEventStatus", "adapt_target_source", "build_spec_from_profile_mapping", "evaluate_c0_bridge", "evaluate_preflight", "make_c0_replay_lineage", "make_oracle_event", "map_build_environment_profile", "parse_oracle_event"]
