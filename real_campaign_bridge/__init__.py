"""Fail-closed bridge foundations for eventual real CipherLens campaigns."""

from .build_mapping import build_spec_from_profile_mapping, map_build_environment_profile
from .capture_bridge import OracleEventStatus, make_oracle_event, parse_oracle_event
from .c1_gate import evaluate_c1_pre_run_gate
from .c1_fix2 import discover_fixed_source, make_fix2_claim_gate
from .c1_fix3 import make_fix3_claim_gate, make_library_build_provenance_record
from .c1_fix4 import make_c1_pre_run_gate as make_fix4_pre_run_gate
from .c1_retry import evaluate_c1_retry_gate, write_blocked_c1_retry_artifacts
from .c1_fix5 import c1_fix5_audit, write_c1_fix5_blocked_artifacts
from .c1_fix6 import overlay as make_c1_fix6_overlay, resolution as resolve_c1_fix6_values, write_blocked as write_c1_fix6_artifacts
from .c1_repair import check_build_run_materialization, make_repair_claim_gate
from .claim_gate_adapter import evaluate_c0_bridge, evaluate_preflight
from .replay_lineage import make_c0_replay_lineage
from .target_adaptation import adapt_target_source

__all__ = ["OracleEventStatus", "adapt_target_source", "build_spec_from_profile_mapping", "check_build_run_materialization", "c1_fix5_audit", "discover_fixed_source", "evaluate_c0_bridge", "evaluate_c1_pre_run_gate", "evaluate_c1_retry_gate", "evaluate_preflight", "make_c0_replay_lineage", "make_fix2_claim_gate", "make_fix3_claim_gate", "make_fix4_pre_run_gate", "make_library_build_provenance_record", "make_oracle_event", "make_repair_claim_gate", "map_build_environment_profile", "parse_oracle_event", "write_blocked_c1_retry_artifacts", "write_c1_fix5_blocked_artifacts"]
from .c1_fix7 import c1_fix7_documents, write_c1_fix7_artifacts
