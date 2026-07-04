"""Fault-surface enhancement layer for the seed-driven pipeline.

This package is intentionally embedded under ``analysis/``. It does not own a
standalone runner or campaign loop; callers pass the existing seed/template/
runtime context and receive additional feature-layer artifacts.
"""

from analysis.fault_surface.fault_surface_engine import (
    FaultSurfaceEngine,
    emit_failure_trigger_signals,
    run,
    run_cross_library_mode,
    run_cve_consolidation,
    run_cve_final_validation,
    run_cve_validation,
    run_failure_realization_mode,
    run_graph_enhancement_mode,
    run_graph_execution_integration_mode,
    run_graph_fusion_mode,
    run_high_recall_mode,
    run_runtime_security_validation,
    run_security_validation,
    run_unified_validation,
)

__all__ = [
    "FaultSurfaceEngine",
    "run",
    "run_cross_library_mode",
    "emit_failure_trigger_signals",
    "run_failure_realization_mode",
    "run_security_validation",
    "run_cve_consolidation",
    "run_cve_validation",
    "run_cve_final_validation",
    "run_graph_enhancement_mode",
    "run_graph_execution_integration_mode",
    "run_graph_fusion_mode",
    "run_high_recall_mode",
    "run_runtime_security_validation",
    "run_unified_validation",
]
