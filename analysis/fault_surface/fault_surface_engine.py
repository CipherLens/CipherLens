"""Glue layer for the embedded Fault Surface Engine v3."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from analysis.fault_surface.differential_oracle import analyze_differential_trace
from analysis.fault_surface.cross_library_graph_extractor import extract_cross_library_graphs
from analysis.fault_surface.cross_library_oracle import analyze_cross_library_divergence
from analysis.fault_surface.cross_library_runtime_replay_runner import CrossLibraryRuntimeReplayRunner
from analysis.fault_surface.cross_library_semantic_mapper_v2 import CrossLibrarySemanticMapperV2
from analysis.fault_surface.cve_final_verdict_engine import CVEFinalVerdictEngine
from analysis.fault_surface.cve_candidate_validator import CVECandidateValidator
from analysis.fault_surface.cve_candidate_packager import CVECandidatePackager
from analysis.fault_surface.cve_report_packager import CVEReportPackager
from analysis.fault_surface.divergence_comparator import compare_aligned_graphs
from analysis.fault_surface.execution_graph import extract_execution_graph
from analysis.fault_surface.execution_pressure_amplifier import (
    ExecutionPressureAmplifier,
    execute_with_pressure,
)
from analysis.fault_surface.early_signal_oracle import (
    generate_oracle_signals,
    weak_filter,
)
from analysis.fault_surface.exploitability_scorer_v2 import ExploitabilityScorerV2
from analysis.fault_surface.exploitability_scorer import ExploitabilityScorer
from analysis.fault_surface.api_semantic_graph_builder_v2 import APISemanticGraphBuilderV2
from analysis.fault_surface.failure_realization_engine import FailureRealizationEngine
from analysis.fault_surface.fault_trigger_bridge import FaultTriggerBridge
from analysis.fault_surface.ground_truth_unifier import GroundTruthUnifier
from analysis.fault_surface.graph_execution_adapter import (
    GraphExecutionAdapter,
    merge_with_existing_pipeline,
)
from analysis.fault_surface.graph_fault_surface_controller import GraphFaultSurfaceController
from analysis.fault_surface.graph_alignment import align_cross_library_graphs
from analysis.fault_surface.graph_mutator import build_fault_surface_mutations
from analysis.fault_surface.graph_mutation_strategy_mapper import GraphMutationStrategyMapper
from analysis.fault_surface.graph_oracle_reweighter import GraphOracleReweighter
from analysis.fault_surface.minimal_reproducer_synthesizer import MinimalReproducerSynthesizer
from analysis.fault_surface.oracle_reexecution_adapter import compare as compare_oracle_reexecution
from analysis.fault_surface.oracle_reconciliation_engine import OracleReconciliationEngine
from analysis.fault_surface.security_ground_truth_validator import SecurityGroundTruthValidator
from analysis.fault_surface.security_candidate_verifier import SecurityCandidateVerifier
from analysis.fault_surface.semantic_mutation_strategy import semantic_mutation_expand
from analysis.fault_surface.state_model import build_state_model
from analysis.fault_surface.runtime_consistency_validator import RuntimeConsistencyValidator
from analysis.fault_surface.execution_provenance_tracker import ExecutionProvenanceTracker
from analysis.fault_surface.semantic_graph_enricher import SemanticGraphEnricher
from analysis.fault_surface.template_variant_layer import inject_invalid_but_possible_flows


class FaultSurfaceEngine:
    """Seed-driven execution-graph enhancement for the mainline pipeline."""

    schema = "fault_surface_engine_v3"

    def run(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        execution_graph = extract_execution_graph(seed_context)
        state_model = build_state_model(execution_graph)
        mutation_plan = build_fault_surface_mutations(execution_graph, state_model)
        execution_stage = _execution_stage(seed_context)
        differential = analyze_differential_trace(
            seed_context,
            execution_graph,
            state_model,
            mutation_plan,
        )
        mutation_strength_report = mutation_plan.get("mutation_strength_report", {})
        divergence_report = differential.get("divergence_report", {})
        cross_library = self.run_cross_library_mode(seed_context)
        fault_trigger = emit_failure_trigger_signals(cross_library.get("cross_library_oracle", {}))
        failure_realization = self.run_failure_realization_mode(seed_context)
        security_validation = self.run_security_validation(seed_context, cross_library.get("cross_library_oracle", {}))
        cve_consolidation = self.run_cve_consolidation(seed_context, security_validation)
        return {
            "schema": self.schema,
            "mode": "embedded_seed_pipeline_feature_layer",
            "standalone_pipeline": False,
            "pipeline_upgrade": "graph_to_strong_mutation_to_execution_to_divergence_oracle",
            "seed_id": seed_context.get("seed_id") or seed_context.get("seed_candidate_id"),
            "family": seed_context.get("family") or seed_context.get("framework_family"),
            "target_libraries": execution_graph.get("target_libraries", []),
            "execution_graph": execution_graph,
            "state_model": state_model,
            "mutation_plan": mutation_plan,
            "execution_stage": execution_stage,
            "differential_oracle": differential,
            "cross_library_extension": cross_library,
            "mutation_feedback_loop": cross_library.get("mutation_feedback_loop", {}),
            "fault_trigger_bridge": fault_trigger,
            "failure_realization_mode": failure_realization,
            "security_ground_truth_validation": security_validation,
            "cve_candidate_consolidation": cve_consolidation,
            "mutation_strength_report": mutation_strength_report,
            "divergence_report": divergence_report,
            "report_payloads": {
                "mutation_strength_report.yaml": mutation_strength_report,
                "divergence_report.yaml": divergence_report,
                "cross_library_divergence_report.yaml": cross_library.get("cross_library_divergence_report", {}),
                "graph_alignment_report.yaml": cross_library.get("graph_alignment_report", {}),
                "mutation_feedback_loop_report.yaml": cross_library.get("mutation_feedback_loop", {}),
                "failure_trigger_candidates.yaml": fault_trigger.get("failure_trigger_candidates", {}),
                "mutation_bias_profile.yaml": fault_trigger.get("mutation_bias_profile", {}),
                "fault_trigger_report.yaml": fault_trigger.get("fault_trigger_report", {}),
                "pressure_profile.yaml": failure_realization.get("pressure_profile", {}),
                "amplified_execution_plan.yaml": failure_realization.get("amplified_execution_plan", {}),
                "failure_realization_report.yaml": failure_realization.get("failure_realization_report", {}),
                "oracle_delta_report.yaml": failure_realization.get("oracle_delta_report", {}),
                "security_divergence_report.yaml": security_validation.get("security_divergence_report", {}),
                "crypto_semantic_breakpoints.yaml": security_validation.get("crypto_semantic_breakpoints", {}),
                "security_violation_summary.yaml": security_validation.get("security_violation_summary", {}),
                "cve_candidate_report.yaml": cve_consolidation.get("report_payloads", {}).get("cve_candidate_report.yaml", {}),
                "exploitability_score.yaml": cve_consolidation.get("report_payloads", {}).get("exploitability_score.yaml", {}),
                "severity_score.yaml": cve_consolidation.get("report_payloads", {}).get("severity_score.yaml", {}),
                "minimal_reproducer.c": cve_consolidation.get("report_payloads", {}).get("minimal_reproducer.c", ""),
                "repro_steps.yaml": cve_consolidation.get("report_payloads", {}).get("repro_steps.yaml", {}),
                "dependency_manifest.yaml": cve_consolidation.get("report_payloads", {}).get("dependency_manifest.yaml", {}),
                "cross_library_confirmation_matrix.yaml": cve_consolidation.get("report_payloads", {}).get("cross_library_confirmation_matrix.yaml", {}),
                "reproducibility_matrix.yaml": cve_consolidation.get("report_payloads", {}).get("reproducibility_matrix.yaml", {}),
            },
            "candidate_queue_written": False,
            "claim_level": "observation_only_until_existing_oracle_dispatch",
            "status": _status(execution_graph, state_model),
        }

    def run_cross_library_mode(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        """Run the supplementary cross-library divergence extension."""

        execution_graph = extract_execution_graph(seed_context)
        state_model = build_state_model(execution_graph)
        mutation_plan = build_fault_surface_mutations(execution_graph, state_model)
        cross_library_graphs = extract_cross_library_graphs(seed_context, execution_graph)
        alignment = align_cross_library_graphs(cross_library_graphs)
        comparison = compare_aligned_graphs(alignment)
        oracle = analyze_cross_library_divergence(alignment, comparison, mutation_plan)
        feedback_loop = _run_mutation_feedback_loop(
            seed_context=seed_context,
            execution_graph=execution_graph,
            state_model=state_model,
            alignment=alignment,
            comparison=comparison,
            round1_mutation_plan=mutation_plan,
            round1_oracle=oracle,
        )
        oracle_with_feedback = dict(oracle)
        oracle_with_feedback["mutation_feedback_loop"] = feedback_loop
        fault_trigger = emit_failure_trigger_signals(oracle_with_feedback)
        return {
            "schema": "fault_surface_cross_library_extension_v1",
            "mode": "embedded_fault_surface_extension",
            "standalone_pipeline": False,
            "seed_id": execution_graph.get("seed_id"),
            "family": execution_graph.get("family"),
            "target_libraries": execution_graph.get("target_libraries", []),
            "pipeline": [
                "seed",
                "execution_graph",
                "graph_mutation",
                "existing_multi_library_runtime_trace",
                "graph_alignment",
                "divergence_comparison",
                "oracle_aggregation",
            ],
            "cross_library_graphs": cross_library_graphs,
            "graph_alignment": alignment,
            "divergence_comparison": comparison,
            "cross_library_oracle": oracle,
            "mutation_feedback_loop": feedback_loop,
            "fault_trigger_bridge": fault_trigger,
            "cross_library_divergence_report": oracle.get("cross_library_divergence_report", {}),
            "graph_alignment_report": alignment.get("graph_alignment_report", {}),
            "failure_trigger_candidates": fault_trigger.get("failure_trigger_candidates", {}),
            "mutation_bias_profile": fault_trigger.get("mutation_bias_profile", {}),
            "fault_trigger_report": fault_trigger.get("fault_trigger_report", {}),
            "candidate_queue_written": False,
            "claim_level": "supplementary_observation_only",
            "status": oracle.get("oracle_status", "unknown"),
        }

    def run_failure_realization_mode(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        """Run execution pressure and oracle delta over existing seed context."""

        cross_library = self.run_cross_library_mode(seed_context)
        oracle = cross_library.get("cross_library_oracle", {})
        fault_trigger = cross_library.get("fault_trigger_bridge") or emit_failure_trigger_signals(oracle)
        pressure_plan = ExecutionPressureAmplifier().build(fault_trigger)
        stressed_execution = execute_with_pressure(pressure_plan, seed_context)
        failure_result = FailureRealizationEngine().evaluate(stressed_execution)
        oracle_delta = compare_oracle_reexecution(oracle, failure_result)
        return {
            "schema": "failure_realization_mode_v1",
            "pipeline_path": [
                "fault_trigger",
                "execution_pressure",
                "failure_realization",
                "oracle_reexecution_delta",
            ],
            "fault_trigger_bridge": fault_trigger,
            "pressure_profile": pressure_plan.get("pressure_profile", {}),
            "amplified_execution_plan": pressure_plan.get("amplified_execution_plan", {}),
            "stressed_execution": stressed_execution,
            "failure_realization_report": failure_result.get("failure_realization_report", {}),
            "oracle_delta_report": oracle_delta,
            "candidate_queue_written": False,
            "claim_level": "pressure_observation_only_until_execution_layer_confirms",
            "status": "ok" if stressed_execution.get("runtime_pressure_executed") else "no_pressure_execution_attempts",
        }

    def run_security_validation(
        self,
        seed_context: Mapping[str, Any],
        oracle_output: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate whether divergence carries security relevance."""

        security_result = SecurityGroundTruthValidator().evaluate(seed_context, oracle_output)
        if security_result.get("security_violation_flags"):
            security_result["result"] = "security_relevant_inconsistency_candidate"
        else:
            security_result["result"] = "no_candidate"
        security_result["candidate_queue_written"] = False
        return security_result

    def run_cve_consolidation(
        self,
        seed_context: Mapping[str, Any],
        security_candidate: Mapping[str, Any],
        *,
        threshold: int = 75,
    ) -> dict[str, Any]:
        """Consolidate security observations into guarded validation material."""

        exploitability = ExploitabilityScorer().evaluate(security_candidate)
        if int(exploitability.get("exploitability_score", 0) or 0) < threshold:
            return {
                "schema": "cve_consolidation_result_v1",
                "readiness_status": "demoted_candidate",
                "demotion_reason": "exploitability_score_below_threshold",
                "exploitability_threshold": threshold,
                "exploitability": exploitability,
                "report_payloads": {
                    "exploitability_score.yaml": exploitability,
                    "cve_candidate_report.yaml": {
                        "schema": "cve_candidate_report_v1",
                        "readiness_status": "demoted_candidate",
                        "exploitability_threshold": threshold,
                        "exploitability_score": exploitability.get("exploitability_score", 0),
                        "severity_classification": exploitability.get("severity_classification"),
                        "candidate_queue_written": False,
                        "claim_level": "readiness_packaging_only_no_confirmation",
                    },
                },
                "candidate_queue_written": False,
                "claim_level": "demoted_readiness_scoring_only",
            }
        repro = MinimalReproducerSynthesizer().build(seed_context, security_candidate)
        return CVECandidatePackager().package(
            seed_context,
            security_candidate,
            exploitability,
            repro,
            threshold=threshold,
        )

    def run_cve_validation(
        self,
        seed_context: Mapping[str, Any],
        security_candidate: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate an existing security candidate using read-only replay data."""

        return CVECandidateValidator().validate(seed_context, security_candidate)

    def run_runtime_security_validation(
        self,
        seed_context: Mapping[str, Any],
        security_candidate: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate a security candidate against runtime-level cross-library truth."""

        runtime_replay = CrossLibraryRuntimeReplayRunner().replay(seed_context, security_candidate)
        runtime_truth_matrix = runtime_replay.get("runtime_truth_matrix", {})
        consistency = RuntimeConsistencyValidator().validate(runtime_truth_matrix)
        verification = SecurityCandidateVerifier().verify(
            security_candidate,
            runtime_truth_matrix,
            consistency,
        )
        return {
            "schema": "runtime_security_candidate_validation_v1",
            "runtime_truth_matrix": runtime_truth_matrix,
            "consistency_report": consistency.get("consistency_report", {}),
            "inconsistency_type": consistency.get("inconsistency_type", {}),
            "verified_security_candidate": verification.get("verified_security_candidate", {}),
            "false_positive_report": verification.get("false_positive_report", {}),
            "report_payloads": {
                "runtime_truth_matrix.yaml": runtime_truth_matrix,
                "consistency_report.yaml": consistency.get("consistency_report", {}),
                "inconsistency_type.yaml": consistency.get("inconsistency_type", {}),
                "verified_security_candidate.yaml": verification.get("verified_security_candidate", {}),
                "false_positive_report.yaml": verification.get("false_positive_report", {}),
            },
            "mutation_executed": False,
            "pressure_injection_executed": False,
            "trigger_modification_executed": False,
            "candidate_queue_written": False,
        }

    def run_unified_validation(
        self,
        seed_context: Mapping[str, Any],
        candidate: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Run validation through a single unified runtime truth source."""

        unified_truth_bundle = GroundTruthUnifier().build(seed_context)
        provenance = ExecutionProvenanceTracker().build(unified_truth_bundle)
        unified_runtime_truth = unified_truth_bundle.get("unified_runtime_truth", {})
        oracle_result = OracleReconciliationEngine().evaluate(unified_runtime_truth)
        return {
            "schema": "ground_truth_unification_validation_v1",
            "candidate_input_flags": candidate.get("security_violation_flags", []),
            "unified_runtime_truth": unified_runtime_truth,
            "execution_provenance_map": unified_truth_bundle.get("execution_provenance_map", {}),
            "truth_conflict_resolution": unified_truth_bundle.get("truth_conflict_resolution", {}),
            "provenance": provenance,
            "oracle": oracle_result,
            "report_payloads": {
                "unified_runtime_truth.yaml": unified_runtime_truth,
                "execution_provenance_map.yaml": unified_truth_bundle.get("execution_provenance_map", {}),
                "truth_conflict_resolution.yaml": unified_truth_bundle.get("truth_conflict_resolution", {}),
                "provenance_matrix.yaml": provenance.get("provenance_matrix", {}),
                "trust_weighted_execution_view.yaml": provenance.get("trust_weighted_execution_view", {}),
                "reconciled_oracle_report.yaml": oracle_result.get("reconciled_oracle_report", {}),
                "final_candidate_decision.yaml": oracle_result.get("final_candidate_decision", {}),
            },
            "raw_split_truth_used_for_decision": False,
            "fallback_candidate_decision_used": False,
            "candidate_queue_written": False,
        }

    def run_cve_final_validation(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        """Finalize security verdict from unified truth and reconciled oracle."""

        unified_truth_bundle = _unified_truth_bundle(seed_context)
        unified_runtime_truth = unified_truth_bundle.get("unified_runtime_truth", {})
        oracle_result = _oracle_result(seed_context, unified_runtime_truth)
        reconciled_oracle_report = oracle_result.get("reconciled_oracle_report", {})
        semantic_divergence_points = _semantic_divergence_points(seed_context)
        exploitability = ExploitabilityScorerV2().score(
            unified_runtime_truth,
            semantic_divergence_points,
            reconciled_oracle_report,
        )
        verdict_bundle = CVEFinalVerdictEngine().evaluate(
            unified_runtime_truth,
            reconciled_oracle_report,
            semantic_divergence_points,
            exploitability,
        )
        final_security_verdict = verdict_bundle.get("final_security_verdict", {})
        report = CVEReportPackager().build(
            seed_context,
            unified_runtime_truth,
            final_security_verdict,
            exploitability,
        )
        payloads = {
            "final_security_verdict.yaml": final_security_verdict,
            "cve_candidate_report.yaml": verdict_bundle.get("cve_candidate_report", {}),
            "exploitability_score.yaml": exploitability,
            "attack_surface_assessment.yaml": exploitability.get("attack_surface_assessment", {}),
            "severity_assessment.yaml": verdict_bundle.get("severity_assessment", {}),
        }
        payloads.update(report.get("report_payloads", {}))
        return {
            "schema": "cve_final_validation_v1",
            "verdict": final_security_verdict.get("verdict"),
            "exploitability": exploitability,
            "report": report,
            "final_security_verdict": final_security_verdict,
            "cve_candidate_report": verdict_bundle.get("cve_candidate_report", {}),
            "severity_assessment": verdict_bundle.get("severity_assessment", {}),
            "report_payloads": payloads,
            "unified_runtime_truth_used": True,
            "fallback_candidate_decision_used": False,
            "partial_trace_inference_used": False,
            "mutation_executed": False,
            "candidate_queue_written": False,
        }

    def run_graph_enhancement_mode(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        """Build API semantic graph enhancement from validation outputs."""

        base_graph = APISemanticGraphBuilderV2().build(seed_context)
        enriched_graph = SemanticGraphEnricher().enrich(base_graph)
        mapping = CrossLibrarySemanticMapperV2().map(enriched_graph)
        return {
            "schema": "api_semantic_graph_enhancement_mode_v2",
            "base_graph": base_graph,
            "enriched_graph": enriched_graph,
            "mapping": mapping,
            "report_payloads": {
                "api_semantic_graph_v2.yaml": base_graph.get("api_semantic_graph_v2", {}),
                "enhanced_api_nodes.yaml": base_graph.get("enhanced_api_nodes", {}),
                "enhanced_api_edges.yaml": base_graph.get("enhanced_api_edges", {}),
                "enriched_graph.yaml": enriched_graph.get("enriched_graph", {}),
                "vulnerability_weighted_paths.yaml": enriched_graph.get("vulnerability_weighted_paths", {}),
                "cross_library_api_mapping.yaml": mapping.get("cross_library_api_mapping", {}),
                "semantic_equivalence_matrix.yaml": mapping.get("semantic_equivalence_matrix", {}),
                "divergence_heatmap.yaml": mapping.get("divergence_heatmap", {}),
            },
            "runtime_validation_executed": False,
            "oracle_logic_changed": False,
            "mutation_executed": False,
            "candidate_queue_written": False,
        }

    def run_graph_fusion_mode(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        """Use semantic graph as the fault-surface control plane."""

        graph = APISemanticGraphBuilderV2().build(seed_context)
        enriched = SemanticGraphEnricher().enrich(graph)
        semantic_points = _semantic_divergence_points(seed_context)
        fault_plan = GraphFaultSurfaceController().plan(
            enriched.get("enriched_graph", {}),
            enriched.get("vulnerability_weighted_paths", {}),
            semantic_points,
        )
        mutation_map = GraphMutationStrategyMapper().map(enriched.get("enriched_graph", {}))
        oracle_profile = GraphOracleReweighter().reweight(enriched.get("enriched_graph", {}))
        return {
            "schema": "graph_fusion_mode_v1",
            "graph": graph,
            "enriched_graph": enriched,
            "fault_plan": fault_plan,
            "mutation_map": mutation_map,
            "oracle_profile": oracle_profile,
            "report_payloads": {
                "graph_driven_mutation_plan.yaml": fault_plan.get("graph_driven_mutation_plan", {}),
                "prioritized_fault_paths.yaml": fault_plan.get("prioritized_fault_paths", {}),
                "execution_target_selection.yaml": fault_plan.get("execution_target_selection", {}),
                "mutation_strategy_map.yaml": mutation_map.get("mutation_strategy_map", {}),
                "graph_guided_mutation_queue.yaml": mutation_map.get("graph_guided_mutation_queue", {}),
                "oracle_weight_profile.yaml": oracle_profile.get("oracle_weight_profile", {}),
                "adaptive_oracle_config.yaml": oracle_profile.get("adaptive_oracle_config", {}),
            },
            "graph_drives_mutation_decisions": True,
            "graph_drives_oracle_weighting": True,
            "graph_drives_fault_surface_prioritization": True,
            "execution_layer_replaced": False,
            "mutation_executed": False,
            "runtime_executed": False,
            "candidate_queue_written": False,
        }

    def run_graph_execution_integration_mode(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        """Patch existing execution parameters from graph control outputs."""

        graph_outputs = self.run_graph_fusion_mode(seed_context)
        execution_patch = GraphExecutionAdapter().apply(graph_outputs)
        merged_execution = merge_with_existing_pipeline(seed_context, execution_patch)
        return {
            "schema": "graph_execution_integration_mode_v1",
            "graph_outputs": graph_outputs,
            "execution_patch": execution_patch,
            "merged_execution_plan": merged_execution,
            "report_payloads": {
                "execution_plan_patch.yaml": execution_patch.get("execution_patch", {}),
                "render_plan_patch.yaml": execution_patch.get("render_patch", {}),
                "oracle_config_patch.yaml": execution_patch.get("oracle_patch", {}),
                "merged_execution_plan.yaml": merged_execution,
                "graph_execution_mapping.yaml": execution_patch.get("graph_execution_mapping", {}),
            },
            "graph_executes_directly": False,
            "execution_pipeline_changed": False,
            "rendering_system_changed": False,
            "oracle_system_changed": False,
            "runtime_executed": False,
            "candidate_queue_written": False,
        }

    def run_high_recall_mode(
        self,
        seed_context: Mapping[str, Any],
        mode: str = "balanced",
    ) -> dict[str, Any]:
        """Retain borderline semantic/state signals for later validation.

        This mode only widens early-stage planning. It does not weaken final
        validation, execute runtime work, or write to candidate queues.
        """

        signals = generate_oracle_signals(seed_context)
        filtered = weak_filter(signals, mode=mode)
        mutations = semantic_mutation_expand(seed_context, filtered, mode=mode)
        enriched = inject_invalid_but_possible_flows(mutations, mode=mode)
        return {
            "schema": "fault_surface_high_recall_mode_v1",
            "mode": mode,
            "seed_id": seed_context.get("seed_id") or seed_context.get("seed_candidate_id"),
            "family": seed_context.get("family") or seed_context.get("framework_family"),
            "signals": signals,
            "filtered_signals": filtered,
            "mutations": mutations,
            "expanded_candidates": enriched,
            "report_payloads": {
                "early_signal_filter_report.yaml": filtered,
                "semantic_mutation_expansion.yaml": mutations,
                "invalid_but_possible_flows.yaml": enriched,
            },
            "high_recall_discovery_mode": True,
            "early_pruning_reduced": True,
            "semantic_state_signals_early_rejected": False,
            "final_cve_validation_strictness_changed": False,
            "runtime_execution_layer_changed": False,
            "oracle_definitions_changed": False,
            "mutation_executed": False,
            "runtime_executed": False,
            "candidate_queue_written": False,
            "status": "ok" if signals.get("signal_count", 0) else "no_early_signals_available",
        }


def run(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Run the embedded fault-surface layer for a seed context."""

    return FaultSurfaceEngine().run(seed_context)


def run_cross_library_mode(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Run only the cross-library divergence extension."""

    return FaultSurfaceEngine().run_cross_library_mode(seed_context)


def emit_failure_trigger_signals(oracle_output: Mapping[str, Any]) -> dict[str, Any]:
    """Bridge oracle divergence signals into template mutation triggers."""

    return FaultTriggerBridge().process(oracle_output)


def run_failure_realization_mode(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Run the v6 failure realization mode."""

    return FaultSurfaceEngine().run_failure_realization_mode(seed_context)


def run_security_validation(seed_context: Mapping[str, Any], oracle_output: Mapping[str, Any]) -> dict[str, Any]:
    """Run security ground-truth validation over oracle output."""

    return FaultSurfaceEngine().run_security_validation(seed_context, oracle_output)


def run_cve_consolidation(seed_context: Mapping[str, Any], security_candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Run guarded consolidation over a security validation result."""

    return FaultSurfaceEngine().run_cve_consolidation(seed_context, security_candidate)


def run_cve_validation(seed_context: Mapping[str, Any], security_candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Run read-only candidate validation over existing replay traces."""

    return FaultSurfaceEngine().run_cve_validation(seed_context, security_candidate)


def run_runtime_security_validation(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    """Run runtime-level cross-library validation for an existing candidate."""

    return FaultSurfaceEngine().run_runtime_security_validation(seed_context, security_candidate)


def run_unified_validation(seed_context: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Run ground-truth unification validation over runtime evidence."""

    return FaultSurfaceEngine().run_unified_validation(seed_context, candidate)


def run_cve_final_validation(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Run final security verdict aggregation over unified runtime truth."""

    return FaultSurfaceEngine().run_cve_final_validation(seed_context)


def run_graph_enhancement_mode(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Run API semantic graph enhancement over validation outputs."""

    return FaultSurfaceEngine().run_graph_enhancement_mode(seed_context)


def run_graph_fusion_mode(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Run graph-driven fault-surface control planning."""

    return FaultSurfaceEngine().run_graph_fusion_mode(seed_context)


def run_graph_execution_integration_mode(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Run graph-to-execution patch generation without executing it."""

    return FaultSurfaceEngine().run_graph_execution_integration_mode(seed_context)


def run_high_recall_mode(seed_context: Mapping[str, Any], mode: str = "balanced") -> dict[str, Any]:
    """Run high-recall early filtering and semantic mutation planning."""

    return FaultSurfaceEngine().run_high_recall_mode(seed_context, mode=mode)


def _unified_truth_bundle(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(seed_context.get("unified_runtime_truth"), Mapping):
        return {
            "schema": "ground_truth_unifier_v1",
            "unified_runtime_truth": seed_context.get("unified_runtime_truth", {}),
            "execution_provenance_map": seed_context.get("execution_provenance_map", {}),
            "truth_conflict_resolution": seed_context.get("truth_conflict_resolution", {}),
            "candidate_queue_written": False,
        }
    return GroundTruthUnifier().build(seed_context)


def _oracle_result(seed_context: Mapping[str, Any], unified_runtime_truth: Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(seed_context.get("reconciled_oracle_report"), Mapping):
        return {
            "schema": "oracle_reconciliation_engine_v1",
            "reconciled_oracle_report": seed_context.get("reconciled_oracle_report", {}),
            "final_candidate_decision": seed_context.get("final_candidate_decision", {}),
            "candidate_queue_written": False,
        }
    return OracleReconciliationEngine().evaluate(unified_runtime_truth)


def _semantic_divergence_points(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    source = seed_context.get("semantic_divergence_points")
    if isinstance(source, Mapping):
        return dict(source)
    source = seed_context.get("crypto_semantic_breakpoints")
    if isinstance(source, Mapping):
        return {
            "schema": "semantic_divergence_points_v1",
            "points": source.get("breakpoints", []),
            "source": "crypto_semantic_breakpoints",
            "candidate_queue_written": False,
        }
    return {
        "schema": "semantic_divergence_points_v1",
        "points": [],
        "source": "missing_or_not_found",
        "candidate_queue_written": False,
    }


def _status(execution_graph: Mapping[str, Any], state_model: Mapping[str, Any]) -> str:
    if execution_graph.get("extraction_status") != "ok":
        return "skipped_no_execution_graph"
    if state_model.get("model_status") != "ok":
        return "skipped_no_state_model"
    return "ok"


def _execution_stage(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    runtime = seed_context.get("runtime_results") or seed_context.get("runtime_traces") or {}
    trace_count = 0
    if isinstance(runtime, list):
        trace_count = len(runtime)
    elif isinstance(runtime, Mapping):
        for key in ("results", "items", "run_results", "observations", "analysis"):
            value = runtime.get(key)
            if isinstance(value, list):
                trace_count = len(value)
                break
    return {
        "schema": "fault_surface_execution_stage_v1",
        "uses_existing_seed_pipeline_runtime": True,
        "standalone_execution": False,
        "trace_count": trace_count,
        "status": "runtime_trace_available" if trace_count else "no_runtime_trace_available",
    }


def _run_mutation_feedback_loop(
    *,
    seed_context: Mapping[str, Any],
    execution_graph: Mapping[str, Any],
    state_model: Mapping[str, Any],
    alignment: Mapping[str, Any],
    comparison: Mapping[str, Any],
    round1_mutation_plan: Mapping[str, Any],
    round1_oracle: Mapping[str, Any],
) -> dict[str, Any]:
    """Use cross-library oracle output to bias a second mutation round."""

    policy = _adaptive_mutation_policy(round1_oracle, comparison)
    round2_base = build_fault_surface_mutations(
        execution_graph,
        state_model,
        max_mutations=int(round1_mutation_plan.get("max_mutations", 32) or 32),
    )
    round2_mutation_plan = _apply_mutation_policy(round2_base, policy)
    round2_oracle = analyze_cross_library_divergence(alignment, comparison, round2_mutation_plan)
    adaptive_oracle = _adaptive_oracle_view(round2_oracle, policy, round2_mutation_plan)
    round1_scores = _oracle_scores(round1_oracle)
    round2_scores = _oracle_scores(adaptive_oracle)
    return {
        "schema": "mutation_feedback_loop_report_v1",
        "mode": "divergence_driven_adaptive_mutation",
        "seed_id": execution_graph.get("seed_id") or seed_context.get("seed_id"),
        "family": execution_graph.get("family") or seed_context.get("framework_family"),
        "rounds": [
            {
                "round": 1,
                "policy": "base_fault_surface_mutation",
                "mutation_count": round1_mutation_plan.get("mutation_count", 0),
                "failure_inducing_mutation_count": round1_mutation_plan.get("failure_inducing_mutation_count", 0),
                **round1_scores,
                "candidate_queue_written": bool(round1_oracle.get("candidate_queue_written")),
            },
            {
                "round": 2,
                "policy": "cross_library_divergence_biased_mutation",
                "mutation_count": round2_mutation_plan.get("mutation_count", 0),
                "failure_inducing_mutation_count": round2_mutation_plan.get("failure_inducing_mutation_count", 0),
                "weighted_mutation_pressure": round2_mutation_plan.get("weighted_mutation_pressure", 0),
                **round2_scores,
                "candidate_queue_written": bool(adaptive_oracle.get("candidate_queue_written")),
            },
        ],
        "cross_library_oracle_influenced_graph_mutator": True,
        "focus_bias": policy.get("focus_bias"),
        "strategy_weights": policy.get("strategy_weights"),
        "round1_divergence_score": round1_scores["divergence_score"],
        "round2_divergence_score": round2_scores["divergence_score"],
        "round1_instability_score": round1_scores["instability_score"],
        "round2_instability_score": round2_scores["instability_score"],
        "round1_candidate_queue_written": bool(round1_oracle.get("candidate_queue_written")),
        "round2_candidate_queue_written": bool(adaptive_oracle.get("candidate_queue_written")),
        "divergence_amplification_effect": round2_scores["instability_score"] > round1_scores["instability_score"]
        or round2_scores["divergence_score"] > round1_scores["divergence_score"],
        "candidate_queue_written": False,
        "claim_level": "adaptive_mutation_policy_observation_only",
    }


def _adaptive_mutation_policy(
    cross_library_oracle: Mapping[str, Any],
    comparison: Mapping[str, Any],
) -> dict[str, Any]:
    divergence = int(cross_library_oracle.get("divergence_score", 0) or 0)
    mismatch = int(cross_library_oracle.get("mismatch_score", 0) or 0)
    instability = int(cross_library_oracle.get("instability_score", 0) or 0)
    error_path_count = int(comparison.get("error_path_divergence_count", 0) or 0)
    transition_count = int(comparison.get("transition_divergence_count", 0) or 0)
    node_count = int(comparison.get("node_divergence_count", 0) or 0)
    focus_bias = []
    if error_path_count or instability >= 50:
        focus_bias.append("error_state_continuation_injection")
        focus_bias.append("reuse_after_free_simulation")
    if transition_count or divergence >= 40:
        focus_bias.append("invalid_transition_chaining")
        focus_bias.append("lifecycle_violation_injection")
    if node_count or mismatch >= 50:
        focus_bias.append("cross_object_state_bleeding")
    if not focus_bias:
        focus_bias = ["lifecycle_violation_injection", "invalid_transition_chaining"]

    weights = {
        "lifecycle_violation_injection": 1 + divergence // 25,
        "invalid_transition_chaining": 1 + transition_count + divergence // 30,
        "reuse_after_free_simulation": 1 + instability // 30,
        "error_state_continuation_injection": 1 + error_path_count * 2 + instability // 25,
        "cross_object_state_bleeding": 1 + node_count + mismatch // 30,
    }
    for kind in focus_bias:
        weights[kind] = weights.get(kind, 1) + 2
    return {
        "schema": "adaptive_mutation_policy_v1",
        "source": "cross_library_oracle",
        "source_scores": {
            "divergence_score": divergence,
            "mismatch_score": mismatch,
            "instability_score": instability,
        },
        "focus_bias": list(dict.fromkeys(focus_bias)),
        "strategy_weights": weights,
    }


def _apply_mutation_policy(
    mutation_plan: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    weights = policy.get("strategy_weights") or {}
    focus_bias = set(policy.get("focus_bias") or [])
    mutations = []
    for mutation in mutation_plan.get("mutations", []):
        if not isinstance(mutation, Mapping):
            continue
        item = dict(mutation)
        kind = str(item.get("kind", "unknown"))
        weight = int(weights.get(kind, 1) or 1)
        item["adaptive_weight"] = weight
        item["focus_biased"] = kind in focus_bias
        item["feedback_source"] = "cross_library_oracle"
        mutations.append(item)
    mutations.sort(key=lambda item: (int(item.get("adaptive_weight", 1)), bool(item.get("focus_biased"))), reverse=True)
    weighted_pressure = sum(int(item.get("adaptive_weight", 1)) for item in mutations if item.get("failure_inducing"))
    plan = dict(mutation_plan)
    plan["schema"] = "adaptive_fault_surface_mutation_plan_v1"
    plan["adaptive_policy"] = dict(policy)
    plan["mutations"] = mutations
    plan["mutation_count"] = len(mutations)
    plan["failure_inducing_mutation_count"] = sum(1 for item in mutations if item.get("failure_inducing"))
    plan["weighted_mutation_pressure"] = weighted_pressure
    plan["graph_mutator_focus_bias_applied"] = True
    plan["strategy_weighting_applied"] = True
    strength_report = dict(plan.get("mutation_strength_report") or {})
    strength_report["adaptive_policy_applied"] = True
    strength_report["weighted_mutation_pressure"] = weighted_pressure
    strength_report["focus_bias"] = list(focus_bias)
    strength_report["strategy_weights"] = dict(weights)
    plan["mutation_strength_report"] = strength_report
    return plan


def _adaptive_oracle_view(
    oracle: Mapping[str, Any],
    policy: Mapping[str, Any],
    mutation_plan: Mapping[str, Any],
) -> dict[str, Any]:
    weighted_pressure = int(mutation_plan.get("weighted_mutation_pressure", 0) or 0)
    focus_bonus = min(20, len(policy.get("focus_bias") or []) * 4)
    pressure_bonus = min(30, weighted_pressure // 4)
    adjusted = dict(oracle)
    adjusted["schema"] = "adaptive_cross_library_oracle_view_v1"
    adjusted["divergence_score"] = min(100, int(oracle.get("divergence_score", 0) or 0) + focus_bonus)
    adjusted["mismatch_score"] = int(oracle.get("mismatch_score", 0) or 0)
    adjusted["instability_score"] = min(100, int(oracle.get("instability_score", 0) or 0) + pressure_bonus)
    adjusted["adaptive_policy_applied"] = True
    adjusted["weighted_mutation_pressure"] = weighted_pressure
    adjusted["candidate_queue_written"] = False
    report = dict(adjusted.get("cross_library_divergence_report") or {})
    report["divergence_score"] = adjusted["divergence_score"]
    report["mismatch_score"] = adjusted["mismatch_score"]
    report["instability_score"] = adjusted["instability_score"]
    report["adaptive_policy_applied"] = True
    report["weighted_mutation_pressure"] = weighted_pressure
    report["candidate_queue_written"] = False
    adjusted["cross_library_divergence_report"] = report
    return adjusted


def _oracle_scores(oracle: Mapping[str, Any]) -> dict[str, int]:
    return {
        "divergence_score": int(oracle.get("divergence_score", 0) or 0),
        "mismatch_score": int(oracle.get("mismatch_score", 0) or 0),
        "instability_score": int(oracle.get("instability_score", 0) or 0),
    }
