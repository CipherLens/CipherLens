"""Build the canonical 18-stage mining pipeline registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analysis.analysis_records import load_yaml, now_iso
from analysis.pipeline_records import stage_record


STAGE_NAMES = [
    ("01", "ingestion", "analysis.pipeline_executor"),
    ("02", "family_correction", "analysis.pipeline_executor"),
    ("03", "rag_lookup", "migration.evidence_collector"),
    ("04", "mapping_gate", "migration.candidate_mapper"),
    ("05", "family_template_recipe", "template_maker.family_render_plan"),
    ("06", "family_template_generalization", "template_maker.family_render_plan"),
    ("07", "adapter_recipe", "migration.adapter_filler"),
    ("08", "slot_filling_plan", "migration.adapter_filler"),
    ("09", "llm_slot_filling", "migration.adapter_filler"),
    ("10", "adapter_validate", "migration.adapter_validate"),
    ("11", "mutation_planner", "mutation.generic_mutation_engine"),
    ("12", "render_plan", "template_maker.family_render_plan"),
    ("13", "render_cases", "template_maker.family_case_renderer"),
    ("14", "compile_run", "runner.family_compile_runner"),
    ("15", "oracle_aware_analyze", "analyzer.oracle_aware_analyzer"),
    ("16", "triage", "analysis"),
    ("17", "runtime_feedback", "analysis.runtime_feedback"),
    ("18", "scheduler_update", "analysis.scheduler_runtime_loop"),
]


DEFAULT_IO: dict[str, tuple[list[str], list[str]]] = {
    "01_ingestion": (["historical PoC / issue / CVE / regression test"], ["ingested PoC artifact"]),
    "02_family_correction": (["ingested PoC artifact"], ["family correction / scheduler seed review"]),
    "03_rag_lookup": (["family corrected artifact"], ["RAG evidence"]),
    "04_mapping_gate": (["RAG evidence", "candidate APIs"], ["mapping gate decision"]),
    "05_family_template_recipe": (["mapping gate decision"], ["family template recipe"]),
    "06_family_template_generalization": (["family template recipe"], ["generalized family template"]),
    "07_adapter_recipe": (["generalized family template"], ["adapter recipe"]),
    "08_slot_filling_plan": (["adapter recipe"], ["slot filling plan"]),
    "09_llm_slot_filling": (["slot filling plan", "RAG evidence"], ["slot_bindings.yaml"]),
    "10_adapter_validate": (["slot_bindings.yaml", "adapter recipe"], ["validated adapter"]),
    "11_mutation_planner": (["validated adapter", "verified seeds"], ["mutation plan"]),
    "12_render_plan": (["mutation plan"], ["render plan"]),
    "13_render_cases": (["render plan"], ["rendered cases"]),
    "14_compile_run": (["rendered cases"], ["compile/run results"]),
    "15_oracle_aware_analyze": (["compile/run results"], ["oracle-aware analysis"]),
    "16_triage": (["oracle-aware analysis"], ["triage report"]),
    "17_runtime_feedback": (["triage report"], ["runtime feedback"]),
    "18_scheduler_update": (["runtime feedback", "family status"], ["scheduler task queue"]),
}


def build_registry(repo_root: Path, registry_path: Path | None = None) -> dict[str, Any]:
    config = load_yaml(registry_path) if registry_path else {}
    configured = {str(item.get("stage_id", "")).zfill(2): item for item in config.get("stages", []) or []}
    stages = []
    for sid, name, owner in STAGE_NAMES:
        key = f"{sid}_{name}"
        configured_item = configured.get(sid, {})
        inputs, outputs = DEFAULT_IO[key]
        uses_llm = bool(configured_item.get("uses_llm", name == "llm_slot_filling"))
        stages.append(
            stage_record(
                sid,
                name,
                configured_item.get("owner_module", owner),
                inputs,
                outputs,
                "defined",
                [],
                uses_llm,
                configured_item.get("llm_allowed_output", "slot_bindings.yaml" if uses_llm else ""),
                False,
                [
                    "dry-run registry definition",
                    "GLM/LLM stages may only produce slot_bindings.yaml" if uses_llm else "no LLM required",
                ],
            )
        )
    return {
        "schema": "pipeline_stage_registry_v1",
        "generated_at": now_iso(),
        "stage_count": len(stages),
        "stages": stages,
        "source_config": registry_path.as_posix() if registry_path else "",
    }
