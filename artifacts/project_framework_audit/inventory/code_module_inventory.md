# Code Module Inventory

## Reusable Components

- `migration/adapter_filler.py`, `migration/adapter_validate.py`: strict recipe-slot adapter workflow.
- `template_maker/cross_generator_from_adapters.py`, `template_maker/render_cases.py`: A-path template generation/rendering.
- `runner/compile_run.py`, `runner/analyze_results.py`, `runner/analyze_cross_results.py`: core execution and generic verdict analysis.
- `knowledge/rag_builder.py`, `knowledge/rag_query.py`, `knowledge/build_pattern_bank.py`: RAG and pattern-bank infrastructure.
- `analysis/build_candidate_queue.py`, `analysis/plan_execution_paths.py`: scheduler-oriented routing.

## Family-Specific Components

- `mutation/apply_secure_heap_state_matrix.py`
- `mutation/apply_der_full_consumption_matrix.py`
- `mutation/apply_mac_lifecycle_matrix_to_template.py`
- `runner/analyze_secure_heap_state.py`
- `runner/analyze_der_full_consumption.py`
- `runner/analyze_mac_lifecycle.py`

These are useful but should converge toward a shared matrix/render/analyze interface.

## Hardcode Risk

- Family-specific renderers can freeze one-off assumptions.
- Analyzer verdict rules can diverge across families.
- Pattern bank and markdown pattern docs may drift if not generated or validated together.
- Logs/build artifacts under `artifacts/` can become noisy commit payloads.

## Refactor Direction

1. Add a `harness_family` renderer/analyzer registry.
2. Normalize mutation matrix schema across B/C paths.
3. Add version/novelty classification into scheduler scoring.
4. Keep A-path strict: GLM generates only `slot_bindings`, never free-form C.
