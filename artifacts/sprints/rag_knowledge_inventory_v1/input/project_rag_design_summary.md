# project RAG design summary

- rag_position: RAG supplies structured evidence for candidate API mapping, adapter/recipe decisions, route planning, scheduler ranking, and feedback-aware triage.
- llm_position: GLM/LLM should fill structured adapters/slot_bindings after evidence is collected; it should not generate raw C harnesses.
- why_not_bulk_poc_import: Unaudited raw PoCs/logs/HTML can introduce noisy, duplicate, or misleading evidence and blur safe/bug/triage distinctions.
- rag_serves_modules: ['candidate_mapper', 'adapter_filler', 'route_planner', 'auto_scheduler', 'feedback analysis']
