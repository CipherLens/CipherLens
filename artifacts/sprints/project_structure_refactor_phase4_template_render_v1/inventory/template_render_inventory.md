# Template/Render Inventory

```yaml
schema: template_render_inventory_v1
task: project_structure_refactor_phase4_template_render_v1
template_maker_existing_files:
- template_maker/__init__.py
- template_maker/ast_mask.py
- template_maker/ast_mask_lite.py
- template_maker/ast_mask_select.py
- template_maker/ast_mask_tree_sitter.py
- template_maker/cross_generator.py
- template_maker/cross_generator_from_adapters.py
- template_maker/cross_generator_from_candidates.py
- template_maker/family_case_renderer.py
- template_maker/family_render_plan.py
- template_maker/generator.py
- template_maker/mac_lifecycle_sequences.py
- template_maker/mask.py
- template_maker/mask_report.py
- template_maker/normalize_enriched.py
- template_maker/oracle_instrumentation.py
- template_maker/pkey_verify_snippets.py
- template_maker/render_cases.py
- template_maker/render_records.py
- template_maker/render_template.py
- template_maker/validate_template.py
template_render_file_count: 53
template_render_rg_match_count: 304198
new_core_modules:
- template_maker/family_render_plan.py
- template_maker/family_case_renderer.py
- template_maker/oracle_instrumentation.py
- template_maker/render_records.py
tools_render_entrypoints:
- tools/render_plan_v1.py
- tools/render_cases_v1.py
- tools/valid_prefix_pipeline_to_analyze_v1.py
existing_template_modules_preserved:
- template_maker/__init__.py
- template_maker/ast_mask.py
- template_maker/ast_mask_lite.py
- template_maker/ast_mask_select.py
- template_maker/ast_mask_tree_sitter.py
- template_maker/cross_generator.py
- template_maker/cross_generator_from_adapters.py
- template_maker/cross_generator_from_candidates.py
- template_maker/generator.py
- template_maker/mac_lifecycle_sequences.py
- template_maker/mask.py
- template_maker/mask_report.py
- template_maker/normalize_enriched.py
- template_maker/pkey_verify_snippets.py
- template_maker/render_cases.py
- template_maker/render_template.py
- template_maker/validate_template.py
reusable_old_logic:
  tools/render_plan_v1.py: render plan construction, preflight, manifest and report generation
  tools/render_cases_v1.py: family case rendering, metadata, render trace and ORACLE_EVENT-aware harness
    construction
  tools/valid_prefix_pipeline_to_analyze_v1.py: valid-prefix pipeline orchestration; retained as compatible
    pipeline entrypoint
conflict_risk: 'low: target module names did not exist; existing template_maker modules were not overwritten'
```
