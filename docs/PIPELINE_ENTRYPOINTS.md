# Pipeline Entrypoints

The current pipeline is still sprint-driven. It is not yet scheduler-driven.
`tools/` contains command-line entrypoints and orchestration scripts, while core
logic lives in package directories.

## Recommended Entrypoint Pattern

Use `python3 -m <package.module>` for core package modules when possible.
Use `python3 tools/<name>.py` only for compatibility wrappers or sprint
orchestration.

## Current Ownership

```text
runner/
  runner.sanitizer_env
  runner.run_records
  runner.family_compile_runner

analyzer/
  analyzer.oracle_event_parser
  analyzer.oracle_aware_analyzer
  analyzer.semantic_labels
  analyzer.candidate_labels

mutation/
  mutation.family_mutation_planner
  mutation.valid_prefix_refinement
  mutation.mutation_policy
  mutation.mutation_case_records

template_maker/
  template_maker.family_render_plan
  template_maker.family_case_renderer
  template_maker.oracle_instrumentation
  template_maker.render_records

analysis/
  analysis.runtime_feedback
  analysis.candidate_queue
  analysis.mutation_feedback
  analysis.scheduler_proposal
  analysis.family_loop_closure
  analysis.analysis_records
```

## Wrapper Policy

Compatibility wrappers may remain in `tools/`, for example:

```text
tools/render_plan_v1.py
tools/render_cases_v1.py
tools/runtime_feedback_integration_v1.py
tools/family_loop_closure_report_v1.py
```

These wrappers should import and call package-level `main()` functions. They
should not contain core rendering, analysis, mutation, execution, or feedback
logic.

## Current Mainline

The next functional mainline is:

```text
valid_seed_discovery_pkcs_v1
```

Reason:

- `asn1_nested_boundary` has reached a family-level runtime feedback loop.
- Candidate observations remain `external_validation_pending`.
- `pkcs_container_parsing` remains blocked by missing verified valid seed.

Do not promote sprint artifacts into the pattern bank or scheduler seed until
their import gate and validation criteria are satisfied.
