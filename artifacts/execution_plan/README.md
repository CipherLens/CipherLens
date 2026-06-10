# Execution Path Planner

`analysis/plan_execution_paths.py` consumes the candidate queue, scheduler seed, and unified pattern bank, then emits a deterministic A/B/C/D execution plan.

The important integration point is that AST-lite masking, selected_mask_units, and LLM slot filling are still part of the framework. They are required for path A, where a source API pattern is migrated to a target API through recipe-slot adapters and `adapter_validate`.

DER app-level full-consumption does not require AST masking in its current path because the observable is application behavior: command exit status, generated output artifact, stderr, and malformed-tail controls.

MAC lifecycle has completed the GLM-assisted full A-path. The completed artifact is `artifacts/migrations/mac_lifecycle_glm_full_a_path/` and the verified chain is:

```text
GLM slot filling -> adapter_validate -> cross_generator_from_adapters -> render_cases -> compile_run -> generic analyze_results/analyze_cross_results
```

The result is `full_a_path_compliant`, with 8 run_ok cases, 4 OpenSSL/mbedTLS pairs, 2 migrated_safe pairs, and 2 migration_needs_triage pairs. The triage pairs are semantic divergence around repeated-final and update-after-final behavior, not vulnerability claims.

The crash/sanitizer top5 audit is a D-path evidence check, not a vulnerability discovery claim. It recommends `secure_heap_state_lifecycle_v1` seeded by `OPENSSL-ISSUE-28669` because that is the only top5 item with local SIGSEGV / exit 139 / Valgrind Invalid read evidence. The remaining top5 issues require manual confirmation.

`secure_heap_state_lifecycle_v1` has now completed D-then-B seed validation and
version provenance. It should be treated as oracle calibration and a
current-version robustness candidate with unknown historical overlap, not as a
full migration result. The next step is pattern expansion across OpenSSL
same-family APIs, OpenSSL versions, or analogous lifecycle APIs in other
libraries.
