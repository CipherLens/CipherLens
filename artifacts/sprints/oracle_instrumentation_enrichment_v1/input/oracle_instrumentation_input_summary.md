# Oracle Instrumentation Input Summary

- Previous analyze_results_v1 saw normal_exit/no_crash_observed for all 14 cases.
- normal_exit only proves no observed crash/sanitizer in the bounded run, not parser accept/reject semantics.
- Parser divergence and full-consumption require structured runtime observations from the harness.

- compile/run/analyze: `false`
- original render_cases_v1 overwritten: `false`
- runtime feedback written: `false`
