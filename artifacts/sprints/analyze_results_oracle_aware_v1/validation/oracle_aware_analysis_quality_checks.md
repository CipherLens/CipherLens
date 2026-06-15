# Quality Checks

```yaml
schema: oracle_aware_analysis_quality_checks_v1
generated_at: '2026-06-12T03:39:14+00:00'
expected_cases: 14
cases_analyzed: 14
oracle_events_loaded: 49
cases_with_events: 14
openssl_only: true
mbedtls_analyzed: false
all_cases_have_semantic_observation: true
all_cases_have_candidate_label: true
all_cases_have_family: true
all_cases_have_mutation_strategy: true
no_rerun_executed: true
no_compile_executed: true
no_glm_called: true
no_feedback_written: true
no_confirmed_vulnerability_claim: true
quality_status: pass
notes:
- offline oracle-aware analysis only
- normal_exit is not interpreted as proof of safety
- full_consumption=false on accepted=false paths is not treated as vulnerability evidence
```
