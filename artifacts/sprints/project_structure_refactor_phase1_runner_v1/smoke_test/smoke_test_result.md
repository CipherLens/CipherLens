# Smoke Test Result

```yaml
schema: runner_refactor_smoke_test_v1
case:
  render_job_id: render__pkcs_container_parsing__openssl__seed_preserving_baseline__case_001
  case_id: pkcs_container_parsing_openssl__mut_001__seed_preserving_baseline
  family: pkcs_container_parsing
  target_library: openssl
  mutation_strategy: seed_preserving_baseline
  case_dir: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__seed_preserving_baseline__case_001
  harness_c: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__seed_preserving_baseline__case_001/harness.c
  oracle_instrumentation:
    enabled: true
    profile: oracle_event_v1
    expected_event_prefix: ORACLE_EVENT
  render_status: rendered
openssl_install: /home/wen/work/clean_sources/openssl-3.5.5/_install
include_dir_exists: false
lib_dir: /home/wen/work/clean_sources/openssl-3.5.5/_install/lib
lib_dir_exists: false
gcc: /usr/bin/gcc
executed: false
compile: not_run
run: not_run
quality: partial
notes:
- smoke test skipped because gcc or OpenSSL install paths are missing
- dry-run compile command generated through runner.family_compile_runner.command_for
dry_run_compile_command_generated: true
dry_run_compile_command: gcc -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
  -I/home/wen/work/clean_sources/openssl-3.5.5/_install/include artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__seed_preserving_baseline__case_001/harness.c
  -L/home/wen/work/clean_sources/openssl-3.5.5/_install/lib -Wl,-rpath,/home/wen/work/clean_sources/openssl-3.5.5/_install/lib
  -lssl -lcrypto -ldl -pthread -o artifacts/sprints/project_structure_refactor_phase1_runner_v1/smoke_test/dry_run/case.bin
dry_run_binary_path: artifacts/sprints/project_structure_refactor_phase1_runner_v1/smoke_test/dry_run/case.bin
```
