# Execution Path Plan

This planner routes candidate-queue entries into four execution paths. The new framework does not remove AST-lite masking, selected mask units, or LLM slot filling; it scopes them to path A where recipe-slot cross-library migration needs structured source and target API binding.

## Paths

- A: recipe-slot cross-library migration
- B: controlled family mutation sprint
- C: app-level validation gap triage
- D: crash/sanitizer evidence audit

## Module Scope

- Path A requires AST-lite mask, selected_mask_units, LLM slot_bindings, adapter_validate, and controlled template rendering.
- Path B uses family-level controlled mutation matrices and controlled renderers; it does not require source-PoC AST for every family.
- Path C tests app/CLI behavior with exit status, output artifacts, stderr, and malformed-input controls.
- Path D audits crash logs, sanitizer signatures, versions, and harness validity before any family expansion.

DER v2 is routed to path C because its current evidence is app-level valid-prefix plus malformed-tail acceptance. MAC lifecycle has now completed path A as `full_a_path_compliant`: GLM slot filling, adapter_validate, cross_generator_from_adapters, render_cases, compile_run, and generic analyze_results/analyze_cross_results all ran in the standard artifact layout.

## Current Audit Status

- A path: MAC lifecycle is `full_a_path_compliant`. The completed artifact is `artifacts/migrations/mac_lifecycle_glm_full_a_path/`; it records 8 run_ok cases, 4 cross-library pairs, 2 migrated_safe pairs, and 2 migration_needs_triage pairs.
- C path: DER full-consumption v2 has completed app-level validation-gap triage. It remains a semantic validation-gap candidate, not a crash and not a confirmed CVE.
- D path: crash/sanitizer top5 evidence audit is complete. `OPENSSL-ISSUE-28669` is the only audited top5 item with local SIGSEGV / exit 139 / Valgrind Invalid read evidence and is recommended as the next sprint seed. The other top5 items need manual confirmation before promotion.
- D-then-B secure heap path: `secure_heap_state_lifecycle_v1` has completed seed validation and oracle calibration. It is not full migration. Version provenance confirms current OpenSSL 3.5.5 static `libcrypto.a` linkage, while historical affected/fixed versions remain unknown locally. The current novelty label is `current_version_robustness_candidate_with_unknown_historical_overlap`; next action is same-family, cross-version, or analogous lifecycle pattern expansion.

## Summary

- A: 16 candidates
- B: 7 candidates
- C: 1 candidates
- D: 18 candidates

## Candidate Table

| candidate_id | path | readiness | severity | combined | next action |
| --- | --- | ---: | ---: | ---: | --- |
| asn1_nested_boundary:OPENSSL-ISSUE-27572 | A | 1.0000 | 0.5500 | 0.7975 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| asn1_nested_boundary:OPENSSL-ISSUE-16196 | D | 0.8000 | 0.7500 | 0.7775 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| asn1_nested_boundary:OPENSSL-ISSUE-18168 | D | 0.8000 | 0.7500 | 0.7775 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| asn1_nested_boundary:OPENSSL-ISSUE-26106 | D | 0.8000 | 0.7500 | 0.7775 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| asn1_nested_boundary:OPENSSL-ISSUE-28669 | D | 0.8000 | 0.7500 | 0.7775 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| asn1_nested_boundary:OPENSSL-ISSUE-30581 | D | 0.8000 | 0.7500 | 0.7775 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| cipher_aead_lifecycle:MBEDTLS-POC-0004 | A | 0.7500 | 0.7000 | 0.7275 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| memory_length_boundary:MBEDTLS-POC-0001 | D | 0.6500 | 0.7500 | 0.6950 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| memory_length_boundary:MBEDTLS-POC-0011 | D | 0.6500 | 0.7500 | 0.6950 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| mac_lifecycle:OPENSSL-ISSUE-22842 | A | 0.8000 | 0.5500 | 0.6875 | prepare recipe-slot adapter, validate slot bindings, then render a small MAC lifecycle matrix |
| pkey_verify_semantic:MBEDTLS-POC-0003 | D | 0.9000 | 0.4000 | 0.6750 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| pkey_verify_semantic:OPENSSL-ISSUE-15899 | D | 0.9000 | 0.4000 | 0.6750 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| pkey_verify_semantic:OPENSSL-ISSUE-19524 | D | 0.9000 | 0.4000 | 0.6750 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| pkey_verify_semantic:OPENSSL-ISSUE-21935 | D | 0.9000 | 0.4000 | 0.6750 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| pkey_verify_semantic:OPENSSL-ISSUE-30889 | D | 0.9000 | 0.4000 | 0.6750 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| der_full_consumption:MBEDTLS-POC-0020 | C | 1.0000 | 0.2500 | 0.6625 | triage app-level command behavior with output artifacts, exit status, and malformed-tail controls |
| pkey_verify_semantic:OPENSSL-ISSUE-22388 | B | 1.0000 | 0.2000 | 0.6400 | queue_for_family_triage |
| pkey_verify_semantic:OPENSSL-ISSUE-30291 | B | 1.0000 | 0.2000 | 0.6400 | queue_for_family_triage |
| pkey_verify_semantic:OPENSSL-ISSUE-30432 | B | 1.0000 | 0.2000 | 0.6400 | queue_for_family_triage |
| pkey_verify_semantic:OPENSSL-ISSUE-8435 | B | 1.0000 | 0.2000 | 0.6400 | queue_for_family_triage |
| cipher_aead_lifecycle:MBEDTLS-POC-0028 | A | 0.7500 | 0.4500 | 0.6150 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| asn1_nested_boundary:MBEDTLS-POC-0017 | A | 0.8000 | 0.3500 | 0.5975 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| pkey_verify_semantic:PKEY_VERIFY_FAMILY_V0 | B | 1.0000 | 0.0000 | 0.5500 | retain as stable safe-negative regression baseline and use feedback-guided dimensions for v2 |
| pkey_verify_semantic:PKEY_VERIFY_FAMILY_V1 | B | 1.0000 | 0.0000 | 0.5500 | retain as stable safe-negative regression baseline and use feedback-guided dimensions for v2 |
| api_state_machine:OPENSSL-ISSUE-18659 | D | 0.5000 | 0.5500 | 0.5225 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| api_state_machine:OPENSSL-ISSUE-2630 | D | 0.5000 | 0.5500 | 0.5225 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| api_state_machine:OPENSSL-ISSUE-29645 | D | 0.5000 | 0.5500 | 0.5225 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| cipher_aead_lifecycle:OPENSSL-ISSUE-17715 | D | 0.5000 | 0.5500 | 0.5225 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| cipher_aead_lifecycle:OPENSSL-ISSUE-8980 | D | 0.5000 | 0.5500 | 0.5225 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| x509_parsing:MBEDTLS-POC-0027 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-11567 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-11772 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-14457 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-23325 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-29418 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-29574 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-6788 | A | 0.7500 | 0.2000 | 0.5025 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-9043 | D | 0.5000 | 0.4000 | 0.4550 | audit crash log, sanitizer signature, version, and harness validity before promoting to runnable family |
| api_state_machine:MBEDTLS-POC-0005 | A | 0.5000 | 0.1500 | 0.3425 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-13860 | A | 0.0000 | 0.0000 | 0.0000 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| x509_parsing:OPENSSL-ISSUE-14675 | A | 0.0000 | 0.0000 | 0.0000 | run recipe-slot adapter generation through adapter_validate before rendering harnesses |
| bn_mpi_arithmetic:MBEDTLS-POC-0002 | B | 0.0000 | 0.0000 | 0.0000 | document_projection_limitation |
