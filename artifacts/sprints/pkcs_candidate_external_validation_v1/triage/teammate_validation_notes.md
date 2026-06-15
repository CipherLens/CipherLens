# PKCS Candidate External Validation Notes

These are not confirmed vulnerabilities, CVEs, or exploitability claims.
They are local prefix-consumption candidates that need API/app-level validation.

## Candidates

### pkcs_candidate_001

- case_id: `pkcs_container_parsing_openssl__supp_002__valid_pkcs12_plus_trailing_seed_required`
- container_type: `pkcs12`
- seed_id: `synthetic_pkcs12_valid_minimal`
- mutation_strategy: `valid_seed_plus_trailing_00`
- oracle accepted: True
- oracle full_consumption: False
- oracle full_consumption_gap: True
- replay command: `/usr/bin/openssl pkcs12 -in /home/wen/work/crypto-pattern-fuzz/artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1/rendered_cases/pkcs_valid_prefix__case_002/input.bin -noout -passin pass:`
- replay return_code: 0
- classification: `caller_must_check_consumption`
- reason: d2i-style parser accepted a prefix while trailing bytes remain; this is a caller-consumption-check obligation rather than a standalone vulnerability claim
- next_action: external validation should determine whether any real app-level caller omits full-consumption checks

### pkcs_candidate_002

- case_id: `pkcs_container_parsing_openssl__supp_003__preserve_outer_pkcs_mutate_inner_seed_required`
- container_type: `pkcs7`
- seed_id: `synthetic_pkcs7_valid_certbag`
- mutation_strategy: `valid_pkcs7_seed_plus_trailing_ff00`
- oracle accepted: True
- oracle full_consumption: False
- oracle full_consumption_gap: True
- replay command: `/usr/bin/openssl pkcs7 -inform DER -in /home/wen/work/crypto-pattern-fuzz/artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1/rendered_cases/pkcs_valid_prefix__case_003/input.bin -noout`
- replay return_code: 0
- classification: `caller_must_check_consumption`
- reason: d2i-style parser accepted a prefix while trailing bytes remain; this is a caller-consumption-check obligation rather than a standalone vulnerability claim
- next_action: external validation should determine whether any real app-level caller omits full-consumption checks

## Recommended External Checks

- Confirm OpenSSL `d2i_*` prefix-parse semantics for PKCS12/PKCS7 inputs with trailing bytes.
- Check whether any app-level parser wrapper is expected to require full input consumption.
- Treat CLI acceptance as parser replay evidence only; consumed length comes from the instrumented harness event.
- Do not escalate to vulnerability language without an app-level missing-consumption-check path.
