# Next Family Recommendation

- Recommended next family: `asn1_nested_boundary`
- Proposed execution path: `D_then_A`
- Next task name: `asn1_nested_boundary_d_path_audit_v1`

## Why This Is Better Than Continuing AEAD-GCM

The three high-value GCM candidates were downgraded to legal semantics or harmless/mapping-gap behavior. Continuing those exact paths would mostly add repetition. `asn1_nested_boundary` has better oracle shape for the next sprint: malformed nested structures, explicit parser rejection/crash/semantic behavior, and existing historical seeds.

## Evidence To Read First

- `MBEDTLS-POC-0017`
- `normalized_templates/x509/x509_asn1_inner_boundary/`
- Existing `d2i_X509` safe/safe migration results, as negative-control context.
- `OPENSSL-ISSUE-30581` if available under `datasets/openssl/poc_artifacts/`.

## GLM / D-Path

Do not start with GLM. First run a D-path audit to stabilize the issue seed, reproduction boundary, oracle, and sanitizer/return-code evidence. Use GLM later only for recipe-slot adapter bindings after the target API and oracle are stable.
