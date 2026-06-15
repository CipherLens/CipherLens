# Seed Discovery Report

- OPENSSL-ISSUE-30581 artifact found: `true`
- seed_status: `only_placeholder_input_found`
- strict_reproduction_possible: `false`
- reason: only placeholder input available
- expected original input: `['/tmp/pbmac1_null_salt.p12']`
- local input: `datasets/openssl/poc_artifacts/issue_30581/inputs/test.p12`
- local input sha256: `2335c07d81b41521135bc2061cab82e6bf5e7d553e29d82d5f79f7360357aad0`

The local `.p12` is not treated as a real reproduction seed because metadata explicitly says `placeholder_input_used` and `missing_original_input: true`.
