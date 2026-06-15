# Seed Search Report

- real_seed_search_result: `candidate_seed_found_but_unverified`
- original seed found: `false`
- original seed path: `/tmp/pbmac1_null_salt.p12`
- placeholder found: `datasets/openssl/poc_artifacts/issue_30581/inputs/test.p12`

## Candidate Source Test Vectors

OpenSSL 3.5.5 contains related PBMAC1 malformed salt vectors:

- `pbmac1_256_256.no-salt.p12`
- `pbmac1_256_256.bad-salt-type.p12`
- `pbmac1_256_256.bad-salt.p12`

These are not the original issue seed. They are useful reconstruction hints only.
