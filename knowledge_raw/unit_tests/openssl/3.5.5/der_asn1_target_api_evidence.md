# Unit Test / Example Evidence: OpenSSL DER / ASN.1 Target APIs

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## APIs Covered

- `d2i_X509`
- `d2i_X509_bio`
- `ASN1_item_d2i`
- `d2i_PrivateKey`
- `d2i_AutoPrivateKey`
- `d2i_RSAPrivateKey`
- `d2i_RSA_PUBKEY`
- `d2i_PUBKEY`

## Found Evidence

status: partially_found_in_local_tests

- `test/x509_test.c`
  - Direct `d2i_X509()`, `d2i_PUBKEY()`, and `d2i_PrivateKey()` calls.
- `test/pkcs7_test.c`
  - Direct `d2i_X509_bio()` calls.
- `test/evp_extra_test.c`
  - `test_d2i_AutoPrivateKey` checks returned key type and `p == input + input_len`.
- `test/evp_extra_test2.c`
  - `test_d2i_AutoPrivateKey_ex` and legacy `d2i_RSAPrivateKey()` usage.
- `crypto/x509/v3_lib.c`
  - Internal extension decode through `ASN1_item_d2i()`.

## Missing Local Evidence

status: not_found_in_local_tests

api: `d2i_RSA_PUBKEY`

searched_paths:
- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/apps`
- `/home/wen/work/clean_sources/openssl-3.5.5/demos`
- `/home/wen/work/clean_sources/openssl-3.5.5/crypto/x509`

missing_reason: local source contains the implementation in `crypto/x509/x_pubkey.c`, but no direct local unit test was found that calls `d2i_RSA_PUBKEY()` as the top-level API.

recommended_next_search:
- upstream_github_tests
- upstream_github_regression_tests
- upstream_github_commit_diff
- upstream_github_issue_or_pr_discussion

## Harness Relevance

- `d2i_X509()` and `ASN1_item_d2i()` are strong candidates for nested ASN.1 boundary migration.
- `d2i_RSAPrivateKey()`, `d2i_AutoPrivateKey()`, `d2i_PrivateKey()`, and `d2i_PUBKEY()` are useful for DER trailing-garbage migration, especially when pointer advancement is checked.
