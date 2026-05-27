# Unit Test / Example Evidence: OpenSSL PEM Target APIs

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## APIs Covered

- `PEM_read_bio_PrivateKey`
- `PEM_read_bio_PUBKEY`
- `PEM_read_bio_X509`
- `PEM_bytes_read_bio`

## Found Evidence

status: partially_found_in_local_tests

- `test/bio_pw_callback_test.c`
  - Direct encrypted/private-key callback coverage for `PEM_read_bio_PrivateKey()`.
- `test/threadstest.c`, `test/ocspapitest.c`, `test/x509_check_cert_pkey_test.c`
  - Direct `PEM_read_bio_PrivateKey()` usage.
- `test/x509_test.c`, `test/crltest.c`, `test/algorithmid_test.c`, `test/v3ext.c`
  - Direct `PEM_read_bio_X509()` usage.
- `engines/e_ossltest.c`
  - Direct `PEM_read_bio_PUBKEY()` and `PEM_read_bio_PrivateKey()` usage.
- `crypto/pem/pem_pkey.c`
  - Internal high-level key readers call `PEM_bytes_read_bio()` / `PEM_bytes_read_bio_secmem()`.

## Missing Local Evidence

status: not_found_in_local_tests

api: `PEM_bytes_read_bio`

searched_paths:
- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/apps`
- `/home/wen/work/clean_sources/openssl-3.5.5/demos`
- `/home/wen/work/clean_sources/openssl-3.5.5/crypto/pem`

missing_reason: no direct local test harness was found that calls `PEM_bytes_read_bio()` as the top-level test subject; local evidence reaches it mainly through higher-level PEM readers and implementation callers.

recommended_next_search:
- upstream_github_tests
- upstream_github_regression_tests
- upstream_github_commit_diff
- upstream_github_issue_or_pr_discussion
