# Unit Test and Example Evidence: mbedTLS 4.1.0 Core APIs

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## mbedtls_mpi_write_string

Status: found in local tests.

Searched paths:

- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/tests`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/programs`

Evidence:

- `tf-psa-crypto/tests/suites/test_suite_bignum.function`: direct calls around lines 138, 162, 182, and 202.
- `tf-psa-crypto/drivers/builtin/src/bignum.c`: internal use around line 766.

Harness notes:

- Test evidence covers output-size handling and `MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL`.
- Useful for buffer-length and `olen` adapter generation.

## mbedtls_mpi_sub_abs

Status: found in local tests.

Searched paths:

- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src`

Evidence:

- `tf-psa-crypto/tests/suites/test_suite_bignum.function`: direct calls around lines 671, 781, 789, and 797.
- `tf-psa-crypto/tests/suites/test_suite_bignum.misc.data`: many `mbedtls_mpi_sub_abs` cases around lines 817-880, including `|B| > |A|` and more-limbs cases.

Harness notes:

- Local tests cover arithmetic return behavior.
- They do not by themselves expose a canary-after-output-limbs oracle; that remains a specialized PoC harness pattern.

## mbedtls_pk_verify_ext

Status: found in local tests and library callers.

Searched paths:

- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/tests/suites`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/library`

Evidence:

- `tf-psa-crypto/tests/suites/test_suite_pk.function`: direct calls around lines 812, 817, 899, 1129, 1363, 1526, 1561, 1620, 1624, and 1636.
- `tests/suites/test_suite_x509write.function`: direct use around line 43.
- Library callers include `library/x509_crt.c`, `library/pkcs7.c`, `library/ssl_tls12_client.c`, `library/ssl_tls12_server.c`, and `library/ssl_tls13_generic.c`.

Harness notes:

- Good evidence for signature verification and RSA-PSS paths.
- Current 4.1.0 uses `mbedtls_pk_sigalg_t`, e.g. `MBEDTLS_PK_SIGALG_RSA_PSS`.

## mbedtls_cipher_finish

Status: found in local tests and docs.

Searched paths:

- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/docs`

Evidence:

- `tf-psa-crypto/tests/suites/test_suite_cipher.function`: direct calls around lines 272, 274, 469, 490, 559, 651, 758, 782, 839, 919, and 1333.
- `tf-psa-crypto/docs/psa-transition.md`: documents update/finish usage around lines 390 and 417.

Harness notes:

- Good evidence for public finalization call sequence.
- Useful for output pointer and output length oracle patterns.

## get_pkcs_padding / mbedtls_get_pkcs_padding

Status: found in local tests.

Searched paths:

- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src`

Evidence:

- `tf-psa-crypto/tests/suites/test_suite_cipher.function`: direct wrapper `get_pkcs_padding` around lines 1573 and 1580.
- `tf-psa-crypto/tests/suites/test_suite_cipher.constant_time.data`: direct valid and invalid PKCS padding cases.
- Current implementation name is `mbedtls_get_pkcs_padding` in `tf-psa-crypto/drivers/builtin/src/cipher.c`.

Harness notes:

- Direct internal tests are useful for constant-time and invalid-padding output-length evidence.
- Public migration harnesses should usually reach this through `mbedtls_cipher_finish`.

## mbedtls_asn1_store_named_data

Status: found in local tests and library callers.

Searched paths:

- `/home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites`
- `/home/wen/work/clean_sources/mbedtls-4.1.0/library`

Evidence:

- `tf-psa-crypto/tests/suites/test_suite_asn1write.function`: direct calls around lines 508, 563, and 601.
- `library/x509_create.c`: callers around lines 531 and 573.

Harness notes:

- Evidence covers repeated named-data storage patterns.
- For CVE-style stale pointer/length migration, include explicit zero-length update and same-OID update sequence.

## mbedtls_pk_rsa

```yaml
status: not_found_in_local_tests
searched_paths:
  - /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/include
  - /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/extras
  - /home/wen/work/clean_sources/mbedtls-4.1.0/include
  - /home/wen/work/clean_sources/mbedtls-4.1.0/library
  - /home/wen/work/clean_sources/mbedtls-4.1.0/tests
  - /home/wen/work/clean_sources/mbedtls-4.1.0/programs
missing_reason: local mbedTLS 4.1.0 source does not contain a current public mbedtls_pk_rsa API or direct current test/example for it
recommended_next_search:
  - upstream_github_tests
  - upstream_github_regression_tests
  - upstream_github_commit_diff
  - upstream_github_issue_or_pr_discussion
  - mbedTLS official GitHub repository tests/suites/
  - mbedTLS official GitHub repository programs/
  - mbedTLS official GitHub repository library/
```
