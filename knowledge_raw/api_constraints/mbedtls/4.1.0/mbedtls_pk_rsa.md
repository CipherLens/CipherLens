# API Constraints: mbedtls_pk_rsa (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API Availability

- API/function name: `mbedtls_pk_rsa`
- Status in mbedTLS 4.1.0 current source: `not_available_in_current_public_api`
- Evidence: local `rg` did not find a declaration or implementation of `mbedtls_pk_rsa()` in `tf-psa-crypto/include`, `tf-psa-crypto/extras`, `include`, or `library`.
- Compatibility note: `tf-psa-crypto/docs/1.0-migration-guide.md` states that `mbedtls_pk_setup()`, `mbedtls_pk_rsa()` and `mbedtls_pk_ec()` have been removed.

## Harness Generation Notes

- New mbedTLS 4.1.0 harnesses should not call `mbedtls_pk_rsa()`.
- For RSA-PSS verification, prefer `mbedtls_pk_verify_ext()` and public key setup/parsing APIs available in the current version.
- If reproducing older-version bugs such as `MBEDTLS-POC-0003`, treat `mbedtls_pk_rsa()` as historical/internal compatibility evidence, not as a current API target.

## Vulnerability-Pattern Migration Notes

- `MBEDTLS-POC-0003` involved a NULL RSA-context extraction path in older code.
- In current 4.1.0, migration knowledge should focus on generic key dispatch and safe rejection of incompatible/opaque contexts, not on direct RSA internal pointer access.

## Related Tests or Examples Found Locally

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
