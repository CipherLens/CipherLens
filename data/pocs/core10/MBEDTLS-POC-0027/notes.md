# Working Notes

## Manual tasks

- [ ] Confirm exact fixing commit.
- [ ] Locate exact regression test case.
- [ ] Extract minimal PoC or API call sequence.
- [ ] Identify buggy and fixed versions.
- [ ] Run reproduction test locally.
- [ ] Record failure signal.
- [ ] Confirm AST mutation point.
- [ ] Prepare RAG context sources.

## Investigation log

- TBD

## Candidate commands

```bash
# Inspect source files
cat library_files.txt

# Inspect test files
cat test_files.txt

# Inspect commits
cat commits.txt
```

## Exact fixing commit confirmed

Confirmed direct fix commit:

- ef41d8ccbe91c5c59e32f47ceda3365525c47124

Buggy version:

- ef41d8ccbe91c5c59e32f47ceda3365525c47124^

Root cause:
In TLS 1.3 certificate validation, keyUsage and extKeyUsage failures were detected, but the corresponding verification flags were not propagated into verify_result.

Affected public API:
- mbedtls_ssl_get_verify_result()

Direct mutation point:
- library/ssl_tls13_generic.c: ssl_tls13_validate_certificate()

Confirmed missing buggy behavior:
- keyUsage failure did not set MBEDTLS_X509_BADCERT_KEY_USAGE
- extKeyUsage failure did not set MBEDTLS_X509_BADCERT_EXT_KEY_USAGE

Confirmed fixed behavior:
- keyUsage failure sets MBEDTLS_X509_BADCERT_KEY_USAGE
- extKeyUsage failure sets MBEDTLS_X509_BADCERT_EXT_KEY_USAGE

Regression test source:
- tests/ssl-opt.sh

## Minimal reproduction completed

The fixed regression-test expectation was copied into the buggy worktree and run against the buggy binaries.

Fixed result:

- fixed program with fixed ssl-opt expectation passed
- the expected verify_result detail is present:
  - `! Usage does not match the keyUsage extension`

Buggy result:

- buggy program with fixed ssl-opt expectation failed
- missing expected pattern:
  - `! Usage does not match the keyUsage extension`
- exit_code = 1

Conclusion:

MBEDTLS-POC-0027 is now locally reproduced. The confirmed failure signal is that TLS 1.3 keyUsage/extKeyUsage verification failure is not propagated to `mbedtls_ssl_get_verify_result()` through the expected verify_result flags.

Direct mutation point:

- library/ssl_tls13_generic.c: ssl_tls13_validate_certificate()
