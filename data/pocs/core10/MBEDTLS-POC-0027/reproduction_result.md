# Reproduction Result: MBEDTLS-POC-0027

## Status

reproduced

## Source

CVE-2024-45159

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0027-buggy
- commit: ef41d8ccbe91c5c59e32f47ceda3365525c47124^

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0027-fixed
- commit: ef41d8ccbe91c5c59e32f47ceda3365525c47124

## Direct fix commit

- ef41d8ccbe91c5c59e32f47ceda3365525c47124

## Minimal reproduction method

This PoC uses the fixed regression-test expectation from `tests/ssl-opt.sh` and runs it against the buggy program binaries.

The copied fixed-expectation script is:

- repos/worktrees/MBEDTLS-POC-0027-buggy/tests/ssl-opt.poc0027-fixed-expect.sh

## Trigger

Regression test:

keyUsage cli-auth 1.3: RSA, KeyEncipherment: fail (soft)

This is a TLS 1.3 optional client-authentication case where the client certificate has an incompatible keyUsage extension.

## Fixed behavior

The fixed version passes the fixed regression test.

Expected evidence:

- `! Usage does not match the keyUsage extension` appears in the server output.
- The handshake remains soft/optional and does not hard-fail.

## Buggy behavior

The buggy version fails the fixed regression test.

Observed output:

keyUsage cli-auth 1.3: RSA, KeyEncipherment: fail (soft) .......... FAIL
! pattern '! Usage does not match the keyUsage extension' MUST be present in the Server output
FAILED (0 / 1 tests (0 skipped))
exit_code=1

## Root cause

In the buggy TLS 1.3 certificate validation path, keyUsage and extKeyUsage failures are detected, but the corresponding verification flags are not propagated into `verify_result`.

As a result, `mbedtls_ssl_get_verify_result()` does not report the expected certificate verification failure bits.

## Confirmed mutation point

- library/ssl_tls13_generic.c: ssl_tls13_validate_certificate()

Missing buggy behavior:

- keyUsage failure does not set `MBEDTLS_X509_BADCERT_KEY_USAGE`
- extKeyUsage failure does not set `MBEDTLS_X509_BADCERT_EXT_KEY_USAGE`

Fixed behavior:

- keyUsage failure sets `MBEDTLS_X509_BADCERT_KEY_USAGE`
- extKeyUsage failure sets `MBEDTLS_X509_BADCERT_EXT_KEY_USAGE`

## Failure signal

TLS 1.3 keyUsage/extKeyUsage verification failure is not propagated to `mbedtls_ssl_get_verify_result()`.

## Logs

- fixed log: logs/poc0027_exact_fix/run_fixed_sslopt_keyusage_soft.log
- buggy with fixed expectation log: logs/poc0027_exact_fix/run_buggy_with_fixed_expect_sslopt_keyusage_soft.log
