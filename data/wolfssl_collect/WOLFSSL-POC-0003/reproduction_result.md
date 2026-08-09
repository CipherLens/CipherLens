
## PR 10071 Patch Analysis

### Patch Summary

PR 10071 adds bounds checks around wolfSSL X.509 date handling APIs.

Relevant APIs:

- wolfSSL_X509_notBefore
- wolfSSL_X509_notAfter
- wolfSSL_X509_set_notBefore
- wolfSSL_X509_set_notAfter

### Root Cause Hypothesis

The vulnerable implementation may propagate an oversized ASN1_TIME length into the WOLFSSL_X509 date fields. Later, wolfSSL_X509_notBefore or wolfSSL_X509_notAfter returns an ASN-encoded date in the form:

[type][length][data...]

If the stored length is too large, the function may write beyond the fixed-size notBeforeData or notAfterData buffer.

### Patch Behavior

The fixed implementation rejects oversized date lengths using bounds checks equivalent to:

- length < 0
- length > CTC_DATE_SIZE - 2

### Official Test Clue

The PR test constructs a crafted WOLFSSL_ASN1_TIME with:

- type = ASN_UTC_TIME
- length = 255

and expects wolfSSL_X509_set_notAfter / wolfSSL_X509_set_notBefore to reject it.

### Reproduction Strategy

Use an API-level minimal harness first:

1. Create X509 object.
2. Create crafted WOLFSSL_ASN1_TIME.
3. Set crafted_time.length = 255.
4. Call wolfSSL_X509_set_notAfter and wolfSSL_X509_notAfter.
5. Call wolfSSL_X509_set_notBefore and wolfSSL_X509_notBefore.
6. Compare vulnerable v5.9.0-stable, fixed v5.9.1-stable, and current wolfSSL.

## Successful Reproduction: wolfSSL v5.9.0-stable API-level X.509 Date Harness

### Build

- Library: wolfSSL
- Version: v5.9.0-stable
- Commit: 922d04b3568c6428a9fb905ddee3ef5a68db3108
- Latest commit:
  - 922d04b35 2026-03-18 15:57:35 -0700 Merge pull request #10008 from JacobBarthelmeh/release
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-v5.9.0-stable-asan-x509date
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq

### Harness

- Harness source: poc/poc_x509_date_min.c
- Harness type: API-level minimal harness
- Triggered APIs:
  - wolfSSL_X509_set_notAfter
  - wolfSSL_X509_notAfter
  - wolfSSL_X509_set_notBefore
  - wolfSSL_X509_notBefore

### Crafted Input

- Input type: crafted WOLFSSL_ASN1_TIME object
- type: ASN_UTC_TIME
- length: 255
- data: initialized safely inside WOLFSSL_ASN1_TIME::data
- Input provenance: reconstructed_from_pr_10071_official_test_pattern

### Observed Result

Both notAfter and notBefore paths triggered AddressSanitizer heap-buffer-overflow.

#### notAfter path

- Exit code: 134
- ERROR: AddressSanitizer: heap-buffer-overflow
- WRITE of size 255
- SUMMARY: AddressSanitizer: heap-buffer-overflow in memcpy
- ABORTING

#### notBefore path

- Exit code: 134
- ERROR: AddressSanitizer: heap-buffer-overflow
- WRITE of size 255
- SUMMARY: AddressSanitizer: heap-buffer-overflow in memcpy
- ABORTING

### Evidence Logs

- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-x509date/ldd.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-x509date/after_repro.log
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-x509date/after_exit_code.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-x509date/before_repro.log
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-x509date/before_exit_code.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-x509date/asan_grep_result.txt

### Current Conclusion

The API-level minimal harness successfully reproduces the X.509 date length overflow on wolfSSL v5.9.0-stable. Both wolfSSL_X509_notAfter and wolfSSL_X509_notBefore paths produce ASan heap-buffer-overflow with WRITE of size 255 and exit code 134.

## Fixed Release Candidate Test: wolfSSL v5.9.1-stable

### Build

- Library: wolfSSL
- Version: v5.9.1-stable
- Commit: 1d363f3adceba9d1478230ede476a37b0dcdef24
- Latest commit:
  - 1d363f3ad 2026-04-08 10:40:06 -0700 Merge pull request #10163 from JacobBarthelmeh/release
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-v5.9.1-stable-asan-x509date
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq

### Harness

- Harness source: poc/poc_x509_date_min.c
- Harness type: API-level minimal harness
- Tested APIs:
  - wolfSSL_X509_set_notAfter
  - wolfSSL_X509_notAfter
  - wolfSSL_X509_set_notBefore
  - wolfSSL_X509_notBefore

### Crafted Input

- Input type: crafted WOLFSSL_ASN1_TIME object
- type: ASN_UTC_TIME
- length: 255
- Input provenance: reconstructed_from_pr_10071_official_test_pattern

### Observed Result

wolfSSL v5.9.1-stable did not trigger the ASan heap-buffer-overflow observed on v5.9.0-stable.

Observed behavior:

- notAfter exit code: 1
- notBefore exit code: 1
- No ERROR: AddressSanitizer
- No heap-buffer-overflow
- No WRITE of size 255 crash
- No ABORTING
- Precise crash-signal check: NO_CRASH_SIGNAL

The exit code 1 is expected for the fixed version because the oversized ASN1_TIME length is rejected by the added bounds check.

### Evidence Logs

- logs/fixed_version/wolfssl-v5.9.1-stable-asan-x509date/ldd.txt
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-x509date/after_repro.log
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-x509date/after_exit_code.txt
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-x509date/before_repro.log
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-x509date/before_exit_code.txt
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-x509date/asan_grep_result.txt

### Current Conclusion

wolfSSL v5.9.1-stable is a fixed release candidate for WOLFSSL-POC-0003. The same API-level harness that triggers ASan heap-buffer-overflow on v5.9.0-stable is safely rejected on v5.9.1-stable without sanitizer crash evidence.

## Current Version Test: wolfSSL current

### Build

- Library: wolfSSL
- Version description: v5.9.1-stable-1373-g8fca95ce6
- Commit: 8fca95ce651d6e370d91f5598786de4bc66aa2c2
- Latest commit:
  - 8fca95ce6 2026-06-05 16:27:00 -0500 Merge pull request #10532 from rlm2002/zd21800
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-current-asan-x509date
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq

### Harness

- Harness source: poc/poc_x509_date_min.c
- Harness type: API-level minimal harness
- Tested APIs:
  - wolfSSL_X509_set_notAfter
  - wolfSSL_X509_notAfter
  - wolfSSL_X509_set_notBefore
  - wolfSSL_X509_notBefore

### Crafted Input

- Input type: crafted WOLFSSL_ASN1_TIME object
- type: ASN_UTC_TIME
- length: 255
- Input provenance: reconstructed_from_pr_10071_official_test_pattern

### Observed Result

The current wolfSSL version did not trigger the ASan heap-buffer-overflow observed on v5.9.0-stable.

Observed behavior:

- notAfter exit code: 1
- notBefore exit code: 1
- No ERROR: AddressSanitizer
- No heap-buffer-overflow
- No WRITE of size 255 crash
- No ABORTING
- Precise crash-signal check: NO_CRASH_SIGNAL

The exit code 1 is expected because the oversized ASN1_TIME length is rejected by the bounds check.

### Evidence Logs

- logs/current_version/wolfssl-current-asan-x509date/ldd.txt
- logs/current_version/wolfssl-current-asan-x509date/after_repro.log
- logs/current_version/wolfssl-current-asan-x509date/after_exit_code.txt
- logs/current_version/wolfssl-current-asan-x509date/before_repro.log
- logs/current_version/wolfssl-current-asan-x509date/before_exit_code.txt
- logs/current_version/wolfssl-current-asan-x509date/asan_grep_result.txt

### Current Conclusion

The current wolfSSL version safely rejects the same oversized ASN1_TIME input in both notAfter and notBefore paths without sanitizer crash evidence.
