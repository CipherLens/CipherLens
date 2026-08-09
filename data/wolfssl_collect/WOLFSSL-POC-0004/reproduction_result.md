
## PR 10112 Patch Analysis

### Patch Summary

PR 10112 fixes a copy length check in CertFromX509.

The vulnerable logic is related to AuthorityKeyIdentifier handling.

### Root Cause Hypothesis

The old code checked x509->authKeyIdSz against sizeof(cert->akid), but under the WOLFSSL_AKID_NAME branch it copied x509->authKeyIdSrcSz bytes into cert->akid.

This creates a size confusion:

- authKeyIdSz: size of the keyIdentifier sub-field
- authKeyIdSrcSz: size of the full AuthorityKeyIdentifier extension

If keyIdentifier is small but the full AuthorityKeyIdentifier extension is large, the old guard can pass while the later XMEMCPY writes far beyond cert->akid.

### Official Test Pattern

The PR test constructs a DER certificate with an oversized AuthorityKeyIdentifier extension:

- [0] keyIdentifier: 20 bytes
- [1] authorityCertIssuer: one URI of approximately 4000 bytes
- [2] authorityCertSerialNumber

The test then parses the DER certificate using wolfSSL_X509_d2i and attempts re-encoding via wolfSSL_i2d_X509_bio.

Before the fix, this path overflows cert->akid. After the fix, the conversion should fail gracefully without sanitizer crash evidence.

### Reproduction Strategy

Use a certificate-level reconstructed DER input based on the PR 10112 official test pattern.

Planned trigger path:

1. Build DER certificate with oversized AuthorityKeyIdentifier.
2. Parse it with wolfSSL_X509_d2i.
3. Trigger CertFromX509 through wolfSSL_i2d_X509_bio.
4. Compare wolfSSL v5.9.0-stable, wolfSSL v5.9.1-stable, and current wolfSSL.

## Successful Reproduction: wolfSSL v5.9.0-stable CertFromX509 AKID Overflow

### Build

- Library: wolfSSL
- Version: v5.9.0-stable
- Commit: 922d04b3568c6428a9fb905ddee3ef5a68db3108
- Latest commit:
  - 922d04b35 2026-03-18 15:57:35 -0700 Merge pull request #10008 from JacobBarthelmeh/release
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-v5.9.0-stable-asan-akid
- Build mode: ASan/UBSan, debug, -O0
- Required compile-time option:
  - WOLFSSL_AKID_NAME
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

### Reconstructed Input

- Input file: inputs/reconstructed/cve-2026-5447-akid-overflow-long.der
- Input type: reconstructed DER X.509 certificate
- Input provenance: reconstructed_from_pr_10112_official_test_pattern
- Crafted extension: AuthorityKeyIdentifier
- keyIdentifier length: 20 bytes
- full AuthorityKeyIdentifier source length: approximately 20046 bytes
- Purpose: make authKeyIdSz small while authKeyIdSrcSz exceeds Cert.akid and the Cert heap object boundary.

### Root Cause Confirmation

The vulnerable wolfSSL v5.9.0-stable source contains the old logic:

- checks x509->authKeyIdSz against sizeof(cert->akid)
- under WOLFSSL_AKID_NAME, copies x509->authKeyIdSrcSz bytes into cert->akid

Local layout probing showed:

- sizeof(Cert): 7432
- offsetof(Cert, akid): 2724
- sizeof(Cert.akid): 1332
- bytes from akid start to Cert end: 4708
- minimum copy length to exceed Cert object: 4709

The shorter 4046-byte AKID source caused an internal object overwrite but did not exceed the end of the Cert heap object, so ASan did not report it. The long reconstructed AKID source triggered an ASan-visible heap-buffer-overflow.

### Trigger Path

The harness performs:

1. Build DER certificate with oversized AuthorityKeyIdentifier.
2. Parse DER using wolfSSL_X509_d2i.
3. Trigger CertFromX509 using wolfSSL_i2d_X509_bio.
4. Observe ASan heap-buffer-overflow in CertFromX509.

### Observed Result

- Exit code: 134
- ERROR: AddressSanitizer: heap-buffer-overflow
- WRITE of size 20046
- Crash function: CertFromX509
- Crash location: src/x509.c:11863
- Summary: AddressSanitizer heap-buffer-overflow in memcpy
- ABORTING

### Evidence Logs

- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-akid/akid_repro.log
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-akid/akid_exit_code.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-akid-long/akid_long_repro.log
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-akid-long/akid_long_exit_code.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-akid-long/asan_grep_result.txt
- inputs/reconstructed/cve-2026-5447-akid-overflow-long.der

### Current Conclusion

The certificate-level reconstructed input successfully reproduces CVE-2026-5447 on wolfSSL v5.9.0-stable. The vulnerability is exposed through wolfSSL_X509_d2i followed by wolfSSL_i2d_X509_bio, producing an ASan heap-buffer-overflow in CertFromX509.

## Fixed Release Candidate Test: wolfSSL v5.9.1-stable

### Build

- Library: wolfSSL
- Version: v5.9.1-stable
- Commit: 1d363f3adceba9d1478230ede476a37b0dcdef24
- Latest commit:
  - 1d363f3ad 2026-04-08 10:40:06 -0700 Merge pull request #10163 from JacobBarthelmeh/release
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-v5.9.1-stable-asan-akid
- Build mode: ASan/UBSan, debug, -O0
- Required compile-time option:
  - WOLFSSL_AKID_NAME
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

### Reconstructed Input

- Input file: inputs/reconstructed/cve-2026-5447-akid-overflow-long.der
- Input type: reconstructed DER X.509 certificate
- Input provenance: reconstructed_from_pr_10112_official_test_pattern
- Crafted extension: oversized AuthorityKeyIdentifier

### Observed Result

wolfSSL v5.9.1-stable did not trigger the ASan heap-buffer-overflow observed on v5.9.0-stable.

Observed behavior:

- Exit code: 1
- wolfSSL_i2d_X509_bio returned 0
- No ERROR: AddressSanitizer
- No heap-buffer-overflow
- No WRITE of size 20046
- No ABORTING
- Precise crash-signal check: NO_CRASH_SIGNAL

The exit code 1 is expected because the fixed version safely rejects the oversized AuthorityKeyIdentifier during X.509 re-encoding instead of overflowing cert->akid.

### Evidence Logs

- logs/fixed_version/wolfssl-v5.9.1-stable-asan-akid/akid_repro.log
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-akid/akid_exit_code.txt
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-akid/asan_grep_result.txt
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-akid/der_sha256.txt

### Current Conclusion

wolfSSL v5.9.1-stable is a fixed release candidate for WOLFSSL-POC-0004. The same reconstructed DER certificate that triggers ASan heap-buffer-overflow on v5.9.0-stable is safely rejected on v5.9.1-stable without sanitizer crash evidence.

## Current Version Test: wolfSSL current

### Build

- Library: wolfSSL
- Version description: v5.9.1-stable-1373-g8fca95ce6
- Commit: 8fca95ce651d6e370d91f5598786de4bc66aa2c2
- Latest commit:
  - 8fca95ce6 2026-06-05 16:27:00 -0500 Merge pull request #10532 from rlm2002/zd21800
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-current-asan-akid
- Build mode: ASan/UBSan, debug, -O0
- Required compile-time option:
  - WOLFSSL_AKID_NAME
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

### Reconstructed Input

- Input file: inputs/reconstructed/cve-2026-5447-akid-overflow-long.der
- SHA256: 429c84c39342e7d668d6ac43dd8d513b6abbcfa8abeee420ce6de689d09b84be
- Input type: reconstructed DER X.509 certificate
- Input provenance: reconstructed_from_pr_10112_official_test_pattern
- Crafted extension: oversized AuthorityKeyIdentifier

### Observed Result

The current wolfSSL version did not trigger the ASan heap-buffer-overflow observed on v5.9.0-stable.

Observed behavior:

- Exit code: 1
- wolfSSL_i2d_X509_bio returned 0
- No ERROR: AddressSanitizer
- No heap-buffer-overflow
- No WRITE of size 20046
- No ABORTING
- Precise crash-signal check: NO_CRASH_SIGNAL

The exit code 1 is expected because the current version safely rejects the oversized AuthorityKeyIdentifier during X.509 re-encoding instead of overflowing cert->akid.

### Evidence Logs

- logs/current_version/wolfssl-current-asan-akid/ldd.txt
- logs/current_version/wolfssl-current-asan-akid/akid_repro.log
- logs/current_version/wolfssl-current-asan-akid/akid_exit_code.txt
- logs/current_version/wolfssl-current-asan-akid/asan_grep_result.txt
- logs/current_version/wolfssl-current-asan-akid/der_sha256.txt

### Current Conclusion

The current wolfSSL version safely rejects the same reconstructed DER certificate without sanitizer crash evidence.
