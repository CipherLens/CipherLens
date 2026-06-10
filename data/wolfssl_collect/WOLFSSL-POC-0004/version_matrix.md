# Version Matrix

## PoC

- PoC ID: WOLFSSL-POC-0004
- CVE: CVE-2026-5447
- Input: inputs/reconstructed/cve-2026-5447-akid-overflow-long.der
- Input provenance: reconstructed_from_pr_10112_official_test_pattern
- Bug class: X.509 AuthorityKeyIdentifier heap buffer overflow
- Harness family: x509_authority_key_identifier_memory_safety
- Oracle type: crash_sanitizer_oracle

## Build Configuration

The vulnerable reproduction used:

- CFLAGS: -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -DWOLFSSL_AKID_NAME
- LDFLAGS: -fsanitize=address,undefined
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

## Matrix

| Version / Commit | Role | Result | Evidence |
|---|---|---|---|
| wolfSSL v5.9.0-stable, commit 922d04b3568c6428a9fb905ddee3ef5a68db3108 | vulnerable version | confirmed crash | ASan heap-buffer-overflow; WRITE of size 20046; CertFromX509 src/x509.c:11863; wolfSSL_i2d_X509_bio; exit 134 |
| wolfSSL v5.9.1-stable, commit 1d363f3adceba9d1478230ede476a37b0dcdef24 | fixed release candidate | safe rejection | wolfSSL_i2d_X509_bio returned 0; exit 1; NO_CRASH_SIGNAL; no ASan heap-buffer-overflow |
| current wolfSSL v5.9.1-stable-1373-g8fca95ce6, commit 8fca95ce651d6e370d91f5598786de4bc66aa2c2 | current version | safe rejection | wolfSSL_i2d_X509_bio returned 0; exit 1; NO_CRASH_SIGNAL; no ASan heap-buffer-overflow |

## Conclusion

WOLFSSL-POC-0004 has confirmed certificate-level vulnerable-version reproduction on wolfSSL v5.9.0-stable. Release-level version matrix is complete: wolfSSL v5.9.0-stable reproduces ASan heap-buffer-overflow with WRITE of size 20046 in CertFromX509, while wolfSSL v5.9.1-stable and current wolfSSL safely reject the oversized AuthorityKeyIdentifier input without sanitizer crash evidence.
