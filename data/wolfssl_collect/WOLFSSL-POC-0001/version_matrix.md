# Version Matrix

## PoC

- PoC ID: WOLFSSL-POC-0001
- Input: inputs/original/crash_000_FreeDecodedCert.pem
- Input provenance: original GitHub issue attachment
- Bug class: X.509 / ASN.1 certificate parsing memory safety
- Harness family: x509_asn1_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Build Configuration

The successful vulnerable reproduction and all fixed/current checks used the same ASan/UBSan extra build style:

- CFLAGS: -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
- LDFLAGS: -fsanitize=address,undefined
- Configure options:
  - --enable-debug
  - --enable-dtls
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

## Matrix

| Version / Commit | Role | Result | Evidence |
|---|---|---|---|
| wolfSSL v4.2.0-stable, commit 48c4b2fedcee4d61b6a76c5ce9e33ab212d6ab4a | vulnerable version | confirmed crash | UBSan index 19 out of bounds in GetName; ASan SEGV during FreeDecodedCert; exit 134 |
| commit 88bf5d967 | candidate fix commit | still vulnerable | UBSan index out of bounds; ASan SEGV; FreeDecodedCert crash; exit 134 |
| wolfSSL v4.3.0-stable | fixed release candidate | safe reject | GetLength value exceeds buffer length; no UBSan/ASan/SEGV |
| current wolfSSL, v5.9.1-stable-1299-geeab53205, commit eeab53205ab57451778f7a76aad25f5349547ce5 | current version | safe reject | GetLength - value exceeds buffer length; no UBSan/ASan/SEGV |

## Conclusion

WOLFSSL-POC-0001 has a complete release-level version matrix.

The original crafted certificate triggers a sanitizer-confirmed crash on wolfSSL v4.2.0-stable under the ASan/UBSan extra build configuration. The same input is safely rejected by wolfSSL v4.3.0-stable and by the current wolfSSL version. The tested candidate commit 88bf5d967 is not an effective fix for this PoC.
