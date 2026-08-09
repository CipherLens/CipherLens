
## Attempt 1: wolfSSL 4.2.0 ASan server -c

- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-4.2.0-asan
- Command: ./examples/server/server -c inputs/original/crash_000_FreeDecodedCert.pem
- Exit code: 1
- Result: no ASan / UBSan / SEGV observed
- Observed behavior: parser rejected the crafted certificate early
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

Current conclusion: vulnerable-version crash has not been reproduced yet. Further triage is required.

## Attempt: wolfSSL 4.2.0 ASan

### Build

- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-4.2.0-asan
- Build mode: ASan/UBSan, debug, -O0
- Note: examples/server and examples/client were built successfully.

### Command 1

./examples/server/server -c inputs/original/crash_000_FreeDecodedCert.pem

### Result 1

- Exit code: 1
- No ASan / UBSan / SEGV observed.
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

### Command 2

./examples/server/server -u -c inputs/original/crash_000_FreeDecodedCert.pem

### Result 2

- Exit code: 1
- No certificate parsing reached.
- Key log:
  - wolfSSL error: Bad SSL version
- Reason: current build has DTLS disabled.

### Command 3

./examples/client/client -c inputs/original/crash_000_FreeDecodedCert.pem

### Result 3

- Exit code: 1
- No ASan / UBSan / SEGV observed.
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load client cert file

### Current Conclusion

The original crafted certificate was loaded into the wolfSSL 4.2.0 certificate parsing path, but this local 4.2.0 ASan build rejected the input early. The historical crash has not been reproduced on this build. Further triage is required with wolfSSL 4.1.0 or an exact vulnerable commit.

## Attempt: wolfSSL 4.1.0 ASan

### Build

- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-4.1.0-asan
- Build mode: ASan/UBSan, debug, -O0
- DTLS: enabled
- examples/server and examples/client were built successfully.

### Command 1

./examples/server/server -c inputs/original/crash_000_FreeDecodedCert.pem

### Result 1

- Exit code: 1
- No ASan / UBSan / SEGV observed.
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

### Command 2

./examples/server/server -u -c inputs/original/crash_000_FreeDecodedCert.pem

### Result 2

- Exit code: 1
- No ASan / UBSan / SEGV observed.
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

### Command 3

./examples/client/client -c inputs/original/crash_000_FreeDecodedCert.pem

### Result 3

- Exit code: 1
- No ASan / UBSan / SEGV observed.
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load client cert file

### Current Conclusion

The original crafted certificate reaches the wolfSSL X.509 parsing path on wolfSSL 4.1.0, but this local ASan build rejects the input early. The historical crash has not been reproduced on wolfSSL 4.1.0.

## Input Integrity Check

### Files

- inputs/original/crash_000_FreeDecodedCert.zip
- inputs/original/crash_000_FreeDecodedCert.pem

### Observed File Information

- crash_000_FreeDecodedCert.pem is detected as a PEM certificate.
- BEGIN CERTIFICATE count: 1
- END CERTIFICATE count: 1
- OpenSSL x509 failed to parse the certificate, which is acceptable because this is a malformed crafted certificate.

### SHA256

- crash_000_FreeDecodedCert.pem: 05393adbec28fd99c8221c0efcbbcf21f9c38c004fe723290b109087a41ca788
- crash_000_FreeDecodedCert.zip: 6e6cea0a7cc27a618e3bf59faacf09075c5f94ff308529c4c594e18d370f47e3

### Current Interpretation

The original issue attachment appears to be present and structurally recognized as a PEM certificate. However, local wolfSSL 4.1.0 and 4.2.0 ASan builds currently reject the input early with "GetLength value exceeds buffer length" instead of reproducing the historical ASan crash.

## Successful Reproduction: wolfSSL 4.2.0 ASan Extra Build

### Build

- Library: wolfSSL
- Version: v4.2.0-stable
- Commit: 48c4b2fedcee4d61b6a76c5ce9e33ab212d6ab4a
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-4.2.0-asan-extra
- Build mode: ASan/UBSan, debug, -O0
- Important configure options:
  - --enable-debug
  - --enable-dtls
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

### Input

- Input file: inputs/original/crash_000_FreeDecodedCert.pem
- Input provenance: original GitHub issue attachment
- SHA256: 05393adbec28fd99c8221c0efcbbcf21f9c38c004fe723290b109087a41ca788

### Commands

TLS server:

./examples/server/server -c crash_000_FreeDecodedCert.pem

DTLS server:

./examples/server/server -u -c crash_000_FreeDecodedCert.pem

TLS client:

./examples/client/client -c crash_000_FreeDecodedCert.pem

### Observed Results

All three commands triggered sanitizer/crash evidence.

Observed UBSan evidence:

wolfcrypt/src/asn.c:5121:27: runtime error: index 19 out of bounds for type 'int [19]'

Observed ASan evidence:

ERROR: AddressSanitizer: SEGV on unknown address 0xfffffffffffffffa

Observed crash path:

- GetName, wolfcrypt/src/asn.c:5121
- wc_GetPubX509, wolfcrypt/src/asn.c:5988
- DecodeToKey, wolfcrypt/src/asn.c:6006
- ProcessBuffer, src/ssl.c:5396
- ProcessFile, src/ssl.c:6339
- wolfSSL_CTX_use_certificate_chain_file, src/ssl.c:6912
- FreeDecodedCert, wolfcrypt/src/asn.c:4532
- wolfSSL_Free, wolfcrypt/src/memory.c:205
- free, ASan allocator

Exit code:

- server -c: 134
- server -u -c: 134
- client -c: 134

### Evidence Logs

- logs/vulnerable_version/wolfssl-4.2.0-asan-extra/server_repro.log
- logs/vulnerable_version/wolfssl-4.2.0-asan-extra/server_dtls_repro.log
- logs/vulnerable_version/wolfssl-4.2.0-asan-extra/client_repro.log

### Current Conclusion

The historical crash has been successfully reproduced on wolfSSL v4.2.0-stable with the original crafted certificate under the ASan/UBSan extra build configuration. This PoC is upgraded to Q1_strict_reproduction_candidate.

## Fixed Release Candidate Test: wolfSSL v4.3.0-stable

### Build

- Library: wolfSSL
- Version: v4.3.0-stable
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-4.3.0-asan-extra
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-dtls
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext
- Note: -Werror was removed from Makefile for compatibility with the local compiler.

### Input

- Input file: inputs/original/crash_000_FreeDecodedCert.pem
- Input provenance: original GitHub issue attachment

### Commands and Results

#### server -c

- Command: ./examples/server/server -c crash_000_FreeDecodedCert.pem
- Exit code: 1
- Result: safe reject
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

#### server -u -c

- Command: ./examples/server/server -u -c crash_000_FreeDecodedCert.pem
- Exit code: 1
- Result: safe reject
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

#### client -c

- Command: ./examples/client/client -c crash_000_FreeDecodedCert.pem
- Exit code: 1
- Result: safe reject
- Key log:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load client cert file

### Sanitizer Check

No sanitizer or crash evidence was observed.

Absent signals:

- runtime error: index 19 out of bounds
- ERROR: AddressSanitizer
- SEGV
- FreeDecodedCert crash

### Evidence Logs

- logs/fixed_version/wolfssl-4.3.0-asan-extra/server_repro.log
- logs/fixed_version/wolfssl-4.3.0-asan-extra/server_dtls_repro.log
- logs/fixed_version/wolfssl-4.3.0-asan-extra/client_repro.log

### Current Conclusion

wolfSSL v4.3.0-stable safely rejects the crafted certificate under the same ASan/UBSan extra build configuration that reproduces the crash on v4.2.0-stable. Therefore, v4.3.0-stable is a fixed release candidate for WOLFSSL-POC-0001.

## Current Version Test: wolfSSL current

### Build

- Library: wolfSSL
- Version description: v5.9.1-stable-1299-geeab53205
- Commit: eeab53205ab57451778f7a76aad25f5349547ce5
- Latest commit:
  - eeab53205 2026-06-05 20:55:43 +1000 Merge pull request #10600 from douzzer/20260604-asm-and-linuxkm-fixes
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-current-asan-extra
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-dtls
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

### Input

- Input file: inputs/original/crash_000_FreeDecodedCert.pem
- Input provenance: original GitHub issue attachment

### Commands and Results

#### server -c

- Command: ./examples/server/server -c crash_000_FreeDecodedCert.pem
- Exit code: 1
- Result: safe reject
- Key log:
  - GetLength - value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

#### server -u -c

- Command: ./examples/server/server -u -c crash_000_FreeDecodedCert.pem
- Exit code: 1
- Result: safe reject
- Key log:
  - GetLength - value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load server cert file

#### client -c

- Command: ./examples/client/client -c crash_000_FreeDecodedCert.pem
- Exit code: 1
- Result: safe reject
- Key log:
  - GetLength - value exceeds buffer length
  - Decode to key failed
  - wolfSSL error: can't load client cert file

### Sanitizer Check

No sanitizer or crash evidence was observed.

Absent signals:

- runtime error: index 19 out of bounds
- ERROR: AddressSanitizer
- SEGV
- FreeDecodedCert crash

### Evidence Logs

- logs/current_version/wolfssl-current-asan-extra/server_repro.log
- logs/current_version/wolfssl-current-asan-extra/server_dtls_repro.log
- logs/current_version/wolfssl-current-asan-extra/client_repro.log

### Current Conclusion

The current wolfSSL version safely rejects the crafted certificate under the same ASan/UBSan extra build configuration. The historical crash is not present in the current version.
