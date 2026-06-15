
## Initial PoC Source Check

### Exploit-DB Raw File

- File: poc/exploitdb_41984_raw.txt
- Source: https://www.exploit-db.com/raw/41984
- Detected type: C source / ASCII advisory text
- Contains PEM certificate: false
- Contains vulnerability description: true
- Contains certfields trigger description: true

### Important Observation

The Exploit-DB raw file contains the Talos vulnerability report text, but it does not directly include the crafted X.509 certificate.

The report states that the vulnerability can be triggered by supplying the attached PoC X.509 certificate to the certfields example app from wolfssl-examples.

### Current Conclusion

Original bug-triggering input has not yet been collected. The next step is to locate the attached PoC X.509 certificate referenced by the Talos / Exploit-DB report.

## PoC Input Generation Result

### Generated Input

- Certificate: inputs/reconstructed/cve-2017-2800-cert1.pem
- Original generated certificate: inputs/reconstructed/generated_from_exploitdb_command/cert1.pem
- Private key: inputs/reconstructed/generated_from_exploitdb_command/key.pem
- SHA256 record: inputs/reconstructed/generated_from_exploitdb_command/SHA256SUMS.txt

### Observed Certificate Subject

subject=C = US, ST = Maryland, L = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, O = E, CN = A

### Current Conclusion

The PoC certificate was successfully generated from the public Exploit-DB / Talos OpenSSL command. The next step is to build wolfSSL 3.10.2 with ASan/UBSan and reproduce the reported stack-buffer-overflow using the certfields example.

## Successful Reproduction: wolfSSL 3.10.2 ASan Minimal certfields Harness

### Build

- Library: wolfSSL
- Version: v3.10.2-stable
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-3.10.2-asan
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-opensslextra

### Input

- Certificate DER: inputs/reconstructed/cve-2017-2800-cert1.der
- Certificate PEM: inputs/reconstructed/cve-2017-2800-cert1.pem
- Input provenance: reconstructed_from_exploitdb_talos_poc_command
- DER SHA256: ebbd400e3007c5fac9ba31cfba0e7e83e6699a5420d36d11c7c7112867972cf5
- PEM SHA256: 1d747331d8d19ac035f0a7e9059991eb213a968930d999068863c6e7620f3289

### Harness

- Harness source: poc/poc_certfields_min.c
- Harness binary: poc/poc_certfields_min_3_10_2_asan
- Triggered API: wolfSSL_X509_NAME_get_text_by_NID
- Triggered field: localityName
- NID used: 0x07, matching ASN_LOCALITY_NAME

### Command

poc/poc_certfields_min_3_10_2_asan inputs/reconstructed/cve-2017-2800-cert1.der

### Observed Result

The vulnerable wolfSSL version triggers an AddressSanitizer stack-buffer-overflow.

Observed ASan evidence:

- ERROR: AddressSanitizer: stack-buffer-overflow
- WRITE of size 1
- wolfSSL_X509_NAME_get_text_by_NID src/ssl.c:12471
- localityName stack buffer overflow
- exit code: 134

### Evidence Logs

- logs/vulnerable_version/wolfssl-3.10.2-asan-certfields/poc_certfields_min_repro.log
- logs/vulnerable_version/wolfssl-3.10.2-asan-certfields/poc_certfields_min_exit_code.txt

### Current Conclusion

The reconstructed certificate generated from the public Exploit-DB / Talos PoC command successfully reproduces CVE-2017-2800 on wolfSSL v3.10.2-stable with ASan. The crash matches the reported root cause: wolfSSL_X509_NAME_get_text_by_NID writes a trailing NUL byte one byte past the 80-byte localityName stack buffer.

## Fixed Release Candidate Test: wolfSSL v3.11.0-stable

### Build

- Library: wolfSSL
- Version: v3.11.0-stable
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-v3.11.0-stable-asan-certfields
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-opensslextra

### Build Note

The first build attempt failed because the older wolfSSL source was compiled with `-Werror` under a newer compiler. Warnings such as `implicit-fallthrough` and `stringop-overflow` were treated as errors.

After removing `-Werror` from `Makefile`, the library built successfully.

These build warnings are unrelated to the CVE-2017-2800 runtime PoC behavior.

### Input

- Certificate DER: inputs/reconstructed/cve-2017-2800-cert1.der
- Input provenance: reconstructed_from_exploitdb_talos_poc_command

### Harness

- Harness source: poc/poc_certfields_min.c
- Triggered API: wolfSSL_X509_NAME_get_text_by_NID
- Triggered field: localityName
- NID used: 0x07

### Command

poc_certfields_min_v3.11.0-stable_asan inputs/reconstructed/cve-2017-2800-cert1.der

### Observed Result

wolfSSL v3.11.0-stable did not trigger the ASan stack-buffer-overflow observed on v3.10.2-stable.

Observed behavior:

- Exit code: 0
- No ERROR: AddressSanitizer
- No stack-buffer-overflow
- No WRITE of size 1
- No ABORTING

The precise crash-signal check returned:

- NO_CRASH_SIGNAL

The broader grep output only contains the harness debug message:

- calling wolfSSL_X509_NAME_get_text_by_NID for localityName, nid=0x07

### Evidence Logs

- logs/fixed_version/wolfssl-v3.11.0-stable-asan-certfields/build_info.txt
- logs/fixed_version/wolfssl-v3.11.0-stable-asan-certfields/ldd.txt
- logs/fixed_version/wolfssl-v3.11.0-stable-asan-certfields/poc_certfields_min_repro.log
- logs/fixed_version/wolfssl-v3.11.0-stable-asan-certfields/poc_certfields_min_exit_code.txt
- logs/fixed_version/wolfssl-v3.11.0-stable-asan-certfields/asan_grep_result.txt

### Current Conclusion

wolfSSL v3.11.0-stable is a fixed release candidate for WOLFSSL-POC-0002. The same reconstructed PoC certificate and minimal certfields harness that trigger ASan stack-buffer-overflow on v3.10.2-stable execute without sanitizer evidence on v3.11.0-stable.

## Current Version Test: wolfSSL current

### Build

- Library: wolfSSL
- Version description: v5.9.1-stable-1299-geeab53205
- Commit: eeab53205ab57451778f7a76aad25f5349547ce5
- Latest commit:
  - eeab53205 2026-06-05 20:55:43 +1000 Merge pull request #10600 from douzzer/20260604-asm-and-linuxkm-fixes
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-current-asan-certfields
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-opensslextra

### Input

- Certificate DER: inputs/reconstructed/cve-2017-2800-cert1.der
- Input provenance: reconstructed_from_exploitdb_talos_poc_command

### Harness

- Harness source: poc/poc_certfields_min.c
- Triggered API: wolfSSL_X509_NAME_get_text_by_NID
- Triggered field: localityName
- NID used: 0x07

### Observed Result

The current wolfSSL version did not trigger the ASan stack-buffer-overflow observed on v3.10.2-stable.

Observed behavior:

- Exit code: 0
- No ERROR: AddressSanitizer
- No stack-buffer-overflow
- No WRITE of size 1
- No ABORTING
- Precise crash-signal check: NO_CRASH_SIGNAL

### Evidence Logs

- logs/current_version/wolfssl-current-asan-certfields/build_info.txt
- logs/current_version/wolfssl-current-asan-certfields/ldd.txt
- logs/current_version/wolfssl-current-asan-certfields/poc_certfields_min_repro.log
- logs/current_version/wolfssl-current-asan-certfields/poc_certfields_min_exit_code.txt
- logs/current_version/wolfssl-current-asan-certfields/asan_grep_result.txt

### Current Conclusion

The current wolfSSL version safely executes the same reconstructed PoC certificate and minimal certfields harness without sanitizer evidence.
