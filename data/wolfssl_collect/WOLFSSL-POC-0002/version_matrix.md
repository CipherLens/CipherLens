# Version Matrix

## PoC

- PoC ID: WOLFSSL-POC-0002
- CVE: CVE-2017-2800
- Input: inputs/reconstructed/cve-2017-2800-cert1.der
- Input provenance: reconstructed_from_exploitdb_talos_poc_command
- Bug class: X.509 certificate text parsing off-by-one
- Harness family: x509_text_field_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Build Configuration

The vulnerable reproduction used:

- CFLAGS: -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
- LDFLAGS: -fsanitize=address,undefined
- Configure options:
  - --enable-debug
  - --enable-opensslextra

## Matrix

| Version / Commit | Role | Result | Evidence |
|---|---|---|---|
| wolfSSL v3.10.2-stable | vulnerable version | confirmed crash | ASan stack-buffer-overflow; WRITE of size 1; wolfSSL_X509_NAME_get_text_by_NID; localityName overflow; exit 134 |
| wolfSSL v3.11.0-stable | fixed release candidate | safe execution | Exit code 0; no ASan stack-buffer-overflow; no WRITE of size 1; no abort |
| current wolfSSL v5.9.1-stable-1299-geeab53205, commit eeab53205ab57451778f7a76aad25f5349547ce5 | current version | safe execution | Exit code 0; NO_CRASH_SIGNAL; no ASan stack-buffer-overflow; no WRITE of size 1; no abort |

## Conclusion

WOLFSSL-POC-0002 has confirmed vulnerable-version reproduction on wolfSSL v3.10.2-stable using a reconstructed certificate generated from the public Exploit-DB / Talos PoC command. Release-level version matrix is complete: wolfSSL v3.10.2-stable reproduces the ASan stack-buffer-overflow, while wolfSSL v3.11.0-stable and current wolfSSL execute the same reconstructed PoC certificate without sanitizer crash evidence.
