# WOLFSSL-POC-0010 Candidate Selection

## Selected Candidate

- Candidate PoC ID: WOLFSSL-POC-0010
- CVE: CVE-2026-3547
- Module family: TLS extension parsing
- Bug class: ALPN parsing out-of-bounds read
- Expected trigger surface:
  - ALPN extension parsing
  - malformed ALPN protocol list
  - build with --enable-alpn
- Expected vulnerable version:
  - wolfSSL v5.8.4-stable or earlier
- Expected fixed version:
  - wolfSSL v5.9.0-stable

## Selection Rationale

This candidate adds a TLS extension parser sample to the dataset.

Existing samples cover X.509, ASN.1 time/name fields, DTLS 1.3 ACK serialization, PKCS7/CMS, TLS 1.3 PQC cleanup, and SSL_SESSION deserialization. CVE-2026-3547 adds ALPN protocol-list parsing, which improves protocol-parser coverage.

## Expected Trigger Shape

- Build wolfSSL with ALPN enabled.
- Feed a crafted ALPN protocol list or TLS handshake message containing malformed ALPN length fields.
- Trigger ALPN parser validation failure.
- Observe whether v5.8.4 reads beyond the ALPN buffer under ASan.
