# WOLFSSL-POC-0009 Candidate Selection

## Selected Candidate

- Candidate PoC ID: WOLFSSL-POC-0009
- CVE: CVE-2026-2646
- Module family: SSL session serialization / deserialization
- Bug class: wolfSSL_d2i_SSL_SESSION heap-buffer-overflow
- Expected trigger surface:
  - wolfSSL_d2i_SSL_SESSION
  - serialized SSL_SESSION restoration
  - SESSION_CERTS enabled
- Expected vulnerable condition:
  - certificate and session id lengths are read from untrusted serialized session data
  - missing bounds validation before copying into fixed-size buffers
- Expected fixed version:
  - wolfSSL v5.9.0-stable

## Selection Rationale

This candidate adds a session deserialization parsing sample to the dataset.

The existing dataset already covers X.509, DTLS ACK serialization, PKCS7/CMS, TLS 1.3 PQC KeyShare cleanup, and ASN.1 time/name parsing. CVE-2026-2646 expands the dataset into serialized session restore APIs and fixed-buffer overflow in compatibility/session parsing logic.

## Expected Trigger Shape

- Build wolfSSL with session serialization/deserialization support and SESSION_CERTS enabled.
- Feed a crafted serialized SSL_SESSION buffer to wolfSSL_d2i_SSL_SESSION.
- Encode oversized certificate or session id length fields.
- Observe whether the vulnerable version copies untrusted session data into fixed-size buffers without capacity validation.

## Initial Quality Status

- Status: candidate selected
- Vulnerable version: pending
- Fixed version: pending
- Current version: pending
