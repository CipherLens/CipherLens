# x509 / DER / ASN.1 Boundary Distinction

- `x509_parsing`: certificate/CRL/CSR loader, printer, purpose, time, chain, CRL, and verification-result behavior.
- `der_full_consumption`: top-level DER trailing garbage, prefix acceptance, consumed pointer vs input length. x509 seed 只有在主 oracle 是 full-consumption 时才进这里。
- `asn1_nested_boundary`: nested ASN.1 length/child/optional-field malformed structure, crash/sanitizer evidence, CSR/cert internal boundary bugs。
- 本轮结论：`OPENSSL-ISSUE-29574` 标为 ASN.1 overlap；`OPENSSL-ISSUE-9043` 标为 D-path crash audit；`MBEDTLS-POC-0027` 更像 TLS verify-result semantic，不直接进入 pure x509 parser。
