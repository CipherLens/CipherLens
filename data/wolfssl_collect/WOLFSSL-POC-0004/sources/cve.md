# CVE Evidence

- CVE: CVE-2026-5447
- Affected library: wolfSSL
- Vulnerability class: X.509 AuthorityKeyIdentifier heap buffer overflow
- Affected component: CertFromX509
- Root cause summary: AuthorityKeyIdentifier size confusion during internal X.509 certificate conversion
- Reported fixed PR: wolfSSL PR 10112
- Affected versions: wolfSSL versions before 5.9.1 according to NVD

## Summary

CVE-2026-5447 is a heap buffer overflow in CertFromX509 via AuthorityKeyIdentifier size confusion. The vulnerability occurs when converting an X.509 certificate internally due to incorrect size handling of the AuthorityKeyIdentifier extension.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2026-5447
- https://github.com/wolfSSL/wolfssl/pull/10112
