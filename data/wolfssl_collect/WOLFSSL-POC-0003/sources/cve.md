# CVE Evidence

- CVE: CVE-2026-5448
- Affected library: wolfSSL
- Vulnerability class: X.509 date buffer overflow
- Affected API:
  - wolfSSL_X509_notAfter
  - wolfSSL_X509_notBefore
- Affected path: OpenSSL compatibility layer API
- Native TLS impact: not affected according to public advisory text
- Reported fixed PR: wolfSSL PR 10071
- Affected versions: wolfSSL versions before 5.9.1 according to NVD CPE range

## Summary

A buffer overflow may occur when parsing date fields from a crafted X.509 certificate via the wolfSSL OpenSSL compatibility layer API. The issue is triggered when an application directly calls wolfSSL_X509_notAfter or wolfSSL_X509_notBefore on a crafted X.509 certificate.

## References

- https://www.wolfssl.com/docs/security-vulnerabilities/
- https://nvd.nist.gov/vuln/detail/CVE-2026-5448
- https://github.com/wolfSSL/wolfssl/pull/10071
- https://github.com/wolfSSL/wolfssl/blob/master/README
