# wolfSSL Rejected Candidates

| Candidate ID | Source | Reason | Final Quality |
|---|---|---|---|
| WOLFSSL-POC-0005-rejected-issue8353 | GitHub issue #8353 | Minimal wc_PemToDer(CERT_TYPE) API probe returned 0 without ASan crash; issue discussion indicates the crash was caused by harness-side strlen on a non-NUL-terminated buffer before wolfSSL was called. | Q5_rejected_harness_bug |

## Summary

- Rejected candidates: 1
- Reason category: harness-side bug, not wolfSSL library vulnerability
