# RAG Evidence Summary

- MBEDTLS-POC-0017 recalled: `true`
- x509_asn1_inner_boundary recalled: `true`
- OPENSSL-ISSUE-30581 recalled: `true`
- crash/sanitizer evidence recalled: `true`
- API/parser oracle evidence recalled: `true`
- Enough for A-path: `false`

RAG recalls the right neighborhood, but the evidence does not yet justify A-path generation. `MBEDTLS-POC-0017` is safe/safe in the current migration result; `OPENSSL-ISSUE-30581` needs strict D-path reproduction with original or equivalent malformed input.
