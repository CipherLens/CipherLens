# Audit Input Summary

- Chosen seed: `OPENSSL-ISSUE-30581`
- Why chosen: Most valuable D-path seed from previous audit; metadata marks PKCS12/ASN1 NULL_DEREFERENCE_CRASH and HIGH_CANDIDATE.
- Why `MBEDTLS-POC-0017` is not continued now: Current MBEDTLS-POC-0017 d2i_X509 migration is safe/safe migrated_safe negative feedback.

## Missing Evidence

- real original input artifact `/tmp/pbmac1_null_salt.p12`
- strict reproduction against the target OpenSSL build
- ASAN/UBSAN or gdb crash evidence

## Success Criteria

real input seed plus current target OpenSSL crash or sanitizer/gdb evidence; placeholder input cannot satisfy strict reproduction
