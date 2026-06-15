# WOLFSSL-POC-0009 Reproduction Route

## Candidate

CVE-2026-2646 targets wolfSSL_d2i_SSL_SESSION when SESSION_CERTS is enabled.

The vulnerable path deserializes an SSL_SESSION from external data. Session ID size and SESSION_CERTS chain fields are read from the input buffer and then used to copy data into WOLFSSL_SESSION buffers / allocated certificate buffers.

## High-Priority Commits

- f94eb68ea add missing checks in wolfSSL_d2i_SSL_SESSION
- 86212fd33 add test for session deserialization input validation
- 0a99a08b0 ssl_sess: check fields in wolfSSL_d2i_SSL_SESSION
- PR #9748 wolfSSL_d2i_SSL_SESSION-fix
- PR #9759 test_wolfSSL_d2i_SSL_SESSION
- PR #9949 fix_d2i_SSL_SESSION

## Planned Route

1. Extract fixed-version d2i_SSL_SESSION bounds checks from src/ssl_sess.c.
2. Extract official test vector or mutation strategy from test commit 86212fd33.
3. Build v5.8.4 with OPENSSL_EXTRA and SESSION_CERTS under ASan.
4. Feed crafted serialized session buffer to wolfSSL_d2i_SSL_SESSION.
5. Verify v5.8.4 sanitizer crash and v5.9.0 safe rejection.
