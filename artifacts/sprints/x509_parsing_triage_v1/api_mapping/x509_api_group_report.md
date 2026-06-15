# x509 API Group Report

- OpenSSL app-level: `openssl x509`, `openssl verify`, `openssl crl`, `openssl req`, `OSSL_STORE / OSSL_DECODER`。
- OpenSSL C API: `d2i_X509`, `PEM_read_bio_X509`, `X509_new`, `X509_free`, `X509_verify_cert`, `X509_STORE_CTX_init`, `X509_cmp_time`, `X509_check_purpose`, `X509_get_pubkey`。
- mbedTLS API: `mbedtls_x509_crt_parse`, `mbedtls_x509_crt_parse_der`, `mbedtls_x509_crt_verify`, `mbedtls_x509_crt_free`, plus `mbedtls_ssl_get_verify_result` for TLS-specific 0027。
- 结论：当前最稳是 C-path app-level semantic triage；A-path 暂不放行。
