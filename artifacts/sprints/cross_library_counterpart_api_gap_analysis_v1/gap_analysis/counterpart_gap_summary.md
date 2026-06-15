# Counterpart Gap Summary

## OpenSSL missing API cards
- `ASN1_item_d2i`
- `CRYPTO_secure_free`
- `CRYPTO_secure_malloc`
- `CRYPTO_secure_malloc_init`
- `OPENSSL_secure_free`
- `OPENSSL_secure_malloc`
- `PEM_read_bio_X509`
- `PKCS12_free`
- `PKCS12_parse`
- `PKCS7_free`
- `PKCS7_verify`
- `SSL_CTX_free`
- `SSL_CTX_new`
- `SSL_accept`
- `SSL_connect`
- `SSL_free`
- `SSL_new`
- `SSL_read`
- `SSL_write`
- `X509_free`
- `d2i_ASN1_SEQUENCE_ANY`
- `d2i_PKCS12`
- `d2i_PKCS7`

## mbedTLS missing API cards
- `mbedtls_calloc`
- `mbedtls_free`
- `mbedtls_platform_set_calloc_free`
- `mbedtls_ssl_config_free`
- `mbedtls_ssl_config_init`
- `mbedtls_ssl_free`
- `mbedtls_ssl_handshake`
- `mbedtls_ssl_init`
- `mbedtls_ssl_read`
- `mbedtls_ssl_setup`
- `mbedtls_ssl_write`
- `mbedtls_x509_crt_free`
- `mbedtls_x509_crt_init`
- `mbedtls_x509_crt_parse`
- `mbedtls_x509_crt_parse_der`

## Families needing target-side knowledge
- `tls_protocol_state_lifecycle`
- `pkcs_container_parsing`
- `secure_heap_state_lifecycle`
- `x509_parsing`
- `asn1_nested_boundary`

