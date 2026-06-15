# ASN.1 / X.509 API Mapping

## OpenSSL

- `d2i_X509`: DER X.509 parser; useful for safe reject and pointer advancement checks.
- `d2i_X509_bio`: BIO-backed X.509 parser.
- `X509_new`, `X509_free`: lifecycle helpers.
- `ASN1_item_d2i`: generic ASN.1 item parser, potentially useful for nested child object or item-level oracle work.
- `OSSL_DECODER`: decoder/provider path; D-path first due configuration surface.
- `X509_verify_cert`: only relevant if parsed object reaches validation semantics.
- `d2i_PKCS12_fp`, `PKCS12_parse`: relevant for `OPENSSL-ISSUE-30581` PKCS12/ASN.1 path.

## mbedTLS

- `mbedtls_x509_crt_parse`
- `mbedtls_x509_crt_parse_der`
- `mbedtls_x509_crt_free`

## A-Path Status

Possible later, but not now. The current task should stabilize D-path seed evidence and oracle boundaries first.
