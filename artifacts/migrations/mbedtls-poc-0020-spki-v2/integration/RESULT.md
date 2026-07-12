# MBEDTLS-POC-0020 Cross-Library Integration Result

## Environment

- Source library: mbedTLS 4.1.0
- Target library: OpenSSL 3.5.5
- Harness family: `der_pointer_consumption`
- Oracle: pure-DER positive control plus pointer-consumption check

## Summary

- Records: 18
- Status counts: `{'run_ok': 9, 'run_nonzero': 9}`
- Library counts: `{'mbedtls': 9, 'openssl': 9}`
- Valid semantic configurations: 9
- Rendered C files: 18
- mbedTLS safe rejections: 9
- OpenSSL exact-consumption-policy candidates: 9

## Per API

| Target API | mbedTLS cases | OpenSSL cases | Positive controls | Pointer candidates |
|---|---:|---:|---:|---:|
| `d2i_PrivateKey` | 3 | 3 | 3 | 3 |
| `d2i_RSAPrivateKey` | 3 | 3 | 3 | 3 |
| `d2i_RSA_PUBKEY` | 3 | 3 | 3 | 3 |

## Interpretation

All OpenSSL target cases first decoded the corresponding pure DER object and consumed it exactly. After trailing bytes were appended, the decoder returned success while the input pointer stopped at the end of the first DER object.

This result is a cross-library semantic difference under an exact-input-consumption policy. It is not, by itself, evidence of an OpenSSL vulnerability, because OpenSSL `d2i_*` APIs expose pointer advancement and callers may be responsible for enforcing full input consumption.

The public-key target uses SubjectPublicKeyInfo DER, while the source mbedTLS harness continues to use the original PKCS#1 RSA public-key DER.
