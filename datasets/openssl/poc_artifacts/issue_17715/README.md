# OpenSSL CLI-to-C PoC Candidate: issue_17715

## Source

- Issue: https://github.com/openssl/openssl/issues/17715
- Title: DRBG fails to initialize cipher_data prior to EVP_EncryptUpdate leading to segfault
- Template: multi_crypto_cli_path

## Original CLI Command

openssl x509 -in input.pem -out output.pem; openssl req -new -key key.pem -out req.pem; openssl pkcs12 -export -in cert.pem -out pkcs12.pem -name user; openssl pkey -in pkey.pem -out pkey_out.pem; openssl rsa -in rsa.pem -out rsa_out.pem

## Generated C API Path

- PEM_read_bio_X509
- PEM_read_bio_X509_REQ
- d2i_PKCS12_fp
- PKCS12_parse
- PEM_read_bio_PrivateKey
- PEM_write_bio_PrivateKey

## Expected Inputs

- inputs/input.pem
- inputs/req.pem
- inputs/pkcs12.pem
- inputs/pkey.pem
- inputs/rsa.pem

## PoC Info

- Original PoC type: CLI+SANITIZER_LOG
- Component: RAND_DRBG/EVP_CIPHER_CTX
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: 1.1.1a
- Quality: HIGH_CANDIDATE

## Root Cause

ctx->cipher_data is not being initialized prior to EVP_EncryptUpdate

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
