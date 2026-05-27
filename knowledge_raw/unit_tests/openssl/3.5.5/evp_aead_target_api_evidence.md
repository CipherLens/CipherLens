# Unit Test / Example Evidence: OpenSSL EVP AEAD Target APIs

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

status: found_in_local_tests

## APIs Covered

- `EVP_DecryptInit_ex`
- `EVP_CIPHER_CTX_ctrl`
- `EVP_DecryptUpdate`
- `EVP_DecryptFinal_ex`
- `EVP_aes_128_ccm`
- `EVP_aes_128_gcm`

## Evidence

- `test/evp_extra_test.c`
  - Stepwise EVP cipher initialization tests use `EVP_CipherInit_ex`, `EVP_CIPHER_CTX_ctrl`, AEAD set/get tag controls, and select `EVP_aes_128_ccm()` / `EVP_aes_128_gcm()`.
  - GCM decrypt tests use `EVP_DecryptUpdate()` and `EVP_DecryptFinal_ex()`.
- `demos/cipher/aesccm.c`
  - Full AES-CCM decrypt setup flow:
    - `EVP_DecryptInit_ex2()`
    - `EVP_DecryptInit_ex()`
    - `EVP_DecryptUpdate()` for length, AAD, and ciphertext/tag verification.
- `demos/cipher/aesgcm.c`
  - Full AES-GCM decrypt flow:
    - init with cipher/key/IV
    - process AAD and ciphertext
    - set expected tag
    - `EVP_DecryptFinal_ex()` for authentication result.
- Existing local RAG file `knowledge_raw/api_constraints/openssl/3.5.5/EVP_DecryptFinal_ex.md` also records direct tests and demos.

## Harness Relevance

- OpenSSL AEAD mapping for `MBEDTLS-POC-0028` needs multiple APIs: cipher selection, decrypt setup, tag ctrl/params, update, and final/update authentication.
- CCM invalid tag length may become observable during ctrl/setup/update rather than being encoded in a single algorithm macro as in PSA.
