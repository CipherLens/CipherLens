# AEAD API Group Report

## OpenSSL EVP AEAD

Evidence file:

```text
artifacts/sprints/cipher_aead_lifecycle_family_triage_v1/evidence/openssl_evp_aead_api_hits.txt
```

The local source search found 505 hits.

API group:

- init: `EVP_EncryptInit_ex`, `EVP_EncryptInit_ex2`, `EVP_DecryptInit_ex`, `EVP_DecryptInit_ex2`
- AAD update: `EVP_EncryptUpdate(..., NULL, ...)`, `EVP_DecryptUpdate(..., NULL, ...)`
- data update: `EVP_EncryptUpdate`, `EVP_DecryptUpdate`, `EVP_CipherUpdate`
- final: `EVP_EncryptFinal_ex`, `EVP_DecryptFinal_ex`
- tag set: `EVP_CIPHER_CTX_ctrl` with AEAD/GCM/CCM set-tag controls
- tag get: `EVP_CIPHER_CTX_ctrl` with AEAD/GCM/CCM get-tag controls
- cleanup: `EVP_CIPHER_CTX_free`, `EVP_CIPHER_CTX_reset`
- ctx reuse: init with NULL cipher/key/iv, `EVP_CIPHER_CTX_copy`, reset/reinit

## mbedTLS GCM / CCM / PSA AEAD

Evidence file:

```text
artifacts/sprints/cipher_aead_lifecycle_family_triage_v1/evidence/mbedtls_aead_api_hits.txt
```

The local source search found 1772 hits.

API group:

- setup/init: `psa_aead_encrypt_setup`, `psa_aead_decrypt_setup`, `mbedtls_gcm_init`, `mbedtls_ccm_init`
- starts/setup: `mbedtls_gcm_starts`, PSA operation setup APIs
- AAD update: `psa_aead_update_ad`, `mbedtls_gcm_update_ad`
- data update: `psa_aead_update`, `mbedtls_gcm_update`
- finish/verify: `psa_aead_finish`, `psa_aead_verify`, `mbedtls_gcm_finish`, `mbedtls_gcm_auth_decrypt`
- tag verify: `psa_aead_verify`, `mbedtls_gcm_auth_decrypt`, `mbedtls_ccm_auth_decrypt`
- cleanup: `psa_aead_abort`, `mbedtls_gcm_free`, `mbedtls_ccm_free`
- state reuse: repeated finish/verify, setup after finish, abort then reuse

## Assessment

A-path is feasible but not yet ready for immediate rendering. B-path controlled
mutation is the right next step because it lets us isolate state sequence and
oracle behavior before cross-library adapter recipes are finalized.
