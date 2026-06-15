# RAG Evidence Summary

## Query Results

Three RAG queries were run:

- `openssl_cipher_aead_lifecycle.json`
- `mbedtls_aead_lifecycle.json`
- `aead_lifecycle_oracle.json`

Each returned 20 results.

## OpenSSL Evidence

RAG recalled OpenSSL EVP AEAD evidence including:

- `EVP_aes_128_gcm`
- `EVP_DecryptInit_ex`
- `EVP_DecryptUpdate`
- local EVP AEAD target API evidence

These support an OpenSSL API group around init, AAD update, data update, final,
tag set/get, cleanup, and context reuse.

## mbedTLS / PSA Evidence

RAG recalled `MBEDTLS-POC-0028`, whose root cause is missing validation of AEAD
tag lengths from PSA drivers. It also recalled related PSA lifecycle concepts
through existing pattern sources.

## Cross-Library Evidence

The evidence partially supports A-path because both sides expose AEAD lifecycle
concepts. It is still not recipe-slot precise enough to immediately render/run
cross-library harnesses.

## Route Implication

The best initial path is:

```text
B_controlled_family_mutation
```

A-path should remain a follow-up once recipes and adapter slots are sharpened.
