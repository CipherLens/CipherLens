# API Constraints: EVP_aes_128_gcm (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_aes_128_gcm`
- Header declaration: `include/openssl/evp.h`
- Implementation family: EVP AES cipher methods / provider cipher implementation
- Signature:

```c
const EVP_CIPHER *EVP_aes_128_gcm(void);
```

## Semantics

- Returns the AES-128-GCM cipher descriptor for EVP operations.
- Used with `EVP_DecryptInit_ex()` / `EVP_DecryptInit_ex2()` and AEAD tag controls/params.

## Return Value Semantics

- Returns a non-NULL cipher descriptor when available.
- May be unavailable depending on provider/build configuration.

## Ownership and Buffer Constraints

- Returned descriptor is library-owned.
- Caller owns `EVP_CIPHER_CTX`, key, IV, AAD, ciphertext, plaintext, and tag buffers.

## Harness Generation Notes

- For GCM decrypt, initialize cipher, optionally set IV length, process AAD, process ciphertext, set expected tag, then call `EVP_DecryptFinal_ex()`.
- GCM is useful as a comparison target for AEAD shortened tag validation but is not the same mode as the CCM source PoC.

## Vulnerability-Pattern Migration Notes

- Secondary OpenSSL AEAD candidate for `MBEDTLS-POC-0028`.
- Tag length rules differ from CCM, so migration scoring should reduce operation-family specificity if source is strictly CCM.

## Related Tests or Examples Found Locally

- `demos/cipher/aesgcm.c`: full AES-GCM decrypt example.
- `test/evp_extra_test.c`, `test/tls13encryptiontest.c`: GCM EVP test usage.
