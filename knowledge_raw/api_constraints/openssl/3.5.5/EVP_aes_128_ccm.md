# API Constraints: EVP_aes_128_ccm (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_aes_128_ccm`
- Header declaration: `include/openssl/evp.h`
- Implementation family: EVP AES cipher methods / provider cipher implementation
- Signature:

```c
const EVP_CIPHER *EVP_aes_128_ccm(void);
```

## Semantics

- Returns the AES-128-CCM cipher descriptor for EVP operations.
- Used with `EVP_DecryptInit_ex()` / `EVP_DecryptInit_ex2()` and AEAD tag controls/params.

## Return Value Semantics

- Returns a non-NULL cipher descriptor when available.
- May be unavailable depending on provider/build configuration.

## Ownership and Buffer Constraints

- Returned descriptor is library-owned; caller must not free it.
- Cipher context and key/IV/tag buffers remain caller-owned.

## Harness Generation Notes

- For CCM decrypt, set tag before key/IV, specify total ciphertext length, process AAD, then process ciphertext.
- OpenSSL CCM tag length is configured through ctrl/params, not the algorithm identifier.

## Vulnerability-Pattern Migration Notes

- Primary OpenSSL AEAD candidate for `MBEDTLS-POC-0028` because the source bug is invalid CCM shortened tag length.
- Adapter should test invalid tag lengths such as 3 and observe whether setup/control/update rejects them.

## Related Tests or Examples Found Locally

- `demos/cipher/aesccm.c`: full AES-CCM decrypt example.
- `test/evp_extra_test.c`: selects `EVP_aes_128_ccm()` in EVP tests.
- `tf-psa-crypto` mbedTLS source states valid CCM tag lengths are 4, 6, 8, 10, 12, 14, 16; OpenSSL behavior must be measured locally by harness.
