# API Constraints: EVP_CipherFinal_ex (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_CipherFinal_ex`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/evp_enc.c`
- Manpage: `doc/man3/EVP_EncryptInit.pod`
- Signature:

```c
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
```

## Semantics

- Generic cipher finalization wrapper.
- Dispatches to `EVP_EncryptFinal_ex` or `EVP_DecryptFinal_ex` depending on the context operation.
- Writes final output bytes to caller-provided `outm` and length to `outl`.

## Return Value Semantics

- Returns `1` on success.
- Returns `0` on encryption/decryption failure.

## Object and Buffer Constraints

- `EVP_CIPHER_CTX` is opaque. Harnesses must not access internal fields.
- `outm` is caller-owned output buffer.
- `outl` is caller-visible output length pointer.

## Adapter Generation Notes

- Uses caller-provided output buffer: yes.
- Exposes explicit output length: yes, `int *outl`.
- Writes into caller buffer: yes.
- For decrypt padding error migration, use `EVP_DecryptFinal_ex` directly when possible to avoid ambiguity.

## Vulnerability-Pattern Migration Notes

- Potential target for mbedTLS cipher finish output-length patterns.
- Must preserve finalization error path and caller-visible output length.

## Related Tests or Examples Found Locally

- `test/evp_extra_test.c`: direct calls around lines 4967, 5014, 5021, 5081, 5097, 5184, 5262, and 5296.
- `test/evp_test.c`: direct call around line 1410.
- `test/afalgtest.c` and `test/evp_fetch_prov_test.c`: direct calls.
- Manpage examples in `doc/man3/EVP_EncryptInit.pod`.
