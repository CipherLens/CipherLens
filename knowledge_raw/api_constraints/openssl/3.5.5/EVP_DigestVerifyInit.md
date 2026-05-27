# API Constraints: EVP_DigestVerifyInit / EVP_DigestVerifyInit_ex (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function names: `EVP_DigestVerifyInit`, `EVP_DigestVerifyInit_ex`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/m_sigver.c`
- Manpage: `doc/man3/EVP_DigestVerifyInit.pod`
- Signatures:

```c
int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *mdname, OSSL_LIB_CTX *libctx,
    const char *props, EVP_PKEY *pkey,
    const OSSL_PARAM params[]);

int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e,
    EVP_PKEY *pkey);
```

## Semantics

- Initializes an `EVP_MD_CTX` for signature verification.
- May create or reuse an `EVP_PKEY_CTX`; if created by the init call, it is freed with the `EVP_MD_CTX`.
- `_ex` variant supports provider/libctx/properties and parameter array.

## Return Value Semantics

- Returns `1` on success.
- Returns `0` on failure.

## Object Lifetime Constraints

- `EVP_MD_CTX`, `EVP_PKEY_CTX`, and `EVP_PKEY` are opaque. Harnesses must not access internal fields.
- The `EVP_MD_CTX` must be initialized and later freed by public APIs.
- Ignoring failure returns can lead to later errors in `EVP_DigestVerify*` calls.

## Adapter Generation Notes

- Uses caller-provided output buffer: no.
- Exposes explicit output length: no.
- This is setup for verification; it does not write signature or plaintext output.
- Good migration target for generic signature verification setup with opaque key dispatch.

## Related Tests or Examples Found Locally

- `test/evp_extra_test.c`: direct `EVP_DigestVerifyInit` tests around lines 1949, 1996, 2009, 2017, 2530, 2639, and 2657.
- `test/algorithmid_test.c`: `EVP_DigestVerifyInit_ex` around line 154.
- Demos: `demos/signature/EVP_*_Signature_demo.c`, `demos/signature/rsa_pss_hash.c`.
