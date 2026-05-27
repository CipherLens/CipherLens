# API Constraints: EVP_DigestVerify (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_DigestVerify`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/m_sigver.c`
- Manpage: `doc/man3/EVP_DigestVerifyInit.pod`
- Signature:

```c
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
    size_t siglen, const unsigned char *tbs,
    size_t tbslen);
```

## Semantics

- One-shot verification of `tbs` against signature `sigret`.
- Requires a context initialized by `EVP_DigestVerifyInit` or `EVP_DigestVerifyInit_ex`.
- Can be called only once before reinitializing the `EVP_MD_CTX`.

## Return Value Semantics

- Returns `1` on valid signature.
- Returns `0` for verification failure or invalid signature form.
- Negative or other non-1 values indicate more serious errors depending on provider/path.

## Object and Buffer Constraints

- `EVP_MD_CTX`, `EVP_PKEY_CTX`, and `EVP_PKEY` are opaque. Do not access internal fields.
- `sigret` and `tbs` are caller-owned input buffers.
- The API does not write to a caller output buffer.

## Adapter Generation Notes

- Uses caller-provided output buffer: no.
- Exposes explicit output length: input lengths only (`siglen`, `tbslen`).
- Good oracle: return value `1`, `0`, or negative error.

## Vulnerability-Pattern Migration Notes

- Candidate for signature verification behavior and generic/opaque key dispatch patterns.
- Does not preserve caller-output-buffer memory boundary patterns.

## Related Tests or Examples Found Locally

- `test/ecdsatest.c`: direct success/failure `EVP_DigestVerify` checks around lines 255, 257, 260, 262, 265, 267, 273, 275, 280, 282, 315, 317, 322, and 324.
- `test/slh_dsa_test.c`: direct one-shot calls around line 578.
- Demos: `demos/signature/EVP_ED_Signature_demo.c` uses one-shot `EVP_DigestVerify`.
