# API Contract Notes: EVP_EncodeBlock

Local sources checked only; no public target or network access was used.

## Local evidence

- Header: `/home/wen/work/openssl-3.5.5-asan-src/include/openssl/evp.h` declares `int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);`.
- Manpage: `/home/wen/work/openssl-3.5.5-asan-src/doc/man3/EVP_EncodeInit.pod` says `EVP_EncodeBlock()` encodes a full block of input data in `f` and of length `n`, stores it in `t`, and returns encoded length excluding the NUL terminator.
- Implementation: `/home/wen/work/openssl-3.5.5-asan-src/crypto/evp/encode.c` calls `evp_encodeblock_int(NULL, t, f, dlen)`. Inside `evp_encodeblock_int`, the loop reads `f[0]`, `f[1]`, and `f[2]` whenever `dlen > 0`; there is no internal NULL guard for `f`.

## Contract answers

- NULL input + zero length: observed locally as no sanitizer/no crash because the loop is skipped and only the output terminator is written. The manpage does not explicitly document NULL as allowed.
- NULL input + nonzero length: treated as invalid by the pointer/length contract. The API describes `f` as input data of length `n`; if `n > 0`, `f` must point to readable input bytes.
- Does documentation require a valid input buffer: it does not use the exact phrase "must be non-NULL", but it requires input data in `f` for length `n`; this is enough to classify NULL+nonzero as invalid API use.
- OpenSSL internal NULL guard: no guard was found in the local implementation path for `EVP_EncodeBlock()`.
- If no documentation evidence: not applicable; local manpage and implementation were found. The contract is implicit rather than spelled out as a dedicated NULL-precondition sentence.
