# EVP_DecodeBlock Contract Notes

Local sources checked only; no network or public target access was used.

## Local evidence

- Header: `/home/wen/work/openssl-3.5.5-asan-src/include/openssl/evp.h` declares `int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);`.
- Manpage: `/home/wen/work/openssl-3.5.5-asan-src/doc/man3/EVP_EncodeInit.pod` says `EVP_DecodeBlock()` decodes `n` characters of base64 data in `f` and stores the result in `t`.
- Manpage output formula: for every 4 input bytes exactly 3 output bytes are produced. Padding bytes are decoded to zero bits, and the caller must account for trailing padding by ignoring bytes at the tail of returned output.
- Implementation: `/home/wen/work/openssl-3.5.5-asan-src/crypto/evp/encode.c` has no output buffer size parameter. `EVP_DecodeBlock()` calls `evp_decodeblock_int(NULL, t, f, n, 0)`, which writes decoded bytes into `t` according to processed input length.

## Contract answers

- EVP_DecodeBlock requires the caller to provide a sufficiently large output buffer because no output buffer length is passed to the API.
- The output buffer capacity should be at least `(input_len / 4) * 3` after valid base64 trimming rules; callers must handle padding by ignoring returned tail bytes as documented.
- A deliberately short output buffer is invalid API use and should be classified as contract-boundary observation unless documentation or controls show the buffer was sufficient.
- Malformed input may return `-1`, but the documentation does not provide a safe short-output-buffer exception; `t` still must be large enough for the API's possible writes.
- Padding edge cases affect the meaningful decoded data length, but `EVP_DecodeBlock()` still returns/produces bytes according to base64 block processing and documents that the caller accounts for padding.
- OpenSSL does not have an output buffer size parameter in `EVP_DecodeBlock`, so it cannot prevent caller-provided short output buffer writes.

## Original candidate interpretation

The original campaign case passed `input_len=16` for the string `QUJDREVGR0g=`, whose available byte length is shorter than 16. The ASAN excerpt reports a stack-buffer-overflow read over the `b64` input object, so the original sanitizer signal is primarily an input length contract violation, not proof that the output canary layout caught an OpenSSL write beyond a correctly sized output buffer.
