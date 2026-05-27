# OpenSSL BIGNUM serialization APIs

Library: OpenSSL
Version: 3.5.5
API family: BignumSerialize

Related APIs:
- BN_new
- BN_free
- BN_set_word
- BN_set_negative
- BN_bn2binpad
- BN_bn2bin
- BN_bn2hex
- BN_bn2dec

BN_bn2binpad:
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)

Parameters:
- a: input BIGNUM.
- to: output byte buffer.
- tolen: output buffer length.

Security-sensitive cases:
- negative BIGNUM.
- undersized output buffer.
- zero-length output buffer.
- output buffer boundary.
- return value normalization.

Expected behavior:
- The function should not write out of bounds.
- If the output buffer is too small, the function should report failure.
- The adapter should normalize OpenSSL return values into success or failure.
- Canary bytes after the output buffer should remain intact.

Related vulnerability pattern:
BIGNUM_SERIALIZE_NEGATIVE_SMALL_BUFFER
