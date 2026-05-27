# Botan BigInt serialization APIs

Library: Botan
Version: 3.10.0
API family: BignumSerialize

Related APIs:
- Botan::BigInt
- Botan::BigInt::encode
- Botan::BigInt::serialize_to
- Botan::BigInt::to_dec_string
- Botan::BigInt::to_hex_string

Security-sensitive cases:
- negative BigInt serialization.
- undersized output buffer.
- binary encoding length mismatch.
- exception handling.
- output length normalization.

Expected behavior:
- The adapter should catch exceptions and normalize them into error codes.
- The implementation should not write out of bounds.
- Canary bytes should remain intact.
- For invalid or unsupported inputs, the adapter should return failure rather than crash.

Related vulnerability pattern:
BIGNUM_SERIALIZE_NEGATIVE_SMALL_BUFFER
