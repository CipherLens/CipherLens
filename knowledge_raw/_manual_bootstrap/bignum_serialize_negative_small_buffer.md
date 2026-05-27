# BIGNUM_SERIALIZE_NEGATIVE_SMALL_BUFFER

Source type: PoC
Source library: mbedTLS
Source API: mbedtls_mpi_write_string
API family: BignumSerialize

Root cause abstraction:
A negative big integer is serialized into an undersized output buffer.
The test checks whether the serialization API writes beyond the user-provided buffer or returns an unreasonable success status.

Trigger condition:
- The input big integer is negative.
- The output radix is 2, 10, or 16.
- The output buffer length is smaller than the required serialized length.
- The output buffer is followed by canary bytes.

Mutation points:
- [VALUE_SIGN]&#58; negative, zero, positive.
- [VALUE_MAGNITUDE]&#58; -1, -2, -255, large_negative, 0, 1, large_positive.
- [RADIX]&#58; 2, 10, 16.
- [BUFFER_LENGTH]&#58; 0, 1, 2, 3, 4, 8, 16.
- [OUTPUT_FORMAT]&#58; string, binary.
- [ERROR_HANDLER]&#58; return code, exception, abort.

Oracle:
- no crash.
- ASAN should be clean.
- Canary bytes should remain intact.
- Invalid or insufficient-buffer cases should not be reported as normal success.
- Output length should be reasonable.

Expected migration:
- mbedTLS: mbedtls_mpi_write_string.
- OpenSSL: BN_bn2binpad.
- Botan: Botan::BigInt::encode or string conversion APIs.
