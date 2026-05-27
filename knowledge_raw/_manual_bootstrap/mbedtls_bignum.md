# mbedtls_mpi_write_string

Library: mbedTLS
Version: 4.1
API family: BignumSerialize
Function: mbedtls_mpi_write_string

Signature:
int mbedtls_mpi_write_string(const mbedtls_mpi *X, int radix, char *buf, size_t buflen, size_t *olen)

Parameters:
- X: input big integer.
- radix: output base.
- buf: output buffer.
- buflen: output buffer length.
- olen: output length or required length.

Initialization and cleanup:
- mbedtls_mpi_init initializes the big integer object.
- mbedtls_mpi_lset assigns a small signed integer to mbedtls_mpi.
- mbedtls_mpi_free releases internal resources.

Security-sensitive cases:
- negative integer serialization.
- undersized output buffer.
- zero-length output buffer.
- radix boundary.
- null output pointer.
- olen pointer handling.

Expected behavior:
- The function should not write out of bounds.
- The function should return an error when the output buffer is insufficient.
- Canary bytes after the output buffer should remain intact.
- The function should not crash for invalid but well-formed inputs.

Related vulnerability pattern:
BIGNUM_SERIALIZE_NEGATIVE_SMALL_BUFFER
