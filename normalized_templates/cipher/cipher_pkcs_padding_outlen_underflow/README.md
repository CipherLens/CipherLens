# CIPHER_PKCS_PADDING_INVALID_OUTLEN_UNDERFLOW

## Source

- PoC ID: `MBEDTLS-POC-0004`
- Source API: `mbedtls_cipher_finish`
- Internal helper: `get_pkcs_padding` / `mbedtls_get_pkcs_padding`
- Source file: `data/pocs/core10/MBEDTLS-POC-0004/poc/poc_get_pkcs_padding_outlen.c`

## API

The harness uses AES-128-CBC decryption with PKCS#7 padding enabled. It first
encrypts a single 16-byte block without padding so that the decrypted final
plaintext block ends with a controllable invalid padding byte.

## Vulnerability

In the buggy implementation, `get_pkcs_padding()` reads the final byte as
`padding_len` and computes:

```c
*data_len = input_len - padding_len;
```

before rejecting `padding_len > input_len`. With `input_len == 16` and
`padding_len == 0x80`, the unsigned subtraction underflows and leaves a huge
caller-visible output length on the `mbedtls_cipher_finish()` error path.

## Trigger Condition

- Cipher: `MBEDTLS_CIPHER_AES_128_CBC`
- Operation: `MBEDTLS_DECRYPT`
- Padding mode: `MBEDTLS_PADDING_PKCS7`
- Final block length: `16`
- Invalid padding byte: `0x80` by default

## Mutation Points

- `PADDING_BYTE`: final plaintext byte interpreted as PKCS#7 padding length.
- `INPUT_LEN`: final decrypted block length.
- `PADDING_MODE`: padding mode used by the mbedTLS cipher context.
- `EXPECT_RET`: expected invalid padding error.

The mask report also tracks the finish call, the invalid-padding guard, and the
output-length oracle.

## Oracle

This is a `return_code_outlen_semantic` family harness. It is not a crash
oracle.

Safe/fixed behavior:

```text
ret == MBEDTLS_ERR_CIPHER_INVALID_PADDING && finish_olen == 0
```

Bug behavior:

```text
ret == MBEDTLS_ERR_CIPHER_INVALID_PADDING && finish_olen != 0
```

The output length can become a huge `size_t` value on buggy versions, creating a
caller-side overflow hazard if trusted.
