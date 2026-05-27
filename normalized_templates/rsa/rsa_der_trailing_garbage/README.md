# RSA DER Top-Level SEQUENCE Trailing Garbage

This normalized template comes from `MBEDTLS-POC-0020`.

The vulnerability pattern is RSA DER parser acceptance of trailing garbage after
the complete top-level ASN.1 `SEQUENCE`. A buggy parser consumes the valid RSA
private or public key object and returns success even though extra DER bytes
remain outside the top-level object.

## Source APIs

- Source public API: `mbedtls_pk_parse_key`
- Internal isolation APIs:
  - `mbedtls_rsa_parse_key`
  - `mbedtls_rsa_parse_pubkey`

The original local PoC isolates the parser behavior through the internal RSA
parsers. The normalized template keeps `mbedtls_pk_parse_key` as the public
source API and preserves the internal parser paths as explicit trigger options.

## Mutation Points

- `DER_KIND`: selects private or public RSA DER input.
- `PARSE_API_KIND`: selects the public PK parser or internal RSA parser path.
- `TRAILING_GARBAGE_BYTES`: bytes appended after the complete top-level RSA
  `SEQUENCE`.
- `TRAILING_GARBAGE_LEN`: expected decoded byte length of the appended garbage.
- `EXPECT_RET`: expected fixed/safe rejection return code.
- `TOP_LEVEL_SEQUENCE_END_CHECK`: source-level boundary check that rejects bytes
  remaining after the top-level `SEQUENCE`.
- `RSA_PRIVATE_PARSE_CALL`: internal private-key parser trigger.
- `RSA_PUBLIC_PARSE_CALL`: internal public-key parser trigger.

## Oracle

The oracle is return-code based.

- Buggy behavior: parser returns `0` and accepts DER input with trailing garbage.
- Fixed/safe behavior: parser rejects the malformed input, typically with
  `MBEDTLS_ERR_RSA_BAD_INPUT_DATA`.

The template treats successful parsing of the malformed DER as the bug signal
and treats non-zero rejection as safe behavior, with
`MBEDTLS_ERR_RSA_BAD_INPUT_DATA` as the primary expected fixed return code.

## Original PoC

`poc_original.c` is copied from the most relevant local PoC source:

`data/pocs/core10/MBEDTLS-POC-0020/poc/poc_rsa_trailing_garbage.c`

It preserves the original PoC semantics and does not contain template
placeholders.
