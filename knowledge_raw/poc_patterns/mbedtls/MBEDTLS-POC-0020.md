# MBEDTLS-POC-0020: RSA DER parser accepts trailing garbage

## Source

This pattern comes from Mbed TLS PR #8804 and issue #8799. The normalized
public API is `mbedtls_pk_parse_key`; the local minimal PoC isolates the root
cause by directly calling `mbedtls_rsa_parse_key()` and
`mbedtls_rsa_parse_pubkey()`.

The confirmed fixed merge commit is
`a7f651cf160a3753367e032c4471699822b37e30`; the local buggy worktree used
`a7f651cf160a3753367e032c4471699822b37e30^1`. The library fix commit is
`9de84bd67775e05fabca1907cd9f2ea33078d99a`.

## Root Cause

The buggy RSA key parsers parse the top-level ASN.1 SEQUENCE but do not verify
that the caller-provided DER input ends exactly at the end of that SEQUENCE.
Thus a valid RSA key followed by extra bytes can be accepted.

The fixed guard is:

```c
if (end != p + len) {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
}
```

## Trigger Condition

The PoC uses regression-test-derived PKCS#1 DER inputs:

- RSA private key with an extra INTEGER outside the top-level SEQUENCE.
- RSA public key with an extra INTEGER outside the top-level SEQUENCE.

## Buggy and Fixed Behavior

Buggy behavior:

```text
private ret=0
[BUG] private key parser accepted trailing garbage.
public ret=0
[BUG] public key parser accepted trailing garbage.
[BUG] both RSA parsers accepted trailing garbage.
```

Fixed behavior:

```text
private ret=-16512
[OK] private key parser rejected trailing garbage.
public ret=-16512
[OK] public key parser rejected trailing garbage.
[OK] both RSA parsers rejected trailing garbage.
```

## Oracle

Bug signal:

- private and public RSA parser return `0`,
- malformed DER with trailing bytes is accepted.

Safe signal:

- parsers return `MBEDTLS_ERR_RSA_BAD_INPUT_DATA`,
- trailing garbage is rejected.

## Mutation Points

- `TOP_LEVEL_SEQUENCE_END_CHECK`: `end != p + len` rejection guard.
- `TRAILING_GARBAGE_BYTES`: extra INTEGER outside the top-level SEQUENCE.
- `RSA_PRIVATE_PARSE_CALL`: `mbedtls_rsa_parse_key(...)`.
- `RSA_PUBLIC_PARSE_CALL`: `mbedtls_rsa_parse_pubkey(...)`.

## Vulnerability Path Features

Must preserve:

- DER key parser,
- top-level ASN.1 SEQUENCE length,
- valid object followed by trailing bytes,
- parser accepts versus rejects extra data,
- observable return code.

Optional:

- RSA private key path,
- RSA public key path,
- PKCS#1 DER encoding.

Not required:

- exact key values,
- exact extra INTEGER bytes,
- exact internal helper names.

## Migration Guidance

Good target APIs parse DER key objects, expose or imply complete-input-consumed
validation, can be given valid object plus trailing bytes, and return observable
success or invalid-input errors. Preserve the top-level object-boundary
condition.

## References

- PR: `https://github.com/Mbed-TLS/mbedtls/pull/8804`
- Evidence: `data/pocs/core10/MBEDTLS-POC-0020/reproduction_result.md`
- PoC: `data/pocs/core10/MBEDTLS-POC-0020/poc/poc_rsa_trailing_garbage.c`
- Logs: `data/pocs/core10/MBEDTLS-POC-0020/poc/run_buggy.log`, `data/pocs/core10/MBEDTLS-POC-0020/poc/run_fixed.log`
