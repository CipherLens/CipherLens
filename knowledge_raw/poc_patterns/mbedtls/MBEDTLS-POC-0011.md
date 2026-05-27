# MBEDTLS-POC-0011: encrypted PEM empty decoded buffer underflow

## Source

This pattern comes from CVE-2025-52497. The affected public API is
`mbedtls_pem_read_buffer`, with related exposure through higher-level PEM/PK
parsing such as `mbedtls_pk_parse`.

The confirmed fixed merge commit is
`3f82706cb76b80f5c136b91edc6688dea299fbdb`; the local buggy worktree used
`3f82706cb76b80f5c136b91edc6688dea299fbdb^1`. The library fix commit is
`6165e715899a9b370851e2868fe312d7e0a2cb83`, and the regression test commit is
`9325883d9fb270cae63af5a254eb6a855813a189`.

## Root Cause

Malformed encrypted PEM input with fewer than four base64 characters can reach
`pem_check_pkcs_padding()` with `input_len == 0`. The buggy helper reads:

```c
input[input_len - 1]
```

without first checking that `input_len >= 1`, causing a one-byte read before
the decoded heap buffer.

The fixed guard is:

```c
if (input_len < 1) {
    return MBEDTLS_ERR_PEM_INVALID_DATA;
}
```

## Trigger Condition

The PoC calls `mbedtls_pem_read_buffer()` on an encrypted EC private key PEM
block with:

- `Proc-Type: 4,ENCRYPTED`
- `DEK-Info: AES-128-CBC,...`
- password `pwd`
- malformed base64 body `8Q` immediately before the footer

This drives the encrypted PEM path into PKCS padding validation with an empty
or invalid decoded buffer.

## Buggy and Fixed Behavior

Buggy behavior:

```text
calling mbedtls_pem_read_buffer...
READ of size 1
pem_check_pkcs_padding
address is located 1 bytes before a heap-allocated region
exit_code=1
```

Fixed behavior:

```text
calling mbedtls_pem_read_buffer...
ret=-4352
expected fixed ret=-4352
use_len=140
[OK] fixed behavior: malformed PEM rejected safely.
```

## Oracle

Bug signal:

- AddressSanitizer reports a one-byte heap-buffer-underflow/overflow.
- The read occurs in `pem_check_pkcs_padding`.
- The reported address is one byte before the decoded heap buffer.

Safe signal:

- `mbedtls_pem_read_buffer()` returns `MBEDTLS_ERR_PEM_INVALID_DATA`.
- No ASan report occurs.

## Mutation Points

- `PEM_BODY_LENGTH`: controls whether decoded content is empty or too short.
- `ENCRYPTION_HEADER`: selects the encrypted PEM/padding-check path.
- `INPUT_LEN_GUARD`: fixed guard `input_len < 1`.
- `PEM_READ_CALL`: public parser call and return-code oracle.

## Vulnerability Path Features

Must preserve:

- PEM parser entrypoint,
- encrypted PEM path,
- malformed or short base64 body,
- decoded buffer length can be zero,
- padding check reads last byte,
- ASan underflow or safe invalid-data return.

Optional:

- AES-128-CBC `DEK-Info`,
- EC private key label,
- password-based decryption path.

Not required:

- exact heap address,
- exact ASan wording,
- exact PEM line wrapping.

## Migration Guidance

Good target APIs parse PEM or armored key material, support encrypted PEM or a
padding-validation path, decode attacker-controlled text into a binary buffer,
and expose a malformed-input error. The key migration point is a short decoded
buffer reaching a final-byte padding check; do not reduce this pattern to a
generic PEM parse failure.

## References

- CVE: `CVE-2025-52497`
- Advisory: `https://github.com/Mbed-TLS/mbedtls-docs/blob/main/security-advisories/mbedtls-security-advisory-2025-06-2.md`
- Evidence: `data/pocs/core10/MBEDTLS-POC-0011/reproduction_result.md`
- PoC: `data/pocs/core10/MBEDTLS-POC-0011/poc/poc_pem_underflow.c`
- Logs: `data/pocs/core10/MBEDTLS-POC-0011/poc/run_buggy.log`, `data/pocs/core10/MBEDTLS-POC-0011/poc/run_fixed.log`
