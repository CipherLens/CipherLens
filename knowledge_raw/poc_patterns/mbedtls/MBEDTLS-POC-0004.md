# MBEDTLS-POC-0004: mbedtls_cipher_finish invalid PKCS padding output length

## Source

This pattern comes from Mbed TLS PR #9082 and issue #9083. The affected public
API is `mbedtls_cipher_finish`, with the root cause in the internal
`get_pkcs_padding()` helper in `library/cipher.c`.

The confirmed merge commit is `94f07689d6af26030184c176ba44ecd148eff75a`.
The local buggy worktree used `94f07689d6af26030184c176ba44ecd148eff75a^1`,
and the library fix commit inside the merge is
`30666d478b44082744c0a1832b68f98ad69a0c9f`.

## Root Cause

In the buggy version, `get_pkcs_padding()` reads `padding_len` from the final
byte of the decrypted block and computes:

```c
*data_len = input_len - padding_len;
```

before rejecting impossible padding lengths. When `padding_len > input_len`,
the `size_t` subtraction underflows and leaves a huge caller-visible output
length on the error path.

The fixed version checks the padding length before assigning `*data_len`:

```c
if (padding_len == 0 || padding_len > input_len) {
    return MBEDTLS_ERR_CIPHER_INVALID_PADDING;
}
```

## Trigger Condition

The minimal PoC builds a one-block AES-128-CBC decrypt finalization case:

- cipher: `MBEDTLS_CIPHER_AES_128_CBC`
- operation: `MBEDTLS_DECRYPT`
- padding mode: `MBEDTLS_PADDING_PKCS7`
- final block length: `16`
- final plaintext byte: `0x80`
- interpreted `padding_len`: `128`

The final padding byte is larger than the input block length, so the buggy
`input_len - padding_len` computation underflows.

## Buggy and Fixed Behavior

Buggy output:

```text
cipher_finish ret=-25088
expected ret=-25088
update_olen=0
finish_olen=18446744073709551504
[BUG] invalid padding rejected but outlen is unsafe/nonzero.
```

Fixed output:

```text
cipher_finish ret=-25088
expected ret=-25088
update_olen=0
finish_olen=0
[OK] fixed behavior: invalid padding rejected and outlen remains zero.
```

The oracle is invalid-padding error plus unsafe output length versus
invalid-padding error plus zero/bounded output length.

## Mutation Points

- `PADDING_BYTE`: controls the invalid PKCS padding length.
- `INPUT_LEN`: controls the boundary checked against `padding_len`.
- `PADDING_MODE`: selects the PKCS#7 finalization path.
- `CIPHER_FINISH_CALL`: exposes the caller-visible output length.
- `INVALID_PADDING_GUARD`: the fixed validation statement before `*data_len`.

## Multi-granularity Masking Guidance

### Identifier-level Candidates

- `padding_len`: length read from the final plaintext byte.
- `input_len`: decrypted final-block length.
- `data_len`: internal output length pointer.
- `finish_olen`: caller-visible output length from `mbedtls_cipher_finish`.

### Expression-level Candidates

- `padding_len == 0 || padding_len > input_len`
- `input_len - padding_len`

### Statement-level Candidates

- `*data_len = input_len - padding_len;`
- `return MBEDTLS_ERR_CIPHER_INVALID_PADDING;`

### Block-level Candidates

```c
if (padding_len == 0 || padding_len > input_len) {
    return MBEDTLS_ERR_CIPHER_INVALID_PADDING;
}
```

## Vulnerability Path Features

The migrated target API should preserve these features:

- block-cipher decrypt finalization,
- PKCS#7 or PKCS-style padding validation,
- padding length derived from the last plaintext byte,
- caller-visible output length pointer,
- invalid-padding error path,
- unsafe or safe output length observable after error.

Optional features:

- AES-128-CBC,
- exact invalid padding byte `0x80`,
- separate update and finish calls.

Not required features:

- exact Mbed TLS error-code value,
- exact encryption helper used to construct ciphertext,
- exact output buffer contents.

## Migration Guidance

This pattern is about error-path output-length safety, not just padding
validation.

Good target API features:

- supports block-cipher decryption with PKCS-style padding,
- exposes finalization output length through a caller-provided pointer,
- reports invalid padding with an observable error,
- leaves output length observable on both success and error paths,
- permits crafted final plaintext padding bytes.

Weak target API features:

- validates PKCS padding but does not expose output length on error,
- combines update and finalization in a way that hides the vulnerable state.

Bad target API features:

- does not implement padded block-cipher finalization,
- never exposes caller-visible output length,
- always overwrites output length to zero before any error is observable.

## Expected Oracle

Bug candidate signals:

- return value is invalid padding,
- `finish_olen` is nonzero on the error path,
- `finish_olen` is a huge `size_t` value.

Safe or fixed behavior:

- return value is `MBEDTLS_ERR_CIPHER_INVALID_PADDING`,
- `finish_olen == 0`,
- no sanitizer crash.

## Evidence Files

- Metadata: `data/pocs/core10/MBEDTLS-POC-0004/metadata.json`
- Notes: `data/pocs/core10/MBEDTLS-POC-0004/notes.md`
- Reproduction result: `data/pocs/core10/MBEDTLS-POC-0004/reproduction_result.md`
- PoC source: `data/pocs/core10/MBEDTLS-POC-0004/poc/poc_get_pkcs_padding_outlen.c`
- Buggy log: `data/pocs/core10/MBEDTLS-POC-0004/poc/run_buggy.log`
- Fixed log: `data/pocs/core10/MBEDTLS-POC-0004/poc/run_fixed.log`
- Library files: `data/pocs/core10/MBEDTLS-POC-0004/library_files.txt`
- Test files: `data/pocs/core10/MBEDTLS-POC-0004/test_files.txt`
- Commits: `data/pocs/core10/MBEDTLS-POC-0004/commits.txt`
- Fix commits: `data/pocs/core10/MBEDTLS-POC-0004/fix_commits.txt`

## Notes

No local `fix.patch` file is present for this PoC. The value
`18446744073709551516` in `commits.txt` is documented as an oversized output
length, not a commit hash.
