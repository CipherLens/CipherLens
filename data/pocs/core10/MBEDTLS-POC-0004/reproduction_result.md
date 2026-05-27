# Reproduction Result: MBEDTLS-POC-0004

## Status

reproduced

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0004-buggy
- commit: 94f07689d6af26030184c176ba44ecd148eff75a^1

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0004-fixed
- commit: 94f07689d6af26030184c176ba44ecd148eff75a

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0004/poc/poc_get_pkcs_padding_outlen.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0004/poc/poc_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0004/poc/poc_fixed

## Trigger

The PoC constructs one AES-CBC ciphertext block whose decrypted plaintext ends with an invalid PKCS#7 padding byte:

- input_len: 16
- padding_len: 0x80 / 128

## Buggy output

cipher_finish ret=-25088
expected ret=-25088
update_olen=0
finish_olen=18446744073709551504
[BUG] invalid padding rejected but outlen is unsafe/nonzero.

## Fixed output

cipher_finish ret=-25088
expected ret=-25088
update_olen=0
finish_olen=0
[OK] fixed behavior: invalid padding rejected and outlen remains zero.

## Root cause

In the buggy version, get_pkcs_padding() reads padding_len from the final byte of the decrypted block and then computes:

*data_len = input_len - padding_len;

before rejecting invalid padding lengths. When padding_len > input_len, this causes size_t underflow and leaves a huge output length on the error path.

## Confirmed fix

The fixed version adds:

if (padding_len == 0 || padding_len > input_len) {
    return MBEDTLS_ERR_CIPHER_INVALID_PADDING;
}

before assigning:

*data_len = input_len - padding_len;

## Confirmed mutation point

library/cipher.c: get_pkcs_padding()

Statement-level mutation point:

if (padding_len == 0 || padding_len > input_len) {
    return MBEDTLS_ERR_CIPHER_INVALID_PADDING;
}

## Occlusion candidates

- identifier-level: `padding_len`, `input_len`
- expression-level: `padding_len == 0 || padding_len > input_len`
- statement-level: `return MBEDTLS_ERR_CIPHER_INVALID_PADDING;`
- block-level: the full invalid-padding check
