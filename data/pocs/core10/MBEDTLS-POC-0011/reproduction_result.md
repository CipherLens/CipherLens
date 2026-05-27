# Reproduction Result: MBEDTLS-POC-0011

## Status

reproduced

## CVE

CVE-2025-52497

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0011-buggy
- commit: 3f82706cb76b80f5c136b91edc6688dea299fbdb^1

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0011-fixed
- commit: 3f82706cb76b80f5c136b91edc6688dea299fbdb

## Library fix commit

- 6165e715899a9b370851e2868fe312d7e0a2cb83

## Regression test commit

- 9325883d9fb270cae63af5a254eb6a855813a189

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0011/poc/poc_pem_underflow.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0011/poc/poc_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0011/poc/poc_fixed

## Build mode

The buggy and fixed libraries were built with AddressSanitizer:

- -fsanitize=address
- -g
- -O0
- -fno-omit-frame-pointer

## Trigger

Malformed encrypted PEM input with fewer than 4 base64 characters:

- header: -----BEGIN EC PRIVATE KEY-----
- footer: -----END EC PRIVATE KEY-----
- encryption: AES-128-CBC
- malformed base64 body: 8Q-----END EC PRIVATE KEY-----

## Buggy output

calling mbedtls_pem_read_buffer...

AddressSanitizer reports:

READ of size 1
pem_check_pkcs_padding
library/pem.c:247

The reported address is located 1 byte before a heap-allocated region.

Failure signal:

- one-byte heap-buffer-underflow
- ASan exit_code = 1

## Fixed output

calling mbedtls_pem_read_buffer...
ret=-4352
expected fixed ret=-4352
use_len=140
[OK] fixed behavior: malformed PEM rejected safely.

## Root cause

In the buggy version, malformed encrypted PEM input can reach `pem_check_pkcs_padding()` with an invalid or effectively empty decoded buffer. The function then reads:

input[input_len - 1]

without first checking that `input_len >= 1`. When `input_len` is too small, this causes a one-byte heap-buffer-underflow.

## Confirmed fix

The fixed version adds:

if (input_len < 1) {
    return MBEDTLS_ERR_PEM_INVALID_DATA;
}

before reading:

size_t pad_len = input[input_len - 1];

## Confirmed mutation point

library/pem.c: pem_check_pkcs_padding()

Statement-level mutation point:

if (input_len < 1) {
    return MBEDTLS_ERR_PEM_INVALID_DATA;
}

## Occlusion candidates

- identifier-level: `input_len`
- expression-level: `input_len < 1`
- statement-level: `return MBEDTLS_ERR_PEM_INVALID_DATA;`
- block-level: the full `input_len < 1` guard
