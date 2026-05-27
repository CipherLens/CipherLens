# Reproduction Result: MBEDTLS-POC-0005

## Status

reproduced

## CVE

CVE-2025-48965

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0005-buggy
- commit: 2df7ab7c0c3d5bb8a31481073c494521d10d4eba^

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0005-fixed
- commit: 2df7ab7c0c3d5bb8a31481073c494521d10d4eba

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0005/poc/poc_asn1_store_named_data_null_deref.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0005/poc/poc_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0005/poc/poc_fixed

## Trigger

The PoC uses the same OID three times:

1. Store nonzero value with `val_len = 4`
2. Store zero-length value with `val_len = 0`
3. Store nonzero value with `val_len = 4` again

## Buggy output

step1: store nonzero value len=4
after step1: val.p=... val.len=4
step2: store zero-length value len=0
after step2: val.p=(nil) val.len=4
step3: store nonzero value len=4 again; buggy version may crash now
Segmentation fault
exit_code=139

## Fixed output

step1: store nonzero value len=4
after step1: val.p=... val.len=4
step2: store zero-length value len=0
after step2: val.p=(nil) val.len=0
step3: store nonzero value len=4 again
after step3: val.p=... val.len=4
[OK] fixed behavior: value buffer was safely reallocated and updated.

## Root cause

In the buggy version, `mbedtls_asn1_store_named_data()` frees `cur->val.p` when `val_len == 0` and sets `cur->val.p = NULL`, but it does not reset `cur->val.len`.

This leaves the internal ASN.1 named-data object in an inconsistent state:

- `cur->val.p == NULL`
- `cur->val.len != 0`

A later call with the same OID and a value length equal to the stale `cur->val.len` can skip reallocation and attempt to copy data into `cur->val.p == NULL`, causing a NULL pointer dereference.

## Confirmed fix

The fixed version adds:

cur->val.len = 0;

inside the `val_len == 0` branch.

## Confirmed mutation point

library/asn1write.c: mbedtls_asn1_store_named_data()

Statement-level mutation point:

cur->val.len = 0;

## Occlusion candidates

- identifier-level: `cur->val.len`
- statement-level: `cur->val.len = 0;`
- block-level: the full `val_len == 0` branch
