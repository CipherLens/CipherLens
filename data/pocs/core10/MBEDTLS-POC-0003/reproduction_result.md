# Reproduction Result: MBEDTLS-POC-0003

## Status

reproduced

## Source

PR #8942

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0003-buggy
- commit: b2b90682646629698ddc0287b4e3967591e1cebc^1

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0003-fixed
- commit: b2b90682646629698ddc0287b4e3967591e1cebc

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0003/poc/poc_pk_verify_ext_null_deref_v2.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0003/poc/poc_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0003/poc/poc_fixed

## Logs

- buggy log: data/pocs/core10/MBEDTLS-POC-0003/poc/run_v2_buggy.log
- fixed log: data/pocs/core10/MBEDTLS-POC-0003/poc/run_v2_fixed.log

## Failure signal

NULL dereference crash / segmentation fault

## Root cause

In the buggy version, `mbedtls_pk_verify_ext()` can enter the RSA-PSS verification path without first ensuring that the supplied PK context is a compatible RSA context.

This allows an incompatible or invalid PK context to reach code paths that dereference invalid internal pointers, resulting in a NULL dereference crash.

## Fixed behavior

The fixed version adds validation before entering the RSA-PSS-specific verification path. Invalid or incompatible PK contexts are rejected safely instead of causing a crash.

## Confirmed mutation point

library/pk.c: mbedtls_pk_verify_ext()

Missing buggy check:

- PK context type compatibility check before RSA-PSS verification path

## Occlusion candidates

- identifier-level: `ctx`, `type`, `pk_info`
- expression-level: PK type compatibility condition
- statement-level: RSA/RSA-PSS context validation guard
- block-level: RSA-PSS-specific verification branch
