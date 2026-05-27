# Reproduction Result: MBEDTLS-POC-0020

## Status

reproduced

## Source

PR #8804

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0020-buggy
- commit: a7f651cf160a3753367e032c4471699822b37e30^1

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0020-fixed
- commit: a7f651cf160a3753367e032c4471699822b37e30

## Library fix commit

- 9de84bd67775e05fabca1907cd9f2ea33078d99a

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0020/poc/poc_rsa_trailing_garbage.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0020/poc/poc_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0020/poc/poc_fixed

## Trigger

The PoC uses regression-test-derived PKCS#1 RSA DER inputs:

1. RSA private key with an extra INTEGER outside the top-level SEQUENCE
2. RSA public key with an extra INTEGER outside the top-level SEQUENCE

## Buggy output

Testing RSA private key with trailing garbage...
private ret=0
private expected_buggy=0
private expected_fixed=-16512
[BUG] private key parser accepted trailing garbage.

Testing RSA public key with trailing garbage...
public ret=0
public expected_buggy=0
public expected_fixed=-16512
[BUG] public key parser accepted trailing garbage.

[BUG] both RSA parsers accepted trailing garbage.

## Fixed output

Testing RSA private key with trailing garbage...
private ret=-16512
private expected_buggy=0
private expected_fixed=-16512
[OK] private key parser rejected trailing garbage.

Testing RSA public key with trailing garbage...
public ret=-16512
public expected_buggy=0
public expected_fixed=-16512
[OK] public key parser rejected trailing garbage.

[OK] both RSA parsers rejected trailing garbage.

## Root cause

In the buggy version, `mbedtls_rsa_parse_key()` and `mbedtls_rsa_parse_pubkey()` parse the top-level ASN.1 SEQUENCE but do not verify that the DER input ends exactly at the end of that SEQUENCE.

As a result, a valid RSA key followed by trailing garbage outside the main SEQUENCE is accepted.

## Confirmed fix

The fixed version adds this check after parsing the top-level SEQUENCE length:

if (end != p + len) {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
}

## Confirmed mutation points

- library/rsa.c: mbedtls_rsa_parse_key()
  - missing check for bytes outside the main RSAPrivateKey SEQUENCE

- library/rsa.c: mbedtls_rsa_parse_pubkey()
  - missing check for bytes outside the main RSAPublicKey SEQUENCE

## Occlusion candidates

- identifier-level: `end`, `p`, `len`
- expression-level: `end != p + len`
- statement-level: `return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;`
- block-level: the full trailing-garbage rejection guard
