# OpenSSL PoC Artifact: issue_15899

## Basic Information

- Issue: https://github.com/openssl/openssl/issues/15899
- Title: openssl rsa -modulus segfaults: bn_expand_internal: Assertion `b->top <= words' failed
- Artifact class: B2_cli_to_c_candidate
- PoC origin: translated_from_cli_command
- Component: BN/ASN1
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: 3.0.0-beta2-dev

## API Path

- BIO_new_file
- PEM_read_bio_X509
- X509_get_pubkey
- EVP_PKEY_get1_RSA
- RSA_get0_key
- BN_print_fp

## Validation

- Local compile: True
- Local run: True
- Strict reproduction: False
- Input status: placeholder_input_used
- Local test result: compiled_and_executed_with_non_buggy_sample_input
- Tested library: OpenSSL 3.0.13 / system libssl-libcrypto

## Notes

This artifact is part of the standardized OpenSSL PoC artifact dataset used by CipherLens.

Unless `strict_reproduction` is explicitly marked as true, this artifact should be interpreted as a validated C harness for API-path analysis rather than a strict vulnerability reproduction.
