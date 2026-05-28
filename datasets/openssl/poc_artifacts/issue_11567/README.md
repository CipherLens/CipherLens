# OpenSSL PoC Artifact: issue_11567

## Basic Information

- Issue: https://github.com/openssl/openssl/issues/11567
- Title: semantic bug when verifying certificate file
- Artifact class: B2_cli_to_c_candidate
- PoC origin: translated_from_cli_command
- Component: X509/ASN1
- Trigger behavior: WRONG_RESULT
- Affected version: Libressl (3.1.0), openssl (commit 031c9bd3f3e9a02fa126c7dbc47f3d934678a195), openssl-1.0.2t

## API Path

- BIO_new_file
- PEM_read_bio_X509
- X509_print_fp

## Validation

- Local compile: True
- Local run: True
- Strict reproduction: False
- Input status: placeholder_input_used
- Local test result: compiled_and_executed_with_non_buggy_sample_input
- Tested library: OpenSSL 3.0.13 / libcrypto.so.3

## Notes

This artifact is part of the standardized OpenSSL PoC artifact dataset used by CipherLens.

Unless `strict_reproduction` is explicitly marked as true, this artifact should be interpreted as a validated C harness for API-path analysis rather than a strict vulnerability reproduction.
