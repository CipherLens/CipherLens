# OpenSSL PoC Artifact: issue_16196

## Basic Information

- Issue: https://github.com/openssl/openssl/issues/16196
- Title: openssl req segfault
- Artifact class: B2_cli_to_c_candidate
- PoC origin: translated_from_cli_command
- Component: REQ/ASN1
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: None

## API Path

- BIO_new_file
- PEM_read_bio_X509_REQ
- X509_REQ_get_pubkey
- EVP_PKEY_get1_RSA
- RSA_get0_key
- BN_print_fp

## Validation

- Local compile: True
- Local run: True
- Strict reproduction: False
- Input status: placeholder_input_used
- Local test result: compiled_and_executed_with_generated_csr
- Tested library: OpenSSL 3.0.13 / system libssl-libcrypto

## Notes

This artifact is part of the standardized OpenSSL PoC artifact dataset used by CipherLens.

Unless `strict_reproduction` is explicitly marked as true, this artifact should be interpreted as a validated C harness for API-path analysis rather than a strict vulnerability reproduction.
