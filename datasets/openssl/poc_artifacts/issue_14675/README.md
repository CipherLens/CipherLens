# OpenSSL PoC Artifact: issue_14675

## Basic Information

- Issue: https://github.com/openssl/openssl/issues/14675
- Title: openssl verify silently ignores any but the first certificate in the certificates argument
- Artifact class: B2_cli_to_c_candidate
- PoC origin: translated_from_cli_command
- Component: X509/VERIFY
- Trigger behavior: WRONG_ALERT_OR_PROTOCOL_BEHAVIOR
- Affected version: 1.1.1f

## API Path

- PEM_read_bio_X509
- X509_STORE_new
- X509_STORE_add_cert
- X509_STORE_CTX_new
- X509_STORE_CTX_init
- X509_verify_cert

## Validation

- Local compile: True
- Local run: True
- Strict reproduction: False
- Input status: placeholder_input_used
- Local test result: compiled_and_executed_with_placeholder_cert_bundle
- Tested library: OpenSSL 3.0.13 / system libssl-libcrypto

## Notes

This artifact is part of the standardized OpenSSL PoC artifact dataset used by CipherLens.

Unless `strict_reproduction` is explicitly marked as true, this artifact should be interpreted as a validated C harness for API-path analysis rather than a strict vulnerability reproduction.
