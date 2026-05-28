# OpenSSL PoC Artifact: issue_18168

## Basic Information

- Issue: https://github.com/openssl/openssl/issues/18168
- Title: Assertion failure in WPACKET_put_bytes__, packet.c:387, openssl-rsa
- Artifact class: B2_cli_to_c_candidate
- PoC origin: translated_from_cli_command
- Component: WPACKET/DER_WRITER/RSA
- Trigger behavior: ASSERTION_FAILURE
- Affected version: 3.1.0-dev

## API Path

- BIO_new_file
- PEM_read_bio_RSAPrivateKey
- PEM_write_bio_RSAPrivateKey
- RSA_free

## Validation

- Local compile: True
- Local run: True
- Strict reproduction: False
- Input status: placeholder_input_used
- Local test result: compiled_and_executed_with_generated_rsa_key
- Tested library: OpenSSL 3.0.13 / system libssl-libcrypto

## Notes

This artifact is part of the standardized OpenSSL PoC artifact dataset used by CipherLens.

Unless `strict_reproduction` is explicitly marked as true, this artifact should be interpreted as a validated C harness for API-path analysis rather than a strict vulnerability reproduction.
