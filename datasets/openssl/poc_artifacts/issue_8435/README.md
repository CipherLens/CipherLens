# OpenSSL PoC Artifact: issue_8435

## Basic Information

- Issue: https://github.com/openssl/openssl/issues/8435
- Title: SM2 private key cannot produce valid signatures
- Artifact class: B2_cli_to_c_candidate
- PoC origin: translated_from_cli_command
- Component: PKEY/ECC/SM2
- Trigger behavior: WRONG_RESULT
- Affected version: None

## API Path

- PEM_read_bio_PrivateKey
- PEM_write_bio_PUBKEY
- EVP_DigestSignInit
- EVP_PKEY_CTX_set1_id
- EVP_DigestSign
- EVP_DigestVerifyInit
- EVP_DigestVerify

## Validation

- Local compile: True
- Local run: True
- Strict reproduction: False
- Input status: placeholder_input_used
- Local test result: compiled_and_executed_with_generated_sm2_key
- Tested library: OpenSSL 3.0.13 / system libssl-libcrypto

## Notes

This artifact is part of the standardized OpenSSL PoC artifact dataset used by CipherLens.

Unless `strict_reproduction` is explicitly marked as true, this artifact should be interpreted as a validated C harness for API-path analysis rather than a strict vulnerability reproduction.
