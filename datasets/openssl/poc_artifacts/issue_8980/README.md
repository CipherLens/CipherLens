# OpenSSL PoC Artifact: issue_8980

## Basic Information

- Issue: https://github.com/openssl/openssl/issues/8980
- Title: OpenSSL 1.0.2 branch on uninitialized memory in EVP_CIPHER_CTX_copy
- Artifact class: A_ast_ready
- PoC origin: extracted_c_code_from_issue_evidence
- Component: EVP/AES_GCM
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: 1.0.2

## API Path

- EVP_CIPHER_CTX_new
- EVP_aes_128_gcm
- EVP_EncryptInit_ex
- EVP_CIPHER_CTX_copy

## Validation

- Local compile: True
- Local run: True
- Strict reproduction: False
- Input status: no_external_input_required
- Local test result: compiled_and_executed_with_local_openssl
- Tested library: OpenSSL 3.0.13 / system libssl-libcrypto

## Notes

This artifact is part of the standardized OpenSSL PoC artifact dataset used by CipherLens.

Unless `strict_reproduction` is explicitly marked as true, this artifact should be interpreted as a validated C harness for API-path analysis rather than a strict vulnerability reproduction.
