# Botan AEAD API Notes

## Answers

- create_aes_128_gcm: Botan::AEAD_Mode::create_or_throw("AES-128/GCM", Botan::Cipher_Dir::Encryption) or Decryption; shortened tag is expressed as "AES-128/GCM(8)".
- set_key: Cipher_Mode/AEAD object uses set_key(key bytes).
- set_nonce_iv: Use start(nonce) before finish/update.
- set_aad: Use set_associated_data(ad), documented to be after set_key and before start.
- encryption_finish: Use finish(buffer); if entire message is available, finish without update is documented as efficient/convenient.
- decryption_finish_verify: Use finish(ciphertext_and_tag); invalid tag throws Invalid_Authentication_Tag per cipher_mode.h.
- post_final_set_tag_ctrl: No OpenSSL-style post-final SET_TAG ctrl found in local C++ AEAD API; authentication tag is part of decrypt final input.
- tag_length_parameter_or_limit: Algorithm name can encode tag length, e.g. local test vectors include AES-128/GCM(8). Exact accepted range beyond local evidence is unknown_from_local_evidence.

## Evidence

- `_install/include/botan-3/botan/aead.h`: `AEAD_Mode::create/create_or_throw`, `set_associated_data`.
- `_install/include/botan-3/botan/cipher_mode.h`: `finish()` semantics and authentication-tag exception behavior.
- `src/tests/test_aead.cpp`: empty input encrypt through `finish()`.
- `src/tests/data/aead/gcm.vec`: `AES-128/GCM(8)` test vector exists.
