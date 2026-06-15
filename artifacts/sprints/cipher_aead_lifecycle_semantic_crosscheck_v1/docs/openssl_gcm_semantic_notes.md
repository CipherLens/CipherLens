# OpenSSL GCM Semantic Notes

## Evidence

- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3/EVP_EncryptInit.pod`
- `/home/wen/work/clean_sources/openssl-3.5.5/crypto/evp/e_aes.c`
- `/home/wen/work/clean_sources/openssl-3.5.5/providers/implementations/ciphers/ciphercommon_gcm.c`
- `/home/wen/work/clean_sources/openssl-3.5.5/providers/implementations/ciphers/ciphercommon_gcm_hw.c`

## Answers

- gcm_encrypt_empty_plaintext_allowed: yes
  Evidence: AEAD flow allows psa/OpenSSL-style zero or more data updates; OpenSSL GCM final can produce tag with no plaintext update. Prior harness observed Final_without_data_update ret=1 and GetTag ret=1.
- evp_encryptfinal_gcm_success_with_no_output: yes
  Evidence: EVP_EncryptFinal_ex returns success/failure; GCM provider final computes tag and does not necessarily emit ciphertext bytes.
- get_tag_after_encrypt_final_required: yes
  Evidence: EVP_CTRL_AEAD_GET_TAG doc says only when encrypting and after all data has been processed, e.g. after EVP_EncryptFinal().
- set_tag_before_decrypt_final_required: yes
  Evidence: EVP_CTRL_AEAD_SET_TAG doc says tag must be set prior to EVP_DecryptFinal()/EVP_DecryptFinal_ex().
- gcm_tag_length_range: 1..16 bytes for SET_TAG while decrypting
  Evidence: EVP_CTRL_AEAD_SET_TAG doc says taglen must be between 1 and 16 inclusive.
- wrong_tag_length_case_validity: allowed_truncated_tag
  Evidence: The case uses tag length 8, which is within OpenSSL GCM allowed 1..16-byte tag lengths.
- set_tag_after_final_ctrl_success_meaning: permissive_ctrl_state_after_failed_final
  Evidence: legacy ctrl path validates taglen and decrypt/encrypt direction but does not check whether decrypt final already happened; final verification uses taglen/tag buffer at final time.

## Bottom Line

- `final_without_update` is legal empty-message/AAD-only GCM encryption behavior, not a bug signal by itself.
- `wrong_tag_length` with 8 bytes is allowed truncated-tag behavior in OpenSSL GCM.
- `set_tag_after_final` is a permissive ctrl-layer state observation; available evidence does not show it can alter already completed authentication.
