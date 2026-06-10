# Naming Correction

- Old term: `wrong_tag_length`
- Preferred term: `truncated_tag_length` or `allowed_truncated_tag_length`
- Affected case: `aead_012_wrong_tag_length_gcm_decrypt`
- Preferred case name: `aead_012_truncated_tag_length_gcm_decrypt`

The old name is misleading because the checked 8-byte GCM tag length is allowed in the observed OpenSSL, mbedTLS PSA, and Botan paths. Future tests should reserve `invalid_tag_length` for lengths that are documented as invalid for the target API and oracle.
