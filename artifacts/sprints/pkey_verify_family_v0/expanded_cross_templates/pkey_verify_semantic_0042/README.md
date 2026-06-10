# PKEY Verify Semantic OpenSSL Controlled Template

This template is the v0 controlled harness surface for `pkey_verify_semantic`.

It is intentionally framework-owned:

```text
render_matrix.yaml
  -> mutation.apply_pkey_verify_matrix_to_template
  -> template_maker.pkey_verify_snippets
  -> template_maker.render_cases
```

The LLM must not provide free-form C blocks for this flow.

The v0 OpenSSL template supports:

```text
EVP_DigestVerify
EVP_PKEY_verify
RSA keys
rsa_pkcs1_v15
rsa_pss
pss_saltlen_mismatch
valid_signature
invalid_signature
truncated_signature
all_zero_signature
bitflip_signature
matching_digest
wrong_digest_algorithm
wrong_hash_length
matching_key
wrong_key
```

Unsupported combinations are written to `render_matrix_skipped_cases.yaml`.
