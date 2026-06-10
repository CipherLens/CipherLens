# PKEY Verify Family Template Requirements

This document records the required template support for `pkey_verify_semantic`
main-chain exploration.

## Current Blocker

The existing reusable seed is:

```text
artifacts/migrations/mbedtls-poc-0003-pk-verify-ext-null-deref/
```

That seed is valuable for `null_deref_dispatch`, but it is not a controlled
signature verification mutation template. Its cross template currently exposes
legacy placeholders such as:

```text
[KEY_BITS]
[HASH_LEN]
[SIG_LEN]
[MD_ALG]
[PK_VERIFY_TYPE]
[EXPECTED_SALT_LEN]
```

The `pkey_verify_v0` render matrix instead needs controlled signature-verification
slots. The current template should not be used to render or run those cases,
because doing so would conflate an opaque-key null-deref dispatch oracle with
invalid-signature acceptance and padding/digest semantic oracles.

## Required Placeholders

A reusable `pkey_verify_semantic` template should expose at least:

```text
[VERIFY_API]
[KEY_TYPE]
[PADDING_MODE]
[DIGEST_ALG]
[HASH_BYTES]
[HASH_LEN]
[SIGNATURE_BYTES]
[SIGNATURE_LEN]
[VERIFY_CALL]
[VERIFY_ORACLE_OBSERVATION]
[EXPECTED_VERDICT_CLASS]
```

Recommended additional placeholders:

```text
[SIGNATURE_MUTATION]
[DIGEST_MUTATION]
[KEY_MUTATION]
[PADDING_MUTATION]
[SIGNING_KEY_SETUP]
[VERIFY_KEY_SETUP]
[ERROR_STACK_OBSERVATION]
```

## Required Framework-Owned Snippets

The renderer should own and validate snippets for:

```text
valid signature generation
invalid_signature / bitflip_signature / all_zero_signature construction
truncated_signature length handling
wrong_digest and wrong_hash_length construction
matching_key and wrong_key setup
rsa_pkcs1_v15 and rsa_pss setup
pss_saltlen_mismatch setup
padding_mismatch setup
return-code and signature-acceptance oracle observation
error stack observation for OpenSSL
safe cleanup for all initialized objects
```

The LLM may fill structured `slot_bindings`, but it must not generate:

```text
init_block
input_construction_block
trigger_block
cleanup_block
oracle_strategy
free-form C harness code
```

## Oracle Classes

The controlled verify template should preserve these candidate classes:

```text
unexpected_success_candidate
behavior_divergence_candidate
safe_negative
projection_limitation
crash_candidate
harness_error
```

Important interpretation rule:

```text
setup failure != invalid signature rejection
invalid signature rejection != crash
success on intentionally invalid signature material = high-value semantic candidate
```

## Render-Matrix Integration

The current planning artifacts are:

```text
artifacts/sprints/pkey_verify_family_v0/mutation_plan.yaml
artifacts/sprints/pkey_verify_family_v0/render_matrix.yaml
```

`template_maker/render_cases.py` does not directly consume external
`render_matrix.yaml`. A future renderer-side integration should map matrix
entries into template metadata or recipe slot bindings before `render_cases.py`
is invoked.

Expected path shape after integration:

```text
artifacts/sprints/pkey_verify_family_v0/expanded_cross_templates/
artifacts/sprints/pkey_verify_family_v0/rendered_cases/
artifacts/sprints/pkey_verify_family_v0/results/
```

## Do Not Use As Substitute

Do not substitute the existing `PK_VERIFY_EXT_OPAQUE_RSA_PSS_NULL_DEREF`
template for this family. It is intended to test:

```text
generic key dispatch
opaque/mismatched key type
RSA-PSS path reaching type-specific logic
crash or safe error return
```

It is not sufficient for:

```text
invalid signature accepted
wrong digest accepted
wrong hash length accepted
wrong key accepted
padding mismatch accepted
PSS salt length mismatch accepted
```
