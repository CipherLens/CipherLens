# OpenSSL CMAC Lifecycle Extended Cases

This directory contains OpenSSL-only follow-up experiments for the MAC
lifecycle v2 triage.

## Cases

- `min_openssl_cmac_resume_equivalence.c`
- `min_openssl_cmac_final_idempotence.c`

## Resume Equivalence

The goal is to determine what `EVP_MAC` CMAC means when `EVP_MAC_update()` is
called after a successful `EVP_MAC_final()`.

The case runs both:

- `AES-128-CBC` CMAC
- `AES-256-CBC` CMAC

with fixed keys, `message1`, and `message2`.

## Compared Paths

Path A:

1. `EVP_MAC_init`
2. `EVP_MAC_update(message1)`
3. `EVP_MAC_final` -> `tag1`
4. `EVP_MAC_update(message2)`
5. `EVP_MAC_final` -> `tag_after_resume`

Path B:

1. fresh `EVP_MAC_init`
2. `EVP_MAC_update(message1 || message2)`
3. `EVP_MAC_final` -> `tag_fresh_concat`

Path C:

1. fresh `EVP_MAC_init`
2. `EVP_MAC_update(message2)`
3. `EVP_MAC_final` -> `tag_fresh_msg2`

## Output

The program prints all return values, tag lengths, tag hex strings, and:

- `tag_after_resume_eq_fresh_concat`
- `tag_after_resume_eq_fresh_msg2`

Interpretation:

- If `tag_after_resume_eq_fresh_concat=1`, final-then-update behaves like
  continuing the original message stream.
- If `tag_after_resume_eq_fresh_msg2=1`, final-then-update behaves like a fresh
  MAC over only the post-final message.
- If both are `0`, OpenSSL CMAC resume has a distinct legacy/provider state
  transition that needs separate documentation review.

## Final Idempotence

The goal is to distinguish the documented length-query pattern from repeated
output finalization.

The case runs both:

- `AES-128-CBC` CMAC
- `AES-256-CBC` CMAC

with fixed keys and a fixed message.

Compared paths:

Path A:

1. `EVP_MAC_update(message)`
2. `EVP_MAC_final(out)` -> `tag_A`

Path B:

1. `EVP_MAC_update(message)`
2. `EVP_MAC_final(NULL)` length query
3. `EVP_MAC_final(out)` -> `tag_B`

Path C:

1. `EVP_MAC_update(message)`
2. `EVP_MAC_final(out1)` -> `tag_C1`
3. `EVP_MAC_final(out2)` -> `tag_C2`

The program prints all return values, output lengths, tag hex strings, and:

- `tag_A_eq_tag_B`
- `tag_C1_eq_tag_C2`
- `tag_C2_eq_tag_A`

Interpretation:

- `tag_A_eq_tag_B=1` supports the documented length-query pattern.
- `tag_C1_eq_tag_C2=1` would indicate repeated output finalization is
  idempotent.
- `tag_C1_eq_tag_C2=0` with successful return values indicates repeated output
  finalization advances or resumes CMAC state instead of simply returning the
  same tag again.
