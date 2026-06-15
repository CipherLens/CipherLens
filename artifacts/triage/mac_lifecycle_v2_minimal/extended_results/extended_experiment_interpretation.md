# OpenSSL CMAC extended lifecycle experiment interpretation

## Scope

This note interprets two extended OpenSSL-only CMAC lifecycle experiments:

- `extended_cases/min_openssl_cmac_resume_equivalence.c`
- `extended_cases/min_openssl_cmac_final_idempotence.c`

The goal is to determine whether OpenSSL CMAC post-final behavior is merely a cross-library API difference, or whether it can produce non-obvious state-machine behavior that may hide application misuse.

## Experiment 1: resume equivalence

The experiment compares:

Path A:

    update(message1)
    final(tag1)
    update(message2)
    final(tag_after_resume)

Path B:

    fresh update(message1 || message2)
    final(tag_fresh_concat)

Path C:

    fresh update(message2)
    final(tag_fresh_msg2)

Observed result for both AES-128-CBC CMAC and AES-256-CBC CMAC:

    tag_after_resume_eq_fresh_concat=0
    tag_after_resume_eq_fresh_msg2=0

Interpretation:

OpenSSL CMAC accepts `EVP_MAC_update()` after `EVP_MAC_final()` and produces a new 16-byte tag after a subsequent finalization. However, the resulting tag is not equivalent to a fresh CMAC over `message1 || message2`, and it is also not equivalent to a fresh CMAC over `message2`.

This suggests that post-final continuation is not a simple append/resume semantics from the original message stream, nor an automatic reset semantics. Instead, the context appears to continue from a final-mutated internal state.

## Experiment 2: final idempotence

The experiment compares:

Path A:

    update(message)
    final(out)

Path B:

    update(message)
    final(NULL)
    final(out)

Path C:

    update(message)
    final(out1)
    final(out2)

Observed result for both AES-128-CBC CMAC and AES-256-CBC CMAC:

    tag_A_eq_tag_B=1
    tag_C1_eq_tag_C2=0
    tag_C2_eq_tag_A=0

Interpretation:

The documented length-query pattern `final(NULL) -> final(out)` is stable and produces the same tag as a normal single finalization.

However, repeated output finalization `final(out1) -> final(out2)` is not idempotent. The second output finalization succeeds and produces a different 16-byte tag.

This indicates that `EVP_MAC_final(out)` for CMAC should not be treated as a pure read-only operation by callers. It can mutate the effective CMAC state and allow subsequent operations to produce non-obvious tags.

## Security interpretation

This is still not a crash report, memory corruption report, confirmed vulnerability, or CVE claim.

However, the extended results strengthen the lifecycle semantic divergence finding:

- OpenSSL CMAC is permissive after finalization.
- Post-final operations may succeed instead of reporting misuse.
- Repeated output finalization is non-idempotent.
- Post-final update/final does not correspond to simple fresh CMAC computations over obvious message choices.
- mbedTLS PSA MAC rejects post-finish update/final paths with `PSA_ERROR_BAD_STATE`, exposing the same misuse earlier.

The main security-relevant concern is therefore an application-level state-machine misuse detection gap, especially in code migrated from a strict PSA-style MAC lifecycle to OpenSSL EVP_MAC CMAC.
