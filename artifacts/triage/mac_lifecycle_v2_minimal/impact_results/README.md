# MAC State Machine Misuse Impact Demo

This directory is reserved for outputs from the impact demos in:

- `../impact_cases/mac_state_machine_misuse_demo_openssl.c`
- `../impact_cases/mac_state_machine_misuse_demo_mbedtls.c`

The demos model an upper-layer application state machine with this assumption:

- after MAC final/finish, the operation context should be closed;
- if post-finish update fails, the application rejects post-finish data;
- if post-finish update succeeds, the application computes another final tag
  and accepts the post-finish path.

## What This Demonstrates

The demos show whether different MAC APIs enforce or permit post-finish state
transitions under the same key and messages.

Expected interpretation from the current triage:

- OpenSSL `EVP_MAC` CMAC may allow `EVP_MAC_update()` after a successful
  `EVP_MAC_final()`, so the modeled application can reach
  `APPLICATION_ACCEPTED_POST_FINISH_DATA`.
- mbedTLS PSA MAC rejects post-finish `psa_mac_update()` with a bad-state style
  error, so the modeled application reaches `APPLICATION_REJECT`.

This is useful impact evidence for a state-machine semantic divergence: a caller
that assumes final closes the context can make a different application-level
decision depending on the library.

## What This Does Not Demonstrate

This is not a CVE claim and not a confirmed vulnerability report.

The demos do not by themselves prove:

- memory corruption;
- a crash;
- authentication bypass in a real protocol;
- violation of OpenSSL's documented CMAC contract;
- exploitability in an upstream application.

The result should be classified as lifecycle semantic divergence and possible
documentation ambiguity unless additional evidence shows that OpenSSL's behavior
violates a documented API contract or creates a concrete security impact in a
real caller.

## Output Format

Each demo prints structured text for AES-128-CBC and AES-256-CBC:

```text
library=
algorithm=
setup_status=
update_prefix_status=
finish_status=
tag_prefix=
post_finish_update_status=
final_after_post_finish_status=
tag_after_post_finish=
application_decision=
```

Use the output to compare application-level decisions across libraries while
keeping the vulnerability classification separate from the observed semantic
difference.
