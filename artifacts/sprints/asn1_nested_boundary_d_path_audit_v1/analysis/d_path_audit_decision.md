# D-Path Audit Decision

- audit_result: `D_audit_only`, `migrated_safe_negative_feedback`, `not_enough_for_claim`
- Existing crash/sanitizer seed: yes, `OPENSSL-ISSUE-30581` metadata reports `CLI+SANITIZER_LOG` and `NULL_DEREFERENCE_CRASH`.
- Strict local reproduction: not established; local artifact used placeholder input.
- Safe/safe evidence: `MBEDTLS-POC-0017` migration has 16 `safe_reject_behavior` cases and 8 `migrated_safe` pairs.
- Current-version candidate: `not_confirmed`.
- Needs minimal reproducer: yes.
- Needs ASAN/UBSAN/gdb: yes.
- Should enter A-path now: no.

Missing evidence for A-path: strict reproduction input or equivalent minimized malformed PKCS12/ASN.1 object, sanitizer/gdb evidence on the intended version, and a stable parser-level oracle.
