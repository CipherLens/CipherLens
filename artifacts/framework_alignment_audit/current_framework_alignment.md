# Current Framework Alignment

## Verdict

The project is still a pattern-guided vulnerability migration and candidate
discovery framework, but the `secure_heap_state_lifecycle_v1` result creates a
specific drift risk: if it stops at reproducing `OPENSSL-ISSUE-28669`, it becomes
a historical issue reproducer rather than a migration/discovery result.

```yaml
framework_goal_alignment:
  intended_goal: "historical pattern guided cross-library/cross-version/same-family vulnerability candidate discovery"
  current_status: "partially_aligned"
  risk: "secure_heap_state_lifecycle_v1 currently stops at seed validation unless followed by pattern expansion"
  required_next_step: "version provenance + novelty check + pattern expansion"
```

## Path Status

- Path A: MAC lifecycle is the current full A-path representative. It exercised
  recipe-slot filling, `adapter_validate`, cross-template generation,
  rendering, compile/run, and cross-result analysis.
- Path B: controlled family mutation remains useful, but must feed discovery
  through state/API matrix expansion.
- Path C: DER full-consumption is the current app-level validation-gap
  representative. It is semantic validation evidence, not a crash claim.
- Path D: crash/sanitizer audit remains a seed-selection and evidence-quality
  path. `secure_heap_state_lifecycle_v1` is D-then-B seed validation.

## secure_heap Position

`secure_heap_state_lifecycle_v1` is not a cross-library migration experiment. It
validates and calibrates the `CRYPTO_secure_used()` state-lifecycle oracle on
OpenSSL. It has not yet performed same-family API expansion, cross-version
expansion, or cross-library analogous lifecycle migration.

The next stage must perform same-family, cross-version, or cross-library
analogous lifecycle expansion to return to the framework's new-candidate
discovery objective.
