# Next Step After secure_heap

## secure_heap Status

`secure_heap_state_lifecycle` should not continue as the main exploration line
right now. Its current milestone is closed and the family moves to:

```text
external_validation_track
```

Remaining secure heap work:

- ASAN/UBSAN validation.
- Multi-version matrix.
- API contract confirmation.

The ASAN/UBSAN OpenSSL rebuild is needed, but it should be done separately by a
teammate and should not be mixed into the current exploration workflow.

## Main Exploration Next Family

The recommended next family is:

```text
cipher_aead_lifecycle
```

Recommended execution path:

```text
B_controlled_family_mutation
```

Fallback path:

```text
D_then_A
```

Reason: lifecycle/state-machine lessons from secure heap can transfer to
AEAD/cipher init, update, final, free, and reuse patterns. If cross-library API
equivalence is strong enough, the family can later move into recipe-slot
cross-library migration.

## Historical PoC Intake

Do not blindly batch-run additional historical PoCs. The better next step is
family triage plus scheduler-guided selection.

## Next Codex Task

Start `cipher_aead_lifecycle` family triage and pattern abstraction. Keep the
work family-level and data-driven, and only extend framework code if a genuinely
reusable oracle or harness-family rule is needed.
