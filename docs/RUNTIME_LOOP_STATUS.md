# Runtime Loop Status

The current loop is sprint-driven, not scheduler-driven.

The repository has not moved. It remains at:

```text
~/work/crypto-pattern-fuzz
```

## Current Status

The `asn1_nested_boundary` family has reached a family-level runtime feedback
loop over OpenSSL artifacts:

```text
family template
  -> adapter recipe / slot bindings
  -> mutation planning
  -> render planning
  -> render cases
  -> compile/run
  -> oracle-aware analysis
  -> valid-prefix refinement
  -> staged runtime feedback
  -> family-loop closure report
```

This is not a confirmed vulnerability claim. Candidate observations remain
pending external validation.

## Feedback Status

Runtime feedback is staged. It must not be written directly into:

- main knowledge layers,
- pattern bank,
- scheduler seed,
- adapter recipes,
- normalized templates.

External validation gates are required before promotion.

## Known Limitation

`pkcs_container_parsing` remains blocked by missing verified valid seed. This is
why the next feature mainline is:

```text
valid_seed_discovery_pkcs_v1
```

## Scheduler Status

The current runtime loop is still manually sprint-driven. Scheduler proposals
exist as artifacts, but the system is not yet an autonomous scheduler-driven
loop.

Before making the loop scheduler-driven, require:

1. validated seed discovery for blocked families,
2. external validation import gate for pending candidates,
3. stable module ownership and tool wrapper policy,
4. no direct promotion of unvalidated sprint artifacts into core knowledge.
