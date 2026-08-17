# Vulnerability Contract Schema — canonical v0.3

Status: implemented Contract Foundation schema. The authoritative machine
definition is `contract_miner/vc.schema.yaml`.

## 1. Semantic model

```text
VC = <C, I, X, P, O>
```

- `context` (C): semantic objects, states, and typed preconditions.
- `intervention` (I): the evidence-backed change applied to the context.
- `execution` (X): an ordered sequence of operation roles.
- `expected_relation` (P): typed, deterministic security relations.
- `observable_evidence` (O): typed observations required by P.

Only C/I/X/P/O are behavioral truth sources. Identity, source, family, and
provenance are metadata. v0.2 `roles/states/transitions/guards/mutation/oracle`
must not coexist as a second semantic representation in a v0.3 document.

One Contract has one canonical source vulnerability. It may record one
canonical minimal witness as a provenance evidence item, may be derived from
multiple evidence items, may have multiple SourceValidation records, and may
later be evaluated over multiple target ExecutionWitness records. Concrete
witness observations never appear in C/I/X/P/O.

## 2. Top-level fields

Required fields are:

```yaml
contract_id: UPPER_SNAKE
schema_version: cipherlens.vc.v0_3
contract_family: <closed enum>
source: {...}
context: {...}
intervention: {...}
execution: {...}
expected_relation: {...}
observable_evidence: {...}
provenance: {...}
```

Unknown fields are rejected recursively.

`source` records `pattern_id`, lowercase `library`, `buggy_revision`,
`fixed_revision`, and optional references. It does not describe a target
library.

## 3. Role model

Role kinds have independent registries and exactly one canonical location:

| role kind | canonical location |
|---|---|
| object | `context.objects` |
| state | `context.states` |
| mutation/intervention | `intervention.actions[].kind` |
| operation | `execution.steps[].role` |
| observation | `observable_evidence.observables[].semantic_role` |

The operation registry remains `INIT SETUP UPDATE FINAL PARSE VERIFY SIGN QUERY
RESET REINIT DUP COPY FREE ABORT`. It is not a registry for the other role
kinds.

## 4. Expected Relation P

v0.3 supports exactly seven library/API-independent relation types:

1. `outcome_requirement`
2. `full_consumption_on_success`
3. `output_preserved_on_failure`
4. `state_invariant`
5. `transition_constraint`
6. `failure_propagation`
7. `no_fatal_event`

The first `state_invariant` is
`buffer_absent_implies_length_zero`. Relation operands reference observable
IDs; `transition_constraint.expected_state_ref` references a C state.

Relation evaluation returns only:

```text
HOLDS / BROKEN / NOT_EVALUABLE
```

Every result includes `relation_id`, evidence bindings, a reason code, and
missing observable IDs. Free text, Python expressions, LLM calls, candidate
labels, and old verdict labels are not executable relation inputs.

Family rules are deliberately separate. For example,
`parser_full_consumption_v1` emits `full_consumption_on_success`; the family
rule name never becomes a Contract relation type.

## 5. Observable Evidence O

Every observable declares:

```yaml
observable_id: ...
semantic_role: ...
source:
  phase: before_step | after_step | between_steps | process_end
  step_ref: ...
value_type: integer | boolean | bytes | enum | outcome | state | event | duration
requirement: required | conditional | optional
extraction:
  kind: trace_field | out_state_field | process_field | normalized_return | derived
  field: ...
  rule_id: ...
provenance_refs: [...]
```

Extraction and normalization use closed registries. Missing observations are
different from observations that exist with a null/no-event value. Conditional
observations become required when their relation is active. For example,
consumed/input length is not required when the parse is rejected, but is
required when it succeeds.

## 6. Provenance

Provenance contains:

- producer name, version, and deterministic/manual mode;
- a non-empty evidence list;
- per-field derivation records;
- human-review status.

Every evidence item has a closed kind, repository-relative path, and SHA-256.
Absolute paths, repository escapes, missing files, and digest mismatch are
invalid. A minimal witness is an optional evidence item, not Contract identity.

## 7. Divergence artifact

`cipherlens.divergence.v0_1` is independent of the Contract. It records only
Buggy/Fixed observation facts and their equality/presence difference. It may
not contain vulnerability, Contract-violation, target-expectation, or transfer
eligibility fields.

Batch 1 accepts only `same_library_fix` divergence pairs.

## 8. Family-scoped miner

Batch 1 supports:

- `parser_full_consumption_v1`
- `failure_output_preservation_v1`
- `pointer_length_state_consistency_v1`

The miner consumes structured evidence metadata plus a validated Divergence,
applies a deterministic family rule, emits C/I/X/P/O, records field provenance,
and validates the final Contract. It performs no LLM or target-library work.
Canonical YAML output is byte-stable.

## 9. Three evaluation layers

The APIs are intentionally separate:

```text
Relation Evaluation
  -> HOLDS / BROKEN / NOT_EVALUABLE

Source Contract Validation
  -> PASS / FAIL / INCONCLUSIVE / INVALID_INPUT

Future Target Contract Verdict
  -> SATISFIED / VIOLATED / UNKNOWN
```

Batch 1 implements only the first two. A SourceValidation `PASS` means the
Contract explains and distinguishes the supplied historical Buggy/Fixed
witnesses. It says nothing about transfer success or a target-library verdict.

Future witness-level meanings are fixed as follows:

- SATISFIED: evidence required by the Contract is sufficient for the current
  witness and no violation of P was observed. This is not a proof for all
  inputs, a proof of absolute safety, or proof that no other vulnerability
  exists.
- VIOLATED: sufficient current-witness evidence shows that P was broken. This
  does not automatically establish a confirmed vulnerability, CVE, or
  exploitability.
- UNKNOWN: the current witness lacks sufficient evidence or execution
  conditions to determine whether P held or was broken.

No Batch 1 schema or API emits these three target Verdicts.

## 10. Source validation

Inputs are a v0.3 Contract, Buggy trace, Fixed trace, Divergence, and evidence
manifest. Validation checks schema, evidence digests, source/revision identity,
same-library pair kind, step/evidence references, and Intervention alignment.

PASS requires at least one primary relation BROKEN on the Buggy witness, no
primary relation BROKEN on the Fixed witness, and sufficient required Fixed
evidence. Missing active observations produce INCONCLUSIVE. Contradictory
historical separation produces FAIL. Invalid schema, provenance, identity, or
pair alignment produces INVALID_INPUT.

## 11. v0.2 compatibility

`cipherlens.vc.v0_2` remains read-only and is validated against
`vc.v0_2.schema.yaml`. `upgrade_v02()` returns only:

```text
UPGRADED
NEEDS_STRUCTURED_METADATA
UNSUPPORTED_LEGACY_SEMANTICS
```

An upgrade requires a complete independently structured v0.3 Contract.
Free-text relation, candidate/safe labels, effect, fidelity, and legacy result
labels are never silently converted into P or a Verdict.

## 12. Explicitly outside Batch 1

Transfer Signature, Matcher, CandidateBinding, target Structured Verdict,
UNKNOWN closure, caller impact, UI, cross-library validation, and runner
integration are outside this schema and implementation.
