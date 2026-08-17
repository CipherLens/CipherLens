# Transfer Signature v0.1

## Position

Transfer Signature is the Contract-derived Target Eligibility Specification.

- Vulnerability Contract v0.3 defines what must be validated.
- Transfer Signature v0.1 defines which target semantic surfaces qualify for
  migration.
- Transfer Signature is target-agnostic. It contains neither a target API nor
  a CandidateBinding.
- Eligibility is not a security Verdict. `ELIGIBLE`, `INELIGIBLE`, and
  `INDETERMINATE` must not be interpreted as `SATISFIED`, `VIOLATED`, or the
  final Contract `UNKNOWN` state.

The implementation is isolated in `transfer_signature/` and has no runtime
dependency on candidate mapping, RAG, adapter generation, runners, or caller
analysis.

## Canonical artifacts

### Transfer Signature

Schema version: `cipherlens.transfer_signature.v0.1`.

The document records a stable Contract reference and digest, one or more
source-validation artifact references, the Contract family, three typed
constraint lists, and field-level derivation provenance:

```text
required_capabilities
excluded_semantics
required_observability
```

Generation accepts only a schema-valid VC v0.3 whose declared canonical digest
matches the supplied Contract, whose source-validation artifacts have matching
canonical digests and Contract provenance, and for which at least one source
validation is `PASS`. A registered deterministic family rule is mandatory.

TS serialization is canonical UTF-8 YAML with sorted mapping keys. Lists are
constructed in stable ID order. Evidence paths are repository-relative and
their SHA-256 digests are checked. Unknown fields are rejected recursively.

TS explicitly forbids target API identity, CandidateBinding, scores, target
execution results, Contract Verdicts, and a copied `expected_relation`.
Contract.P may justify a derivation but is never restated as a TS relation.

### TargetSemanticProfile

Schema version: `cipherlens.target_semantic_profile.v0.1`.

The profile is an internal matcher input, not a new report-level concept. Its
`target_scope` describes a semantic surface rather than assuming one API:

```yaml
target_scope:
  library: example
  version: "1.0"
  surface_ref: example:decode-surface
```

The surface may contain API, API-group, wrapper, interface, object-model,
call-surface, object, and observation-channel subjects. Every fact has a
`subject_ref`. Execution-shape and correlation facts may name multiple
participant subjects.

Facts use closed assertions (`TRUE`, `FALSE`, `UNKNOWN`), epistemic states
(`VERIFIED`, `INFERRED`, `PROPOSED`), and coverage (`SUBJECT`, `SURFACE`). Only
semantically compatible `VERIFIED` facts are determinate. A negative fact must
cover the complete target surface to establish a deterministic mismatch.
Conflicting verified assertions are profile validation errors.

LLM evidence cannot establish `VERIFIED`. API-card, adapter-recipe, or RAG
evidence alone is also insufficient. Such legacy knowledge remains inferred or
proposed until deterministic documentation, source, test, runtime, or reviewed
evidence verifies it.

### Evaluation

Schema version: `cipherlens.ts_evaluation.v0.1`.

Every constraint produces:

```text
MATCH | MISMATCH | UNKNOWN
```

The record includes the constraint ID and class, matched fact references, a
closed reason code, and closed missing-fact requirements. A closed matcher is
registered for every constraint type. Each matcher checks the expected fact
type, typed parameters, subject and surface compatibility, semantic role,
assertion, epistemic status, and any required participant relationship. There
is no fuzzy matching, weighting, model decision, or free-text condition
execution.

Top-level aggregation is:

1. Required-capability `MISMATCH` means `INELIGIBLE`.
2. Required-observability `MISMATCH` means `INELIGIBLE`.
3. Excluded-semantic `MATCH` means `INELIGIBLE`.
4. All required constraints `MATCH` and all excluded constraints `MISMATCH`
   means `ELIGIBLE`.
5. Every other combination means `INDETERMINATE`.

A determinate ineligibility reason takes precedence over unrelated unknowns.

## Closed constraint registry

Required capabilities:

- `supports_operation_role`
- `supports_object_role`
- `supports_precondition_shape`
- `permits_equivalent_intervention`
- `supports_execution_shape`

Excluded semantics:

- `mandatory_complete_input_enforcement`
- `failure_output_transactionality`
- `atomic_clear_precludes_inconsistent_intermediate_state`
- `mandatory_terminalization_precludes_followup`

Required observability:

- `contract_observable_resolvable`
- `observable_set_correlatable`

Relation names and family names are not constraint types.

## Deterministic derivation

Context objects and preconditions derive object-role and precondition-shape
capabilities. Interventions derive equivalent-intervention capabilities.
Execution steps derive operation-role and ordered execution-shape capabilities.
Contract.O produces observable references without copying observable
definitions into TS. Family rules produce attack-surface exclusions and the
required correlation scope.

Each constraint names a derivation record. Each derivation records its method,
versioned rule, Contract field references, family-rule reference where relevant,
and source evidence references.

The current family registry covers:

- `input_consumption`
- `failure_output_integrity`
- `object_state_consistency`

## Observability boundary

TS states which Contract.O evidence must be resolvable and correlated.
TargetSemanticProfile states whether a target semantic surface has a verified
abstract channel. This foundation does not choose concrete API parameters,
before/after acquisition instructions, hooks, instrumentation points, or an
observation plan. Those are future Matcher and CandidateBinding responsibilities.

## Golden scope

The v0.1 snapshots reuse, rather than copy, the existing validated Contracts for
MBEDTLS-POC-0020, MBEDTLS-POC-0004, and MBEDTLS-POC-0005. Each has one eligible,
one clearly ineligible, and one evidence-indeterminate synthetic target profile,
plus its complete deterministic evaluation artifact.
