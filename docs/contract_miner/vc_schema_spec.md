# Vulnerability Contract Schema Spec (vc.yaml) — v0.3

> Status: DRAFT v0.3 — incorporates the evidence-backed review of v0.1
> (all P0/P1/P2 items accepted) and the Schema/Instance/Family conceptual
> correction (v0.3). Codex must implement exactly what this file
> says; any field not listed here is out of scope.
> Target location: `docs/contract_miner/vc_schema_spec.md`

## Changelog v0.2 → v0.3

- §1: added the three-layer conceptual model (Contract Schema / Contract
  Instance / Contract Family) and the slot-skeleton mapping. **What is
  unified is the description structure, not the vulnerability behavior.**
  This corrects the lifecycle-centric framing caused by earlier examples;
  the 7-tuple fields are UNCHANGED.
- §2.1: added optional top-level field `contract_family` (closed enum).
- §2.2: clarified that semantic roles come in five kinds (object /
  operation / mutation / state / observation); the 14-role closed
  vocabulary governs OPERATION roles only — other role kinds live in
  `states`, `mutation.*`, and `oracle`/`out_state`.
- §1: cardinality rule — one CVE/patch MAY yield multiple VCs; VC:witness
  is 1:1.

## Changelog v0.1 → v0.2

- §2.2: role vocabulary frozen at 14; bignum/EC-arithmetic families
  explicitly OUT OF SCOPE for v0.x (human decision Q1).
- §2.4: added `to` field (required iff `expected != forbidden`).
- §2.8: this section declared the provisional authoritative sink registry
  (human decision Q2).
- §3: V1 recursive unknown-field rejection; V3 extended (`to`, witness_ref);
  V5 relaxed to {forbidden, required}; V6 clarified as assertion + human
  review gate; V7 made explicit.
- §4: example relabeled "illustrative, not fixture ground truth".

## 1. Purpose

`vc.yaml` is the machine-readable serialization of a Vulnerability Contract
(VC). It is an **evolution of `template_meta.yaml`**, not a replacement:
the three-layer oracle structure (`memory_safety` / `bug_candidate` /
`fixed_or_safe`) and `mutation_points` are inherited; the VC adds the
semantic-layer components (roles, states, transitions, guards, effect,
fidelity) that template_meta does not have.

Design rules:

- Closed vocabularies everywhere; free text only where marked.
- Every auto-derived field carries provenance (`derived_from`).
- No timestamps, no absolute paths, no library-build references.
- One contract per file. File name: `vc.yaml` inside
  `artifacts/contract_mining/<slug>/`.
- **Cardinality:** one CVE / patch MAY yield multiple VCs (a patch can
  change several behaviors); each VC has exactly ONE minimal witness
  (VC:witness is 1:1).

## 1.1 Conceptual Model: Schema / Instance / Family

The VC framework has three layers; confusing them leads to the false
impression that "all vulnerabilities are squeezed into one lifecycle
pattern". They are not:

- **Contract Schema** — this document. The unified REPRESENTATION
  framework: fields, vocabularies, evidence rules, validation gates.
- **Contract Instance** — one concrete safety constraint mined from ONE
  historical vulnerability. Instances differ fundamentally in behavior:
  e.g. `FINALIZED --UPDATE--> REJECT` (lifecycle) and
  `VALID_OBJECT + TRAILING_DATA --WHOLE_OBJECT_PARSE--> NO_SILENT_PARTIAL_ACCEPTANCE`
  (input consumption) are different instances, and they SHOULD be different.
- **Contract Family** — a semantic cluster of similar instances
  (§2.1 `contract_family`).

**What is unified is the description structure, not the vulnerability
behavior.** Lifecycle bugs, trailing-data parsers, boundary checks, stale
state, and error-handling defects are different defect behaviors; they are
recorded in the same schema the way different rows share one table.

The 7-tuple fields are the machine realization of this logical slot
skeleton:

| logical slot | vc.yaml fields |
|---|---|
| Context / Precondition | `states`, `guards`, `mutation` preconditions |
| Intervention | `mutation` (mutation roles live here) |
| Execution | `transitions[].on` (operation roles) |
| Expected Behavioral Relation | `transitions[].expected` + `oracle.contract_violation.relation` |
| Observable Evidence | `oracle` layers + trace observations (observation roles) |

## 1.2 Three Evidence Layers (do not conflate)

```text
Concrete Trace      — what actually happened (API events, ret, observations;
                      pure execution record; role/state may be null)
Minimal Witness     — the minimal TRIGGER PROGRAM that still reproduces the
                      divergence. Steps are NOT limited to API calls: a
                      witness step may be an API invocation, an input
                      intervention (e.g. APPEND_TRAILING_DATA), or an
                      observation point. Format defined by the M4 spec.
Vulnerability       — the implementation-independent semantic constraint
Contract              (this document).
```

Consequence: input interventions (e.g. appending trailing bytes) are
first-class WITNESS steps even though they never appear as API events in a
trace. M4's witness format MUST support intervention/observation step
kinds; M0 placeholder witness files will be regenerated then.

## 1.3 What machines read vs. what humans read

Cross-library binding (Contribution 2) consumes ONLY structured fields as
binding keys: `roles`, `states`, `guards`, `mutation.*`, `oracle` signal
layers, `effect.sinks`, `contract_family`. `oracle.contract_violation.relation`
is the human-facing metamorphic statement — deliberately free text, never
parsed by tools. A contract whose semantics cannot be expressed through
the structured fields is incomplete (see Gate 6 in the M2 acceptance
gates); the free-text relation is the summary, not the payload.

## 2. Field Specification

### 2.1 Identity and source

| field | type | required | notes |
|---|---|---|---|
| `contract_id` | string | yes | UPPER_SNAKE, e.g. `MAC_LIFECYCLE_UPDATE_AFTER_FINAL`. Must match `^[A-Z][A-Z0-9_]{2,63}$` |
| `schema_version` | string | yes | literal `cipherlens.vc.v0_3`; `cipherlens.vc.v0_2` is accepted only when `contract_family` is absent (pre-v0.3 instances) |
| `source.pattern_id` | string | yes | e.g. `MBEDTLS-POC-0020` |
| `source.library` | string | yes | source library, lowercase |
| `source.buggy_version` | string | yes | must name a REAL version with repo evidence |
| `source.fixed_version` | string | yes | same |
| `source.references` | list[string] | no | CVE / issue URL / patch commit |
| `contract_family` | enum | no | when present, one of `lifecycle_state`, `input_consumption`, `boundary_range`, `error_handling`, `resource_memory`, `consistency_equivalence`. Classifies the instance for transfer targeting and evaluation grouping; does NOT constrain the instance's behavioral content. Extend only via spec version bump |

### 2.2 R — roles (closed vocabulary, frozen for v0.x)

`roles`: non-empty list, subset of:

```text
INIT SETUP UPDATE FINAL PARSE VERIFY SIGN QUERY RESET REINIT DUP COPY FREE ABORT
```

**Scope note (human decision Q1, 2026-08):** Contract Miner v0.x targets the
three core families only: Typestate/Lifecycle, Parser Consumption, Wrapper
Contract Drift. The `bignum_serialization_boundary` and
`ec_arithmetic_semantic` families are OUT OF SCOPE; how their APIs map onto
roles is deferred. Extending this vocabulary requires a spec version bump
with evidence, never an ad-hoc edit.

**Five kinds of semantic roles.** Semantic abstraction is NOT only API-name
abstraction. The normalizer (M3) recognizes five role kinds, each living in
its own schema location:

| role kind | example | lives in |
|---|---|---|
| operation role | `EVP_MAC_update → UPDATE` | `roles` + `transitions[].on` (the 14-role closed vocabulary governs THIS kind only) |
| object role | encoded certificate bytes → `CERTIFICATE_OBJECT` | `states` / guard descriptions |
| mutation role | `buf + "\x00" → APPEND_TRAILING_DATA` | `mutation.strategy` + `mutation.points` |
| state role | `ctx->finalized → FINALIZED` | `states` |
| observation role | `p != end → PARTIAL_CONSUMPTION` | `oracle` layers / trace `out_state` |

Role semantics are defined in `role_abstraction_spec.md` (M3); this schema
only enforces membership and uniqueness for the 14 operation roles.

### 2.3 S — states

`states`: non-empty list of objects:

| field | type | required | notes |
|---|---|---|---|
| `name` | string | yes | must match `^[A-Z][A-Z0-9_]*$`, unique within file |
| `kind` | enum | yes | one of `initial`, `intermediate`, `terminal`, `error` |

### 2.4 T — transitions

`transitions`: list of objects:

| field | type | required | notes |
|---|---|---|---|
| `from` | string | yes | must be a declared state name |
| `on` | string | yes | must be a declared role |
| `expected` | enum | yes | `forbidden`, `required`, `allowed_with_guard` |
| `to` | string | required iff `expected != forbidden` | must match a declared state name; `forbidden` transitions MUST omit `to` (the transition must not happen; there is no target state) |
| `guard_ref` | string | required iff `expected == allowed_with_guard` | must match a declared guard id |

The contract's core claim is usually ONE `forbidden` transition
(e.g. `FINALIZED --UPDATE--> forbidden`) or ONE `required` property
(e.g. full consumption after successful PARSE); others provide context.

### 2.5 G — guards

`guards`: list (may be empty) of objects:

| field | type | required | notes |
|---|---|---|---|
| `id` | string | yes | unique, e.g. `full_consumption_check` |
| `description` | string | yes | free text, one sentence |

### 2.6 M — mutation

| field | type | required | notes |
|---|---|---|---|
| `mutation.strategy` | enum | yes | `sequence_replay`, `input_tail`, `length_boundary`, `state_reuse`, `value_substitution` |
| `mutation.witness_ref` | string | yes | repo-relative path to `witness.min.seq`; must resolve to an existing regular file at emit time |
| `mutation.points` | list | no | inherited from template_meta `mutation_points` (name/placeholder/type/constraint); may be empty |

### 2.7 O — oracle

Three layers inherited from template_meta, plus one contract-level clause:

| field | type | required | notes |
|---|---|---|---|
| `oracle.memory_safety` | list[string] | yes (may be empty) | e.g. `no_null_pointer_dereference` |
| `oracle.bug_candidate` | list[string] | yes (may be empty) | signals on the buggy side |
| `oracle.fixed_or_safe` | list[string] | yes (may be empty) | signals on the fixed side |
| `oracle.contract_violation` | object | yes | the metamorphic clause (see below) |

`oracle.contract_violation`:

| field | type | required | notes |
|---|---|---|---|
| `relation` | string | yes | free text of the metamorphic relation, stated **solely over trace observations and declared contract semantics**. It MUST NOT reference `mutation.strategy`, `witness_ref`, generator labels, fixture names, or case IDs |
| `independent_of_generator` | boolean | yes | must be `true`; see V6 for the exact meaning and limits of this assertion |

### 2.8 E — effect

**This subsection is the provisional authoritative sink registry for
CipherLens (human decision Q2, 2026-08).** It is versioned with this spec
and will be revised when ImpactLift (Contribution 3) is implemented; until
then, no other document or code may define sinks.

| field | type | required | notes |
|---|---|---|---|
| `effect.summary` | string | yes | one sentence, free text |
| `effect.sinks` | list[enum] | yes (may be empty) | subset of `authentication_decision signature_verification certificate_acceptance handshake_state key_export trust_decision output_file crypto_result` |

### 2.9 Fidelity (reserved for Contribution 2)

| field | type | required | notes |
|---|---|---|---|
| `fidelity.target_states` | list[string] | yes | subset of declared state names; states a migration must reach |
| `fidelity.divergence_required` | boolean | yes | whether target-library behavior must diverge from its own fixed version |

### 2.9a Reserved — Transfer Signature (Contribution 2)

Cross-library binding needs both positive constraints (which roles /
mutations / observations a target must offer — already covered by the
structured fields, see §1.3) and NEGATIVE constraints (which target
semantics disqualify a candidate, e.g. a parser explicitly documented to
accept prefixes must be excluded from a trailing-data contract). The
negative-constraint fields (`excluded_semantics`, observability
requirements, instantiability preconditions) are deliberately NOT frozen in
v0.3; they will be designed in the Contribution-2 transfer spec after M2,
with evidence from real binding attempts. Until then, do not invent them.

### 2.10 Provenance

| field | type | required | notes |
|---|---|---|---|
| `provenance.miner` | string | yes | e.g. `contract_miner v0.2` or `manual` |
| `provenance.derived_from` | list[string] | yes (may be empty) | e.g. `template_meta`, `divergence_report` |
| `provenance.human_reviewed` | boolean | yes | must be `true` before the contract is used in evaluation |

## 3. Validation Rules (M0 acceptance scope)

- **V1** all required fields present; unknown fields are rejected **at every
  object depth**, not only top level.
- **V2** closed vocabularies enforced (roles, state kinds, expected, sinks,
  mutation strategies, `contract_family` when present).
- **V3** referential integrity: every `transitions[].from` ∈ states; every
  present `transitions[].to` ∈ states; every `transitions[].on` ∈ roles;
  every `guard_ref` ∈ guards; `fidelity.target_states` ⊆ states;
  `mutation.witness_ref` is repo-relative and resolves to an existing
  regular file at emit time.
- **V4** `guard_ref` present iff `expected == allowed_with_guard`;
  `to` present iff `expected != forbidden`.
- **V5** at least one transition with `expected ∈ {forbidden, required}`.
  (Parser contracts such as DER full-consumption carry a `required`
  property without a natural forbidden state edge.)
- **V6** `oracle.contract_violation.independent_of_generator == true`.
  This boolean is a **declarative assertion, not proof**. Before evaluation,
  `provenance.human_reviewed` MUST be `true` and the reviewer MUST confirm
  the relation is stated solely over trace observations and declared
  contract semantics, with no dependence on `mutation.strategy`,
  `mutation.witness_ref`, generator labels, fixture names, or case IDs.
- **V7** `contract_id` matches its naming regex; every `states[].name`
  matches `^[A-Z][A-Z0-9_]*$`; roles are unique; state names are unique;
  guard ids are unique.
- **V8** validator reports ALL violations, human-readable, no fail-fast.

## 4. Illustrative MAC Shape — Not Fixture Ground Truth

This example is **syntactic only**. Its placeholder pattern/version values
and semantic claims MUST NOT seed M1 fixtures or evaluation. A real
same-library buggy/fixed evidence pair and an existing `witness_ref` are
required before any contract shaped like this can be relabeled as valid.

```yaml
contract_id: MAC_LIFECYCLE_UPDATE_AFTER_FINAL
schema_version: cipherlens.vc.v0_3
contract_family: lifecycle_state
source:
  pattern_id: MBEDTLS-POC-XXXX          # placeholder — no repo evidence
  library: mbedtls
  buggy_version: "X.Y.Z"                # placeholder
  fixed_version: "X.Y.Z+1"              # placeholder
roles: [INIT, UPDATE, FINAL]
states:
  - {name: INITIALIZED, kind: initial}
  - {name: UPDATED, kind: intermediate}
  - {name: FINALIZED, kind: terminal}
transitions:
  - {from: INITIALIZED, on: UPDATE, expected: required, to: UPDATED}
  - {from: UPDATED, on: FINAL, expected: required, to: FINALIZED}
  - {from: FINALIZED, on: UPDATE, expected: forbidden}   # no `to`
guards: []
mutation:
  strategy: sequence_replay
  witness_ref: witness.min.seq
oracle:
  memory_safety: []
  bug_candidate: [second_final_produces_output]
  fixed_or_safe: [update_after_final_rejected]
  contract_violation:
    relation: "after FINAL, a subsequent UPDATE is accepted and a later FINAL emits a tag; the strict reference rejects the UPDATE"
    independent_of_generator: true
effect:
  summary: "Finalized MAC context accepts more input and emits a second tag."
  sinks: [crypto_result]
fidelity:
  target_states: [FINALIZED]
  divergence_required: true
provenance:
  miner: manual
  derived_from: []
  human_reviewed: false
```
