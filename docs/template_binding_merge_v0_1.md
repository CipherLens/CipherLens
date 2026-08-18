# Template–CandidateBinding Merge v0.1

## Position in the canonical pipeline

Batch 5B implements the deterministic boundary between semantic target binding
and later real execution:

```text
Vulnerability Contract v0.3
  -> Transfer Signature v0.1
  -> Contract-guided Matcher
  -> VALID CandidateBinding v0.1
  -> Template–CandidateBinding Merge v0.1
  -> Bound Template Source + SourceMap
  -> later compile/link/run and Structured Execution Trace
  -> later Contract-driven Verdict
```

CandidateBinding decides which complete target tuple carries the frozen target
semantics. Merge decides how that one tuple maps back to stable Trigger Template
slots and historical structural topology. Adaptation can only express declared
syntax or glue. Execution will later answer what happened in a real run, and the
Contract relation evaluator will later decide whether the security relation was
preserved. Merge validation status is not a vulnerability Verdict.

## Immutable semantic Merge

`cipherlens.template_binding_merge.v0.1` is a closed recursive artifact. Its
`merge_id` is derived from canonical semantic content with the ID removed. It
binds exact Trigger Template, Trigger Template Interface, CandidateBinding, and
CandidateBindingValidation refs and digests. Source bytes are deliberately not
part of this semantic identity.

The input gate accepts only canonical upstream artifacts and fails closed. It
checks the real repository-relative template source digest, exact template
ref/digest agreement, CandidateBinding ref/digest, the supported validation
registry, `status == VALID`, the current interface ref/digest in the upstream
reference-integrity check, and exact target scope when supplied. It never calls
a provider, repairs a binding, changes an API, or falls back to another binding.

Atomic `slot_bindings` map one stable template slot occurrence to one typed
CandidateBinding element. Required slot coverage and manifest multiplicity are
deterministic. Optional structural anchors remain separate typed
`anchor_bindings`.

The Merge also contains deterministic:

- subject and storage realizations;
- ten closed structural-obligation types;
- continuity-derived identity realizations;
- typed observation capture bindings;
- correlation realizations;
- declared adaptation holes with exact resolver, edit, syntax, guard, and
  replacement allowlists.

The current exemplar manifests do not need to be changed when they lack an
OBJECT or STATE_ANCHOR slot. Receiver bindings, identity groups, continuity
bindings, operation sequence indexes, observation participants, and correlation
bindings still produce explicit identity, order, follow-up, and correlation
obligations.

## Bound Source and SourceMap

The trusted renderer produces a separate
`cipherlens.bound_template_source.v0.1` envelope. Changing source bytes changes
the source and envelope digests but cannot mutate CandidateBinding or Merge.
Unresolved syntax/glue is represented only by stable declared-hole sentinels.

`cipherlens.bound_source_map.v0.1` records byte-exact protected template and
mapping regions plus unprotected declared-hole regions. It also carries ordered
operation, observation-capture, and identity-storage records. Region digests and
the semantic records allow deterministic detection of protected mutation, API
or object substitution, intervention/order drift, observation deletion or
replacement, hole-boundary violation, and identity/storage drift.

The renderer performs no API search, semantic inference, Matcher call, or LLM
call. It does not compile or run the result in this Batch.

## Constrained adaptation and completion

`cipherlens.adaptation_proposal.v0.1` is always `PROPOSED`. A restricted edit
must identify an existing `PROPOSAL_ALLOWED` hole, exact base source digest,
allowlisted edit type, matching syntax kind, and exact allowlisted replacement
digest. Arbitrary patches, whole-source replacement, undeclared ranges, new
semantic holes, and edits to API/object/intervention/observable/order/identity
choices are rejected. Provider output is rerendered through trusted code and
then receives the complete deterministic validation pass; it never becomes
trusted source directly.

Programmatic Completion handles only `DETERMINISTIC_ONLY` holes for which the
local completion registry has an exact recipe. The current foundation supplies
the deterministic build-metadata recipe. Completion is deterministic and
idempotent for the same Merge, base Bound Source, and registry version, and
does not alter semantic mappings or create holes.

## Validation and routing

The frozen registry runs exactly 18 non-fuzzy checks:

```text
REFERENCE_INTEGRITY                 VALID_BINDING_GATE
TARGET_SCOPE_CONSISTENCY            SLOT_COVERAGE
SLOT_MULTIPLICITY                   SUBJECT_PRESERVATION
OPERATION_PRESERVATION              INPUT_PRESERVATION
INTERVENTION_PRESERVATION           ORDER_PRESERVATION
STATE_CONTINUITY_PRESERVATION       OBSERVATION_PRESERVATION
CORRELATION_PRESERVATION            STRUCTURAL_OBLIGATION
ADAPTATION_BOUNDARY                 FORBIDDEN_SEMANTIC_DRIFT
SOURCE_BINDING_CONSISTENCY          COMPLETENESS
```

Status precedence is `INVALID > INCOMPLETE > VALID`. `INCOMPLETE` means the
semantic projection is still exact but required declared syntax/glue remains
unresolved. Routing is deterministic:

- `PROPOSAL_ALLOWED` unresolved hole -> `CONSTRAINED_ADAPTATION`;
- only `DETERMINISTIC_ONLY` unresolved holes -> `PROGRAMMATIC_COMPLETION`;
- semantic, structural, protected-source, or forbidden-adaptation failure ->
  `WHOLE_BINDING_SWITCH`;
- all checks pass -> `EXECUTION_HANDOFF`.

Whole-binding switching rejects the current Merge and returns to Matcher for a
new complete CandidateBinding. It never borrows an operation, observable,
object, intervention, or semantic choice from another binding.

## Artifact and trust boundary

The three frozen synthetic golden families are MBEDTLS-POC-0020,
MBEDTLS-POC-0004, and MBEDTLS-POC-0005. Their Merge IDs and completion outcomes
are tested without asserting any new third-party vulnerability conclusion.

This package contains no discovery, RAG, Transfer Signature eligibility,
BindingProposal generation, CandidateBinding selection, compile/link/run,
sanitizer interpretation, Structured Execution Trace, Contract Verdict, or
caller-impact implementation. Tests use only local fixtures and injected data:
zero Codex calls, zero GLM calls, zero external API/network calls, and zero
external model cost.
