# CandidateBinding v0.1

CandidateBinding is the immutable, digest-addressed, complete semantic tuple
that binds one validated Contract, Contract-derived Transfer Signature,
Trigger Template, target semantic profile, and ELIGIBLE evaluation to concrete
subjects, ordered operations, inputs, interventions, continuity obligations,
observation outlets, and correlations.

It is not an API name, ranking result, proposal, legacy Slot Binding, generated
program, execution trace, or verdict. BindingProposal lineage intentionally
does not enter its semantic identity. A later MatcherTrace/construction trace
may preserve proposal lineage without promoting model output to truth.

## Trigger Template Interface

The read-only `cipherlens.trigger_template_interface.v0.1` manifest provides
stable slot references over current legacy templates. Stable identity derives
from the Trigger Template reference, typed slot kind, and repeatable semantic
anchor. ASTLITE IDs or legacy names are retained as provenance/mapping only;
absolute paths, source lines, and temporary indexes do not define identity.
The adapter never edits a template, AST, mask, or PoC and rejects missing or
ambiguous identity evidence.

The CandidateBinding frozen identity still references only
`trigger_template_ref` and `trigger_template_digest`. The manifest is a
deterministically derived construction/validation context, recorded by
REFERENCE_INTEGRITY evidence, not a new CandidateBinding identity field.

## Construction and validation

The constructor accepts explicit concrete mappings and canonical validated
artifacts. It does no LLM call, retrieval, fuzzy choice, ranking, or API
completion. Only an `ELIGIBLE` evaluation passes the construction gate;
`INELIGIBLE` and `INDETERMINATE` are deterministic rejections.

CandidateBindingValidation v0.1 runs ten checks: REFERENCE_INTEGRITY,
TARGET_SCOPE, ELIGIBILITY_GATE, SUBJECT_BINDING, OPERATION_BINDING,
INPUT_BINDING, INTERVENTION_BINDING, CONTINUITY, OBSERVABILITY, and
COMPLETENESS.

Any deterministic FAIL aggregates to `INVALID`. With no FAIL, missing required
or non-VERIFIED evidence aggregates to `INCOMPLETE`. Only all required PASS
results produce `VALID`. INFERRED and PROPOSED facts cannot independently make
a check pass. TS observability proves surface eligibility only; the observation
checks still require a concrete subject, operation, acquisition kind, phase,
channel fact, and correlation.

Changing any subject, operation, input, intervention, continuity, observation,
correlation, or order changes canonical bytes and creates a new binding ID,
digest, and validation artifact. Switching a candidate therefore means
switching the whole immutable CandidateBinding. Combining parts of several
bindings creates a new identity and requires full validation.

The three synthetic-target golden families cover input consumption (0020),
failure output integrity (0004), and object state consistency (0005), each with
VALID, INVALID, and INCOMPLETE artifacts. They are schema/validator fixtures,
not claims about a real third-party vulnerability.

Template–Binding merge, constrained adaptation, programmatic completion,
runner changes, Structured Execution Trace, Contract.P verdict evaluation,
UNKNOWN reruns, ranking, and full Matcher orchestration remain future work.
