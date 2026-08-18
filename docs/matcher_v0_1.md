# Contract-guided Matcher v0.1

## Positioning

The Matcher is an orchestration process. It is not a vulnerability oracle, a
single RAG query, an LLM agent, a similarity score, or a renamed legacy
`candidate_mapper`.

Its canonical foundation is:

```text
TargetKnowledgeBase
  -> RecallQuery
  -> wide recall
  -> multi-subject MatcherCandidate
  -> BindingProposal (PROPOSED)
  -> deterministic fact resolution
  -> immutable TargetSemanticProfile
  -> existing Transfer Signature evaluator
  -> concrete observability feasibility
  -> deterministic post-gate ranking
  -> existing CandidateBinding constructor
  -> existing CandidateBinding validator
  -> MatcherRunOutcome + MatcherTrace
```

Template–Binding merge, code adaptation, harness generation, compile/run,
Structured Execution Trace, Contract Verdict, UNKNOWN closure, and caller
impact analysis are outside Matcher v0.1.

## Trust boundary

RAG supplies possible evidence and candidate seeds. A proposal provider supplies
advisory role assignments. Ranking orders already eligible attempts. None of
those stages may establish `VERIFIED`, `ELIGIBLE`, `VALID`, `SATISFIED`, or
`VIOLATED`.

`BindingProposal` is always `PROPOSED`. Promotion requires an exact,
content-digested artifact with target library/version/surface and subject
provenance. Source, header, official documentation, deterministic static/test
artifacts, and deterministic fixtures may establish `VERIFIED`. RAG hits,
API-card free text, recipe text, legacy scores, feedback, model confidence, and
provider agreement cannot do so alone.

Verifier types such as `SYMBOL_EXISTENCE`, `SIGNATURE_TYPE`, and
`PARAMETER_ROLE` are evidence checks. They do not extend the frozen Profile
fact vocabulary. Resolution continues to use the eleven fact types already
defined by Transfer Signature v0.1.

## Candidate identity and recall

`MatcherCandidate` represents a complete semantic surface, not one function.
It may contain an API group, object model, wrapper/interface, stateful operation
family, multiple subjects, or correlated observation channels.

The identity is a SHA-256 of canonicalized library, version, surface reference,
sorted subject and symbol sets, and semantic surface composition. Retrieval
rank, RAG score, provider identity, proposal ID, evidence arrival order,
ranking position, timestamps, and telemetry are excluded. Evidence refresh
therefore preserves candidate identity; a changed semantic assignment creates a
new identity.

`RecallQuery` deterministically projects Contract C/I/X/O, Transfer Signature
constraints, template slot hints, and family metadata. Contract P contributes
only controlled relation-type and operand-name hints. The query never produces
facts.

`TargetKnowledgeBase` isolates the Matcher from Chroma, Ollama, source checkout,
or another backend. `SyntheticKnowledgeBackend` supplies deterministic,
no-network fixtures. Wide recall records rank and score only in retrieval
provenance. Candidate assembly groups only explicitly compatible surfaces and
fails closed on conflicting composition instead of creating Frankenstein
candidates.

Each provider invocation is append-only. Its canonical request is represented
by a trusted source reference in the BindingProposal envelope, so even repeated
semantic payloads have independent proposal IDs and canonical digests. Every
complete assignment proceeds independently through resolution, eligibility,
observability, and whole-binding validation.

## Eligibility, observability, and ranking

The existing Transfer Signature evaluator is the only eligibility authority:

- `INELIGIBLE` is a hard reject and cannot be ranked or constructed.
- `INDETERMINATE` enters bounded deterministic evidence enhancement.
- `ELIGIBLE` advances to concrete observability.

Transfer Signature observability establishes that a semantic channel exists in
principle. Matcher concrete observability establishes that the current complete
assignment identifies subject, operation, outlet, phase, and correlation
participants. Its internal states are `RESOLVABLE`, `UNRESOLVABLE`, and
`INCOMPLETE`.

Only `ELIGIBLE + RESOLVABLE` attempts enter deterministic ranking. Ranking uses
verified fact, template-slot, observation, continuity/correlation, evidence
quality, signature certainty, optional-field, adaptation-complexity, and weak
legacy-affinity features. Canonical candidate ID is the tie break. Ranking
metadata remains in `RankingRecord` and `MatcherTrace`.

## Immutable profiles and whole bindings

Every evidence round creates a new canonical TargetSemanticProfile with a new
digest. Parent/profile-round lineage is stored in MatcherTrace, not in the
frozen Profile schema. Conflicting verified TRUE/FALSE facts produce
`PROFILE_VERIFIED_FACT_CONFLICT`; no score, provider, or majority vote resolves
the conflict.

After hard gates, Matcher calls the existing CandidateBinding constructor and
the existing ten-check validator. `INVALID` rejects the whole binding;
`INCOMPLETE` returns to deterministic evidence handling or pauses the candidate.
No API, object, operation, observation, or correlation may be borrowed from a
different candidate without creating and validating a new complete binding.

## Outcomes, trace, and telemetry

Matcher has a separate closed outcome space:

```text
MATCH_FOUND
NO_ELIGIBLE_CANDIDATE
EVIDENCE_INSUFFICIENT
PROVIDER_BLOCKED
CANDIDATES_EXHAUSTED
BUDGET_EXHAUSTED
INPUT_INVALID
INTERNAL_ERROR
```

These are not Contract Verdicts. In particular, provider failure or candidate
exhaustion never becomes Contract `UNKNOWN`.

`cipherlens.matcher_trace.v0.1` is a canonical, digest-addressed semantic trace.
It retains every retrieval, candidate assembly, provider attempt, proposal,
resolution, Profile, TS evaluation, observability result, ranking record,
binding attempt, validation, rejection, and selected binding. Timestamps,
latency, token usage, billing, host, PID, machine paths, and memory belong to
non-canonical `MatcherTelemetry` and do not affect the semantic trace digest.

Default budgets are 32 recalled candidates, 2 proposals per candidate, 2
evidence-enhancement rounds, and 16 binding attempts. Budget exhaustion is a
Matcher outcome, never semantic ineligibility.

## Legacy isolation

- `candidate_mapper` and family dispatch are recall hints only.
- `evidence_collector` may be wrapped behind TargetKnowledgeBase.
- API cards, recipes, RAG and feedback are untrusted recall/ranking context.
- `adapter_filler` is excluded from Matcher.
- deterministic portions of `adapter_validate` may be wrapped as verifiers.
- old scores and `generate/skip` have no eligibility authority.
- a compatibility candidate queue must reference complete attempts, not API
  names plus scores.

## Zero-cost replay testing

Default Matcher tests use only `ReplayProposalProvider` and
`SyntheticKnowledgeBackend`. They do not use Codex transport, GLM, Ollama,
OpenAI/Zhipu APIs, internet access, or a production source checkout. The three
architecture goldens reuse the existing synthetic evidence for
MBEDTLS-POC-0020, MBEDTLS-POC-0004, and MBEDTLS-POC-0005; they do not claim real
third-party target security facts.
