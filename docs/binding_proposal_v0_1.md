# BindingProposal v0.1

BindingProposal is an advisory, partial mapping proposal. It is not a
CandidateBinding and cannot establish a verified target fact, target
eligibility, a valid binding, or an execution verdict.

The implementation deliberately uses two schemas. A provider may emit only
`cipherlens.binding_proposal_payload.v0.1`: seven typed proposal lists and an
optional advisory rationale. Trusted code validates that payload and injects
source/target references, provider provenance, evidence references, the stable
proposal identity, and the literal epistemic status `PROPOSED` to form
`cipherlens.binding_proposal.v0.1`.

Both layers are closed recursively. Structured attempts to claim `VERIFIED`,
eligibility, a verdict, vulnerability confirmation, or security truth are
rejected. Natural-language rationale is not filtered by keyword. Secret-like
fields and credential values are rejected; provenance may contain only the
name of a credential environment variable.

Canonical JSON is UTF-8, sorted-key, newline-terminated, and normalizes
proposal/evidence/reference collections into deterministic order. A semantic
proposal change produces a new digest-addressed proposal identity. This
foundation performs no retrieval, fact resolution, TS evaluation, ranking,
CandidateBinding construction, or vulnerability confirmation.
