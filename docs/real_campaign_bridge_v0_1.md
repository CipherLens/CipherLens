# Real Campaign Bridge v0.1 (Batch 7D-B0)

This foundation prepares, but does not execute, a real CipherLens campaign. It
keeps the canonical v2 separation intact: Contract specifies observations and
relations; a valid CandidateBinding supplies the target binding; the frozen
Template–CandidateBinding merge remains the source of merge semantics.

`target_knowledge` materializes local profiles from source, header, artifact,
configuration, and release/Git identity. A draft, partial, blocked, RAG, or
legacy API card is candidate evidence only. Only verifier-backed source/header
evidence can be marked `VERIFIED`; this B0 set is intentionally `PREPARED` or
`NOT_READY`, not real-execution-ready.

Every persisted artifact edge is a ref plus a lowercase SHA-256 digest. An
artifact that does not yet exist is represented only in `missing_artifacts`,
`missing_requirements`, and `blocking_reasons`; B0 never inserts a placeholder
digest. This keeps future 7D-B/7D-C needs from masquerading as evidence.

`real_campaign_bridge.target_adaptation` has two strict OpenSSL skeletons.
`d2i_RSAPrivateKey` declares input, length, decode outcome, and pointer
advancement holes. `EVP_DecryptFinal_ex` declares outcome plus `outl` before
and after holes. It never selects an API or invents a legacy free-form adapter.
Adaptation accepts only an explicitly `VALID`, structured CandidateBinding with
explicit target symbol, operation, input, observation, scope, and Merge mapping
refs. It never searches rationale, comments, serialized YAML, or serialized
JSON for an API name. Missing binding state is `REJECTED` or `INCOMPLETE`, never
implicitly `VALID`.

`ORACLE_EVENT v0.1` is acquisition evidence with explicit status, role, phase,
and correlation. `OBSERVED_ABSENCE`, a sanitizer report, or a crash cannot by
itself establish `SATISFIED` or `VIOLATED`; missing data is not safe. A narrow
compatibility projection exists for the frozen runner marker format, but does
not alter execution schemas or verdict authority.

The preflight artifacts are create-only canonical JSON under
`artifacts/pipeline_v2/real_campaign_preflight/`. They retain the complete
11-unit `CLV2-RQ4-PILOT-001` denominator, including no-direct-equivalent and
blocked outcomes. Their terminal preflight state is always
`PREPARED_FOR_7D_B0_FOUNDATION`; it is explicitly not a 7D-C real-execution or
claim-ready result.
