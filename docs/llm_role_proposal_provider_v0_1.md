# LLM Role Proposal Provider v0.1

`LLMRoleProposalProvider` separates preparation, invocation, strict output
parsing, payload validation, provenance construction, and trusted-envelope
construction. Provider failures remain provider failures; they are never
translated into target ineligibility, CandidateBinding invalidity, Contract
`UNKNOWN`, or a security verdict.

Three providers exist:

- `ReplayProposalProvider` is deterministic, local, credential-free, and the
  default test path.
- `CodexExecProvider` models the subscription-authenticated local Codex plane.
  Its command uses only CLI 0.147.0 capabilities observed in this workspace:
  `codex exec --sandbox read-only --cd ... --ephemeral
  --ignore-user-config --ignore-rules --output-schema ... --json
  --color never -`. The current CLI exposes no independent flag proving that
  model tool-plane external network is disabled, so invocation fails closed
  with `POLICY_REJECTED` unless an embedding runtime explicitly supplies that
  proof. JSONL decoding accepts known event types and requires exactly one
  schema-valid final agent payload.
- `GLMProvider` models the optional metered API plane. It is disabled by
  default, reads a credential only from the configured environment variable,
  and accepts exactly one full JSON document. Markdown fences, substring
  extraction, regex recovery, repair, and synthetic success fallbacks are not
  supported.

The router defaults to `CODEX_EXEC` with fallback `DISABLED`; GLM defaults to
disabled. `MANUAL` never falls back in the same invocation. Automatic GLM
fallback is possible only when both
`API_FALLBACK_EXPLICITLY_ALLOWED` and `glm.enabled=true` are explicitly set.
Thus subscription-backed and API-metered provenance, authorization, and cost
planes cannot be silently mixed.

All default tests use replay or injected fake transports. They make no real
Codex proposal call, no GLM API call, and incur no external LLM cost.
