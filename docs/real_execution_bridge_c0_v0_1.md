# Real Execution Bridge C0 v0.1

C0 validates the canonical execution-path wiring with `unit:track-a:0020:fixed`
as a bounded replay fixture. It is not a real target build, binary run, PoC,
campaign, ExecutionVerdict, ViolationEvidencePackage, or security finding.

The bridge consumes a digest-addressed BuildEnvironmentProfile mapping, projects
`ORACLE_EVENT_V0_1` markers to canonical acquisitions, and runs deterministic
trace, Contract.O projection, and relation evaluation. C0 fixture outputs are
classified `C0_REPLAY_FIXTURE_NOT_REAL_CAMPAIGN`; only pipeline/engineering
validation claims are permitted.

The C0 fixture library input is deliberately non-executable. It exists solely
to test ref/digest propagation into BuildSpec, and must never be resolved or
supplied to a compiler or linker.
