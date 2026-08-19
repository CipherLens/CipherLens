# Real Campaign Preparation v0.1 (7D-B)

Batch 7D-B freezes evidence required to prepare the 11-unit RQ4 pilot without
building or running it. Source identity records bind each local source root to
Git/release identity and a deterministic tree digest. OpenSSL 3.5.5 additionally
records its `configdata.pm` digest; wolfSSL 5.9.1 remains blocked where only
partial cards exist.

Build profiles inventory compiler-version evidence, architecture, configuration,
include evidence, known library evidence, timeout, sanitizer policy, and
controlled environment. A future build input, harness, trace, or campaign claim
is represented only by `missing_artifacts` or `missing_requirements`, never by a
placeholder edge.

The 7D-B readiness gate checks source identities, profiles, target facts, three
differential-pair manifests, the fixed 11-unit denominator, and a capture
readiness specification. Its successful state is `PREPARED_FOR_7D_B`; it always
forbids `7D-C_REAL_CLAIM`. No ExecutionVerdict, ViolationEvidencePackage,
real ORACLE_EVENT witness, build, run, or vulnerability conclusion is produced.
