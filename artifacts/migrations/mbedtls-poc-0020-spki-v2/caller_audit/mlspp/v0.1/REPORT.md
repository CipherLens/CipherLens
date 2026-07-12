# CipherLens Caller Audit v0.1

## Target

- Project: `cisco/mlspp`
- Commit: `92aaa4134fa45ec39957a7c81a342401fba7feb2`
- Candidate API: `d2i_PrivateKey`
- Source case: `MBEDTLS-POC-0020`

## Static audit

- Call sites: 1
- Production call sites without nearby full-consumption check: 1

## Dynamic evidence

- Baseline passed: `True`
- Mutation candidate confirmed: `True`
- Fix control passed: `True`
- ASan error: `False`
- UBSan error: `False`

## Verdict

**downgraded_unreachable**

Caller behavior and fix control are confirmed, but no production or official protocol route was demonstrated.

The v0.1 verdict requires per-case evidence and a patched fix-control regression before a caller behavior is considered fully reproduced.
