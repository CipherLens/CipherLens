# CipherLens Caller Audit v0.1

## Target

- Project: `halon/libdkimpp`
- Commit: `9defa162eebc644b006b7a51e92162640a810ee9`
- Candidate API: `d2i_PUBKEY`
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

**production_reachable_candidate**

Caller behavior and fix control are confirmed on a production-reachable attacker-controlled path.

The v0.1 verdict requires per-case evidence and a patched fix-control regression before a caller behavior is considered fully reproduced.
