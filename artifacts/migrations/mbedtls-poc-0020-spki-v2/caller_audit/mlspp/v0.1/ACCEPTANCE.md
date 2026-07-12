# caller_audit v0.1 Acceptance

## Regression target

- Project: cisco/mlspp
- Commit: 92aaa4134fa45ec39957a7c81a342401fba7feb2
- Component: lib/hpke RSASignature::deserialize_private
- Backend: OpenSSL 3.5.5
- Source pattern: MBEDTLS-POC-0020 / trailing DER data

## Baseline

- Canonical RSA private DER accepted
- Tail 0500 accepted
- Tail 3000 accepted
- Tail 020100 accepted
- Canonical round-trip preserved
- Public key preserved
- Signature operation preserved
- No ASan or UBSan finding

## Fix control

- Canonical RSA private DER still accepted
- Tail 0500 rejected
- Tail 3000 rejected
- Tail 020100 rejected
- Fix applied in an isolated Git worktree

## Verdict

- Caller behavior: confirmed
- Root cause: missing full-input-consumption check
- Fix control: confirmed
- Production reachability: not demonstrated
- Security impact: unproven
- Vulnerability: not confirmed
- Final classification: downgraded_unreachable
