# Historical Issue Version Report

## Summary

Local artifacts for `OPENSSL-ISSUE-28669` do not identify the original reported
version, affected version range, fixed version, or patch commit.

```yaml
original_reported_version: unknown
affected_versions: []
fixed_version: unknown
patch_commit: unknown
confidence: unknown
```

## Evidence

`datasets/openssl/poc_artifacts/issue_28669/metadata.json` records:

```text
affected_version: null
fix_evidence: null
tested_library: OpenSSL 3.0.13 / libcrypto.so.3
strict_reproduction: false
```

The same metadata says the local validation compiled successfully against system
OpenSSL 3.0.13, triggered SIGSEGV / exit 139, and produced a Valgrind Invalid
read summary. This validates a local artifact, but not the original affected
version.

`README.md` similarly says:

```text
Affected version: None
Strict reproduction requires compiling and running against the original affected OpenSSL version.
```

## Answer

- Original reported version: not found locally.
- Affected versions: not found locally.
- Fixed version: not found locally.
- Patch commit: not found locally.
- Current-version fixed status: cannot determine from local artifacts.

Therefore novelty classification must treat historical overlap as unknown.
