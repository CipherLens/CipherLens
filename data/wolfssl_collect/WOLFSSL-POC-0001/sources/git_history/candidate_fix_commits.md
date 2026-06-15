# Candidate Fix Commits

## Candidate 1

- Commit: 88bf5d967
- Title: add sanity check on buffer index and regression tests
- Reason:
  - Found by `git log -S"dName->loc" -- wolfcrypt/src/asn.c`
  - Found by `git log -S"locSz" -- wolfcrypt/src/asn.c`
  - The title directly mentions a sanity check on buffer index.
  - This matches the reproduced failure:
    - `wolfcrypt/src/asn.c:5121:27: runtime error: index 19 out of bounds for type 'int [19]'`
    - ASan SEGV during `FreeDecodedCert`

## Current Judgment

likely_fix_commit

## Patch File

- sources/git_history/patches/88bf5d967.patch

## Next Step

Build and test this commit with the same ASan/UBSan extra configuration used for the vulnerable reproduction.

## Release-Level Fix Evidence

### v4.3.0-stable

- Test result: safe reject
- Sanitizer evidence: none
- Crash evidence: none
- Observed behavior:
  - GetLength value exceeds buffer length
  - Decode to key failed
  - no FreeDecodedCert crash
- Current judgment: fixed_release_candidate

### Version Boundary

- v4.2.0-stable: vulnerable under ASan/UBSan extra build
- 88bf5d967: still vulnerable
- v4.3.0-stable: safe reject

### Current Interpretation

The effective fix is later than 88bf5d967 and no later than v4.3.0-stable. Further commit-level bisection can be performed between the v4.2.0-stable and v4.3.0-stable tags if an exact fixed commit is required.
