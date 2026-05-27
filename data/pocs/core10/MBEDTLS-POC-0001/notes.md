# Working Notes

## Manual tasks

- [ ] Confirm exact fixing commit.
- [ ] Locate exact regression test case.
- [ ] Extract minimal PoC or API call sequence.
- [ ] Identify buggy and fixed versions.
- [ ] Run reproduction test locally.
- [ ] Record failure signal.
- [ ] Confirm AST mutation point.
- [ ] Prepare RAG context sources.

## Investigation log

- TBD

## Candidate commands

```bash
# Inspect source files
cat library_files.txt

# Inspect test files
cat test_files.txt

# Inspect commits
cat commits.txt
```

## Exact fixing commit confirmed

The initial commit_refs in metadata were ChangeLog-only noise and are not the actual fix/test commits.

Confirmed primary fixing commit:

- eff335d575e0949ba25b60a358f31461eab055fe
- message: Fix 1-byte buffer overflow in mbedtls_mpi_write_string()
- fixes: #2404
- changed file: library/bignum.c

Patch summary:
In mbedtls_mpi_write_string(), when X->s == -1, the function writes '-' to the output buffer.
The fix adds buflen-- after writing '-', so the remaining conversion code receives the correct remaining buffer length.
Without this decrement, the function can write one byte past the caller-provided buffer for negative MPIs.

Current reproduction route:
Use patch-derived minimal PoC rather than regression test extraction, because the confirmed fixing commit only modifies library/bignum.c.

## Buggy/fixed worktrees created

Created:

- repos/worktrees/MBEDTLS-POC-0001-buggy at eff335d575^
- repos/worktrees/MBEDTLS-POC-0001-fixed at eff335d575

Confirmed bug location:

- file: library/bignum.c
- function: mbedtls_mpi_write_string()
- buggy behavior: when X->s == -1, the function writes '-' to buf but does not decrement buflen.
- fixed behavior: after writing '-', the function executes buflen--.

This confirms the AST mutation point:
- statement-level: negative sign branch in mbedtls_mpi_write_string()
- expression/statement-level: buflen update after writing '-'

## Local reproduction confirmed

The canary-based PoC successfully distinguishes buggy and fixed versions.

Buggy result:
- value = -1
- radix = 2
- buflen = 4
- ret = 0
- olen = 3
- canary corrupted

Fixed result:
- no canary corruption detected

Conclusion:
MBEDTLS-POC-0001 is now locally reproduced.

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed.

Trigger:

- value = -1
- radix = 2
- buflen = 4

Buggy result:

- ret = 0
- olen = 3
- canary corrupted

Fixed result:

- ret = 0
- olen = 3
- canary intact

Conclusion:

MBEDTLS-POC-0001 is now locally reproduced. The confirmed failure signal is canary corruption / out-of-bounds write.
