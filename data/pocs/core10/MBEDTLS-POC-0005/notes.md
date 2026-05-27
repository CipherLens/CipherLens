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

Confirmed library fixing commit:

- 2df7ab7c0c3d5bb8a31481073c494521d10d4eba

Confirmed unit-test improvement commit:

- 12df5f3a16a2bc53881b9d88556192dcbc2f6774

Root cause:
mbedtls_asn1_store_named_data() frees cur->val.p when val_len == 0 and sets cur->val.p to NULL, but the buggy version keeps the old cur->val.len value. This leaves the named-data object in an inconsistent state:

p == NULL but len != 0

A later call with the same OID and the same nonzero length can skip reallocation and attempt to memcpy() into cur->val.p == NULL, causing NULL pointer dereference.

Confirmed fixed statement:

cur->val.len = 0;

Confirmed mutation point:
library/asn1write.c: mbedtls_asn1_store_named_data(), val_len == 0 branch.

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed.

Buggy result:

- step1 sets val.p to a valid allocation and val.len = 4
- step2 frees val.p and sets val.p = NULL, but leaves val.len = 4
- step3 stores another value with val_len = 4
- buggy version crashes with segmentation fault
- exit_code = 139

Fixed result:

- step2 sets val.p = NULL and val.len = 0
- step3 reallocates the value buffer safely
- fixed version completes successfully

Conclusion:

MBEDTLS-POC-0005 is now locally reproduced. The confirmed failure signal is NULL pointer dereference / segmentation fault. The confirmed mutation point is the missing `cur->val.len = 0;` statement in the `val_len == 0` branch of `mbedtls_asn1_store_named_data()`.
