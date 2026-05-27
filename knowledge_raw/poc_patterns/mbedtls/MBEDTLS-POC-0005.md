# MBEDTLS-POC-0005: mbedtls_asn1_store_named_data zero-length stale state

## Source

This pattern comes from CVE-2025-48965 and the Mbed TLS security advisory. The
affected API is `mbedtls_asn1_store_named_data` in `library/asn1write.c`.

The confirmed library fix commit is
`2df7ab7c0c3d5bb8a31481073c494521d10d4eba`. The local buggy worktree used
`2df7ab7c0c3d5bb8a31481073c494521d10d4eba^`. The related unit-test commit is
`12df5f3a16a2bc53881b9d88556192dcbc2f6774`.

## Root Cause

In the buggy version, `mbedtls_asn1_store_named_data()` frees `cur->val.p` when
`val_len == 0` and sets the pointer to `NULL`, but it does not reset
`cur->val.len`.

This leaves the internal named-data object in an inconsistent state:

- `cur->val.p == NULL`
- `cur->val.len != 0`

A later call with the same OID and a value length equal to the stale
`cur->val.len` can skip reallocation and copy into `cur->val.p == NULL`,
causing a NULL pointer dereference.

The fixed statement is:

```c
cur->val.len = 0;
```

## Trigger Condition

The minimal PoC calls `mbedtls_asn1_store_named_data()` three times with the
same OID, `2.5.4.3` (`commonName`):

1. Store a nonzero value with `val_len = 4`.
2. Store a zero-length value with `val_len = 0`.
3. Store another nonzero value with `val_len = 4`.

The third call reuses the stale length from the first call in the buggy version.

## Buggy and Fixed Behavior

Buggy output:

```text
step1: store nonzero value len=4
after step1: val.p=... val.len=4
step2: store zero-length value len=0
after step2: val.p=(nil) val.len=4
step3: store nonzero value len=4 again; buggy version may crash now
exit_code=139
```

Fixed output:

```text
step1: store nonzero value len=4
after step1: val.p=... val.len=4
step2: store zero-length value len=0
after step2: val.p=(nil) val.len=0
step3: store nonzero value len=4 again; buggy version may crash now
after step3: val.p=... val.len=4
[OK] fixed behavior: value buffer was safely reallocated and updated.
```

The oracle is stale pointer-length state and crash versus length reset and safe
reallocation.

## Mutation Points

- `OID`: reuses the same named-data entry across calls.
- `INITIAL_VALUE_LENGTH`: creates the initial nonzero pointer/length state.
- `ZERO_LENGTH_UPDATE`: enters the vulnerable `val_len == 0` branch.
- `REUSE_VALUE_LENGTH`: matches the stale length and can skip allocation.
- `CLEAR_STALE_LENGTH`: the fixed statement `cur->val.len = 0;`.

## Multi-granularity Masking Guidance

### Identifier-level Candidates

- `cur->val.p`: stored value pointer.
- `cur->val.len`: stored value length.
- `val_len`: new value length argument.
- `oid`: named-data identifier.

### Expression-level Candidates

- `val_len == 0`
- `cur->val.len == val_len`

### Statement-level Candidates

- `cur->val.len = 0;`
- `memcpy(cur->val.p, val, val_len)`

### Block-level Candidates

- The `val_len == 0` branch in `mbedtls_asn1_store_named_data()`.

## Vulnerability Path Features

The migrated target API should preserve these features:

- mutable named-data entry,
- repeated update for the same identifier,
- zero-length update frees or clears value pointer,
- stale length field after pointer clear,
- later same-length nonzero update can skip allocation,
- observable NULL dereference or safe reallocation.

Optional features:

- ASN.1 `commonName` OID,
- exact value length `4`,
- linked-list named-data storage.

Not required features:

- exact CVE advisory source,
- exact pointer addresses,
- exact allocator behavior beyond observable reallocation.

## Migration Guidance

This pattern is about pointer-length consistency across repeated updates, not
only ASN.1 encoding.

Good target API features:

- stores mutable named attributes or ASN.1-like OID/value pairs,
- supports repeated updates of the same key or OID,
- treats zero-length values as a special state transition,
- maintains separate pointer and length fields for stored values,
- can observe stale pointer-length inconsistency through crash or state checks.

Weak target API features:

- supports repeated metadata updates but hides all storage state,
- always reallocates on every update, weakening the stale-length path.

Bad target API features:

- immutable attribute storage,
- no zero-length update path,
- no separate pointer/length consistency invariant.

## Expected Oracle

Bug candidate signals:

- after zero-length update, `val.p == NULL` and `val.len != 0`,
- segmentation fault on later same-length update,
- exit code `139`.

Safe or fixed behavior:

- after zero-length update, `val.p == NULL` and `val.len == 0`,
- later nonzero update reallocates successfully,
- no crash.

## Evidence Files

- Metadata: `data/pocs/core10/MBEDTLS-POC-0005/metadata.json`
- Notes: `data/pocs/core10/MBEDTLS-POC-0005/notes.md`
- Reproduction result: `data/pocs/core10/MBEDTLS-POC-0005/reproduction_result.md`
- PoC source: `data/pocs/core10/MBEDTLS-POC-0005/poc/poc_asn1_store_named_data_null_deref.c`
- Buggy log: `data/pocs/core10/MBEDTLS-POC-0005/poc/run_buggy.log`
- Fixed log: `data/pocs/core10/MBEDTLS-POC-0005/poc/run_fixed.log`
- Library files: `data/pocs/core10/MBEDTLS-POC-0005/library_files.txt`
- Test files: `data/pocs/core10/MBEDTLS-POC-0005/test_files.txt`
- Commits: `data/pocs/core10/MBEDTLS-POC-0005/commits.txt`
- Fix commits: `data/pocs/core10/MBEDTLS-POC-0005/fix_commits.txt`

## Notes

No local `fix.patch` file is present for this PoC. The original metadata
contains broad CVE-search evidence, so this pattern uses the narrowed fixing
commit, local PoC, and local buggy/fixed logs as primary evidence.
