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

Confirmed PR #9082 merge commit:

- 94f07689d6af26030184c176ba44ecd148eff75a

Buggy version:

- 94f07689d6af26030184c176ba44ecd148eff75a^1

Confirmed root cause:
get_pkcs_padding() read padding_len from the last byte of the decrypted block but did not reject padding_len == 0 or padding_len > input_len before computing:

*data_len = input_len - padding_len;

When padding_len > input_len, this can underflow size_t and leave an oversized output length such as 18446744073709551516 on the error path.

Confirmed fixed check:

if (padding_len == 0 || padding_len > input_len) {
    return MBEDTLS_ERR_CIPHER_INVALID_PADDING;
}

Regression test evidence:
test_suite_cipher.function now checks that outlen is zero when mbedtls_cipher_finish() returns an error.

Noise commit refs:
- 18446744073709551516 is the buggy oversized output length, not a commit.
- 1848c561ec39a9ea91ff1bf740a554be274f98b0 and b554eef43b9ac5b92f590da6a120dbfd9ca0582e are OpenSSL references in the commit message, not local mbedTLS commits.

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed.

Trigger:

- AES-128-CBC decrypt path
- PKCS#7 padding mode
- decrypted block length = 16
- invalid final padding byte = 0x80
- padding_len = 128 > input_len = 16

Buggy result:

- cipher_finish ret = -25088
- expected ret = -25088
- finish_olen = 18446744073709551504
- failure signal = unsafe/nonzero oversized output length on error path

Fixed result:

- cipher_finish ret = -25088
- expected ret = -25088
- finish_olen = 0
- fixed behavior = invalid padding rejected and output length remains zero

Conclusion:

MBEDTLS-POC-0004 is now locally reproduced. The confirmed mutation point is the missing invalid-padding-length check before assigning *data_len in get_pkcs_padding().
