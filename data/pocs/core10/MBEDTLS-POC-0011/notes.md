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

Confirmed 3.6 merge commit:

- 3f82706cb76b80f5c136b91edc6688dea299fbdb

The merge contains:

- regression_test_commit=9325883d9fb270cae63af5a254eb6a855813a189
- library_fix_commit=6165e715899a9b370851e2868fe312d7e0a2cb83

Root cause:
A malformed encrypted PEM buffer with fewer than 4 base64 characters can lead to a decoded buffer length of 0. The buggy version then calls pem_check_pkcs_padding() with input_len == 0, but the function reads input[input_len - 1], causing a one-byte read before the buffer.

Confirmed fixed check:

if (input_len < 1) {
    return MBEDTLS_ERR_PEM_INVALID_DATA;
}

Confirmed mutation point:
library/pem.c: pem_check_pkcs_padding(), input_len boundary check before reading input[input_len - 1].

Regression test input:
PEM read (malformed PEM AES-128-CBC with fewer than 4 base64 chars)

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed with AddressSanitizer.

Buggy result:

- malformed encrypted PEM input reaches mbedtls_pem_read_buffer()
- ASan reports a read in pem_check_pkcs_padding()
- the invalid address is 1 byte before a heap-allocated region
- failure signal = one-byte heap-buffer-underflow
- exit_code = 1

Fixed result:

- malformed PEM is rejected safely
- ret = MBEDTLS_ERR_PEM_INVALID_DATA (-4352)
- no ASan error

Conclusion:

MBEDTLS-POC-0011 is now locally reproduced. The confirmed mutation point is the missing input_len boundary check before reading input[input_len - 1] in pem_check_pkcs_padding().
