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

Confirmed PR #5350 merge commit:

- 6d6d93ea4abe7b374ad9e2080c948c59c9752823

Buggy version:

- 6d6d93ea4abe7b374ad9e2080c948c59c9752823^1

Confirmed library fix commit:

- f881601c912b608a7fa62c100b2d0aa7352996ee

Root cause:
psa_aead_setup() accepted AEAD algorithms with invalid shortened tag lengths. Before the fix, invalid tag lengths could pass setup and only fail later, or be mishandled depending on the AEAD algorithm and operation path.

Confirmed fixed behavior:
The fixed version validates tag length during psa_aead_setup().

Confirmed fixed helper:

psa_validate_tag_length()

Confirmed mutation point:
library/psa_crypto.c: psa_aead_setup(), missing call to psa_validate_tag_length() after driver setup.

Regression-test-derived trigger candidate:
PSA AEAD setup: AES - CCM, invalid tag length 3

Expected behavior:
- buggy: psa_aead_decrypt_setup() returns PSA_SUCCESS
- fixed: psa_aead_decrypt_setup() returns PSA_ERROR_INVALID_ARGUMENT

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed.

Buggy result:

- psa_crypto_init returned PSA_SUCCESS
- psa_import_key returned PSA_SUCCESS
- psa_aead_decrypt_setup returned PSA_SUCCESS for CCM tag length 3
- failure signal = invalid AEAD tag length accepted during setup

Fixed result:

- psa_crypto_init returned PSA_SUCCESS
- psa_import_key returned PSA_SUCCESS
- psa_aead_decrypt_setup returned PSA_ERROR_INVALID_ARGUMENT (-135)
- invalid AEAD tag length rejected during setup

Conclusion:

MBEDTLS-POC-0028 is now locally reproduced. The confirmed failure signal is invalid parameter accepted. The confirmed mutation point is the missing `psa_validate_tag_length()` call in `psa_aead_setup()`.
