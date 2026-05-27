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

Confirmed PR #8804 merge commit:

- a7f651cf160a3753367e032c4471699822b37e30

Buggy version:

- a7f651cf160a3753367e032c4471699822b37e30^1

Confirmed library fix commit:

- 9de84bd67775e05fabca1907cd9f2ea33078d99a

Root cause:
mbedtls_rsa_parse_key() and mbedtls_rsa_parse_pubkey() parsed the main ASN.1 SEQUENCE but did not reject bytes outside that main SEQUENCE. Therefore, DER buffers containing a valid RSA key followed by trailing garbage could be accepted.

Confirmed fixed check:

if (end != p + len) {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
}

Confirmed mutation points:
- library/rsa.c: mbedtls_rsa_parse_key(), check for data outside main SEQUENCE.
- library/rsa.c: mbedtls_rsa_parse_pubkey(), check for data outside main SEQUENCE.

Regression-test-derived trigger candidates:
- RSA parse private key - correct values, extra integer outside the SEQUENCE
- RSA parse public key - correct values, extra integer outside the SEQUENCE

Noise:
- 1953825050 is not a Git commit hash.

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed.

Buggy result:

- private key parser returned 0
- public key parser returned 0
- both parsers accepted trailing garbage outside the main ASN.1 SEQUENCE

Fixed result:

- private key parser returned MBEDTLS_ERR_RSA_BAD_INPUT_DATA (-16512)
- public key parser returned MBEDTLS_ERR_RSA_BAD_INPUT_DATA (-16512)
- both parsers rejected trailing garbage

Conclusion:

MBEDTLS-POC-0020 is now locally reproduced. The confirmed failure signal is parser acceptance of malformed RSA key DER input with trailing garbage. The confirmed mutation point is the missing `end != p + len` check after parsing the top-level RSA SEQUENCE.
