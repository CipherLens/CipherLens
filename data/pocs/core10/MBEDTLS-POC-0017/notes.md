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

Confirmed PR #2442 merge commit:

- 7af080a9f9601449601e9c97d21256bdc2205d02

Buggy version:

- 7af080a9f9601449601e9c97d21256bdc2205d02^1

Confirmed library fix commit in the merge:

- 12f62fb82c81aa3f52bed49dff0f9e038d115f75

Equivalent branch commits:

- 1de13dbc49afff1b746407dd1231c889156a6d1e
- 4e1bfc19cc290be576615f7a2825d8aaea66bf74

Noise commit:
- 3c03a881eb37b0ad63d7cdb6813e1106d5f30d74 only corrects ChangeLog placement and is not the library fix.

Root cause:
When parsing ASN.1 substructures inside X.509 objects, some parser routines kept using the parent structure's end pointer instead of the substructure's end pointer. This allowed fields inside a substructure to cross the substructure boundary and changed the parser's behavior on malformed certificates.

Confirmed mutation points:
- library/x509.c: x509_get_attr_type_value(), set end = *p + len after reading the inner AttributeTypeAndValue SEQUENCE.
- library/x509.c: x509_get_attr_type_value(), reject trailing data with *p != end.
- library/x509_crt.c: x509_get_crt_ext(), return early when *p == end and update end = crt->v3_ext.p + crt->v3_ext.len.
- library/x509_crl.c: x509_get_crl_ext(), return early when *p == end and update end = ext->p + ext->len.

Regression-test-derived trigger candidate:
X509 Certificate ASN1 (TBSCertificate, issuer two inner set datas)

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed.

Buggy result:

- ret = -9186
- expected_buggy = -9186
- parser crossed inner ASN.1 substructure bounds
- failure signal = malformed certificate accepted into wrong parsing path / incorrect ASN.1 parser boundary behavior

Fixed result:

- ret = -9184
- expected_fixed = -9184
- parser obeyed inner ASN.1 substructure bounds

Conclusion:

MBEDTLS-POC-0017 is now locally reproduced. The confirmed failure signal is parser boundary behavior difference on malformed X.509 DER input. The confirmed mutation point is the missing update of the ASN.1 parsing `end` pointer to the current substructure boundary.
