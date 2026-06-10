# OSSL_STORE malformed trailing object triage

This artifact extends `ossl_store_trailing_der.c` with malformed trailing ASN.1 objects after a valid DER prefix. It exercises `OSSL_STORE_open()` and loops `OSSL_STORE_load()` until EOF or error.

## Mutations

- `malformed_partial_sequence`: `30 82 10 00`
- `malformed_oversized_len`: `30 84 ff ff ff ff`
- `malformed_indefinite_len`: `30 80`
- `truncated_integer`: `02 04 01`
- `truncated_bit_string`: `03 05 00 aa`
- `bad_asn1_tag`: `ff 01 00`
- `valid_null_then_malformed_seq`: `05 00 30 82 10 00`

## API result

- Total cases: 24
- Verdicts: {'baseline_accept': 3, 'first_object_accepts_malformed_tail': 21}
- `first_load_success`: 24
- `caller_take_first_accept`: 24
- `saw_error`: 0
- `saw_eof`: 24
- ASan/UBSan signal: False

## CLI result

`apps/openssl storeutl` was available and was run against the generated baseline and malformed-tail DER files.

- CLI cases: 24
- Accepted: 24
- Rejected: 0
- Exit code counts: {'0': 24}

## Interpretation

For all malformed-tail cases, the first object was accepted and a full `OSSL_STORE_load()` loop reached EOF without `OSSL_STORE_error()`. This is stronger than a low-level prefix parse result because it is visible through the public OSSL_STORE layer and through `openssl storeutl`. It is still a triage candidate rather than a vulnerability claim: security impact depends on whether a caller treats a DER store URI as a single strict object and requires rejecting trailing malformed bytes.
