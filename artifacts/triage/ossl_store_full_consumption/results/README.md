# OSSL_STORE full-consumption triage

This artifact validates whether trailing DER garbage is accepted through the real outer `OSSL_STORE_open` / `OSSL_STORE_load` path, not only through direct low-level `d2i_*` calls.

## Inputs

The harness generates runtime DER seeds for:

- `x509_der`: self-signed X.509 certificate DER
- `pkcs8_der`: PKCS8 private key DER
- `pubkey_der`: SubjectPublicKeyInfo public key DER

Each seed is tested with:

- `baseline_empty`
- `trailing_00`
- `trailing_ff`
- `trailing_null_der`
- `trailing_integer_zero`
- `trailing_empty_sequence`
- `trailing_random_8`
- `second_der_object`

## Commands

```bash
gcc -Wall -Wextra -g artifacts/triage/ossl_store_full_consumption/cases/ossl_store_trailing_der.c   -I"$CLEAN_SOURCES_ROOT/openssl-3.5.5/include"   "$CLEAN_SOURCES_ROOT/openssl-3.5.5/libcrypto.a"   -ldl -pthread -o artifacts/triage/ossl_store_full_consumption/cases/ossl_store_trailing_der

gcc -Wall -Wextra -g -fsanitize=address,undefined artifacts/triage/ossl_store_full_consumption/cases/ossl_store_trailing_der.c   -I"$CLEAN_SOURCES_ROOT/openssl-3.5.5/include"   "$CLEAN_SOURCES_ROOT/openssl-3.5.5/libcrypto.a"   -ldl -pthread -o artifacts/triage/ossl_store_full_consumption/cases/ossl_store_trailing_der_asan
```

## Summary

- Normal cases: 24
- Normal verdicts: {'expected_baseline_accept': 3, 'real_caller_accepts_trailing_garbage_candidate': 21}
- ASan/UBSan cases: 24
- ASan/UBSan verdicts: {'expected_baseline_accept': 3, 'real_caller_accepts_trailing_garbage_candidate': 21}
- ASan/UBSan signal: False

## Interpretation

`real_caller_accepts_trailing_garbage_candidate` means `OSSL_STORE_load` returned a target object from a DER file that had trailing bytes or a second DER object. This is stronger than direct prefix parsing because it exercises the public outer store layer. It is still a triage candidate rather than a vulnerability claim, because downstream security impact depends on whether a real caller expects single-object full consumption and whether accepting concatenated/trailing DER is documented or relied upon.
