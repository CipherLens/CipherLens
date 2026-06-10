# OSSL_STORE app/helper malformed-tail validation

## Source-level helper

`apps/lib/apps.c:891` defines `load_key_certs_crls()`. The `OSSL_STORE_load()` call is at `apps/lib/apps.c:1006`.

Key behavior from the reviewed source:

- The loop condition is based on requested output pointers and `!OSSL_STORE_eof(ctx)`.
- If `OSSL_STORE_load(ctx)` returns `NULL`, the helper continues without checking `OSSL_STORE_error(ctx)` at that point.
- For single-object wrapper use, once a requested object is found, the corresponding pointer (`ppkey`, `ppubkey`, `pcert`, etc.) is set to `NULL`; this can stop the loop before reading the remaining file contents.

Wrappers reviewed:

- `load_cert_pass()` at `apps/lib/apps.c:435`, used by `openssl x509` at `apps/x509.c:848`.
- `load_key()` at `apps/lib/apps.c:556`, used by `openssl pkey` at `apps/pkey.c:228` and `openssl pkcs8` at `apps/pkcs8.c:247`.
- `load_pubkey()` at `apps/lib/apps.c:575`, used by `openssl pkey -pubin` at `apps/pkey.c:226`.

## App command results

Summary from `ossl_store_app_command_summary.json`:

```json
{
  "pkcs8_nocrypt_out_null": {
    "baseline_success": 1,
    "exit_code_counts": {
      "0": 8
    },
    "malformed_accepted": 7,
    "malformed_cases": 7,
    "malformed_rejected": 0,
    "stderr_nonempty_cases": 0,
    "total_cases": 8
  },
  "pkey_noout": {
    "baseline_success": 1,
    "exit_code_counts": {
      "0": 8
    },
    "malformed_accepted": 7,
    "malformed_cases": 7,
    "malformed_rejected": 0,
    "stderr_nonempty_cases": 0,
    "total_cases": 8
  },
  "pkey_noout_without_pubin": {
    "baseline_success": 0,
    "exit_code_counts": {
      "1": 8
    },
    "malformed_accepted": 0,
    "malformed_cases": 7,
    "malformed_rejected": 7,
    "stderr_nonempty_cases": 8,
    "total_cases": 8
  },
  "pkey_pubin_noout": {
    "baseline_success": 1,
    "exit_code_counts": {
      "0": 8
    },
    "malformed_accepted": 7,
    "malformed_cases": 7,
    "malformed_rejected": 0,
    "stderr_nonempty_cases": 0,
    "total_cases": 8
  },
  "storeutl": {
    "baseline_success": 3,
    "exit_code_counts": {
      "0": 24
    },
    "malformed_accepted": 21,
    "malformed_cases": 21,
    "malformed_rejected": 0,
    "stderr_nonempty_cases": 6,
    "total_cases": 24
  },
  "x509_noout": {
    "baseline_success": 1,
    "exit_code_counts": {
      "0": 8
    },
    "malformed_accepted": 7,
    "malformed_cases": 7,
    "malformed_rejected": 0,
    "stderr_nonempty_cases": 0,
    "total_cases": 8
  }
}
```

Notes:

- `-noout` commands intentionally produce empty stdout on success, so `exit_code=0` is treated as object-loaded success.
- `pkey_noout_without_pubin` on `pubkey_der` is a negative control; public key DER requires `-pubin`.
- No CRL/CSR DER malformed-tail inputs were generated in this artifact; `openssl crl` / `openssl req` are therefore not applicable for this exact input set.

## Interpretation

App/helper-level commands accept the malformed-tail DER inputs for certificate, private key, and public key cases. This supports an app-level validation-gap candidate rather than only a low-level `d2i_*` prefix-consumption observation. It is still not a crash or sanitizer finding.
