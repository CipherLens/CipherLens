# OSSL_STORE App Source Callchain

## Key helper

Function:

- `apps/lib/apps.c:891`: `load_key_certs_crls()`

Critical load site:

- `apps/lib/apps.c:1006`: `OSSL_STORE_load(ctx)`

Loop condition:

- The loop continues while at least one requested output pointer is still non-NULL.
- The loop also checks `!OSSL_STORE_eof(ctx)`.

Single-object behavior:

- For `pcert`, `ppkey`, or `ppubkey`, once a matching object is found, the corresponding output selector is set to NULL.
- In a single-object caller, all requested selectors are then NULL, so the loop exits.
- The helper then closes the store and returns the found object.

EOF/error behavior:

- `OSSL_STORE_load(ctx)` is called inside the loop.
- If it returns NULL, this helper continues rather than immediately checking `OSSL_STORE_error(ctx)`.
- After a requested object is found, the helper does not force another `OSSL_STORE_load()` to examine trailing bytes.
- After a requested object is found, the helper does not require `OSSL_STORE_eof(ctx)` before returning success.

Classification:

- `takes_first_object_only`

## Command call chains

### openssl x509

- `apps/x509.c:848`: calls `load_cert_pass(infile, informat, 1, passin, "certificate")`
- `apps/lib/apps.c:435`: `load_cert_pass()`
- `apps/lib/apps.c:451`: calls `load_key_certs_crls(..., &cert, ...)`
- `apps/lib/apps.c:1006`: `OSSL_STORE_load(ctx)`

Classification:

- Uses the `takes_first_object_only` helper for DER certificate input.

### openssl pkey

- `apps/pkey.c:225-228`: uses `load_pubkey()` when `-pubin` is set, otherwise `load_key()`
- `apps/lib/apps.c:556`: `load_key()`
- `apps/lib/apps.c:575`: `load_pubkey()`
- `apps/lib/apps.c:567` and `apps/lib/apps.c:586`: call `load_key_certs_crls()`
- `apps/lib/apps.c:1006`: `OSSL_STORE_load(ctx)`

Classification:

- Uses the `takes_first_object_only` helper for private-key and public-key input.

### openssl pkcs8

- `apps/pkcs8.c:247`: calls `load_key(infile, informat, 1, passin, e, "key")`
- `apps/lib/apps.c:556`: `load_key()`
- `apps/lib/apps.c:567`: calls `load_key_certs_crls()`
- `apps/lib/apps.c:1006`: `OSSL_STORE_load(ctx)`

Classification:

- Uses the `takes_first_object_only` helper for private-key input when converting to PKCS#8.

### openssl storeutl

- `apps/storeutl.c:403`: calls `OSSL_STORE_load(store_ctx)` in a direct loop.
- `apps/storeutl.c:408`: checks `OSSL_STORE_error(store_ctx)` after NULL.
- `apps/storeutl.c:419`: checks `OSSL_STORE_eof(store_ctx)`.

Classification:

- `reads_all_objects_and_checks_error`
- It can still exit 0 while printing unsupported-object diagnostics for malformed trailing data.

## Additional commands

### openssl req

- `apps/lib/apps.c:480`: `load_csr()`
- `apps/lib/apps.c:491-492`: DER CSR input uses `d2i_X509_REQ_bio()`, not `OSSL_STORE`.

The current malformed-tail corpus contains X509, PKCS#8 private-key, and SPKI public-key files, not CSR files.
`openssl req` is therefore not directly applicable to this corpus.

### openssl crl

The current malformed-tail corpus does not contain CRL DER files.
`openssl crl` is therefore not directly applicable to this corpus.

## Source-level conclusion

`apps/lib/apps.c:1006` belongs to `load_key_certs_crls()`.
For single-object helper callers, the pattern is `takes_first_object_only`:

- one or more `OSSL_STORE_load()` calls until a requested object type is found
- no required post-success EOF check
- no required post-success `OSSL_STORE_error()` check
- successful object returned to x509/pkey/pkcs8 app commands

This source pattern explains why malformed trailing data can be ignored by app-level object extraction and conversion commands.
