# asn1_nested_boundary_minimal_reproducer_v1

This sprint attempted to establish a strict minimal reproduction for `OPENSSL-ISSUE-30581`.

## Result

- Real input seed found: no.
- Bundled input status: placeholder only.
- CLI strict reproduction: blocked by placeholder guard, exit code `3`.
- C API reproducer: not generated because no real seed is available.
- Crash observed: no.
- gdb: not run.
- ASAN/UBSAN: not available in current local OpenSSL 3.5.5 build.
- Confirmed vulnerability: no.
- A-path: no.

## Next

Run `asn1_nested_boundary_seed_enrichment_v1` to recover the original `/tmp/pbmac1_null_salt.p12` or construct an equivalent minimized malformed PKCS12/ASN.1 input before sanitizer/gdb validation.
