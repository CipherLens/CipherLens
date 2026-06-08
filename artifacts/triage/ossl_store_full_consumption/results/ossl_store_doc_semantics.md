# OSSL_STORE / DER Documentation Semantics

## Scope

Evidence files:

- `ossl_store_docs_scan.txt`
- OpenSSL source tree: `${CLEAN_SOURCES_ROOT}/openssl-3.5.5/doc`

## d2i_* semantics

Classification: `documented_prefix_or_multi_object_allowed`

`doc/man3/d2i_X509.pod` documents the generic `d2i_TYPE(TYPE **a, const unsigned char **ppin, long length)` API shape.
On success, the input pointer is advanced to the byte after the parsed object.
This means the API exposes pointer-consumption state to the caller.

Implication:

- Low-level `d2i_*` APIs can successfully parse a valid DER object prefix.
- Full-buffer consumption is caller-observable, not automatically enforced by the API.
- A caller that wants strict DER-file validation must compare the advanced pointer with the input end.

## OSSL_STORE semantics

Classification: `documented_prefix_or_multi_object_allowed`

`doc/man3/OSSL_STORE_open.pod` describes a store as a stream/repository of objects.
The documented iteration pattern is:

- open a URI with `OSSL_STORE_open()`
- read available supported objects with `OSSL_STORE_load()`
- continue until `OSSL_STORE_eof()`
- use `OSSL_STORE_error()` and `OSSL_STORE_eof()` to interpret a NULL result

Implication:

- OSSL_STORE is not documented as a single-object DER strict parser.
- Its public contract supports multiple objects and loader-level continuation after unsupported objects.
- A caller that needs "this file contains exactly one DER object and no trailing bytes" must enforce that policy above OSSL_STORE.

## storeutl

Classification: `documented_prefix_or_multi_object_allowed`

`storeutl` is a STORE inspection command. Its source-level behavior reads objects in a loop and distinguishes error/eof after `OSSL_STORE_load()`.

Implication:

- `storeutl` accepting one object while warning about unsupported trailing bytes is consistent with an object-stream inspection tool.
- `storeutl` exit 0 with stderr diagnostics is weaker evidence than silent acceptance by single-object conversion/checking commands.

## x509 / pkey / pkcs8 command docs

Classification: `documentation_ambiguous`

The app command documentation describes input object formats and conversion/checking operations, but does not clearly state whether DER input is required to be fully consumed when a single object is requested.

Implication:

- Users may reasonably treat commands such as `openssl x509 -inform DER -noout`, `openssl pkey -inform DER -noout`, and `openssl pkcs8 -inform DER -nocrypt -out ...` as object validation/conversion commands.
- The documentation does not clearly warn that a valid leading object plus malformed trailing ASN.1 data may still be accepted.

## Overall documentation conclusion

- `d2i_*`: `documented_prefix_or_multi_object_allowed`
- `OSSL_STORE`: `documented_prefix_or_multi_object_allowed`
- `storeutl`: `documented_prefix_or_multi_object_allowed`
- `x509/pkey/pkcs8`: `documentation_ambiguous`

Security interpretation:

- Low-level API behavior alone is a low-value candidate.
- Silent app-level acceptance in object check/export/conversion commands is a stronger validation-gap candidate.
- The current evidence supports an app-level validation-gap report candidate, not a direct CVE claim.
