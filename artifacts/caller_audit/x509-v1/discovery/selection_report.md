# MLS++ X509 local static selection report

## Scope

This report covers only the fixed local checkout of `cisco/mlspp` at `92aaa4134fa45ec39957a7c81a342401fba7feb2`. It is a defensive static code-quality review. No harness, mutation, service connection, runtime test, security rating, or code change was performed.

Evidence labels mean:

- **confirmed**: directly supported by the fixed local source.
- **inferred**: supported by source structure but not exercised.
- **unproven**: additional evidence is required.

## Which callsite is best suited to a local regression test?

The recommended callsite is `Certificate::ParsedCertificate::parse(const bytes& der)` at `lib/hpke/src/certificate.cpp:96`, which calls `d2i_X509`.

Classification: `exact_single_certificate_candidate`.

Evidence status: **confirmed** for the call mechanics and production-library data flow; **inferred** for regression feasibility.

The parser receives a bounded `bytes` value, initializes `buf` to its beginning, and supplies `der.size()` as the length. It checks only whether an `X509` object was returned. The advanced `buf` pointer is not compared with the end of the input.

The parsed object is not merely converted and discarded. The production X509 credential path:

1. decodes a vector of independently bounded `X509Credential::CertData` values;
2. constructs one `Certificate` per `cert.data`;
3. extracts the leaf public key and signature scheme;
4. checks adjacent certificate signatures with `X509_verify`;
5. exposes `Credential::valid_for` to compare the leaf certificate public key with an MLS `SignaturePublicKey`; this comparison is invoked by `LeafNode::sign` and credential-binding paths.

`LeafNode::verify` is separate: it checks the X509 signature scheme and verifies with the stored `signature_key`; no `credential.valid_for` call is present in the inspected verification function.

The same certificate wrapper also computes a SHA-256 `X509_digest`, extracts identity-related fields, retains the original DER bytes, and uses raw bytes for certificate equality.

## Why does it have single-certificate semantics?

Status: **confirmed**.

The singular `Certificate(const bytes& der)` constructor delegates the entire `bytes` value to one `d2i_X509` call. In the chain container, each `CertData.data` element is separately length-bounded and separately passed to one `Certificate` construction. The surrounding vector represents the chain; an individual vector element represents one certificate.

This differs from `Certificate::parse_pem` at line 405. That function explicitly returns `std::vector<Certificate>`, repeatedly calls `PEM_read_bio_X509`, and treats `PEM_R_NO_START_LINE` as the end of the object sequence. It is therefore classified as `stream_or_multi_object_semantics` and is not selected for an exact-single-certificate regression.

No `d2i_X509_bio` callsite exists in the fixed local checkout.

## What additional evidence is required before continuing?

The next phase would need all of the following local evidence:

1. **Baseline behavior, currently unproven:** with a locally generated self-signed certificate, record success, consumed length, canonical reserialization, SHA-256 certificate digest, public key, and retained raw bytes for canonical DER and bounded trailing-byte mutations.
2. **Fix-control behavior, currently unproven:** add only a local experimental end-pointer check and show that it preserves canonical input while rejecting inputs with unconsumed bytes.
3. **Credential-path behavior, currently unproven:** deserialize a synthetic `X509Credential`, exercise adjacent-certificate `X509_verify` and the explicit `Credential::valid_for` paths, and separately document the relationship to `LeafNode` verification without any network or external service.
4. **Representation behavior, currently unproven:** determine whether distinct raw inputs that parse to the same `X509` object produce different raw equality while producing the same `X509_digest` and public key.
5. **Build evidence, currently inferred:** reproduce the relevant CMake target against the fixed OpenSSL version with ASan and UBSan.
6. **Maintenance evidence, currently unproven:** review public project history, issues, and pull requests only if a later phase explicitly re-authorizes internet research.

Until those checks exist, this remains a local static caller candidate only.
