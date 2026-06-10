# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-04
- Name: AuthorityKeyIdentifier subfield/full-extension length confusion
- Related PoC: WOLFSSL-POC-0004
- Trigger surface: x509_authority_key_identifier_reencode
- Input type: reconstructed_DER_x509_certificate
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

The implementation checks the small keyIdentifier subfield length but copies the much larger full AuthorityKeyIdentifier extension source buffer into a fixed-size destination.

Trust boundary:

parsed AKID subfield and raw AKID extension encoding -> CertFromX509 fixed-size akid buffer

Vulnerable operation:

memcpy guarded by a different length variable than the copied length

Failure modes:

heap_buffer_overflow, length_confusion, oversized_memcpy

## Recipe Slots

- checked_length: length used in guard | observed: 20
- copied_length: length used in memcpy | observed: 20046
- destination_capacity: size of destination buffer | observed: sizeof(cert->akid)
- oversized_substructure: field used to inflate full extension size | observed: authorityCertIssuer URI
- conversion_path: path that converts WOLFSSL_X509 back into Cert / DER

## Mutation Strategy

- Build a DER X.509 certificate.
- Add an AuthorityKeyIdentifier extension.
- Keep keyIdentifier small enough to pass the old guard.
- Add a large authorityCertIssuer URI to inflate the full extension source size.
- Parse the certificate using X.509 DER parser.
- Trigger internal certificate conversion or re-encoding path.
- Observe whether the full extension length is copied into a smaller destination.

## Oracle

Primary oracle: asan_heap_buffer_overflow

Signals:

- WRITE of size 20046
- heap-buffer-overflow
- crash in CertFromX509
- crash during wolfSSL_i2d_X509_bio

Fixed behavior:

- wolfSSL_i2d_X509_bio returns 0
- harness exits nonzero
- NO_CRASH_SIGNAL
- no sanitizer crash

## AST Masking Targets

- memcpy where guard length differs from copy length
- raw extension copy into fixed-size parsed structure
- AuthorityKeyIdentifier conversion code
- X509 to internal Cert conversion
- re-encoding path from parsed certificate

## RAG Keywords

CertFromX509, AuthorityKeyIdentifier, authKeyId, authKeyIdSz, authKeyIdSrc, authKeyIdSrcSz, cert->akid, WOLFSSL_AKID_NAME, wolfSSL_i2d_X509_bio

## Task

You are given source code from a cryptographic library.

Find code regions that may implement the same vulnerability pattern.

Focus on:

1. Whether untrusted ASN.1 / X.509 length or count values cross into fixed-size buffers.
2. Whether the checked length differs from the copied length.
3. Whether setter APIs store untrusted length without capacity validation.
4. Whether getter, text extraction, or DER re-encoding paths trust previously stored values.
5. Whether compatibility APIs copy into caller-provided buffers.

For each suspicious code region, report:

- Function name
- File path
- Relevant variables
- Guard condition
- Copy or write operation
- Destination capacity
- Why it matches this pattern
- A suggested mutation or test input shape
