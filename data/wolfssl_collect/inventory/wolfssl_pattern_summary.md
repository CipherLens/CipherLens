# wolfSSL Vulnerability Pattern Summary

## Overview

This document summarizes vulnerability patterns abstracted from WOLFSSL-POC-0001 to WOLFSSL-POC-0004.

Current scope:

- Library: wolfSSL
- Focus area: X.509 / ASN.1 / OpenSSL compatibility API / memory safety
- Collected Q1 PoCs: 4
- All four PoCs have vulnerable-version reproduction, fixed-release validation, and current-version validation.

## Pattern Index

| Pattern ID | Related PoC | Vulnerability Theme | Trigger Object | Oracle |
|---|---|---|---|---|
| Pattern-01 | WOLFSSL-POC-0001 | X.509 name field repetition / loc array overflow | malformed certificate name fields | sanitizer crash |
| Pattern-02 | WOLFSSL-POC-0002 | X.509 text field fixed-size buffer off-by-one | reconstructed X.509 certificate text field | sanitizer crash |
| Pattern-03 | WOLFSSL-POC-0003 | ASN1_TIME length trust boundary error | crafted WOLFSSL_ASN1_TIME object | sanitizer crash / safe rejection |
| Pattern-04 | WOLFSSL-POC-0004 | AuthorityKeyIdentifier subfield/full-extension length confusion | reconstructed DER certificate with oversized AKID | sanitizer crash / safe rejection |

---

## Pattern-01: X.509 Name Field Repetition / loc Array Overflow

### Related PoC

- PoC ID: WOLFSSL-POC-0001
- Source: GitHub issue #2555
- Input provenance: original_issue_attachment
- Quality level: Q1_strict_reproduction_candidate

### Abstract Pattern

A malformed X.509 certificate contains repeated or unusually structured name fields. During ASN.1 name parsing, the parser records field locations or identifiers into a fixed-size location array. If the number of parsed name components exceeds the array capacity and the parser does not enforce a strict bound, writes can exceed the intended array range.

### Vulnerability Shape

- Parser component: X.509 name parser
- Data structure: fixed-size location array
- Trigger field family:
  - subject name
  - issuer name
  - repeated RDN / AttributeTypeAndValue elements
- Failure mode:
  - out-of-bounds write
  - corrupted certificate parse state
  - later sanitizer-visible crash

### Recipe Slots

| Slot | Meaning | Example Mutation |
|---|---|---|
| name_sequence_count | number of name elements | increase RDN / ATV count |
| name_field_type | selected name OID | CN, O, OU, email, UID, domainComponent |
| nesting_shape | ASN.1 SET / SEQUENCE layout | duplicate nested name structures |
| parser_state_capacity | fixed internal array capacity | exceed expected maximum count |
| terminal_malformed_length | final length inconsistency | truncate final field or overstate length |

### Mutation Recipe

1. Start from a valid or semi-valid X.509 certificate.
2. Locate subject or issuer Name.
3. Repeat one or more AttributeTypeAndValue entries.
4. Prefer fields that the parser stores in an internal location table.
5. Increase repetition until the parser exceeds its expected internal field count.
6. Optionally add malformed terminal length to force error cleanup paths.

### Oracle

- Primary oracle: sanitizer crash
- Secondary oracle:
  - parser error path inconsistency
  - vulnerable / fixed / current version behavior difference

---

## Pattern-02: X.509 Text Field Fixed-Size Buffer Off-by-One

### Related PoC

- PoC ID: WOLFSSL-POC-0002
- CVE: CVE-2017-2800
- Source: TALOS-2017-0293 / EDB-41984
- Input provenance: reconstructed_from_exploitdb_talos_poc_command
- Quality level: Q1_strict_reproduction_candidate

### Abstract Pattern

An X.509 certificate contains a text field whose length is equal to or slightly larger than the caller-provided output buffer. A compatibility API copies the field into a fixed-size caller buffer and appends a string terminator. If the implementation checks only the copied text length but not the terminator position, it can write one byte out of bounds.

### Vulnerability Shape

- API family: OpenSSL compatibility X.509 text extraction API
- Trigger API: wolfSSL_X509_NAME_get_text_by_NID
- Trigger field in reproduced PoC: localityName
- Possible related fields:
  - commonName
  - countryName
  - stateOrProvinceName
  - organizationName
  - organizationalUnitName
- Failure mode:
  - stack-buffer-overflow
  - off-by-one null write
  - caller-provided fixed-size buffer boundary violation

### Recipe Slots

| Slot | Meaning | Example Mutation |
|---|---|---|
| target_text_field | selected X.509 subject field | localityName |
| output_buffer_size | harness buffer size | 80 bytes |
| field_text_length | certificate field length | equal to buffer size |
| terminator_policy | whether API appends NUL | force NUL write at index len |
| NID_selector | selected text field API identifier | NID_localityName |

### Mutation Recipe

1. Build or modify an X.509 certificate subject field.
2. Select a text field consumed by get_text_by_NID-style APIs.
3. Set field length equal to the expected output buffer size.
4. Use a harness that provides a fixed-size stack buffer.
5. Call the text extraction API.
6. Detect whether the implementation writes a terminator out of bounds.

### Oracle

- Primary oracle: ASan stack-buffer-overflow
- Specific signal:
  - WRITE of size 1
  - overflow immediately after fixed-size stack buffer
- Fixed behavior:
  - truncation
  - safe rejection
  - no sanitizer crash

---

## Pattern-03: ASN1_TIME Length Trust Boundary Error

### Related PoC

- PoC ID: WOLFSSL-POC-0003
- CVE: CVE-2026-5448
- Input provenance: reconstructed_from_pr_10071_official_test_pattern
- Quality level: Q1_strict_reproduction_candidate

### Abstract Pattern

An API accepts or stores an ASN.1 time object whose declared length exceeds the internal fixed-size destination buffer. Later, an accessor or encoder trusts the stored length and copies or serializes type / length / data into a smaller internal buffer, causing a buffer overflow.

### Vulnerability Shape

- API family: X.509 time setter / getter API
- Trigger APIs:
  - wolfSSL_X509_set_notAfter
  - wolfSSL_X509_notAfter
  - wolfSSL_X509_set_notBefore
  - wolfSSL_X509_notBefore
- Trigger object: crafted WOLFSSL_ASN1_TIME
- Trigger value: length = 255
- Failure mode:
  - heap-buffer-overflow
  - oversized copy or serialization
  - trust boundary violation between ASN1_TIME length and internal X509 date buffer

### Recipe Slots

| Slot | Meaning | Example Mutation |
|---|---|---|
| time_object_type | ASN.1 time tag | ASN_UTC_TIME |
| declared_time_length | length stored in ASN1_TIME | 255 |
| actual_data_capacity | size of internal data array | smaller than declared length |
| target_date_field | notBefore or notAfter | both |
| accessor_path | API that serializes time | wolfSSL_X509_notAfter |

### Mutation Recipe

1. Create an X.509 object.
2. Create a crafted ASN1_TIME object.
3. Set a valid time type, such as UTC time.
4. Set an oversized declared length.
5. Call notBefore / notAfter setter.
6. Call notBefore / notAfter accessor.
7. Compare vulnerable crash with fixed safe rejection.

### Oracle

- Primary oracle: ASan heap-buffer-overflow
- Fixed-version oracle:
  - setter rejects oversized length
  - accessor refuses invalid internal length
  - no sanitizer crash

---

## Pattern-04: AuthorityKeyIdentifier Subfield / Full-Extension Length Confusion

### Related PoC

- PoC ID: WOLFSSL-POC-0004
- CVE: CVE-2026-5447
- Input provenance: reconstructed_from_pr_10112_official_test_pattern
- Quality level: Q1_strict_reproduction_candidate

### Abstract Pattern

An X.509 AuthorityKeyIdentifier extension contains both a small keyIdentifier subfield and a much larger full extension encoding. The vulnerable implementation checks the size of the small subfield but copies the full extension source buffer into a fixed-size destination. This creates a size confusion between subfield length and full-extension length.

### Vulnerability Shape

- Component: CertFromX509
- Trigger APIs:
  - wolfSSL_X509_d2i
  - wolfSSL_i2d_X509_bio
  - CertFromX509
- Trigger extension: AuthorityKeyIdentifier
- Trigger structure:
  - keyIdentifier: small, 20 bytes
  - authorityCertIssuer: very large URI
  - full AKID source length: approximately 20046 bytes
- Failure mode:
  - heap-buffer-overflow
  - oversized memcpy into cert->akid
  - length confusion between authKeyIdSz and authKeyIdSrcSz

### Root Cause Model

The vulnerable implementation validates authKeyIdSz against the destination capacity, but under WOLFSSL_AKID_NAME copies authKeyIdSrcSz bytes into cert->akid. The checked length and copied length are different variables.

### Recipe Slots

| Slot | Meaning | Example Mutation |
|---|---|---|
| checked_length | length used in guard | authKeyIdSz = 20 |
| copied_length | length used in memcpy | authKeyIdSrcSz = 20046 |
| destination_capacity | destination buffer size | sizeof(cert->akid) |
| oversized_substructure | field inflating full extension | authorityCertIssuer URI |
| conversion_path | API that converts X509 to Cert | wolfSSL_i2d_X509_bio |

### Mutation Recipe

1. Build a DER X.509 certificate.
2. Add AuthorityKeyIdentifier extension.
3. Keep keyIdentifier small enough to pass the old guard.
4. Add a large authorityCertIssuer URI to inflate the full extension source size.
5. Parse certificate using X.509 DER parser.
6. Trigger internal certificate conversion / re-encoding path.
7. Observe whether the full extension length is copied into a smaller destination.

### Oracle

- Primary oracle: ASan heap-buffer-overflow
- Specific signal:
  - WRITE of size 20046
  - crash in CertFromX509
  - crash during wolfSSL_i2d_X509_bio
- Fixed behavior:
  - safe rejection
  - wolfSSL_i2d_X509_bio returns 0
  - no sanitizer crash

---

## Common Pattern Family

### Shared Theme

All four patterns involve X.509 / ASN.1 metadata crossing a trust boundary:

1. ASN.1 encoded input
2. parser-internal representation
3. compatibility API or re-encoding API
4. fixed-size destination buffer

The recurring bug shape is:

- untrusted length or count
- insufficient validation
- fixed-size internal or caller-provided buffer
- sanitizer-visible memory safety failure

### Common Recipe-Slot Dimensions

| Dimension | Meaning |
|---|---|
| encoded_length | length encoded in DER / ASN.1 object |
| parsed_length | length stored in internal object |
| copied_length | length used by memcpy / string copy |
| checked_length | length used in guard |
| destination_capacity | actual size of destination buffer |
| repetition_count | number of repeated ASN.1 elements |
| selected_extension | X.509 extension used as trigger |
| compatibility_api | OpenSSL-compatible API involved |
| conversion_stage | parse, accessor, text extraction, re-encode |

### Fuzzing Guidance

High-value structured mutation directions:

1. Increase field repetition count.
2. Make checked length smaller than copied length.
3. Inflate full extension encoding while keeping parsed subfield small.
4. Set declared object length larger than actual internal buffer.
5. Target API paths that convert parsed X.509 objects back into DER.
6. Compare vulnerable, fixed, and current versions with sanitizer oracle.

### AST / Recipe-Slot Modeling Guidance

Useful code patterns for AST masking and retrieval:

- fixed-size array write indexed by parsed count
- memcpy where guard variable differs from copy-length variable
- setter that stores untrusted length without capacity check
- getter or encoder that trusts stored length
- compatibility wrapper copying into caller-provided buffer
- parser path that preserves both raw and parsed extension forms

### Recommended Dataset Tags

- x509
- asn1
- certificate-parser
- openssl-compat-api
- fixed-buffer
- length-confusion
- count-overflow
- off-by-one
- der-reencode
- sanitizer-oracle

## Pattern-05: DTLS 1.3 ACK record count / 16-bit length truncation overflow

### Related PoC

- WOLFSSL-POC-0005
- CVE-2026-5264

### Bug Class

DTLS 1.3 ACK record processing heap buffer overflow.

### Core Mechanism

The vulnerable implementation stores DTLS 1.3 ACK records in a linked list and computes the ACK list byte length by multiplying the number of records by the fixed record-number encoding size.

In the vulnerable version, the record count is not bounded before the computed length is stored into a 16-bit length field. When the ACK record list grows past the maximum encodable size, the computed byte length is truncated. The output buffer size check is then performed using the truncated length, but the serialization loop still writes every ACK record in the full linked list.

This creates a mismatch between the checked / allocated message size and the actual number of records serialized.

### Trigger Shape

- Establish a DTLS 1.3 client/server context.
- Complete a DTLS 1.3 handshake.
- Add many ACK records through the DTLS 1.3 retransmission ACK tracking path.
- Use 4097 ACK records to exceed the 16-bit ACK list length boundary.
- Trigger ACK message serialization through Dtls13WriteAckMessage.

### Vulnerable Behavior

On wolfSSL v5.9.0-stable:

- 4097 ACK records are accepted.
- Dtls13WriteAckMessage computes a truncated ACK list length.
- CheckAvailableSize is performed using the truncated length.
- Serialization writes the full ACK record list.
- ASan reports an out-of-bounds heap write.
- Crash stack includes:
  - c64toa
  - Dtls13WriteAckMessage
- Exit code: 134

### Fixed Behavior

On wolfSSL v5.9.1-stable and current wolfSSL:

- 4097 attempted ACK insertions are bounded.
- seenRecordsCount is capped at 128.
- Dtls13WriteAckMessage returns 0.
- Encoded ACK length is 2050.
- Exit code is 0.
- No ASan crash is observed.

### Generalized Vulnerability Pattern

This pattern applies to protocol parsers or serializers where:

- A variable-length list is controlled by peer-triggered input or protocol state.
- The list length is counted without an upper bound.
- The encoded message length is stored in a narrower integer type.
- Buffer sizing uses the truncated or wrapped encoded length.
- Serialization later iterates over the full unbounded list.

### Search Keywords

Dtls13WriteAckMessage, Dtls13RtxAddAck, DTLS13_RN_SIZE, DTLS13_ACK_MAX_RECORDS, seenRecords, seenRecordsCount, ACK records, word16 length, c16toa, c64toa, CheckAvailableSize, GetOutputBuffer, DTLS 1.3 ACK

## Pattern-06: PKCS7 custom signed attributes / fixed attribute array overflow

- Related PoC: WOLFSSL-POC-0006
- CVE / Issue: CVE-2026-0819
- Bug class: PKCS7 SignedData encoding out-of-bounds write
- Trigger surface: pkcs7_signeddata_attribute_encoding
- Input type: crafted PKCS7 SignedData encoding request with oversized custom signed attributes
- Quality level: Q1_strict_reproduction_candidate

### Vulnerability Mechanism

The vulnerable implementation stores encoded PKCS7 SignedData signed attributes in a fixed internal attribute array. Caller-controlled custom signed attributes are supplied through `pkcs7->signedAttribs` and `pkcs7->signedAttribsSz`.

In the vulnerable version, the implementation adds `pkcs7->signedAttribsSz` to `esd->signedAttribsCount` and calls `EncodeAttributes(&esd->signedAttribs[atrIdx], ...)` without checking the remaining capacity of the fixed `signedAttribs[7]` array. A request with 8 custom signed attributes causes `EncodeAttributes` to write past the internal fixed array.

### Reproduction Summary

- Vulnerable version: wolfSSL v5.8.4-stable
- Fixed version: wolfSSL v5.9.0-stable
- Current version: current master
- Vulnerable signal:
  - AddressSanitizer stack-buffer-overflow
  - WRITE of size 8
  - crash path: `EncodeAttributes -> wc_PKCS7_BuildSignedAttributes -> wc_PKCS7_EncodeSignedData`
- Fixed behavior:
  - `wc_PKCS7_EncodeSignedData` returns `-132`
  - no ASan crash
- Current behavior:
  - `wc_PKCS7_EncodeSignedData` returns `-132`
  - `NO_ASAN_CRASH_OBSERVED`

### Abstract Pattern

A caller-controlled count of complex PKCS7/CMS attributes crosses into a fixed-size internal encoder array. The vulnerable code trusts the external count during attribute encoding and fails to check remaining array capacity before writing encoded attribute descriptors.

### Mutation Strategy

- Start from a valid PKCS7 SignedData encoding flow.
- Initialize a valid signer certificate and private key.
- Configure custom signed attributes through `pkcs7->signedAttribs`.
- Set `pkcs7->signedAttribsSz` above the internal fixed attribute capacity.
- Trigger `wc_PKCS7_EncodeSignedData` or `wc_PKCS7_EncodeSignedData_ex`.
- Observe whether `EncodeAttributes` writes past the fixed internal array.

### Oracle

Primary oracle: sanitizer crash.

Expected vulnerable signal:

- `ERROR: AddressSanitizer: stack-buffer-overflow`
- `WRITE of size 8`
- stack trace includes:
  - `EncodeAttributes`
  - `wc_PKCS7_BuildSignedAttributes`
  - `wc_PKCS7_EncodeSignedData`

Expected fixed signal:

- safe rejection
- `wc_PKCS7_EncodeSignedData returned: -132`
- no sanitizer crash

### RAG Keywords

`wc_PKCS7_EncodeSignedData`, `wc_PKCS7_EncodeSignedData_ex`, `wc_PKCS7_BuildSignedAttributes`, `EncodeAttributes`, `PKCS7Attrib`, `signedAttribs`, `signedAttribsSz`, `signedAttribsCount`, `MAX_SIGNED_ATTRIBS_SZ`, `availableSpace`, `BUFFER_E`

## Pattern-07: PKCS7 ORI OID / fixed stack OID buffer overflow

- Related PoC: WOLFSSL-POC-0007
- CVE / Issue: CVE-2026-5295
- Bug class: PKCS7 ORI OID processing stack buffer overflow
- Trigger surface: pkcs7_ori_recipient_decryption
- Input type: reconstructed PKCS7/CMS EnvelopedData with oversized ORI OID
- Quality level: Q1_strict_reproduction_candidate

### Vulnerability Mechanism

The vulnerable implementation parses an ASN.1 OtherRecipientInfo structure from PKCS7/CMS EnvelopedData. The ORI recipient contains an `oriType` OBJECT IDENTIFIER and an `oriValue`.

In the vulnerable version, `wc_PKCS7_DecryptOri` obtains the ASN.1 OID length into `oriOIDSz`, then copies the OID bytes into a fixed stack buffer `oriOID[MAX_OID_SZ]` without first checking that `oriOIDSz <= MAX_OID_SZ`.

A crafted ORI recipient with an 80-byte OID causes an out-of-bounds stack write when `XMEMCPY(oriOID, pkiMsg + *idx, oriOIDSz)` is executed.

### Reproduction Summary

- Vulnerable version: wolfSSL v5.9.0-stable
- Fixed version: wolfSSL v5.9.1-stable
- Current version: current master
- Vulnerable signal:
  - AddressSanitizer stack-buffer-overflow
  - WRITE of size 80
  - crash path: `wc_PKCS7_DecryptOri -> wc_PKCS7_DecodeEnvelopedData`
  - overflow object: `oriOID[MAX_OID_SZ]`
- Fixed behavior:
  - `wc_PKCS7_DecodeEnvelopedData` returns `-140`
  - no ASan crash
- Current behavior:
  - `wc_PKCS7_DecodeEnvelopedData` returns `-140`
  - `NO_ASAN_CRASH_OBSERVED`

### Abstract Pattern

An ASN.1 length-controlled OID field crosses into a fixed-size stack buffer. The vulnerable code trusts the parsed OID length and performs a raw copy before validating that the OID fits into the local fixed OID buffer.

### Mutation Strategy

- Start from a valid or semi-valid PKCS7/CMS EnvelopedData structure.
- Include a RecipientInfo of type OtherRecipientInfo / ORI.
- Encode `oriType` as an OBJECT IDENTIFIER with length greater than `MAX_OID_SZ`.
- Register an ORI decrypt callback so the ORI decrypt path is reachable.
- Trigger `wc_PKCS7_DecodeEnvelopedData`.
- Observe whether `wc_PKCS7_DecryptOri` copies the oversized OID into `oriOID[MAX_OID_SZ]`.

### Oracle

Primary oracle: sanitizer crash.

Expected vulnerable signal:

- `ERROR: AddressSanitizer: stack-buffer-overflow`
- `WRITE of size 80`
- stack trace includes:
  - `wc_PKCS7_DecryptOri`
  - `wc_PKCS7_DecodeEnvelopedData`
- sanitizer report shows `oriOID` overflow.

Expected fixed signal:

- safe rejection
- `wc_PKCS7_DecodeEnvelopedData returned: -140`
- no sanitizer crash

### RAG Keywords

`wc_PKCS7_DecodeEnvelopedData`, `wc_PKCS7_DecryptOri`, `wc_PKCS7_SetOriDecryptCb`, `OtherRecipientInfo`, `ORI`, `oriType`, `oriValue`, `oriOID`, `oriOIDSz`, `MAX_OID_SZ`, `GetASNObjectId`, `XMEMCPY`, `ASN_PARSE_E`

## Pattern-08: TLS 1.3 PQC hybrid KeyShare cleanup UAF / double-free

- Related PoC: WOLFSSL-POC-0008
- CVE / Issue: CVE-2026-5460
- Bug class: TLS 1.3 PQC hybrid KeyShare error cleanup heap-use-after-free / double-free
- Trigger surface: tls13_pqc_hybrid_keyshare_processing
- Input type: malicious TLS 1.3 ServerHello with truncated PQC hybrid KeyShare
- Quality level: Q1_strict_reproduction_candidate

### Vulnerability Mechanism

The vulnerable TLS 1.3 client processes a malicious ServerHello containing a truncated PQC hybrid KeyShare. The selected group is `WOLFSSL_SECP256R1MLKEM768`, but the `key_exchange` field contains only 10 bytes.

During hybrid KeyShare processing, wolfSSL splits or transfers ownership of ECC and ML-KEM key material. In the vulnerable version, the error cleanup path leaves a KeyShare entry pointing to key material that has already been freed. Later, `wolfSSL_free` walks TLS extensions through `TLSX_FreeAll` and `TLSX_KeyShare_FreeAll`, causing `ForceZero` to write to freed memory.

### Reproduction Summary

- Vulnerable version: wolfSSL v5.9.0-stable
- Fixed version: wolfSSL v5.9.1-stable
- Current version: current master
- Vulnerable signal:
  - AddressSanitizer heap-use-after-free
  - WRITE of size 8
  - crash path: `ForceZero -> TLSX_KeyShare_FreeAll -> TLSX_FreeAll -> wolfSSL_free`
  - earlier free path includes `TLSX_KeyShare_ProcessPqcHybridClient`
- Fixed behavior:
  - `wolfSSL_UseKeyShare returned: 1`
  - `wolfSSL_connect_TLSv13 returned: -1`
  - `wolfSSL_free done`
  - `cleanup done`
  - no ASan crash
- Current behavior:
  - same safe cleanup behavior as fixed

### Abstract Pattern

A protocol parser error path transfers or partially owns nested cryptographic key objects, then fails to null or detach the source pointer before cleanup. A later global cleanup walks the same object graph and frees or wipes already-freed key material.

### Mutation Strategy

- Build wolfSSL with TLS 1.3, ECC, ML-KEM, and PQC hybrid support.
- Configure a TLS 1.3 client to offer a PQC hybrid KeyShare.
- Inject a malicious ServerHello with `WOLFSSL_SECP256R1MLKEM768`.
- Set `key_exchange` length to a value much smaller than the expected hybrid key share length.
- Force `wolfSSL_connect_TLSv13` to fail during key share processing.
- Call `wolfSSL_free` and observe whether cleanup revisits already-freed key material.

### Oracle

Primary oracle: sanitizer crash.

Expected vulnerable signal:

- `ERROR: AddressSanitizer: heap-use-after-free`
- `WRITE of size 8`
- stack trace includes:
  - `ForceZero`
  - `TLSX_KeyShare_FreeAll`
  - `TLSX_FreeAll`
  - `wolfSSL_free`
- earlier allocation/free trace includes:
  - `TLSX_KeyShare_ProcessPqcHybridClient`
  - `wolfSSL_connect_TLSv13`
  - `wolfSSL_UseKeyShare`

Expected fixed signal:

- safe cleanup
- `wolfSSL_free done`
- `cleanup done`
- `NO_ASAN_CRASH_OBSERVED`

### RAG Keywords

`wolfSSL_connect_TLSv13`, `wolfSSL_UseKeyShare`, `wolfSSL_free`, `TLSX_KeyShare_ProcessPqcHybridClient`, `TLSX_KeyShare_FreeAll`, `TLSX_FreeAll`, `ForceZero`, `WOLFSSL_SECP256R1MLKEM768`, `WOLFSSL_PQC_HYBRIDS`, `WOLFSSL_HAVE_MLKEM`, `ML-KEM`, `KyberKey`, `truncated KeyShare`, `ServerHello`, `key_exchange`

## Pattern-09: SSL_SESSION deserialization chain.count fixed array overflow

- Related PoC: WOLFSSL-POC-0009
- CVE / Issue: CVE-2026-2646
- Bug class: SSL_SESSION deserialization heap-buffer-overflow
- Trigger surface: ssl_session_deserialization
- Input type: mutated serialized SSL_SESSION with oversized SESSION_CERTS chain.count
- Quality level: Q1_strict_reproduction_candidate

### Vulnerability Mechanism

`wolfSSL_d2i_SSL_SESSION` deserializes SSL_SESSION data from external input. When `SESSION_CERTS` is enabled, the serialized data contains certificate-chain metadata, including `chain.count`.

In the vulnerable version, `chain.count` is trusted and used to populate a fixed internal certificate-chain array. A crafted serialized session with `chain.count = 0xff` causes writes past the fixed `x509_buffer[9]` array.

### Reproduction Summary

- Vulnerable: wolfSSL v5.8.4-stable
- Fixed: wolfSSL v5.9.0-stable
- Current: current master
- Vulnerable signal:
  - AddressSanitizer heap-buffer-overflow
  - WRITE of size 4
  - crash in `wolfSSL_d2i_SSL_SESSION`
  - source: `src/ssl_sess.c:2831`
  - UBSan: index 9 out of bounds for `x509_buffer[9]`
- Fixed/current behavior:
  - `wolfSSL_d2i_SSL_SESSION returned: (nil)`
  - cleanup done
  - `NO_ASAN_CRASH_OBSERVED`

### RAG Keywords

`wolfSSL_d2i_SSL_SESSION`, `wolfSSL_i2d_SSL_SESSION`, `SSL_SESSION`, `SESSION_CERTS`, `chain.count`, `MAX_CHAIN_DEPTH`, `x509_buffer`, `sessionIDSz`, `altIDLen`, `src/ssl_sess.c`, `serialized session`

## Pattern-10: ALPN protocol list length over-read

- Related PoC: WOLFSSL-POC-0010
- CVE / Issue: CVE-2026-3547
- Bug class: ALPN / NPN protocol-list heap-buffer-over-read
- Trigger surface: alpn_protocol_selection
- Input type: malformed length-prefixed ALPN/NPN protocol lists
- Quality level: Q1_strict_reproduction_candidate

### Vulnerability Mechanism

`wolfSSL_select_next_proto` parses length-prefixed protocol lists. In the vulnerable version, the length byte from the server/client protocol list is trusted before validating that the declared protocol length fits inside the supplied buffer.

A crafted 5-byte heap buffer with a first length byte of 200 causes `wolfSSL_select_next_proto` to call `memcmp` with length 200, reading beyond the 5-byte allocation.

### Reproduction Summary

- Vulnerable: wolfSSL v5.8.4-stable
- Fixed: wolfSSL v5.9.0-stable
- Current: current master
- Vulnerable signal:
  - AddressSanitizer heap-buffer-overflow
  - READ of size 200
  - `memcmp -> wolfSSL_select_next_proto`
  - source: `src/ssl.c:22298`
- Fixed/current behavior:
  - `wolfSSL_select_next_proto returned: 2`
  - cleanup done
  - `NO_ASAN_CRASH_OBSERVED`

### RAG Keywords

`wolfSSL_select_next_proto`, `ALPN`, `NPN`, `protocol list`, `length-prefixed protocol`, `memcmp`, `XMEMCMP`, `serverLen`, `clientLen`, `HAVE_ALPN`, `OPENSSL_ALL`, `src/ssl.c`
