# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-03
- Name: ASN1_TIME length trust boundary error
- Related PoC: WOLFSSL-POC-0003
- Trigger surface: x509_time_setter_getter_api
- Input type: crafted_WOLFSSL_ASN1_TIME_object
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

An oversized ASN1_TIME declared length is accepted or stored, and later trusted by an accessor or serializer that writes into a smaller internal buffer.

Trust boundary:

ASN1_TIME type/length/data object -> internal X.509 date buffer

Vulnerable operation:

copy or serialize using untrusted stored length

Failure modes:

heap_buffer_overflow, oversized_memcpy, invalid_length_trust

## Recipe Slots

- time_object_type: ASN.1 time tag | observed: ASN_UTC_TIME
- declared_time_length: length stored in ASN1_TIME | observed: 255
- actual_data_capacity: actual capacity of internal date data buffer
- target_date_field: selected X.509 validity field
- accessor_path: API that serializes or returns raw date data

## Mutation Strategy

- Create an X.509 object.
- Create a crafted ASN1_TIME object.
- Set a valid time type such as UTC time.
- Set an oversized declared length.
- Call notBefore or notAfter setter.
- Call notBefore or notAfter accessor.
- Compare vulnerable crash with fixed safe rejection.

## Oracle

Primary oracle: asan_heap_buffer_overflow

Signals:

- heap-buffer-overflow
- WRITE of oversized date length
- crash in notBefore or notAfter path

Fixed behavior:

- setter rejects oversized length
- accessor refuses invalid internal length
- harness exits nonzero without sanitizer crash

## AST Masking Targets

- setter storing length without capacity check
- getter trusting stored length
- copy into fixed-size date buffer
- bounds check added around ASN1_TIME length

## RAG Keywords

wolfSSL_X509_set_notAfter, wolfSSL_X509_notAfter, wolfSSL_X509_set_notBefore, wolfSSL_X509_notBefore, WOLFSSL_ASN1_TIME, ASN_UTC_TIME, CTC_DATE_SIZE, notAfterData, notBeforeData

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
