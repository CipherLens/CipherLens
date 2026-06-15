# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-06
- Name: PKCS7 custom signed attributes / fixed attribute array overflow
- Related PoC: WOLFSSL-POC-0006
- Trigger surface: pkcs7_signeddata_attribute_encoding
- Input type: crafted_pkcs7_signeddata_encoding_request
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

Caller-controlled custom signed attributes exceed the capacity of a fixed internal PKCS7 SignedData signed attribute array.

Trust boundary:

caller-supplied PKCS7Attrib array and signedAttribsSz -> ESD fixed signedAttribs array

Vulnerable operation:

EncodeAttributes writes custom attributes into esd->signedAttribs without validating remaining fixed-array capacity

Failure modes:

stack_buffer_overflow, out_of_bounds_write, fixed_array_capacity_overflow, sanitizer_visible_crash

## Recipe Slots

- custom_attribute_count: controls number of caller-supplied custom signed attributes | observed: 8 | mutation: increase pkcs7->signedAttribsSz above the fixed internal attribute capacity
- internal_attribute_capacity: maximum internal signed attribute descriptor slots | observed: signedAttribs[7] / MAX_SIGNED_ATTRIBS_SZ
- existing_attribute_index: current insertion index after default/canned attributes | observed: atrIdx
- remaining_capacity: fixed-version capacity check before custom attribute encoding | observed: MAX_SIGNED_ATTRIBS_SZ - atrIdx
- destination_array: internal encoded attribute destination | observed: esd->signedAttribs
- encoder_function: writes encoded attribute descriptors into destination array | observed: EncodeAttributes
- api_entrypoint: public API path that triggers signed attribute construction

## Mutation Strategy

- Create a valid PKCS7 SignedData encoding request.
- Initialize signing certificate and private key material.
- Provide a custom PKCS7Attrib array.
- Set signedAttribsSz above the internal signed attribute slot capacity.
- Call wc_PKCS7_EncodeSignedData or wc_PKCS7_EncodeSignedData_ex.
- Observe whether custom attributes are rejected before EncodeAttributes writes into the fixed array.

## Oracle

Primary oracle: asan_stack_buffer_overflow

Signals:

- ERROR: AddressSanitizer: stack-buffer-overflow
- WRITE of size 8
- crash in EncodeAttributes
- crash path includes wc_PKCS7_BuildSignedAttributes and wc_PKCS7_EncodeSignedData

Fixed behavior:

- wc_PKCS7_EncodeSignedData returns -132
- safe rejection
- NO_ASAN_CRASH_OBSERVED
- no sanitizer crash

## AST Masking Targets

- fixed-size signed attribute array
- custom attribute count addition
- EncodeAttributes call using caller-controlled count
- missing remaining-capacity check before fixed-array write
- availableSpace / BUFFER_E guard in fixed version

## RAG Keywords

wc_PKCS7_EncodeSignedData, wc_PKCS7_EncodeSignedData_ex, wc_PKCS7_BuildSignedAttributes, EncodeAttributes, PKCS7Attrib, signedAttribs, signedAttribsSz, signedAttribsCount, MAX_SIGNED_ATTRIBS_SZ, availableSpace, BUFFER_E

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
