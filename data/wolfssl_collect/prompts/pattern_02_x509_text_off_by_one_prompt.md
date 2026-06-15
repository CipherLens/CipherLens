# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-02
- Name: X.509 text field fixed-size buffer off-by-one
- Related PoC: WOLFSSL-POC-0002
- Trigger surface: openssl_compat_x509_text_extraction
- Input type: reconstructed_x509_certificate
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

A text extraction API copies an X.509 text field into a caller-provided fixed-size buffer and appends a terminator without correctly accounting for the terminator position.

Trust boundary:

certificate text field length -> caller-provided output buffer

Vulnerable operation:

string copy followed by terminator write

Failure modes:

stack_buffer_overflow, off_by_one_write, out_of_bounds_null_termination

## Recipe Slots

- target_text_field: selected X.509 text field | observed: localityName
- output_buffer_size: caller-provided buffer size | observed: 80
- field_text_length: length of certificate text field | mutation: set equal to output_buffer_size or output_buffer_size - 1
- terminator_policy: whether API appends a string terminator | mutation: force terminator write at boundary
- nid_selector: OpenSSL-compatible NID used to select field | observed: NID_localityName

## Mutation Strategy

- Build or modify an X.509 certificate subject field.
- Select a text field consumed by get_text_by_NID-style APIs.
- Set field length equal to the expected output buffer size.
- Use a harness that provides a fixed-size stack buffer.
- Call the text extraction API.
- Detect whether the implementation writes a terminator out of bounds.

## Oracle

Primary oracle: asan_stack_buffer_overflow

Signals:

- WRITE of size 1
- stack-buffer-overflow
- overflow immediately after fixed-size stack buffer

Fixed behavior:

- safe truncation
- safe rejection
- no sanitizer crash

## AST Masking Targets

- copy into caller-provided buffer
- manual null terminator write
- condition using len without len - 1
- OpenSSL compatibility text extraction wrapper

## RAG Keywords

wolfSSL_X509_NAME_get_text_by_NID, X509_NAME_get_text_by_NID, NID_localityName, localityName, textSz, buffer length, null terminator

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
