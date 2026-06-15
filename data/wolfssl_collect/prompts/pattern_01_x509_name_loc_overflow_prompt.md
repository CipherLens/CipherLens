# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-01
- Name: X.509 name field repetition / loc array overflow
- Related PoC: WOLFSSL-POC-0001
- Trigger surface: x509_name_parser
- Input type: malformed_x509_certificate
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

Repeated or unusually structured X.509 name fields cause the parser to record more name locations than a fixed-size internal array can safely hold.

Trust boundary:

ASN.1 encoded certificate name fields -> parser-internal fixed-size location array

Vulnerable operation:

fixed-size array write indexed by parsed name-field count

Failure modes:

out_of_bounds_write, corrupted_parse_state, sanitizer_visible_crash

## Recipe Slots

- name_sequence_count: controls the number of parsed name elements | mutation: increase RDN / AttributeTypeAndValue count
- name_field_type: selects name OID stored by parser
- nesting_shape: controls SET / SEQUENCE nesting | mutation: duplicate nested name structures
- parser_state_capacity: internal fixed array capacity to exceed
- terminal_malformed_length: optional malformed terminal length | mutation: truncate final field or overstate length

## Mutation Strategy

- Start from a valid or semi-valid X.509 certificate.
- Locate subject or issuer Name.
- Repeat one or more AttributeTypeAndValue entries.
- Prefer fields stored in an internal location table.
- Increase repetition until the parser exceeds its expected internal field count.
- Optionally add malformed terminal length to force error cleanup paths.

## Oracle

Primary oracle: sanitizer_crash

Signals:

- AddressSanitizer error
- out-of-bounds write
- heap-buffer-overflow
- different vulnerable/fixed/current behavior

Fixed behavior:

- safe rejection
- bounded name-field count
- no sanitizer crash

## AST Masking Targets

- fixed-size array write indexed by count
- name-field parser loop
- missing upper-bound check before count increment
- error cleanup after malformed ASN.1 name

## RAG Keywords

GetName, DecodedName, loc, locSz, subject name, issuer name, RDN, AttributeTypeAndValue, ASN.1 name parser

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
