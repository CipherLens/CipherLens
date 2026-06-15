# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-10
- Name: ALPN protocol list length over-read
- Related PoC: WOLFSSL-POC-0010
- Trigger surface: alpn_protocol_selection
- Input type: malformed_length_prefixed_alpn_protocol_lists
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

A length byte from a length-prefixed ALPN/NPN protocol list is trusted before validating that the declared protocol length fits within the provided buffer.

Trust boundary:

external ALPN/NPN protocol list buffer -> wolfSSL_select_next_proto protocol comparison loop

Vulnerable operation:

wolfSSL_select_next_proto calls memcmp/XMEMCMP using an attacker-controlled protocol length that exceeds the actual heap buffer size

Failure modes:

heap_buffer_over_read, length_prefixed_protocol_parser_error, out_of_bounds_read, sanitizer_visible_crash

## Recipe Slots

- server_protocol_length:  | observed: 200 | mutation: set server protocol length byte larger than actual server protocol buffer
- client_protocol_length:  | observed: 200 | mutation: set client protocol length byte larger than actual client protocol buffer
- actual_buffer_size: actual heap allocation size for each malformed protocol list | observed: 5
- comparison_length:  | observed: protocol length byte used as memcmp length
- comparison_operation:  | observed: memcmp / XMEMCMP
- api_entrypoint: 
- fixed_guard:  | observed: validate declared protocol length against remaining input length before comparison

## Mutation Strategy

- Build wolfSSL with ALPN and OpenSSL compatibility APIs enabled.
- Allocate small heap buffers for server and client protocol lists.
- Set the first byte of each list to a large protocol length such as 200.
- Provide only a few actual payload bytes after the length byte.
- Call wolfSSL_select_next_proto.
- Observe whether the parser validates length fields before calling memcmp/XMEMCMP.

## Oracle

Primary oracle: asan_heap_buffer_overflow_read

Signals:

- ERROR: AddressSanitizer: heap-buffer-overflow
- READ of size 200
- memcmp / XMEMCMP
- wolfSSL_select_next_proto
- src/ssl.c:22298

Fixed behavior:

- wolfSSL_select_next_proto returns safely
- cleanup completes
- NO_ASAN_CRASH_OBSERVED

## AST Masking Targets

- protocol list length-byte read
- remaining-buffer length check
- nested protocol-list iteration
- memcmp/XMEMCMP length argument
- fixed-version malformed-list rejection

## RAG Keywords

wolfSSL_select_next_proto, ALPN, NPN, protocol list, length-prefixed protocol, memcmp, XMEMCMP, serverLen, clientLen, HAVE_ALPN, OPENSSL_ALL, src/ssl.c

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
