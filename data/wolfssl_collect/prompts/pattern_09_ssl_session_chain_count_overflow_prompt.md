# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-09
- Name: SSL_SESSION deserialization chain.count fixed array overflow
- Related PoC: WOLFSSL-POC-0009
- Trigger surface: ssl_session_deserialization
- Input type: mutated_serialized_ssl_session_chain_count
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

A deserialized SESSION_CERTS chain.count value is trusted and used to index a fixed certificate-chain array without validating it against MAX_CHAIN_DEPTH.

Trust boundary:

external serialized SSL_SESSION data -> wolfSSL_d2i_SSL_SESSION internal certificate-chain state

Vulnerable operation:

wolfSSL_d2i_SSL_SESSION iterates over untrusted chain.count and writes past the fixed x509_buffer array

Failure modes:

heap_buffer_overflow, fixed_array_capacity_overflow, deserialized_count_trust_boundary_error, sanitizer_visible_crash

## Recipe Slots

- serialized_session_source:  | observed: wolfSSL_i2d_SSL_SESSION
- chain_count:  | observed: 255 | mutation: mutate SESSION_CERTS chain.count byte to 0xff
- destination_capacity:  | observed: MAX_CHAIN_DEPTH / x509_buffer[9]
- destination_array:  | observed: x509_buffer certificate chain array
- api_entrypoint: 
- fixed_guard:  | observed: chain.count > MAX_CHAIN_DEPTH

## Mutation Strategy

- Create a valid WOLFSSL_SESSION object.
- Serialize it using wolfSSL_i2d_SSL_SESSION.
- Compute the SESSION_CERTS chain.count offset.
- Mutate chain.count to 0xff.
- Call wolfSSL_d2i_SSL_SESSION on the mutated serialized session.
- Observe whether the deserializer rejects the count before writing into the fixed certificate-chain array.

## Oracle

Primary oracle: asan_heap_buffer_overflow

Signals:

- ERROR: AddressSanitizer: heap-buffer-overflow
- WRITE of size 4
- crash in wolfSSL_d2i_SSL_SESSION
- src/ssl_sess.c:2831
- UBSan index 9 out of bounds for x509_buffer[9]

Fixed behavior:

- wolfSSL_d2i_SSL_SESSION returns NULL
- cleanup completes
- NO_ASAN_CRASH_OBSERVED

## AST Masking Targets

- deserialized chain.count read
- loop over certificate-chain count
- fixed x509_buffer certificate-chain array
- missing MAX_CHAIN_DEPTH bounds check
- fixed-version chain.count validation

## RAG Keywords

wolfSSL_d2i_SSL_SESSION, wolfSSL_i2d_SSL_SESSION, SSL_SESSION, SESSION_CERTS, chain.count, MAX_CHAIN_DEPTH, x509_buffer, sessionIDSz, altIDLen, src/ssl_sess.c, serialized session

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
