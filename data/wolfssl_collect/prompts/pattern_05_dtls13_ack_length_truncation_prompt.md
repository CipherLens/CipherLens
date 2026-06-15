# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-05
- Name: DTLS 1.3 ACK record count / 16-bit length truncation overflow
- Related PoC: WOLFSSL-POC-0005
- Trigger surface: dtls13_ack_record_serialization
- Input type: reconstructed_dtls13_ack_record_stress_pattern
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

The vulnerable implementation counts an unbounded DTLS 1.3 ACK record linked list and stores the computed serialized ACK list length into a 16-bit length field. The truncated length is used for output buffer sizing, while the serialization loop still writes every record in the full linked list.

Trust boundary:

DTLS 1.3 ACK/retransmission record tracking state -> ACK message serialization buffer

Vulnerable operation:

unbounded linked-list serialization after 16-bit length truncation

Failure modes:

out_of_bounds_heap_write, length_truncation, record_count_overflow, sanitizer_visible_crash

## Recipe Slots

- ack_record_count: controls the number of ACK records serialized | observed: 4097 | mutation: increase ACK record insertions beyond the 16-bit encoded length boundary
- record_number_encoding_size: bytes written per ACK record during serialization | observed: 16
- encoded_length_type: narrow integer type used to store the computed ACK list byte length | observed: word16
- truncated_length_expression: computed length that can wrap or truncate before buffer sizing | observed: (word16)(DTLS13_RN_SIZE * numberElements)
- serialization_loop: writes all ACK records from the linked list regardless of truncated length | observed: while (recordNumberList != NULL)
- output_buffer_path: buffer sizing and output buffer retrieval path
- fixed_record_bound: maximum ACK records allowed in fixed versions | observed: 128

## Mutation Strategy

- Create or reuse a DTLS 1.3 client/server context.
- Complete a DTLS 1.3 handshake so that ACK message serialization state is initialized.
- Insert many ACK records through the retransmission ACK tracking path.
- Use a record count that exceeds the maximum encodable 16-bit ACK list length.
- Trigger ACK message serialization through Dtls13WriteAckMessage or an equivalent ACK send path.
- Compare vulnerable, fixed, and current behavior under the same ACK record stress pattern.

## Oracle

Primary oracle: asan_out_of_bounds_heap_write

Signals:

- ERROR: AddressSanitizer
- unknown-crash or heap-buffer-overflow
- WRITE of size 8
- c64toa
- Dtls13WriteAckMessage
- 0 bytes after heap region
- exit code 134

Fixed behavior:

- seenRecordsCount is bounded
- Dtls13WriteAckMessage returns 0
- encoded ACK length remains bounded
- exit code 0
- no ASan crash

## AST Masking Targets

- unbounded linked-list count used for message length
- integer narrowing from record count expression to word16
- buffer size check using truncated length
- serialization loop over full list
- missing maximum record-count guard before insertion
- protocol ACK / retransmission record serializer

## RAG Keywords

Dtls13WriteAckMessage, Dtls13RtxAddAck, DTLS13_RN_SIZE, DTLS13_ACK_MAX_RECORDS, seenRecords, seenRecordsCount, ACK records, word16, c16toa, c64toa, CheckAvailableSize, GetOutputBuffer, DTLS 1.3 ACK

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
