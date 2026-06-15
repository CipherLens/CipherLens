# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-08
- Name: TLS 1.3 PQC hybrid KeyShare cleanup UAF / double-free
- Related PoC: WOLFSSL-POC-0008
- Trigger surface: tls13_pqc_hybrid_keyshare_processing
- Input type: malicious_tls13_serverhello_truncated_pqc_hybrid_keyshare
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

A truncated TLS 1.3 PQC hybrid KeyShare triggers an error cleanup path that leaves a KeyShare entry pointing to already-freed key material.

Trust boundary:

malicious TLS 1.3 ServerHello KeyShare extension -> client-side hybrid KeyShare ownership and cleanup state

Vulnerable operation:

cleanup frees or wipes key material through TLSX_KeyShare_FreeAll after the same key material was already released during hybrid KeyShare processing

Failure modes:

heap_use_after_free, double_free, cleanup_path_ownership_error, sanitizer_visible_crash

## Recipe Slots

- hybrid_group: selects PQC hybrid KeyShare processing path | observed: WOLFSSL_SECP256R1MLKEM768
- key_exchange_length: controls length of server key_exchange bytes | observed: 10 | mutation: truncate key_exchange far below expected hybrid key share length
- expected_keyshare_size: expected ECC plus ML-KEM hybrid key share size | observed: 1120+ bytes for SECP256R1MLKEM768-like hybrid key share
- ownership_transfer: tracks key object ownership between temporary ECC/PQC split entries and final hybrid keyShareEntry
- cleanup_path: later cleanup path that revisits key material
- processing_path: path that processes truncated hybrid key share and creates stale ownership state
- fixed_pointer_sanitization: fixed-version action to detach transferred key pointers before cleanup | observed: set transferred key pointers to NULL before TLSX_KeyShare_FreeAll

## Mutation Strategy

- Enable TLS 1.3, ECC, ML-KEM, and PQC hybrid support.
- Create a TLS 1.3 client and offer WOLFSSL_SECP256R1MLKEM768 as a KeyShare.
- Inject a malicious ServerHello containing a key_share extension for the same hybrid group.
- Set key_exchange length to 10 bytes instead of the expected full hybrid key share length.
- Run wolfSSL_connect_TLSv13 and allow it to fail during KeyShare processing.
- Call wolfSSL_free to trigger cleanup of TLS extensions and KeyShare entries.
- Observe whether cleanup touches already-freed key material.

## Oracle

Primary oracle: asan_heap_use_after_free

Signals:

- ERROR: AddressSanitizer: heap-use-after-free
- WRITE of size 8
- crash in ForceZero
- crash path includes TLSX_KeyShare_FreeAll, TLSX_FreeAll, and wolfSSL_free
- earlier free path includes TLSX_KeyShare_ProcessPqcHybridClient

Fixed behavior:

- wolfSSL_UseKeyShare returns 1
- wolfSSL_connect_TLSv13 returns -1
- wolfSSL_free completes
- cleanup completes
- NO_ASAN_CRASH_OBSERVED

## AST Masking Targets

- PQC hybrid KeyShare split/merge ownership transfer
- temporary KeyShareEntry cleanup
- missing pointer nulling after ownership transfer
- TLSX_KeyShare_FreeAll cleanup of key objects
- error path after truncated ServerHello KeyShare

## RAG Keywords

wolfSSL_connect_TLSv13, wolfSSL_UseKeyShare, wolfSSL_free, TLSX_KeyShare_ProcessPqcHybridClient, TLSX_KeyShare_FreeAll, TLSX_FreeAll, ForceZero, WOLFSSL_SECP256R1MLKEM768, WOLFSSL_PQC_HYBRIDS, WOLFSSL_HAVE_MLKEM, ML-KEM, KyberKey, MlKemKey, truncated KeyShare, ServerHello, key_exchange, ecc_kse, pqc_kse, keyShareEntry

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
