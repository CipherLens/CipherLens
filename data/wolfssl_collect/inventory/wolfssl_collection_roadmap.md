# wolfSSL Collection Roadmap

## Completed Batch

### Batch v1: X.509 / ASN.1 Memory Safety Patterns

Completed PoCs:

- WOLFSSL-POC-0001
- WOLFSSL-POC-0002
- WOLFSSL-POC-0003
- WOLFSSL-POC-0004

Status:

- Total Q1 samples: 4
- Vulnerable-version verified: 4
- Fixed-version verified: 4
- Current-version verified: 4
- Pattern prompt JSONL: complete
- Code localization JSONL: complete

## Next Batch Goal

### Batch v2: Diversity-Oriented wolfSSL PoCs

Goal:

Collect 4 to 6 additional high-quality wolfSSL PoCs with bug types different from the current X.509-focused batch.

## Preferred Target Categories

| Priority | Category | Desired Pattern |
|---|---|---|
| P1 | PEM / DER / Base64 parsing | decoded length mismatch, malformed boundary, parser cleanup bug |
| P1 | TLS / DTLS record or handshake parsing | extension length confusion, fragmented record boundary issue |
| P2 | PKCS#12 / PKCS#7 | nested ASN.1 object length confusion, bag/cert/key parsing bug |
| P2 | Key parsing | RSA/ECC/Ed25519 key decode length or field validation issue |
| P3 | Error cleanup path | double free, use-after-free, cleanup-after-partial-parse |
| P3 | Crypto API buffer handling | output buffer size mismatch, tag length mismatch, padding boundary |

## PoC Quality Requirements

A new PoC should preferably satisfy:

- Has public source: CVE, GitHub issue, PR, advisory, or commit
- Has original input or reconstructable input
- Reproduces on a vulnerable version
- Has sanitizer crash or clear oracle
- Has fixed release or fixed commit candidate
- Current version tested
- Can be abstracted into a reusable vulnerability pattern
- Can be added to recipe JSON and JSONL datasets

## Quality Levels

- Q1_strict_reproduction_candidate:
  - vulnerable, fixed, and current versions verified
  - concrete input or reconstructed input
  - clear sanitizer or safe-rejection evidence

- Q2_partial_reproduction_candidate:
  - vulnerable version verified
  - fixed/current validation incomplete

- Q3_reference_only:
  - useful for pattern discovery
  - not yet reproducible

## Next Planned IDs

- WOLFSSL-POC-0005: target non-X.509 parser bug
- WOLFSSL-POC-0006: target TLS/DTLS parser or state-machine bug
- WOLFSSL-POC-0007: target PKCS#12/PKCS#7 or key parsing bug
- WOLFSSL-POC-0008: target cleanup path / memory lifecycle bug

## Long-Term Direction

After wolfSSL Batch v2, start cross-library migration:

- mbedTLS
- OpenSSL
- LibreSSL
- Botan
- GnuTLS
- BearSSL

The goal is to build a cross-library cryptographic vulnerability pattern dataset for AST masking, RAG, and fuzz-guided discovery.
