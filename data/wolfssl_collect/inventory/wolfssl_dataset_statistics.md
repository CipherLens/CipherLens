# wolfSSL Dataset Statistics

## Overall Counts

| Metric | Count |
|---|---:|
| Q1 strict reproduction PoCs | 10 |
| Vulnerability patterns | 10 |
| Pattern prompt eval rows | 10 |
| Code localization eval rows | 10 |
| Rejected candidates | 1 |

## PoC to Pattern Mapping

| PoC ID | Pattern ID | Family |
|---|---|---|
| WOLFSSL-POC-0001 | Pattern-01 | X.509 name parser |
| WOLFSSL-POC-0002 | Pattern-02 | X.509 text extraction |
| WOLFSSL-POC-0003 | Pattern-03 | ASN1_TIME setter/getter |
| WOLFSSL-POC-0004 | Pattern-04 | X.509 AuthorityKeyIdentifier |
| WOLFSSL-POC-0005 | Pattern-05 | DTLS 1.3 ACK serialization |
| WOLFSSL-POC-0006 | Pattern-06 | PKCS7 SignedData attributes |
| WOLFSSL-POC-0007 | Pattern-07 | PKCS7 ORI OID parsing |
| WOLFSSL-POC-0008 | Pattern-08 | TLS 1.3 PQC KeyShare cleanup |
| WOLFSSL-POC-0009 | Pattern-09 | SSL_SESSION deserialization |
| WOLFSSL-POC-0010 | Pattern-10 | ALPN protocol-list parsing |

## Family Distribution

| Family | Count |
|---|---:|
| X.509 / ASN.1 | 4 |
| DTLS 1.3 | 1 |
| PKCS7 / CMS | 2 |
| TLS 1.3 PQC cleanup | 1 |
| SSL_SESSION deserialization | 1 |
| ALPN / NPN parsing | 1 |

## Dataset Files

| Dataset | Rows |
|---|---:|
| data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl | 10 |
| data/jsonl/wolfssl_code_localization_eval_v1.jsonl | 10 |
