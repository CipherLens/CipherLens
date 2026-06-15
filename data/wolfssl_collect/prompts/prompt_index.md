# wolfSSL Pattern Prompt Index

| Pattern ID | Related PoC | Prompt File | Theme |
|---|---|---|---|
| Pattern-01 | WOLFSSL-POC-0001 | prompts/pattern_01_x509_name_loc_overflow_prompt.md | X.509 name field repetition / loc array overflow |
| Pattern-02 | WOLFSSL-POC-0002 | prompts/pattern_02_x509_text_off_by_one_prompt.md | X.509 text field fixed-size buffer off-by-one |
| Pattern-03 | WOLFSSL-POC-0003 | prompts/pattern_03_asn1_time_length_prompt.md | ASN1_TIME length trust boundary error |
| Pattern-04 | WOLFSSL-POC-0004 | prompts/pattern_04_akid_length_confusion_prompt.md | AuthorityKeyIdentifier subfield/full-extension length confusion |
| Pattern-05 | WOLFSSL-POC-0005 | prompts/pattern_05_dtls13_ack_length_truncation_prompt.md | DTLS 1.3 ACK record count / 16-bit length truncation overflow |
| Pattern-06 | WOLFSSL-POC-0006 | prompts/pattern_06_pkcs7_signedattrs_array_overflow_prompt.md | PKCS7 custom signed attributes / fixed attribute array overflow |
| Pattern-07 | WOLFSSL-POC-0007 | prompts/pattern_07_pkcs7_ori_oid_stack_overflow_prompt.md | PKCS7 ORI OID / fixed stack OID buffer overflow |
| Pattern-08 | WOLFSSL-POC-0008 | prompts/pattern_08_tls13_pqc_keyshare_cleanup_uaf_prompt.md | TLS 1.3 PQC hybrid KeyShare cleanup UAF / double-free |
| Pattern-09 | WOLFSSL-POC-0009 | prompts/pattern_09_ssl_session_chain_count_overflow_prompt.md | SSL_SESSION deserialization chain.count fixed array overflow |
| Pattern-10 | WOLFSSL-POC-0010 | prompts/pattern_10_alpn_protocol_list_overread_prompt.md | ALPN protocol list length over-read |

## Usage

These prompts are generated from machine-readable recipe definitions in:

- inventory/wolfssl_pattern_recipes.json

They are intended for:

- LLM/RAG vulnerability pattern search
- AST masking experiment prompt construction
- structured mutation planning
- fuzz seed selection
