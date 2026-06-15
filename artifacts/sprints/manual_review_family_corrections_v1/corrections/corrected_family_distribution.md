# corrected family distribution

| family | count |
| --- | --- |
| tls_protocol_state_lifecycle | 13 |
| asn1_nested_boundary | 11 |
| pkcs_container_parsing | 8 |
| bignum_serialization_boundary | 4 |
| x509_parsing | 4 |
| cipher_padding_output_length | 2 |
| cipher_aead_lifecycle | 2 |
| secure_heap_state_lifecycle | 2 |
| needs_review | 2 |
| bignum_arithmetic_precondition | 1 |
| mac_lifecycle | 1 |

## answers

| question | answer |
| --- | --- |
| bignum_serialization_boundary 是否仍然异常集中 | False |
| pkcs_container_parsing 是否仍然 top | False |
| x509/asn1 count | 15 |
| tls count | 13 |
| secure_heap count | 2 |
| mac count | 1 |
| aead count | 2 |
| 是否还需要 ingestion rules refinement | False |
