# PoC pattern / feedback coverage

| metric | value |
| --- | --- |
| pattern_files | 29 |
| known_families | 80 |
| feedback_files | 16 |
| missing_families | ['bignum_arithmetic_precondition', 'bignum_serialization_boundary', 'cipher_padding_output_length', 'mac_lifecycle', 'pkcs_container_parsing', 'secure_heap_state_lifecycle', 'tls_protocol_state_lifecycle'] |
| needs_ingestion_snippet_import | True |

## top family pattern coverage

| family | covered |
| --- | --- |
| tls_protocol_state_lifecycle | False |
| asn1_nested_boundary | True |
| pkcs_container_parsing | False |
| x509_parsing | True |
