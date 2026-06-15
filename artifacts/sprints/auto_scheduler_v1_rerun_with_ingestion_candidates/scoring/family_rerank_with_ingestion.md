# family rerank with ingestion

| rank | family | count | high | medium | avg | max | suspicious | next_action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | pkcs_container_parsing | 2 | 0 | 2 | 29.0 | 30 | False | template_generalizer_v1 |
| 2 | x509_parsing | 1 | 0 | 1 | 28.0 | 28 | False | template_generalizer_v1 |
| 3 | tls_protocol_state_lifecycle | 10 | 0 | 10 | 25.0 | 28 | False | template_generalizer_v1 |
| 4 | cipher_aead_lifecycle | 1 | 1 | 0 | 27.0 | 27 | False | template_generalizer_v1 |
| 5 | secure_heap_state_lifecycle | 2 | 2 | 0 | 27.0 | 27 | False | template_generalizer_v1 |
| 6 | mac_lifecycle | 1 | 1 | 0 | 25.0 | 25 | False | template_generalizer_v1 |
| 7 | cipher_padding_output_length | 2 | 0 | 2 | 24.0 | 24 | False | template_generalizer_v1 |
| 8 | bignum_serialization_boundary | 21 | 18 | 3 | 16.24 | 19 | True | historical_poc_ingestion_rules_refinement_v1 |
