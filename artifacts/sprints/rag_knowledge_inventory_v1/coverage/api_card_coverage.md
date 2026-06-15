# API card coverage

| library | count | examples |
| --- | --- | --- |
| openssl | 14 | BN_bn2binpad.yaml, BN_usub.yaml, EVP_DigestVerify.yaml, EVP_DigestVerifyInit.yaml, EVP_MAC_CTX_get_mac_size.yaml |
| mbedtls | 3 | mbedtls_pk_verify.yaml, psa_mac_sign_finish.yaml, psa_verify_hash.yaml |
| wolfssl | 0 |  |
| botan | 0 |  |

| signal | value |
| --- | --- |
| has_wolfssl_api_cards | False |
| missing_or_sparse_libraries | ['wolfssl', 'botan'] |
| top_family_gaps | {'asn1': True, 'pkcs7': True, 'pkcs12': True, 'secure_heap': True} |
