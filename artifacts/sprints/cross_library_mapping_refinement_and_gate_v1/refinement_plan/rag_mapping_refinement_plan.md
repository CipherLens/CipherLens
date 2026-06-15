# Report

```yaml
known_weaknesses:
- wc_ParseCert recall weak in X509/ASN1 query
- no_direct_counterpart label recall weak
recommended_actions:
- add alias/keyword summary for wc_ParseCert / DecodedCert / X509 ASN1 parse
- add explicit no_direct_counterpart summary for mbedTLS PKCS7/PKCS12
- keep these as backlog unless template adapter stage requires them
recommended_next_task_if_needed:
- rag_alias_and_negative_mapping_refinement_v1
```
