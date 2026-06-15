# RAG enrichment plan after inventory

| step | task | action |
| --- | --- | --- |
| 1 | rag_enrichment_from_ingestion_v1 | Import only high-confidence structured PoC summaries. |
| 2 | api_card_enrichment_for_top_families_v1 | Add wolfSSL / TLS / DTLS / ASN.1 / PKCS7 / PKCS12 / X509 API cards. |
| 3 | api_correlation_inventory_v1 | Extract API correlation from corrected candidates and PoC call sequences. |
| 4 | rag_rebuild_and_query_eval_v1 | Rebuild and evaluate whether queries retrieve correct evidence. |
| 5 | template_schema_inventory_v1 | Inventory template schemas before template generation. |

## principles

- Do not import all raw PoCs, raw HTML, or raw logs.
- Import structured summaries only.
- Mark placeholder, synthetic, and source-vector seed provenance.
- Import negative feedback as down-ranking evidence.
- RAG supports gates and adapters; it does not replace analyzers.
