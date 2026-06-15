# RAG Source Integration Check

```yaml
api_knowledge_cards_indexed:
  before: false
  evidence: config/rag_config.yaml previously lacked raw_dirs.api_knowledge_cards;
    rag_builder load_api_cards_layer only read knowledge_base/api_cards.
api_constraints_indexed:
  before: true
cross_lib_equivalence_indexed:
  before: true
source_integration_needed: true
```
