# RAG tooling inventory

| builder layer | supported |
| --- | --- |
| api_constraints | True |
| unit_tests | True |
| poc_patterns | True |
| cross_lib_equivalence | True |
| wycheproof_vectors | True |
| api_cards | True |

## query flags

| flag | supported |
| --- | --- |
| --query | True |
| --top-k | True |
| --json | True |

## collectors

| field | value |
| --- | --- |
| exists | True |
| needs_new_collector | False |
| recommendation | Current builder can index files written under configured knowledge_raw layers; collector is optional unless automated source harvesting is needed. |
