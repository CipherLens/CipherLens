# secure_heap_state_lifecycle_pattern_expansion_v1

## Positioning

This sprint moved `OPENSSL-ISSUE-28669` from seed validation into same-family pattern expansion. It did not rerun the old sprint directory and did not attempt to prove a CVE.

Execution path:

```text
D-path seed validation -> B-path same-family state expansion
```

## Evidence

RAG was used as evidence. The initial sandbox run failed because local Ollama embedding returned `Operation not permitted`; the approved escalated rerun succeeded. After updating pattern notes, `knowledge.rag_builder` rebuilt the index successfully, and the validation query recalled `OPENSSL-ISSUE-28669` plus the new pattern expansion note.

AST/mask was preserved through:

```text
mask/mask_report.yaml
mask/selected_mask_units.yaml
```

The selected slots cover lifecycle init/query/alloc/free/done APIs, state sequence, expected control, crash oracle, and novelty classifier.

GLM was not used. The reason is that the existing helper is A-path adapter-oriented, while this sprint is B-path same-family mutation expansion. No `_llm_status: ok` is claimed.

## API And State Expansion

APIs tested:

- `CRYPTO_secure_used`
- `CRYPTO_secure_malloc_initialized`
- `CRYPTO_secure_allocated`
- `OPENSSL_secure_malloc`
- `OPENSSL_secure_zalloc`
- `OPENSSL_secure_free`
- `CRYPTO_secure_malloc_done`
- `CRYPTO_secure_malloc_init`

State sequences tested:

- `pre_init_query`
- `initialized_query`
- `done_then_query`
- `done_twice`
- `reinit_after_done`
- `done_then_alloc`
- `done_then_free`
- `alloc_then_done_then_free`
- `init_failed_then_query`
- `initialized_alloc_free_control`

## Run Results

```text
total_cases: 19
raw_status_counts: {'run_ok': 16, 'run_nonzero': 3}
verdict_counts: {'normal_defined_behavior': 16, 'crash_candidate': 3}
novelty_counts: {'non_novel_seed_reproduction': 2, 'normal_defined_behavior': 16, 'new_state_combination_candidate': 1}
```

The two seed reproductions are:

- `secure_heap_exp_0000_seed_pre_init_used`
- `secure_heap_exp_0002_seed_done_then_used`

The non-seed candidate is:

- `secure_heap_exp_0003_new_state_init_failed_then_used`

This case uses `CRYPTO_secure_used` after a failed init attempt and produced `SIGSEGV` / exit `139`. It is a `new_state_combination_candidate` and current-version robustness candidate, not a confirmed vulnerability.

No new API crash candidate was observed. Other tested secure heap APIs returned normal defined behavior under the tested states. No harness error was observed.

## Version Matrix

Only `${CLEAN_SOURCES_ROOT}/openssl-3.5.5` was available locally. The version matrix is therefore `limited_single_version`; no regression candidate can be claimed.

## Claim Boundary

This sprint cannot be called a confirmed vulnerability or CVE. API contract status and multi-version affected/fixed boundaries still need confirmation.

## Next Step

The immediate next step is secure heap version and contract confirmation. After that, the best next families are:

1. `cipher_aead_lifecycle`
2. `asn1_nested_boundary`
3. `pkey_verify_semantic`
