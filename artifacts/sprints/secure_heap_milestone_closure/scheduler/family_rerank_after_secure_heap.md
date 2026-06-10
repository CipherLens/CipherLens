# Family Rerank After secure_heap Closure

## Recommendation

```text
recommended_next_family: cipher_aead_lifecycle
proposed_execution_path: B_controlled_family_mutation
fallback_path: D_then_A
```

`secure_heap_state_lifecycle` is closed for the main exploration track and moves
to external validation. It should not remain top-1 unless the task is explicitly
ASAN/UBSAN, multi-version, or API contract validation.

## Ranking

| Family | Score | Recommended Path | Rationale |
| --- | ---: | --- | --- |
| `cipher_aead_lifecycle` | 0.76 | `B_controlled_family_mutation` | Lifecycle/state-machine experience transfers well; likely init/update/final/free/reuse semantics; can later move to A-path if cross-library API mapping is strong. |
| `mac_lifecycle` | 0.66 | `D_then_A` | Runnable artifacts and API-card work exist, but needs tighter caller-impact or semantic-oracle framing. |
| `asn1_nested_boundary` | 0.62 | `A_recipe_slot_cross_library_migration` | Useful boundary family, but prior safe/safe evidence lowers immediate novelty. |
| `der_full_consumption` | 0.61 | `C_app_level_validation_gap` | Strong semantic gap framing, better as app-level validation-gap follow-up. |
| `x509_parsing` | 0.54 | `A_recipe_slot_cross_library_migration` | Needs sharper triage and oracle selection. |
| `pkey_verify_semantic` | 0.52 | `A_recipe_slot_cross_library_migration` | Stable safe-negative baseline; lower immediate novelty. |
| `secure_heap_state_lifecycle` | 0.35 | `D_crash_sanitizer_evidence_audit` | Main milestone closed; remaining work is external validation. |

## Score Dimensions

- `readiness_score`
- `severity_score`
- `novelty_potential`
- `migration_potential`
- `oracle_quality`
- `prior_safe_negative_penalty`
- `reproduction_only_penalty`
- `external_validation_blocker_penalty`
- `hardcode_cost`
