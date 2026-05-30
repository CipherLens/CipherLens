# MBEDTLS-POC-0002 Migration Plan

Date: 2026-05-29

This plan prepares `MBEDTLS-POC-0002` for the newer recipe/slot-filling migration framework. No LLM adapter generation, cross generation, rendering, compilation, or analysis was run in this phase.

## 1. Current State

Current status: `evidence_only`.

The PoC has a normalized source template, mask reports, selected mask units, candidate mapping, and candidate evidence. No structured adapter, validated adapter, cross template, rendered cases, or result summary was found for `mpi_sub_abs`.

Artifact root prepared:

```text
artifacts/migrations/mbedtls-poc-0002-mpi-sub-abs/
```

Prepared subdirectories:

```text
adapters/
adapters_validated/
adapters_recipe_llm/
adapters_recipe_llm_validated/
cross_templates/
cross_templates_recipe/
rendered_cases/
rendered_cases_recipe/
results/
logs/
```

## 2. Existing Files

PoC pattern:

```text
knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0002.yaml
knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0002.md
```

Normalized template:

```text
normalized_templates/bignum/mpi_sub_abs/README.md
normalized_templates/bignum/mpi_sub_abs/tmpl_mbedtls.c
normalized_templates/bignum/mpi_sub_abs/template_meta.yaml
normalized_templates/bignum/mpi_sub_abs/mask_report.yaml
normalized_templates/bignum/mpi_sub_abs/ast_mask_report.yaml
normalized_templates/bignum/mpi_sub_abs/selected_mask_units.yaml
normalized_templates/bignum/mpi_sub_abs/poc_original.c
```

Candidate and evidence layer:

```text
migration_candidates/bignum/mpi_sub_abs/candidates.yaml
migration_candidates/bignum/mpi_sub_abs/candidates_with_evidence.yaml
```

Relevant API constraints:

```text
knowledge_raw/api_constraints/mbedtls/4.1.0/mbedtls_mpi_sub_abs.md
knowledge_raw/api_constraints/openssl/3.5.5/BN_usub.md
knowledge_raw/api_constraints/openssl/3.5.5/BN_sub.md
```

Early non-recipe OpenSSL template draft:

```text
templates/bignum/mpi_sub_abs/tmpl_openssl.c
```

This file is useful as design context, but should not become the new migration path as-is.

## 3. Source Pattern Summary

Pattern:

```text
pattern_id: MBEDTLS-POC-0002
template_id: BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY
source_library: mbedtls
source_api: mbedtls_mpi_sub_abs
```

Root cause:

```text
The buggy mbedtls_mpi_sub_abs() did not reject the case where B has more effective limbs than A.
It then continued to mpi_sub_hlp(n, X->p, B->p), where n could exceed the allocated limb count of X.
The PoC manually prepares X with one limb followed by a canary, making the out-of-bounds write visible.
```

Trigger:

```text
A radix: 10
A value: "5"
B radix: 16
B value: "123456789abcdef01"
X output limbs: 1
canary size: 16
```

Buggy behavior:

```text
ret = 0
canary after X->p is corrupted
```

Fixed/safe behavior:

```text
ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE (-10)
canary remains intact
```

Oracle:

```text
bug_candidate:
  - canary_corrupted_after_X_p
  - out_of_bounds_write
  - unexpected success return

fixed_or_safe:
  - ret_is_MBEDTLS_ERR_MPI_NEGATIVE_VALUE
  - canary_intact_after_X_p
  - no sanitizer crash
```

Mutation points:

```text
[A_VALUE]
[B_VALUE]
[A_BASE]
[B_BASE]
[X_LIMB_COUNT]
[CANARY_SIZE]
```

Selected mask units exist in:

```text
normalized_templates/bignum/mpi_sub_abs/selected_mask_units.yaml
```

Important selected units include the value/radix mutation points, `prepare_output_with_canary(&X, [X_LIMB_COUNT])`, the trigger call `mbedtls_mpi_sub_abs(&X, &A, &B)`, and canary oracle statements.

## 4. Target Candidates Summary

Existing candidates:

### BN_usub

```text
target_api: BN_usub
decision: skip
migration_applicability: migration_not_applicable
scores:
  operation_family: 85
  function_behavior: 70
  parameter_structure: 60
  vulnerability_path: 45
  harness_feasibility: 70
  final: 63
preserved_features:
  - bignum_subtraction
  - A_B_operand_relation
lost_or_weakened_features:
  - manual_output_limb_boundary_control
  - direct_canary_after_output_limbs
reason:
  Functionally related to unsigned bignum subtraction, but OpenSSL manages BIGNUM allocation internally.
```

Assessment:

`BN_usub` is the closest semantic operation to `mbedtls_mpi_sub_abs` because it performs unsigned subtraction and returns failure when `a < b`. However, it does not expose a public way to force the result BIGNUM's internal limb capacity or place a canary after it. It is a good first recipe candidate for semantic comparison, but not a full vulnerability-path equivalent.

### BN_sub

```text
target_api: BN_sub
decision: skip
migration_applicability: migration_not_applicable
scores:
  operation_family: 85
  function_behavior: 75
  parameter_structure: 60
  vulnerability_path: 40
  harness_feasibility: 75
  final: 63
preserved_features:
  - bignum_subtraction
  - signed_result_behavior
lost_or_weakened_features:
  - manual_output_limb_boundary_control
  - direct_canary_after_output_limbs
reason:
  Functionally related to signed subtraction, but it does not preserve the absolute-subtraction negative-result rejection path or output limb boundary oracle.
```

Assessment:

`BN_sub` can compute a signed negative result for `A - B`, so it is weaker for this specific pattern. It preserves bignum subtraction but not the source oracle's negative-result rejection or manual output limb boundary.

## 5. Recommended Strong Candidate

Recommended first candidate: `BN_usub`.

Rationale:

- It is closer to `mbedtls_mpi_sub_abs` than `BN_sub` because both are unsigned/absolute subtraction variants.
- It exposes an observable return code.
- It can exercise the `A < B` negative-result boundary.
- It does not preserve the manual output limb canary path, so the expected result should be classified as a weakened semantic comparison, not a direct memory-boundary migration.

Do not process all candidates at once. Start with one recipe-backed `BN_usub` adapter.

## 6. Recommended Harness Family

Recommended new family:

```text
bignum_arithmetic_semantic
```

Reason:

`buffer_canary_boundary` is too strong for OpenSSL `BN_usub` / `BN_sub`: public OpenSSL BIGNUM APIs do not expose caller-controlled limb storage. `bignum_output_state_semantic` is also possible, but the primary observable for the first OpenSSL recipe is arithmetic relation plus return code rather than output buffer state.

Recommended oracle type:

```text
bignum_negative_result_rejection_oracle
```

Family features:

```yaml
required_observables:
  - return_code
  - operand_relation
  - output_bignum_value_or_failure
target_api_features:
  - bignum_subtraction
  - observable_return_code
  - public_result_object
source_api_features:
  - bignum_absolute_subtraction
  - negative_result_rejection
  - optional_manual_output_limb_boundary
safe_behavior:
  - A < B is rejected or reported as failure for unsigned subtraction
bug_behavior:
  - A < B succeeds unexpectedly in unsigned subtraction
triage_behavior:
  - API computes signed negative result or otherwise changes operation semantics
```

Important limitation:

This family does not claim to preserve the canary-after-`X->p` memory-boundary path. It is a semantic migration fallback for APIs whose public abstraction hides limb storage.

## 7. Recommended Adapter Recipe

Recommended first recipe file:

```text
adapter_recipes/openssl/BN_usub.bignum_arithmetic_semantic.yaml
```

Suggested fixed recipe responsibilities:

- Include `openssl/bn.h`.
- Allocate `BIGNUM *A`, `BIGNUM *B`, and `BIGNUM *R`.
- Parse `A` and `B` according to base slots using `BN_dec2bn` or `BN_hex2bn`.
- Call `ret = BN_usub(R, A, B)`.
- Optionally compare `A` and `B` with `BN_ucmp(A, B)` before/after the trigger to record operand relation.
- Serialize or print `R` only for diagnostics.
- Free all `BIGNUM` objects and any OpenSSL-allocated strings.

The recipe should forbid direct access to opaque OpenSSL internals:

```text
r->d
r->top
r->dmax
BN_ULONG internal limb mutation
manual BIGNUM internals
```

## 8. Recommended Allowed Slots

Suggested slots:

```yaml
allowed_slots:
  lhs_value:
    default: "5"
  rhs_value:
    default: "123456789abcdef01"
  lhs_base:
    default: 10
  rhs_base:
    default: 16
  result_variable:
    default: R
  lhs_variable:
    default: A
  rhs_variable:
    default: B
  return_code_variable:
    default: ret
  comparison_variable:
    default: cmp
  expected_relation:
    default: lhs_less_than_rhs
  result_observable:
    default: BN_bn2dec
```

Slots from the source template that should be recorded but not mapped to public OpenSSL APIs:

```yaml
weakened_or_unmapped_slots:
  output_limb_count:
    source_placeholder: "[X_LIMB_COUNT]"
    reason: OpenSSL public BIGNUM APIs do not expose result limb capacity control.
  canary_size:
    source_placeholder: "[CANARY_SIZE]"
    reason: No public direct canary-after-result-limbs equivalent.
```

## 9. What The LLM Should Fill

Recipe-fixed C skeleton:

- `BN_new` / input parsing / `BN_usub` trigger / oracle / cleanup.
- No LLM-generated C blocks.
- No direct BIGNUM internals.

LLM-generated fields should be limited to:

```yaml
slot_bindings:
  lhs_value:
  rhs_value:
  lhs_base:
  rhs_base:
  lhs_variable:
  rhs_variable:
  result_variable:
  return_code_variable:
  comparison_variable:
  expected_relation:
  result_observable:
preserved_features:
lost_or_weakened_features:
slot_binding_rationale:
```

The LLM must not output:

```text
init_block
input_construction_block
trigger_block
cleanup_block
raw C code
manual BIGNUM internals
canary layout pretending to control OpenSSL internal limbs
```

## 10. Follow-up Steps

Selected first target API:

```text
BN_usub
```

Selected harness family:

```text
bignum_arithmetic_semantic
```

Selected oracle:

```text
bignum_negative_result_rejection_oracle
```

Selected recipe:

```text
adapter_recipes/openssl/BN_usub.bignum_arithmetic_semantic.yaml
```

Important limitation:

This recipe is a semantic projection. It does not preserve the original
canary-after-`X->p` internal limb boundary oracle because OpenSSL 3.x `BIGNUM`
is opaque and public APIs do not expose direct result limb capacity control.

Next step:

Use recipe/slot-filling `adapter_filler` to generate only `slot_bindings` for
`BN_usub`; do not allow free-form `init_block`, `trigger_block`, or
`cleanup_block` generation.

1. Add `bignum_arithmetic_semantic` to the family registry/design docs.
2. Add `adapter_recipes/openssl/BN_usub.bignum_arithmetic_semantic.yaml`.
3. Extend `migration/adapter_filler.py` recipe mode, if needed, so `BN_usub + bignum_arithmetic_semantic` emits only `slot_bindings`.
4. Extend `migration/adapter_validate.py` with a recipe/slot rule for `BN_usub`.
5. Extend `template_maker/cross_generator_from_adapters.py` with a recipe renderer for `bignum_arithmetic_semantic`.
6. Render/compile/analyze only after the recipe adapter validates.
7. Keep `BN_sub` as a later weak/triage candidate, not the first automatic migration target.

## 11. Open Questions

- Should `template_meta.yaml` be updated to explicitly set `harness_family: bignum_arithmetic_semantic`, or should the family be introduced first in a central registry?
- Should `BN_usub` remain `decision: skip` in `candidates.yaml` while a recipe-driven semantic fallback is tested, or should a separate `needs_llm_review` / `semantic_fallback` decision be introduced?
- Should a future internal OpenSSL-only research harness be allowed to instrument private BIGNUM internals? That would be a different harness family and should not be mixed with public API migration.
