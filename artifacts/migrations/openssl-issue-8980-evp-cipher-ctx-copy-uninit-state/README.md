# OPENSSL-ISSUE-8980: EVP_CIPHER_CTX_copy Uninitialized State

## Migration Status

**status: migration_not_applicable / no_equivalent_public_api**

No mbedTLS migration is possible for this pattern. No `run_recipe.*` files are present.

---

## 1. Source Pattern Summary

| Field | Value |
|---|---|
| Pattern ID | OPENSSL-ISSUE-8980 |
| Template ID | EVP_CIPHER_CTX_COPY_UNINIT_STATE |
| Source issue | https://github.com/openssl/openssl/issues/8980 |
| Title | OpenSSL 1.0.2 branch on uninitialized memory in EVP_CIPHER_CTX_copy |
| Component | EVP/AES_GCM |
| Affected version | OpenSSL 1.0.2 |
| CVE | None assigned |
| Artifact class | A_ast_ready |
| poc_type | C_API (self-contained, no external input required) |
| Quality | HIGH_CANDIDATE |
| Strict reproduction | false |
| Local validation | OpenSSL 3.0.13: compiled and executed, 0 Valgrind errors (safe/fixed behavior) |
| Pattern YAML | knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-8980.yaml |

**Source APIs:**
- `EVP_CIPHER_CTX_new`
- `EVP_aes_128_gcm`
- `EVP_EncryptInit_ex`
- `EVP_CIPHER_CTX_copy` ← **core trigger**

**Root cause:** In OpenSSL 1.0.2, calling `EVP_CIPHER_CTX_copy` on a GCM context
that has been associated with a cipher algorithm (via `EVP_EncryptInit_ex` with NULL key
and NULL IV) but has not completed initialization triggers uninitialized memory access.
The internal GCM state (`EVP_AES_GCM_CTX` / `gcm128_context`) contains pointers that
are not fully initialized until the key and IV are set. Maintainer confirmed this is a
bug but declined to fix in 1.0.2 (security-fix-only mode).

**Core vulnerability path:**
```
EVP_CIPHER_CTX_new()                                       ← allocate src context
EVP_aes_128_gcm()                                          ← get cipher descriptor
EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)          ← associate cipher, NO key, NO IV
EVP_CIPHER_CTX_new()                                       ← allocate dst context
EVP_CIPHER_CTX_copy(ctx2, ctx)                             ← TRIGGER: copy partially-init GCM state
```

---

## 2. Original Artifact Files

- `datasets/openssl/poc_artifacts/issue_8980/poc.c` — self-contained C harness
- `datasets/openssl/poc_artifacts/issue_8980/metadata.json`
- `datasets/openssl/poc_artifacts/issue_8980/README.md`
- `datasets/openssl/poc_artifacts/issue_8980/run.sh`

No external input files required.

---

## 3. Strict Reproduction Limitation

`strict_reproduction = false`

The current harness was validated under OpenSSL 3.0.13 (Valgrind: 0 errors). This confirms
that the harness structure and API call sequence are correct, but it does **not** reproduce
the original bug. The uninitialized memory access is specific to OpenSSL 1.0.2's internal
GCM state management. On OpenSSL 3.x the copy path has been hardened and the harness
produces safe/fixed behavior.

To trigger the original crash, the harness would need to be compiled and run against
an OpenSSL 1.0.2 build — which is outside the scope of the current migration framework.

---

## 4. API Suitability Scoring

Scoring formula from `migration/candidate_mapper.py`:
```
final_score = 0.15 * operation_family
            + 0.20 * function_behavior
            + 0.20 * parameter_structure
            + 0.30 * vulnerability_path
            + 0.15 * harness_feasibility
```
Thresholds: generate ≥ 75 (AND vuln_path ≥ 70) / needs_llm_review ≥ 55 (AND vuln_path ≥ 50)

**Critical constraint:** The defining vulnerability path is `EVP_CIPHER_CTX_copy` on a
partially-initialized context. No mbedTLS public API provides cipher context copy/clone.
Without a copy API, `vulnerability_path` cannot exceed ~5/100 for any mbedTLS candidate.

### Candidate A: mbedtls_cipher (3.6.4 legacy layer)

| Dimension | Score | Rationale |
|---|---|---|
| operation_family | 55 | Both are symmetric cipher operation APIs (AES-GCM family) |
| function_behavior | 35 | init/setup/setkey lifecycle exists, but no copy behavior |
| parameter_structure | 30 | mbedtls_cipher_context_t vs EVP_CIPHER_CTX; structurally different |
| vulnerability_path | **5** | NO cipher context copy API; core trigger cannot be expressed |
| harness_feasibility | 60 | Single-process harness feasible for cipher lifecycle testing |

**Weighted: 0.15×55 + 0.20×35 + 0.20×30 + 0.30×5 + 0.15×60 = 8.25+7.0+6.0+1.5+9.0 = 31.75 → 32**

```
preserved_features:
  - AES-GCM algorithm family coverage
  - lifecycle: init → setup → setkey → free
  - crash_sanitizer_oracle applicable
  - single-process harness feasible

lost_or_weakened_features:
  - NO mbedtls_cipher_copy or mbedtls_cipher_clone (does not exist)
  - core EVP_CIPHER_CTX_copy trigger cannot be expressed at all
  - mbedtls_cipher_context_t fields are MBEDTLS_PRIVATE (no state inspection)
  - partial-initialization semantics differ from OpenSSL 1.0.2

decision: skip
migration_applicability: migration_not_applicable
reason: vulnerability_path=5 < 50; final_score=32 < 55
```

### Candidate B: psa_aead (4.1.0 PSA layer)

| Dimension | Score | Rationale |
|---|---|---|
| operation_family | 50 | PSA AEAD covers AES-GCM algorithm family |
| function_behavior | 25 | Key-based operation setup; fundamentally different from context passing |
| parameter_structure | 20 | psa_aead_operation_t vs EVP_CIPHER_CTX; no meaningful mapping |
| vulnerability_path | **5** | NO psa_aead_operation_t copy; key-based API has no copy concept |
| harness_feasibility | 55 | PSA harness feasible but tests different semantics |

**Weighted: 0.15×50 + 0.20×25 + 0.20×20 + 0.30×5 + 0.15×55 = 7.5+5.0+4.0+1.5+8.25 = 26.25 → 26**

```
decision: skip
migration_applicability: migration_not_applicable
reason: vulnerability_path=5 < 50; final_score=26 < 55
```

### Candidate C: mbedtls_gcm (3.6.4 direct GCM layer)

| Dimension | Score | Rationale |
|---|---|---|
| operation_family | 55 | Directly covers AES-GCM operations |
| function_behavior | 30 | init/setkey/starts/update/finish/free; no copy |
| parameter_structure | 25 | mbedtls_gcm_context; less abstract than cipher layer |
| vulnerability_path | **5** | NO mbedtls_gcm_copy; cannot express copy of partial context |
| harness_feasibility | 55 | Single-process harness feasible |

**Weighted: 0.15×55 + 0.20×30 + 0.20×25 + 0.30×5 + 0.15×55 = 8.25+6.0+5.0+1.5+8.25 = 29.0 → 29**

```
decision: skip
migration_applicability: migration_not_applicable
reason: vulnerability_path=5 < 50; final_score=29 < 55
```

### Candidate D: no_equivalent_public_api

```
score: 0
decision: skip
migration_applicability: no_equivalent_public_api
reason: Confirmed — neither mbedTLS 3.6.4 nor 4.1.0 exposes a cipher context copy/clone
        in the legacy cipher layer, GCM direct layer, or PSA AEAD operation layer.
```

### Scoring Summary

| Candidate | vuln_path | Final Score | Decision |
|---|---|---|---|
| A: mbedtls_cipher (3.6.4) | 5 | **32** | migration_not_applicable |
| B: psa_aead (4.1.0) | 5 | **26** | migration_not_applicable |
| C: mbedtls_gcm (3.6.4) | 5 | **29** | migration_not_applicable |
| D: no_equivalent_public_api | 0 | **0** | no_equivalent_public_api |

No candidate reaches the `needs_llm_review` threshold (final_score ≥ 55).
No candidate reaches the `generate` threshold (final_score ≥ 75 AND vuln_path ≥ 70).

---

## 5. Why No mbedTLS Migration is Possible

The root issue is simple and absolute:

**mbedTLS does not expose a cipher context copy or clone API in any public interface.**

Verified across:
- `mbedtls-3.6.4/include/mbedtls/cipher.h` — no copy/clone function
- `mbedtls-3.6.4/include/mbedtls/gcm.h` — no copy/clone function
- `mbedtls-4.1.0/tf-psa-crypto/include/psa/crypto.h` — no psa_aead_operation copy/clone

Without a context copy API, it is impossible to construct a harness that expresses
"copy a partially-initialized cipher context" — which is the defining trigger of the
`EVP_CIPHER_CTX_COPY_UNINIT_STATE` vulnerability pattern.

Any migration to `mbedtls_cipher_update`, `psa_aead_update`, or similar would lose
the copy step entirely, resulting in a completely different vulnerability path
that tests cipher operation correctness rather than context copy safety.

Additionally:
- The original bug is version-specific (OpenSSL 1.0.2 only)
- OpenSSL 3.x has already fixed this path (current local validation: 0 Valgrind errors)
- Even within OpenSSL, a same-library comparison (buggy 1.0.2 vs fixed 3.x) would require
  access to the affected binary, which is outside the current framework scope

---

## 6. Migration Verdict

```
migration_not_applicable
no_equivalent_public_api
```

**Reasons:**
1. `EVP_CIPHER_CTX_copy` has no mbedTLS equivalent in any public API layer
2. All candidate scores below threshold (highest: 32/100, needs_llm_review requires 55+)
3. vulnerability_path = 5/100 for all candidates (copy operation entirely absent)
4. Original bug is version-specific (1.0.2); current OpenSSL 3.x shows safe behavior

---

## 7. Recommended Future Work

If a cross-library cipher context copy pattern is to be studied in the future:

1. **Within OpenSSL only:** Compare OpenSSL 1.0.2 (buggy) vs 3.x (fixed) using the
   existing harness — this is a valid same-library regression comparison.

2. **mbedTLS internal path (non-public):** If mbedTLS internal GCM context `memcpy`
   patterns exhibit similar issues during cipher setup, this would require a different
   research approach (source-code level analysis, not public API harness testing).

3. **Future mbedTLS clone API:** If mbedTLS were to add `mbedtls_cipher_clone()` or
   `mbedtls_gcm_clone()` in a future release, this pattern could be revisited with
   the `evp_context_state_lifecycle` harness family.

4. **Related families to explore:**
   - `object_state_lifecycle` family (issue_18659, issue_22842) — context lifecycle without copy
   - `null_deref_dispatch` family (issue_19524, issue_21935) — uninitialized state dispatch

---

## 8. Evidence Collector Result

`migration_candidates/openssl/evp_cipher_ctx_copy_uninit_state/candidates_with_evidence.yaml`
was generated successfully by `migration.evidence_collector`. All 4 candidates were
processed and all received `decision: skip` with `negative` features correctly captured.

---

## 9. Same-Library Regression Applicability

### Regression target

This pattern is suitable for same-library regression testing across OpenSSL versions.

**Buggy-side candidate:**
- OpenSSL 1.0.2
- API sequence:
  ```c
  EVP_CIPHER_CTX_new()
  EVP_aes_128_gcm()
  EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)   // no key, no IV
  EVP_CIPHER_CTX_new()
  EVP_CIPHER_CTX_copy(dst, src)                        // TRIGGER
  ```
- Expected signal: uninitialized memory read / NULL dereference / Valgrind error

**Fixed-side candidate:**
- OpenSSL 3.x / OpenSSL 3.5.5
- Same API sequence
- Expected behavior: safe execution, Valgrind 0 errors

### Why same-library regression is valid

The core vulnerability path is **fully preserved** because the identical public OpenSSL API
sequence is used on both sides. Unlike OpenSSL → mbedTLS cross-library migration, no
API-path weakening occurs. The same `EVP_CIPHER_CTX_copy` call that triggers the bug on
1.0.2 is the same call that behaves safely on 3.x.

This is the highest-confidence migration path available for this pattern:

```
vulnerability_path preservation: 100%
oracle_type: crash_sanitizer_oracle (Valgrind / ASAN / exit code)
comparison type: same-API same-library version regression
```

### Why OpenSSL 3.5.5 is safe (code-level analysis)

In OpenSSL 3.5.5 (`crypto/evp/e_aes.c`, `EVP_CTRL_COPY` handler for AES-GCM, ~line 2771):

```c
case EVP_CTRL_COPY: {
    EVP_CIPHER_CTX *out = ptr;
    EVP_AES_GCM_CTX *gctx_out = EVP_C_DATA(EVP_AES_GCM_CTX, out);
    if (gctx->gcm.key) {            // ← NULL check: if no key set, skip key copy
        if (gctx->gcm.key != &gctx->ks)
            return 0;
        gctx_out->gcm.key = &gctx_out->ks;
    }
    if (gctx->iv == c->iv)
        gctx_out->iv = out->iv;
    else {
        if ((gctx_out->iv = OPENSSL_malloc(gctx->ivlen)) == NULL)
            return 0;
        memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
    }
    return 1;
}
```

The `if (gctx->gcm.key)` guard means: when no key has been set (partial initialization,
`gcm.key == NULL`), the copy handler skips the key-pointer fixup entirely and proceeds safely.

In OpenSSL 1.0.2, the equivalent path lacked this NULL guard, allowing the copy to proceed
with an uninitialized `gcm.key` pointer and resulting in an invalid memory read.

Additionally, OpenSSL 3.x moved providers to a new abstraction layer. For provider-backed
ciphers, `EVP_CIPHER_CTX_copy` first checks `in->cipher->dupctx != NULL`
(`crypto/evp/evp_enc.c:1770`) before attempting copy, adding a second layer of protection.

### Current availability of affected version

```
status: requires_affected_version_build

Available in clean_sources:
  - openssl-3.5.5   ← available (fixed/safe side)
  - openssl-1.0.2   ← NOT available (buggy side missing)

Cannot run full regression comparison until OpenSSL 1.0.2 source/build is available.
```

### Proposed artifact layout

```
artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/
  README.md
  buggy_openssl_1_0_2/
    build.log          (placeholder)
    run.log            (placeholder)
    valgrind.log       (placeholder)
  fixed_openssl_3_5_5/
    build.log          (placeholder — harness already validated locally)
    run.log            (placeholder)
    valgrind.log       (placeholder — 0 errors confirmed under 3.0.13)
  results/
    regression_summary.json    (placeholder)
  logs/
```

### Proposed regression verdicts

```
buggy_version_crash_candidate:
  OpenSSL 1.0.2 + EVP_CIPHER_CTX_copy on partial GCM context
  => Valgrind uninitialized-memory-read OR ASAN invalid-read OR SEGV

fixed_version_safe:
  OpenSSL 3.x + same harness
  => Valgrind 0 errors, normal exit

regression_fixed:
  Pair (buggy_crash, fixed_safe) confirms the pattern was fixed between 1.0.2 and 3.x

affected_version_missing:
  Current status — OpenSSL 1.0.2 build not available in clean_sources
  => regression comparison deferred
```

### Future commands (placeholder — do not run until 1.0.2 is available)

```bash
# Buggy side — requires OpenSSL 1.0.2 build
gcc -I/path/to/openssl-1.0.2/include datasets/openssl/poc_artifacts/issue_8980/poc.c \
  -o poc_buggy -g -O0 \
  -L/path/to/openssl-1.0.2/lib -lssl -lcrypto -Wl,-rpath,/path/to/openssl-1.0.2/lib
valgrind --leak-check=full --track-origins=yes ./poc_buggy \
  > artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/buggy_openssl_1_0_2/valgrind.log 2>&1

# Fixed side — OpenSSL 3.5.5 (available in clean_sources)
gcc -I${CLEAN_SOURCES_ROOT}/openssl-3.5.5/include datasets/openssl/poc_artifacts/issue_8980/poc.c \
  -o poc_fixed -g -O0 \
  -L${CLEAN_SOURCES_ROOT}/openssl-3.5.5 -lssl -lcrypto
valgrind --leak-check=full --track-origins=yes ./poc_fixed \
  > artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/fixed_openssl_3_5_5/valgrind.log 2>&1
```

---

## 10. Same-Library API Equivalence Audit

### Search scope

Public headers searched: `include/openssl/evp.h`, `include/openssl/core_dispatch.h`
Source: OpenSSL 3.5.5 (`$CLEAN_SOURCES_ROOT/openssl-3.5.5`)

### EVP_CIPHER_CTX_dup — public API found

```c
// include/openssl/evp.h:654
EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in);

// crypto/evp/evp_enc.c:1759 — implementation
EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in)
{
    EVP_CIPHER_CTX *out = EVP_CIPHER_CTX_new();
    if (out != NULL && !EVP_CIPHER_CTX_copy(out, in)) {
        EVP_CIPHER_CTX_free(out);
        out = NULL;
    }
    return out;
}
```

`EVP_CIPHER_CTX_dup` is a **fully public API** declared in `include/openssl/evp.h`.
It is the canonical "allocate + copy" wrapper: internally it calls `EVP_CIPHER_CTX_new()`
followed by `EVP_CIPHER_CTX_copy()`, traversing the **same** AES-GCM `EVP_CTRL_COPY`
handler path as the original PoC. It is documented in `doc/man3/EVP_EncryptInit.pod`.

**Same-library equivalent API verdict: `same_library_equivalent_api_candidate`**

| Property | EVP_CIPHER_CTX_copy (original) | EVP_CIPHER_CTX_dup (equivalent) |
|---|---|---|
| Public API | YES (`evp.h:655`) | YES (`evp.h:654`) |
| Internal path | EVP_CTRL_COPY on AES-GCM | calls copy → same EVP_CTRL_COPY |
| Partial init trigger | same sequence | same sequence |
| Parameter structure | `(out, in)` — caller allocates dst | `(in)` — library allocates dst |
| Oracle | return int 0/1 | return ptr NULL / non-NULL |
| In OpenSSL 1.0.2 | YES (exists) | NOT in 1.0.2 (added later) |
| Can run now (3.5.5) | YES (safe) | YES (safe) |

### OSSL_FUNC_CIPHER_DUPCTX — not a user API

`OSSL_FUNC_CIPHER_DUPCTX` (`core_dispatch.h:358`) is a **provider dispatch slot macro**.
It is used by provider implementers to register a cipher clone function, and is called
internally by `EVP_CIPHER_CTX_copy` / `EVP_CIPHER_CTX_dup` via the dispatch table.
End users must not call it directly. It is not a user-facing API and cannot be used in
a standard C harness. **Classified: not_public_api / skip.**

### EVP_CIPHER_CTX_reset + EVP_EncryptInit_ex — not a copy equivalent

`EVP_CIPHER_CTX_reset` clears and frees all existing cipher state (`memset` to zero).
`EVP_EncryptInit_ex` then re-associates a cipher algorithm from scratch.
This sequence is **reinitialize-from-scratch**, not **copy-of-partial-state**.
No src→dst relationship; no copy of GCM internal state; `vulnerability_path = 5`.
**Classified: weak_semantic_projection / skip.**

### EVP_CIPHER_fetch + params + EVP_EncryptInit_ex2 — not a copy equivalent

`EVP_CIPHER_CTX_get_params` / `set_params` exchange algorithm parameters (key bytes,
IV bytes, tag length) as `OSSL_PARAM` arrays. They do **not** transfer the internal
opaque algorithmic state blob (`gcm128_context` / `algctx`).
Reconstructing a context via params is not equivalent to copying uninitialized GCM state.
`vulnerability_path = 5`. **Classified: weak_semantic_projection / skip.**

### Scoring summary (same-library candidates)

| Candidate | api_type | vuln_path | Score | Decision |
|---|---|---|---|---|
| EVP_CIPHER_CTX_copy | same_api_regression | 100 | **100** | generate (needs 1.0.2) |
| EVP_CIPHER_CTX_dup | same_library_equivalent_api | 95 | **96** | generate (3.5.5 now) |
| OSSL_FUNC_CIPHER_DUPCTX | not_public_api | 40 | 53 | skip |
| EVP_CIPHER_CTX_reset + reinit | weak_projection | 5 | 38 | skip |
| EVP_CIPHER_fetch + params | weak_projection | 5 | 33 | skip |

### Final same-library verdict

```
same_library_equivalent_api_found

Two generate-tier candidates:
  1. EVP_CIPHER_CTX_copy — same_api_regression
     100% vulnerability path; requires OpenSSL 1.0.2 (deferred)
  2. EVP_CIPHER_CTX_dup — same_library_equivalent_api
     96/100; public API in 3.5.5; can run now; expected safe/fixed result
```

Template for `EVP_CIPHER_CTX_dup` variant created at:
`normalized_templates/openssl/evp_cipher_ctx_dup_uninit_state/`

Same-library candidates recorded at:
`migration_candidates/openssl_same/evp_cipher_ctx_copy_uninit_state/candidates.yaml`

---

## References

- Issue: https://github.com/openssl/openssl/issues/8980
- Artifact: `datasets/openssl/poc_artifacts/issue_8980/`
- Pattern YAML: `knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-8980.yaml`
- Pattern MD: `knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-8980.md`
- Normalized template (copy): `normalized_templates/openssl/evp_cipher_ctx_copy_uninit_state/`
- Normalized template (dup):  `normalized_templates/openssl/evp_cipher_ctx_dup_uninit_state/`
- Cross-library candidates: `migration_candidates/openssl/evp_cipher_ctx_copy_uninit_state/`
- Same-library candidates: `migration_candidates/openssl_same/evp_cipher_ctx_copy_uninit_state/`
- Regression artifact: `artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/`
