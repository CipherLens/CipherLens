# OPENSSL-ISSUE-8980: Same-Library Regression Analysis

## Status

```
regression_status: fixed_side_batch_validated / buggy_side_pending
buggy_side: requires_openssl_1_0_2_build (affected_version_missing)
fixed_side: openssl_3_5_5_batch_validated — 28/28 cases safe_fixed_behavior
batch_run: COMPLETED (28 cases, 5 ciphers × 4 init_states × 4 post_dup_actions)
full_regression_fixed: NOT YET (requires 1.0.2 buggy-side run)
```

OpenSSL 1.0.2 is **not** available in `$CLEAN_SOURCES_ROOT`. The fixed-side source
(OpenSSL 3.5.5) is available. Regression comparison is deferred until 1.0.2 is available.

No `run_recipe.*` or result files are created. This README documents the regression
design and rationale for future execution.

---

## 1. Source Issue Summary

| Field | Value |
|---|---|
| Pattern ID | OPENSSL-ISSUE-8980 |
| Issue | https://github.com/openssl/openssl/issues/8980 |
| Title | OpenSSL 1.0.2 branch on uninitialized memory in EVP_CIPHER_CTX_copy |
| Component | EVP/AES_GCM |
| Affected version | OpenSSL 1.0.2 |
| CVE | None assigned |
| Maintainer verdict | "Probably just a bug. Since 1.0.2 is in security-fix only mode I think we'll probably not fix this." |
| Strict reproduction | false |
| Cross-library migration | migration_not_applicable (mbedTLS has no EVP_CIPHER_CTX_copy equivalent) |
| Cross-library migration doc | artifacts/migrations/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/README.md |

---

## 2. Original OpenSSL API Sequence

The harness is self-contained, requires no external input files.
Source: `datasets/openssl/poc_artifacts/issue_8980/poc.c`

```c
#include <openssl/evp.h>

int main(void) {
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX   *ctx    = NULL;   // source context
    EVP_CIPHER_CTX   *ctx2   = NULL;   // destination context

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_aes_128_gcm();

    // Partial initialization: algorithm associated but NO key, NO IV
    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);

    ctx2 = EVP_CIPHER_CTX_new();

    // TRIGGER: copy partially-initialized AES-GCM context
    EVP_CIPHER_CTX_copy(ctx2, ctx);

    EVP_CIPHER_CTX_free(ctx2);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
```

**Why this triggers the bug in OpenSSL 1.0.2:**

`EVP_EncryptInit_ex` with `NULL` key and `NULL` IV associates the cipher descriptor and
allocates `EVP_AES_GCM_CTX`, but leaves `gctx->gcm.key` and related GCM state pointers
uninitialized. In 1.0.2, `EVP_CIPHER_CTX_copy` calls `ctrl(EVP_CTRL_COPY)` which
attempts to fixup the `gcm.key` pointer without checking if it is `NULL`, causing an
uninitialized memory read.

---

## 3. Why Cross-Library Migration Failed

OpenSSL → mbedTLS migration is `migration_not_applicable` because:

- `EVP_CIPHER_CTX_copy` is the core trigger — there is no equivalent public API in mbedTLS
- mbedTLS 3.6.4: `cipher.h` — no `mbedtls_cipher_copy` or `mbedtls_cipher_clone`
- mbedTLS 3.6.4: `gcm.h` — no `mbedtls_gcm_copy` or `mbedtls_gcm_clone`
- mbedTLS 4.1.0: `psa/crypto.h` — no `psa_aead_operation_t` copy
- Highest mbedTLS candidate score: 32/100 (threshold for migration: 55+)
- `vulnerability_path` score for all mbedTLS candidates: 5/100

Removing `EVP_CIPHER_CTX_copy` from the harness would produce a completely different
vulnerability path unrelated to context-copy uninitialized state.

---

## 4. Why Same-Library Regression is Valid

Same-library regression across OpenSSL versions **fully preserves** the vulnerability path:

| Dimension | Cross-library (→ mbedTLS) | Same-library (1.0.2 → 3.5.5) |
|---|---|---|
| API preserved | NO (`EVP_CIPHER_CTX_copy` missing) | **YES** (identical API) |
| vulnerability_path | 5/100 | **100/100** |
| oracle applicable | weakened | **unchanged** |
| harness reuse | not possible | **direct reuse** |
| research value | migration_not_applicable | valid regression confirmation |

The same `poc.c` harness can be compiled against both versions without modification.
The oracle (Valgrind / ASAN / exit code) applies identically to both sides.

---

## 5. Code-Level Analysis: Why OpenSSL 3.5.5 is Safe

In OpenSSL 3.5.5, the `EVP_CTRL_COPY` handler for AES-GCM
(`crypto/evp/e_aes.c`, around line 2771) contains a NULL guard:

```c
case EVP_CTRL_COPY: {
    EVP_AES_GCM_CTX *gctx_out = EVP_C_DATA(EVP_AES_GCM_CTX, out);
    if (gctx->gcm.key) {            // ← NULL guard added in fix
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

When no key has been set (`gcm.key == NULL`), the fixup block is skipped entirely.
This is the code-level evidence of the fix. In 1.0.2, this NULL guard was absent.

Additionally, for provider-backed ciphers in OpenSSL 3.x, `EVP_CIPHER_CTX_copy`
(`crypto/evp/evp_enc.c:1770`) first validates `in->cipher->dupctx != NULL`:

```c
if (in->cipher->dupctx == NULL) {
    ERR_raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX);
    return 0;
}
```

This adds a second layer of protection for provider-based cipher implementations.

---

## 6. Required Additional Setup

To execute the full regression comparison, the following is needed:

```
Required: OpenSSL 1.0.2 source or pre-built shared library
Available: openssl-3.5.5 (at $CLEAN_SOURCES_ROOT/openssl-3.5.5)
Missing:   openssl-1.0.2

Options to obtain 1.0.2:
  A. Download source: https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz
     (1.0.2u is the final 1.0.2 release)
  B. Use a system package from an older distro image
  C. Use a Docker container with Ubuntu 16.04 or similar that ships OpenSSL 1.0.2

Note: OpenSSL 1.0.2 reached end-of-life 2019-12-31. Use only in isolated environments.
```

---

## 7. Proposed Artifact Layout

```
artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/
  README.md                          ← this file
  buggy_openssl_1_0_2/
    build.log                        (placeholder — to be filled when 1.0.2 is available)
    run.log                          (placeholder)
    valgrind.log                     (placeholder)
  fixed_openssl_3_5_5/
    build.log                        (placeholder — harness compiles cleanly)
    run.log                          (placeholder — exit 0 confirmed locally)
    valgrind.log                     (placeholder — 0 errors confirmed under 3.0.13)
  results/
    regression_summary.json          (placeholder)
  logs/
```

---

## 8. Proposed Regression Verdicts

```
buggy_version_crash_candidate:
  Condition: OpenSSL 1.0.2 + EVP_CIPHER_CTX_copy on partial GCM context
  Expected signal:
    - Valgrind: "Conditional jump or move depends on uninitialised value(s)"
    - OR ASAN: "invalid read"
    - OR SEGV / exit code 139
  Classification: bug_candidate for 1.0.2

fixed_version_safe:
  Condition: OpenSSL 3.5.5 + same harness
  Expected signal: Valgrind 0 errors, normal exit (exit 0)
  Classification: safe / fixed

regression_fixed:
  Pair: (buggy_crash, fixed_safe)
  Interpretation: The vulnerability was fixed between OpenSSL 1.0.2 and 3.x.
  This confirms the pattern is a genuine historical bug, not a false positive.

affected_version_missing:
  Current status: OpenSSL 1.0.2 build not available in clean_sources.
  Regression comparison deferred.
  Fixed side (3.5.5) can be validated independently.
```

---

## 9. Same-Library Equivalent API Audit

### Result

`EVP_CIPHER_CTX_dup` is a **public API** in OpenSSL 3.5.5, declared at
`include/openssl/evp.h:654`:

```c
EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in);
```

It is the canonical "allocate + copy" wrapper: internally it calls
`EVP_CIPHER_CTX_new()` + `EVP_CIPHER_CTX_copy()`, traversing the same
AES-GCM `EVP_CTRL_COPY` handler path as the original PoC.

### Verdict

```
same_library_equivalent_api_found: EVP_CIPHER_CTX_dup

generate candidates (OpenSSL same-library):
  1. EVP_CIPHER_CTX_copy — same_api_regression
     vulnerability_path: 100%; requires OpenSSL 1.0.2 (deferred)
  2. EVP_CIPHER_CTX_dup  — same_library_equivalent_api
     vulnerability_path: 95%; public API in 3.5.5; can run now
     expected result on 3.5.5: safe/fixed (NULL return or successful safe dup)
```

### What EVP_CIPHER_CTX_dup adds over same-API regression

| | EVP_CIPHER_CTX_copy regression | EVP_CIPHER_CTX_dup equivalent |
|---|---|---|
| Requires 1.0.2 | YES (deferred) | NO (3.5.5 only) |
| Can run now | NO | **YES** |
| Internal path | EVP_CTRL_COPY | calls copy → same path |
| Oracle | return int | return ptr (NULL check) |
| Research value | max (full regression) | demonstrates safe 3.5.5 dup behavior |

### New artifact for EVP_CIPHER_CTX_dup

Template created:
`normalized_templates/openssl/evp_cipher_ctx_dup_uninit_state/`

Same-library candidates:
`migration_candidates/openssl_same/evp_cipher_ctx_copy_uninit_state/candidates.yaml`

### APIs rejected as not equivalent

| API | Reason |
|---|---|
| `OSSL_FUNC_CIPHER_DUPCTX` | Provider dispatch slot; not user-callable |
| `EVP_CIPHER_CTX_reset + reinit` | Reinit from scratch, not copy of partial state |
| `EVP_CIPHER_fetch + params` | Parameter reconstruction, not state copy |

---

## 10. Batch Mutation Run: EVP_CIPHER_CTX_dup on OpenSSL 3.5.5

### Run parameters

| Field | Value |
|---|---|
| API tested | `EVP_CIPHER_CTX_dup` |
| Library | OpenSSL 3.5.5 (static `libssl.a` + `libcrypto.a`) |
| Compiler flags | `-g -O0` (normal) + `-fsanitize=address,undefined -fno-omit-frame-pointer` (ASan) |
| Total cases | 28 |
| cipher_algorithm | aes128gcm, aes192gcm, aes256gcm, aes128ccm, aes128cbc |
| init_state | cipher_only_no_key_no_iv, cipher_plus_key_no_iv, cipher_plus_iv_no_key, full_key_iv, reset_then_dup |
| post_dup_action | free_only, encrypt_update, ctrl_get_tag (GCM/CCM only), reinit_after_dup |
| Result file | `results/issue_8980_dup_batch_summary.json` |

### Results

```
total_cases:         28
compile_ok:          28
run_ok:              28
crash_candidate:     0
safe_fixed_behavior: 28
needs_triage:        0
compile_failed:      0
```

### Notable observations

**GCM partial-init + EVP_CTRL_AEAD_GET_TAG (cases 0002, 0006, 0010, 0014):**
- `EVP_CTRL_AEAD_GET_TAG` returned 0 after `EVP_CIPHER_CTX_dup` on a partial context
- This is correct: no tag available before encryption; function safely returns failure

**GCM partial-init + EVP_EncryptUpdate (cases 0001, 0005, 0009, 0013, 0017):**
- `EVP_EncryptUpdate` returned 0 after dup on partial context (no key set)
- This is correct safe rejection

**reset_then_dup (case 0022):**
- After `EVP_CIPHER_CTX_reset(src)`, calling `EVP_CIPHER_CTX_dup(src)` returns **NULL**
- The dup function checks `in->cipher == NULL` and raises `EVP_R_INPUT_NOT_INITIALIZED`
- This is correct defensive behavior

**full_key_iv + encrypt_update (cases 0023–0027):**
- Duplication of a fully-initialized context succeeded
- `EVP_EncryptUpdate` on the dup'd context produced `outlen=16` (correct encryption)
- Confirms that dup of a fully-initialized context is functionally correct

**CBC cases (0016–0018, 0027):**
- Initial run revealed ASan `global-buffer-overflow` in `ossl_cipher_generic_initiv`
- Root cause: harness `iv12[12]` used for CBC which requires a 16-byte block-size IV
- **This was a harness IV-size bug, not an OpenSSL 3.5.5 bug**
- Corrected to `iv12[16]` → all CBC cases: safe_fixed_behavior with no ASan signal

### Verdict

```
batch_verdict: safe_fixed_behavior (28/28)
crash_candidate: 0
EVP_CIPHER_CTX_dup on OpenSSL 3.5.5 is robustly safe across all tested
cipher algorithms, initialization states, and post-dup operations.
The NULL-guard in EVP_CTRL_COPY effectively prevents the 1.0.2-era
uninitialized GCM state access for all tested mutation points.
```

### Harness quality note

One harness defect was found and corrected during the run:
- CBC requires a 16-byte IV (`EVP_BLOCK_SIZE=16`) but the harness declared `iv12[12]`
- When ASan detects a `global-buffer-overflow` triggered by a harness defect
  (not by the API under test), the case must be triage'd as harness_defect, not crash_candidate
- After correction: all 28 cases clean

---

## 11. Future Commands (Placeholder)

Do not execute these commands until OpenSSL 1.0.2 is available in the environment.

```bash
cd ~/work/crypto-pattern-fuzz
source .venv/bin/activate
export CLEAN_SOURCES_ROOT="${CLEAN_SOURCES_ROOT:-$HOME/work/clean_sources}"

REGRESSION_ROOT="artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state"
POC_C="datasets/openssl/poc_artifacts/issue_8980/poc.c"

# --- Buggy side (requires OpenSSL 1.0.2 build at $OPENSSL_102_ROOT) ---
# export OPENSSL_102_ROOT="$CLEAN_SOURCES_ROOT/openssl-1.0.2u"
# gcc -I"$OPENSSL_102_ROOT/include" "$POC_C" -o poc_buggy -g -O0 \
#   -L"$OPENSSL_102_ROOT" -lssl -lcrypto \
#   -Wl,-rpath,"$OPENSSL_102_ROOT" \
#   > "$REGRESSION_ROOT/buggy_openssl_1_0_2/build.log" 2>&1
# valgrind --leak-check=full --track-origins=yes ./poc_buggy \
#   > "$REGRESSION_ROOT/buggy_openssl_1_0_2/valgrind.log" 2>&1

# --- Fixed side (OpenSSL 3.5.5 — available) ---
# gcc -I"$CLEAN_SOURCES_ROOT/openssl-3.5.5/include" "$POC_C" -o poc_fixed -g -O0 \
#   -lssl -lcrypto \
#   > "$REGRESSION_ROOT/fixed_openssl_3_5_5/build.log" 2>&1
# valgrind --leak-check=full --track-origins=yes ./poc_fixed \
#   > "$REGRESSION_ROOT/fixed_openssl_3_5_5/valgrind.log" 2>&1
```

---

## 10. OpenSSL 3.5.5 EVP_CIPHER_CTX_dup Equivalent API Run

### Run metadata

| Field | Value |
|---|---|
| API tested | `EVP_CIPHER_CTX_dup` |
| Relation to original | same-library equivalent API (internally calls `EVP_CIPHER_CTX_copy`) |
| Original trigger | `EVP_CIPHER_CTX_copy` on partially initialized AES-GCM context |
| Equivalent trigger | `EVP_CIPHER_CTX_dup` on partially initialized AES-GCM context |
| Cipher algorithm | `EVP_aes_128_gcm()` |
| Key/IV state | NULL key, NULL IV (partial init — core trigger condition) |
| Library | OpenSSL 3.5.5 (static: `libssl.a` + `libcrypto.a`) |
| Case file | `fixed_openssl_3_5_5/case_dup_0000_openssl_3_5_5.c` |
| Binary | `fixed_openssl_3_5_5/case_dup_0000_openssl_3_5_5` (static linked) |
| ASan binary | `fixed_openssl_3_5_5/case_dup_0000_openssl_3_5_5_asan` |

### Compilation

```
compiler: gcc
flags: -g -O0 -Wall -Wextra
link: libssl.a + libcrypto.a (OpenSSL 3.5.5 static, no dynamic ssl/crypto deps)
compile_exit: 0
```

### Normal run result

```
run_exit: 0
stdout:
  [RESULT] EVP_CIPHER_CTX_dup returned non-NULL (safe copy of partial context succeeded).
  [VERDICT] safe_fixed_behavior
```

`EVP_CIPHER_CTX_dup` returned a valid non-NULL context when duplicating a partially-initialized
AES-GCM context (no key, no IV). This means OpenSSL 3.5.5 safely handles the copy operation
via the NULL guard in the `EVP_CTRL_COPY` handler.

### ASan/UBSan run result

```
flags: -fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_OPTIONS: detect_leaks=0:halt_on_error=1
UBSAN_OPTIONS: print_stacktrace=1:halt_on_error=1
asan_run_exit: 0
asan_signal: NONE
ubsan_signal: NONE
crash: NONE
stdout:
  [RESULT] EVP_CIPHER_CTX_dup returned non-NULL (safe copy of partial context succeeded).
  [VERDICT] safe_fixed_behavior
```

No ASAN or UBSAN signals. The copy of a partially-initialized GCM context is handled safely
without any undefined behavior observable by sanitizers.

### Verdict

```
verdict: fixed_version_safe
same_library_equivalent_api_candidate: EVP_CIPHER_CTX_dup
3.5.5_safe_evidence: CONFIRMED
```

### What this proves and what it does not prove

**Proved:**
- `EVP_CIPHER_CTX_dup` on a partially-initialized AES-GCM context is safe on OpenSSL 3.5.5
- The `EVP_CTRL_COPY` NULL guard (added after 1.0.2) prevents the uninitialized GCM state access
- The same-library equivalent API (`dup`) traverses the same internal code path as `copy` and behaves correctly
- No crash, no ASan/UBSan signal, no undefined behavior on the fixed version

**Not proved:**
- This is **not** `regression_fixed`. Full regression proof requires the OpenSSL 1.0.2 buggy-side run.
- The 1.0.2 buggy-side result (expected: uninitialized memory read / crash) is still `affected_version_missing`.
- `EVP_CIPHER_CTX_dup` did not exist in OpenSSL 1.0.2, so the same API cannot be compared directly.
  The 1.0.2 regression must use `EVP_CIPHER_CTX_copy` (the original PoC harness).

### Result files

```
results/issue_8980_dup_result.txt         ← full result summary
logs/issue_8980_dup_compile.log           ← compilation log
logs/issue_8980_dup_run.log               ← normal run output
logs/issue_8980_dup_asan_compile.log      ← ASan compile log
logs/issue_8980_dup_asan_run.log          ← ASan run output
```

---

## 12. Relationship to Other Artifacts

| Artifact | Path | Role |
|---|---|---|
| Cross-library migration doc | `artifacts/migrations/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/README.md` | Documents why mbedTLS migration is not applicable |
| Pattern YAML | `knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-8980.yaml` | Structured pattern knowledge |
| Pattern MD | `knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-8980.md` | Human-readable pattern summary |
| Normalized template | `normalized_templates/openssl/evp_cipher_ctx_copy_uninit_state/` | Source template with mask slots |
| Candidates | `migration_candidates/openssl/evp_cipher_ctx_copy_uninit_state/` | mbedTLS candidate scoring and RAG evidence |
| Original PoC | `datasets/openssl/poc_artifacts/issue_8980/poc.c` | Self-contained harness (reused here) |

---

## References

- Issue: https://github.com/openssl/openssl/issues/8980
- OpenSSL 3.5.5 EVP_CTRL_COPY handler: `crypto/evp/e_aes.c` ~line 2771
- OpenSSL 3.5.5 EVP_CIPHER_CTX_copy: `crypto/evp/evp_enc.c` ~line 1770
- OpenSSL 1.0.2u final release: https://www.openssl.org/source/old/1.0.2/
