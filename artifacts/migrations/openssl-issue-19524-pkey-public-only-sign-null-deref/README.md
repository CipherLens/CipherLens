# OPENSSL-ISSUE-19524: Public-Only Key Sign Capability Mismatch

## Migration Status

**status: migrated_safe**

Both source (OpenSSL 3.5.5) and target (mbedTLS PSA) safely rejected signing with a
public-only key. No crash, no ASAN/UBSAN signal. Core capability mismatch oracle preserved.

---

## 1. Source Pattern Summary

| Field | Value |
|---|---|
| Pattern ID | OPENSSL-ISSUE-19524 |
| Template ID | PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF |
| Source issue | https://github.com/openssl/openssl/issues/19524 |
| Title | ED25519_sign and ED448_sign missing check for private_key leading to segfault |
| Component | PKEY/ED25519/ED448 |
| Affected versions | OpenSSL 3.0.2, OpenSSL 1.1.1r |
| CVE | None assigned |
| Artifact class | C_rag_seed_to_c_candidate |
| poc_type | C_API (self-contained, no external input) |
| Strict reproduction | false |
| Pattern YAML | knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-19524.yaml |

**Root cause (original bug):**
`EVP_DigestUpdate()` and the ED25519/ED448 sign implementation in affected versions
do not check that a private key is present before dereferencing private key material.
Calling `EVP_DigestSign` with a public-only key (created via `EVP_PKEY_new_raw_public_key`)
causes a NULL dereference in OpenSSL 3.0.2 / 1.1.1r.

**Core vulnerability path:**
```
EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, 32)  ← public-only key
    ↓
EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey)
    ↓
EVP_DigestSign(ctx, sig, &siglen, msg, msglen)                    ← TRIGGER
    ↓
Buggy (3.0.2 / 1.1.1r): NULL deref in private key path
Fixed (3.5.5): PSA error "not a private key" — safe reject
```

---

## 2. Source-Side Result (OpenSSL 3.5.5)

```
API sequence:
  EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, 32)
  EVP_MD_CTX_new()
  EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey)  → returns 1 (accepted)
  EVP_DigestSign(mdctx, sig, &siglen, msg, 4)        → returns 0 (rejected)

OpenSSL error: "not a private key" (eddsa_sig.c:405)

verdict: safe_reject_behavior
crash: NONE
ASAN/UBSAN: NONE (compiled with -fsanitize=address,undefined)
```

OpenSSL 3.5.5 **safely rejects** signing with a public-only key. The bug was fixed
after 1.1.1r / 3.0.2. Current version's behavior is the oracle baseline.

---

## 3. Target-Side Result (mbedTLS PSA 4.1.0)

```
API sequence:
  psa_import_key(PSA_KEY_TYPE_ECC_PUBLIC_KEY(SECP_R1), bits=256,
                 usage=PSA_KEY_USAGE_VERIFY_HASH)           → PSA_SUCCESS
  psa_sign_hash(key_id, PSA_ALG_ECDSA(SHA_256), ...)        → -133

PSA_ERROR_NOT_PERMITTED (-133)

verdict: safe_reject_behavior
crash: NONE
ASAN/UBSAN: NONE (compiled with -fsanitize=address,undefined)
```

**Note:** Ed25519 PSA support (`PSA_WANT_ALG_PURE_EDDSA`) is not enabled in the current
mbedTLS 4.1.0 build (`PSA_WANT_ALG_PURE_EDDSA` not defined in crypto_config.h). ECDSA/
SECP256R1 is used instead to express the same capability mismatch oracle:

```
public-only key (no SIGN capability) + sign attempt = PSA_ERROR_NOT_PERMITTED
```

The core vulnerability semantic is preserved: a library must not allow signing with a
key that has no private component / no sign usage flag.

---

## 4. Migration Result

| Metric | Value |
|---|---|
| total_cases | 2 |
| raw_status_counts | {'run_ok': 2} |
| verdict_counts | {'safe_reject_behavior': 2} |
| total_pairs | 1 |
| migration_verdict_counts | **{'migrated_safe': 1}** |
| incomplete_pair | 0 |
| crash evidence | NONE |

**Migration verdict: `migrated_safe`**

Both libraries correctly reject signing with a public-only key. This is a valid safe/safe
migration result demonstrating that the capability mismatch vulnerability pattern is
handled correctly in both the fixed OpenSSL 3.5.5 and mbedTLS PSA 4.1.0.

---

## 5. Full Artifact Chain

```
knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-19524.yaml
normalized_templates/openssl/pkey_public_only_sign_null_deref/
migration_candidates/openssl/pkey_public_only_sign_null_deref/candidates.yaml
migration_candidates/openssl/pkey_public_only_sign_null_deref/candidates_with_evidence.yaml
adapter_recipes/mbedtls/psa_sign_message.pkey_capability_mismatch_oracle.yaml
adapters_recipe_llm/PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF/mbedtls_psa_sign_message/adapter.yaml
  _llm_status: ok
  _adapter_mode: recipe_slot_filling
adapters_recipe_llm_validated/ (ok: 1, needs_repair: 0)
cross_templates_recipe/PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF/mbedtls_psa_sign_message/tmpl_mbedtls.c
rendered_cases_recipe/
  case_0000_public_only_sign_openssl.c          ← source side (OpenSSL 3.5.5)
  case_0000_psa_sign_message_ed25519_public_only_mbedtls.c  ← target side (mbedTLS PSA)
results/run_recipe.jsonl
results/run_recipe.summary.json
results/run_recipe.verdicts.jsonl
results/run_recipe.migration_summary.json
results/run_recipe.migration_pairs.jsonl
```

---

## 6. How to Re-run

```bash
cd ~/work/crypto-pattern-fuzz
source .venv/bin/activate
export PYTHONPATH=.
export CLEAN_SOURCES_ROOT="${CLEAN_SOURCES_ROOT:-$HOME/work/clean_sources}"

ARTIFACT_ROOT="artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref"
RENDERED_ROOT="$ARTIFACT_ROOT/rendered_cases_recipe"

PYTHONPATH=. python3 -m runner.compile_run \
  --input-root "$RENDERED_ROOT" \
  --result "$ARTIFACT_ROOT/results/run_recipe.jsonl" \
  --keep-going

PYTHONPATH=. python3 -m runner.analyze_results \
  --input "$ARTIFACT_ROOT/results/run_recipe.jsonl" \
  --output "$ARTIFACT_ROOT/results/run_recipe.summary.json" \
  --case-output "$ARTIFACT_ROOT/results/run_recipe.verdicts.jsonl"

PYTHONPATH=. python3 -m runner.analyze_cross_results \
  --input "$ARTIFACT_ROOT/results/run_recipe.summary.json" \
  --output "$ARTIFACT_ROOT/results/run_recipe.migration_summary.json" \
  --pair-output "$ARTIFACT_ROOT/results/run_recipe.migration_pairs.jsonl" \
  --source-lib openssl \
  --target-lib mbedtls
```

---

## References

- Issue: https://github.com/openssl/openssl/issues/19524
- Affected versions: OpenSSL 3.0.2, OpenSSL 1.1.1r
- Pattern YAML: knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-19524.yaml
- Original artifact: datasets/openssl/poc_artifacts/issue_19524/
