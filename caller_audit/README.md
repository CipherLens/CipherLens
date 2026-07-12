# CipherLens Caller Audit v0.1

v0.1 adds:

- per-case structured dynamic parsing;
- a patched fix-control phase;
- a complete MLS++ RSA regression configuration;
- reusable public-key and X.509 parser recipes.

## MLS++ regression

Required environment:

```bash
export MLSPP_ROOT="$HOME/workplace/third_party/caller-audit/mlspp"
export MLSPP_BUILD="$MLSPP_ROOT/build-cipherlens"
export OPENSSL_ROOT="$HOME/workplace/CryptoPoc/clean_sources/openssl-3.5.5"

export MLSPP_FIX_SRC="$HOME/workplace/third_party/caller-audit/mlspp-fix-control"
export MLSPP_FIX_BUILD="$HOME/workplace/third_party/caller-audit/mlspp-fix-control-build"

export BASELINE_HARNESS_BUILD="$PWD/artifacts/migrations/mbedtls-poc-0020-spki-v2/caller_audit/mlspp/v0.1-build/baseline"
export FIX_HARNESS_BUILD="$PWD/artifacts/migrations/mbedtls-poc-0020-spki-v2/caller_audit/mlspp/v0.1-build/fix"
```

Run:

```bash
PYTHONPATH=. python3 -m caller_audit.run \
  --config caller_audit/examples/mlspp_rsa_private_v0_1.yaml \
  --out-root artifacts/migrations/mbedtls-poc-0020-spki-v2/caller_audit/mlspp/v0.1
```

Expected verdict:

```text
[VERDICT] downgraded_unreachable
```

The verdict is emitted only after:

1. the canonical input succeeds;
2. all three tailed inputs succeed in the original caller;
3. the canonical input still succeeds in the patched caller;
4. all three tailed inputs are rejected by the patched caller.
