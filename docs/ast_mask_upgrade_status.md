# AST Mask Upgrade Status

This document summarizes the current upgrade work on the AST masking and
pattern-migration pipeline.

## Goal

The upgrade goal is to move from:

```text
regex / brace matching / role-aware rules
```

to:

```text
real AST backend + family-aware selection + dependency-aware mask units
```

while keeping the existing outputs compatible:

```text
ast_mask_report.yaml
selected_mask_units.yaml
```

The existing lite backend remains the default path. The new tree-sitter backend
is optional and currently runs as a parallel comparison backend.

## Branch And Commit

```text
branch: ast-mask-tree-sitter-upgrade
commit: 4d9258468d3ec357893b894372568485c565ef78
```

## Major Changes

### 1. AST Mask Backend

Changed or added files:

```text
template_maker/ast_mask.py
template_maker/ast_mask_lite.py
template_maker/ast_mask_tree_sitter.py
template_maker/ast_mask_select.py
config/harness_family_ast_rules.yaml
docs/ast_mask_backend.md
```

Implemented features:

- Added unified AST mask CLI:

```bash
python3 -m template_maker.ast_mask --root <template_root> --backend lite
python3 -m template_maker.ast_mask --root <template_root> --backend tree-sitter
```

- Added optional `tree-sitter` backend for C templates.
- Kept lite backend as the default compatible backend.
- Added family-aware selection rules in:

```text
config/harness_family_ast_rules.yaml
```

- Added support for alternate AST report and selected-unit output names:

```bash
python3 -m template_maker.ast_mask_select \
  --root <template_root> \
  --ast-report-name ast_mask_report.tree_sitter.yaml \
  --output-name selected_mask_units.tree_sitter.yaml
```

New or enriched mask-unit fields include:

```text
node_type
line_start
line_end
column_start
column_end
enclosing_function
called_function
identifiers_read
identifiers_written
placeholder_dependencies
control_context
```

### 2. Family-Aware Selection

The selection policy is now driven by harness-family rules rather than only
global hard-coded keywords.

Important examples:

```text
der_pointer_consumption
null_deref_dispatch
return_code_outlen_semantic
x509_asn1_inner_boundary
buffer_canary_boundary
```

This is especially useful for `MBEDTLS-POC-0020`, where DER-specific keywords
such as `DER`, `SEQUENCE`, `trailing`, `der_len`, `consumed_len`, `parse_key`,
and `d2i` are more relevant than bignum/canary terms.

### 3. Migration Tooling

Changed files:

```text
migration/candidate_mapper.py
migration/evidence_collector.py
migration/adapter_filler.py
migration/adapter_validate.py
```

Implemented features:

- Added support for explicitly passing selected mask units:

```bash
--selected-mask-units selected_mask_units.tree_sitter.yaml
```

- Allows `evidence_collector.py` and `adapter_filler.py` to consume either lite
  or tree-sitter selected units.
- Improved fallback evidence handling for cases where RAG evidence is sparse.
- Improved adapter validation for recipe-driven migration paths.

### 4. Recipe-Driven Cross Generation

Changed or added files:

```text
template_maker/cross_generator_from_adapters.py
adapter_recipes/openssl/EVP_DigestVerify.null_deref_dispatch.yaml
adapter_recipes/openssl/d2i_PrivateKey.der_pointer_consumption.yaml
```

Implemented features:

- Added OpenSSL recipe for:

```text
EVP_DigestVerify / null_deref_dispatch
```

- Added OpenSSL recipe for:

```text
d2i_PrivateKey / der_pointer_consumption
```

- The `d2i_PrivateKey` recipe supports the `MBEDTLS-POC-0020` DER trailing
  garbage migration path.

Expected oracle for `d2i_PrivateKey`:

```text
ret == 0 and consumed_len < der_len
  => migrated bug candidate

ret == 0 and consumed_len == der_len
  => safe full consumption

ret != 0
  => safe rejection
```

### 5. Rendering And Runner Analysis

Changed files:

```text
template_maker/render_cases.py
runner/compile_run.py
runner/analyze_results.py
runner/analyze_cross_results.py
```

Implemented features:

- Improved placeholder handling during render checks.
- Added dry-run support and richer metadata propagation in `compile_run.py`.
- Improved verdict classification for the new and existing harness families.
- Improved cross-result analysis for migration verdicts.

### 6. Smoke Test Script

Added file:

```text
scripts/run_pk_null_deref_dry_pipeline.sh
```

Purpose:

- Runs a dry pipeline for `pk_verify_ext_null_deref`.
- Uses generated candidates, evidence, adapters, cross templates, rendered cases,
  dry-run compile results, and analysis outputs.
- Does not require local clean source trees.

Example:

```bash
SELECTED_MASK_UNITS=normalized_templates/pk/pk_verify_ext_null_deref/selected_mask_units.tree_sitter.yaml \
SMOKE_ROOT=/tmp/cipherlens_precommit_pk_tree_smoke \
MAX_CASES=2 \
scripts/run_pk_null_deref_dry_pipeline.sh
```

Observed dry-run result:

```text
total_cases: 4
raw_status_counts: dry_run=4
verdict_counts: not_executed=4
total_pairs: 2
migration_verdict_counts: migration_not_executed=2
placeholder issues: 0
```

## Generated Template Artifacts

Updated or added artifacts include:

```text
normalized_templates/rsa/rsa_der_trailing_garbage/
  ast_mask_report.yaml
  selected_mask_units.yaml
  ast_mask_report.tree_sitter.yaml
  selected_mask_units.tree_sitter.yaml

normalized_templates/pk/pk_verify_ext_null_deref/
  ast_mask_report.yaml
  selected_mask_units.yaml
  ast_mask_report.tree_sitter.yaml
  selected_mask_units.tree_sitter.yaml

normalized_templates/bignum/mpi_sub_abs/
normalized_templates/bignum/mpi_write_string/
```

Current interpretation:

- Lite output remains the default compatibility artifact.
- Tree-sitter output is used for structured comparison and optional downstream
  context.
- The tree-sitter backend selects more precise trigger calls for `0020` and
  `pk_verify_ext_null_deref`.

## Verified Locally

The following checks were run locally before commit:

```bash
python3 -m py_compile \
  template_maker/ast_mask.py \
  template_maker/ast_mask_tree_sitter.py \
  template_maker/ast_mask_lite.py \
  template_maker/ast_mask_select.py \
  template_maker/mask_report.py \
  template_maker/validate_template.py \
  template_maker/render_cases.py \
  template_maker/cross_generator_from_adapters.py \
  migration/candidate_mapper.py \
  migration/evidence_collector.py \
  migration/adapter_filler.py \
  migration/adapter_validate.py \
  runner/compile_run.py \
  runner/analyze_results.py \
  runner/analyze_cross_results.py
```

Also checked:

```text
No obvious API key was found in the diff.
No hard-coded /home/wen/work/clean_sources path was found.
```

Dry-run smoke passed for:

```text
pk_verify_ext_null_deref -> OpenSSL EVP_DigestVerify
```

The `d2i_PrivateKey` DER recipe path was also rendered and dry-run checked.

## Tests Still Needed

These require local clean source trees:

```text
clean_sources/
  mbedtls-4.1.0/
  openssl-3.5.5/
```

Recommended real compile/run tests:

### 1. MBEDTLS-POC-0020 DER Pointer Consumption

Run the full pipeline for:

```text
normalized_templates/rsa/rsa_der_trailing_garbage
target: OpenSSL d2i_PrivateKey / d2i_RSAPrivateKey / d2i_RSA_PUBKEY
```

Expected checks:

- rendered C files have no unresolved placeholders;
- mbedTLS source cases compile and run;
- OpenSSL target cases compile and run;
- `consumed_len` and `der_len` are recorded;
- cross analysis distinguishes:

```text
migrated_bug_candidate
migrated_safe
migration_needs_triage
```

### 2. pk_verify_ext_null_deref

Run real compile/run for:

```text
normalized_templates/pk/pk_verify_ext_null_deref
target: OpenSSL EVP_DigestVerify
```

Expected checks:

- generated harness compiles;
- incompatible key dispatch path is reached;
- safe rejection is not misclassified as a crash;
- sanitizer crash evidence is required before any crash verdict.

### 3. Compare Lite And Tree-Sitter Selection

For each important template:

```bash
python3 -m template_maker.ast_mask_select \
  --root <template_root>

python3 -m template_maker.ast_mask_select \
  --root <template_root> \
  --ast-report-name ast_mask_report.tree_sitter.yaml \
  --output-name selected_mask_units.tree_sitter.yaml
```

Compare:

```text
selected trigger calls
oracle units
mutation points
placeholder dependencies
identifier read/write sets
```

## Known Limitations

- Tree-sitter backend is optional and not yet the default.
- The tree-sitter backend extracts useful C syntax structure, but it is not yet
  a full semantic compiler frontend.
- Identifier read/write inference is lightweight and may need refinement.
- Dependency-aware units are currently heuristic, not full data-flow analysis.
- Real compile/run validation still depends on local source-library paths.
- The current PR may have merge conflicts with `main`; resolve after teammate
  testing or before final merge.

## Recommended Next Steps

1. Ask a teammate with clean source trees to run real compile/run smoke tests.
2. Use the dry-run script as the first reproducibility check.
3. Compare lite and tree-sitter selected units for `0020` and
   `pk_verify_ext_null_deref`.
4. Resolve merge conflicts with `main` when ready to open or finalize a PR.
5. If real tests pass, consider making tree-sitter selected units the preferred
   input for adapter generation while keeping lite as fallback.
6. Continue improving dependency-aware selection:

```text
trigger call dependencies
oracle-observed variables
cleanup-owned objects
input-construction variables
mutation placeholder propagation
```

7. Add more recipe-backed harness families in a data-driven way instead of
   adding one-off Python branches for every PoC.

