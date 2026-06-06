# AST Mask Backends

This project currently supports two AST mask report modes:

```text
lite
  Existing regex / role-aware / template-aware backend.

tree-sitter
  Optional tree-sitter C backend that extracts concrete syntax nodes.
```

The tree-sitter backend is a parallel experimental backend. It does not replace
the default lite backend.

---

## Output Files

Default lite outputs:

```text
ast_mask_report.yaml
selected_mask_units.yaml
```

Tree-sitter parallel outputs:

```text
ast_mask_report.tree_sitter.yaml
selected_mask_units.tree_sitter.yaml
```

Meaning:

```text
ast_mask_report.yaml
  Default AST-lite report used by the existing pipeline.

ast_mask_report.tree_sitter.yaml
  Optional tree-sitter report. It should be used for comparison or explicit
  downstream experiments.

selected_mask_units.yaml
  Default selected high-value mask units derived from ast_mask_report.yaml.

selected_mask_units.tree_sitter.yaml
  Tree-sitter selected high-value mask units derived from
  ast_mask_report.tree_sitter.yaml.
```

---

## Generate Tree-Sitter Reports

Example for `pk_verify_ext_null_deref`:

```bash
.venv/bin/python -m template_maker.ast_mask \
  --root normalized_templates/pk/pk_verify_ext_null_deref \
  --backend tree-sitter

.venv/bin/python -m template_maker.ast_mask_select \
  --root normalized_templates/pk/pk_verify_ext_null_deref \
  --ast-report-name ast_mask_report.tree_sitter.yaml \
  --output-name selected_mask_units.tree_sitter.yaml
```

Example for `MBEDTLS-POC-0020`:

```bash
.venv/bin/python -m template_maker.ast_mask \
  --root normalized_templates/rsa/rsa_der_trailing_garbage \
  --backend tree-sitter

.venv/bin/python -m template_maker.ast_mask_select \
  --root normalized_templates/rsa/rsa_der_trailing_garbage \
  --ast-report-name ast_mask_report.tree_sitter.yaml \
  --output-name selected_mask_units.tree_sitter.yaml
```

The lite backend remains available:

```bash
.venv/bin/python -m template_maker.ast_mask \
  --root normalized_templates/pk/pk_verify_ext_null_deref \
  --backend lite

.venv/bin/python -m template_maker.ast_mask_select \
  --root normalized_templates/pk/pk_verify_ext_null_deref
```

---

## Optional Dependencies

The tree-sitter backend requires:

```text
tree_sitter
tree_sitter_c
```

Recommended local setup:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install tree_sitter tree_sitter_c
```

Do not treat these packages as required for the default lite pipeline unless the
project intentionally promotes tree-sitter to a required dependency.

---

## Current Interpretation

Current observations from `pk_verify_ext_null_deref` and `MBEDTLS-POC-0020`:

```text
tree-sitter trigger_call selection is more precise.
tree-sitter units include more structured source ranges and call metadata.
tree-sitter selected units are useful for downstream comparison.
tree-sitter is still a parallel backend, not the default replacement for lite.
```

Tree-sitter units may include fields such as:

```yaml
node_type:
line_start:
line_end:
column_start:
column_end:
enclosing_function:
called_function:
identifiers_read:
identifiers_written:
placeholder_dependencies:
```

These fields are intended to help later stages understand:

```text
which API call is the trigger,
which variables the trigger reads or writes,
which oracle statements observe behavior,
which mutation placeholders affect each statement or call.
```

---

## Downstream Usage

The default downstream pipeline still reads:

```text
selected_mask_units.yaml
```

To explicitly use tree-sitter selected units, pass:

```bash
--selected-mask-units normalized_templates/.../selected_mask_units.tree_sitter.yaml
```

Example evidence collection:

```bash
.venv/bin/python -m migration.evidence_collector \
  --candidates /tmp/candidates.yaml \
  --mask-report normalized_templates/pk/pk_verify_ext_null_deref/mask_report.yaml \
  --selected-mask-units normalized_templates/pk/pk_verify_ext_null_deref/selected_mask_units.tree_sitter.yaml \
  --output /tmp/candidates_with_evidence.yaml \
  --target-api EVP_DigestVerify \
  --top-k 5
```

Example adapter filling:

```bash
.venv/bin/python -m migration.adapter_filler \
  --mask-report normalized_templates/pk/pk_verify_ext_null_deref/mask_report.yaml \
  --selected-mask-units normalized_templates/pk/pk_verify_ext_null_deref/selected_mask_units.tree_sitter.yaml \
  --candidates-with-evidence /tmp/candidates_with_evidence.yaml \
  --out-root /tmp/adapters \
  --target-library openssl \
  --target-api EVP_DigestVerify \
  --require-recipes \
  --include-non-generate
```

The dry-run smoke script also supports:

```bash
SELECTED_MASK_UNITS=normalized_templates/pk/pk_verify_ext_null_deref/selected_mask_units.tree_sitter.yaml \
SMOKE_ROOT=/tmp/cipherlens_pk_tree_selected_script_smoke \
MAX_CASES=2 \
scripts/run_pk_null_deref_dry_pipeline.sh
```

---

## Compatibility Rule

Keep the default behavior stable:

```text
ast_mask_report.yaml
selected_mask_units.yaml
```

Use tree-sitter files only when explicitly requested:

```text
ast_mask_report.tree_sitter.yaml
selected_mask_units.tree_sitter.yaml
```

This keeps existing pipeline behavior backward-compatible while allowing
tree-sitter evidence and adapter-generation experiments.
