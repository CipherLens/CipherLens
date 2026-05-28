# Artifact Layout

## Why `artifacts/migrations`

The repository already has several root-level generated output directories:

```text
adapters_*
adapters_*_validated
cross_templates_*
rendered_cases_*
runner/results/run_*
```

These directories are useful for preserving historical experiments, but they
make the repository root harder to scan as more PoCs are migrated. Starting
with `MBEDTLS-POC-0004`, new migration run artifacts should be grouped under:

```text
artifacts/migrations/<artifact_slug>/
```

This keeps each experiment reproducible while separating run outputs from the
project's core knowledge and template layers.

## Directories That Stay In Their Standard Locations

The knowledge layer, normalized template layer, and candidate-evidence layer
remain in their existing project locations:

```text
knowledge_raw/poc_patterns/<library>/<POC_ID>.yaml
knowledge_raw/poc_patterns/<library>/<POC_ID>.md
normalized_templates/<category>/<slug>/
migration_candidates/<category>/<slug>/
```

These are part of the framework's core structure and should not be moved into
`artifacts/migrations/`.

## New Run Artifact Layout

For new migrations starting with `MBEDTLS-POC-0004`, place run-generated
artifacts under:

```text
artifacts/migrations/<artifact_slug>/
  adapters/
  adapters_validated/
  cross_templates/
  rendered_cases/
  results/
  logs/
```

Example:

```text
artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/
  adapters/
  adapters_validated/
  cross_templates/
  rendered_cases/
  results/
  logs/
```

## Recommended Variables

```bash
POC_ID="MBEDTLS-POC-0004"
CATEGORY="cipher"
SLUG="cipher_pkcs_padding_outlen_underflow"
ARTIFACT_SLUG="mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow"

TEMPLATE_ROOT="normalized_templates/${CATEGORY}/${SLUG}"
CANDIDATE_DIR="migration_candidates/${CATEGORY}/${SLUG}"
ARTIFACT_ROOT="artifacts/migrations/${ARTIFACT_SLUG}"

ADAPTER_ROOT="${ARTIFACT_ROOT}/adapters"
VALIDATED_ADAPTER_ROOT="${ARTIFACT_ROOT}/adapters_validated"
CROSS_ROOT="${ARTIFACT_ROOT}/cross_templates"
RENDERED_ROOT="${ARTIFACT_ROOT}/rendered_cases"
RESULT_PREFIX="${ARTIFACT_ROOT}/results/run"
LOG_ROOT="${ARTIFACT_ROOT}/logs"
```

## Root-Level Generated Directories

For new PoCs, do not prefer creating root-level generated directories such as:

```text
adapters_<slug>/
adapters_<slug>_validated/
cross_templates_<slug>_from_validated_adapters/
rendered_cases_<slug>_from_validated_adapters/
```

Use root-level generated directories only when preserving compatibility with an
older workflow or when explicitly requested.
