# Full Migration Pipeline Runbook

## A. Conceptual Flow

```text
Real PoC / patch / run logs
  -> vulnerability-pattern abstraction
  -> source-library template generation and multi-granularity masking
  -> RAG-enhanced candidate API semantic mapping
  -> LLM structured adapter generation and validation
  -> cross-library template generation, batch testing, and result analysis
```

The project is pattern-guided rather than coverage-guided. A migration is useful
when the target API preserves the source vulnerability path closely enough to
make the generated harness meaningful.

## B. Command Template

Set variables for the PoC under migration:

```bash
export POC_ID=MBEDTLS-POC-XXXX
export TEMPLATE_ROOT=normalized_templates/<category>/<slug>
export CANDIDATE_DIR=migration_candidates/<category>/<slug>
export ARTIFACT_SLUG=<poc-id-and-short-slug>
export ARTIFACT_ROOT=artifacts/migrations/${ARTIFACT_SLUG}
export ADAPTER_ROOT=${ARTIFACT_ROOT}/adapters
export VALIDATED_ADAPTER_ROOT=${ARTIFACT_ROOT}/adapters_validated
export CROSS_ROOT=${ARTIFACT_ROOT}/cross_templates
export RENDERED_ROOT=${ARTIFACT_ROOT}/rendered_cases
export RESULT_PREFIX=${ARTIFACT_ROOT}/results/run
export LOG_ROOT=${ARTIFACT_ROOT}/logs
```

The knowledge, template, and candidate layers keep their standard locations:

```text
knowledge_raw/
normalized_templates/
migration_candidates/
```

Local library paths are resolved through:

```bash
export CLEAN_SOURCES_ROOT=/path/to/clean_sources
```

If `CLEAN_SOURCES_ROOT` is unset, the default is:

```text
<project_root>/../clean_sources
```

If the LLM adapter stage is used, configure the project-specific LLM key through
an environment variable such as:

```bash
export ZHIPUAI_API_KEY=...
```

Do not write API keys into repository files.

## C. Recommended Artifact Layout

Starting with new PoCs such as `MBEDTLS-POC-0004`, run-generated artifacts
should be grouped under:

```text
artifacts/migrations/<artifact_slug>/
```

Recommended variables:

```bash
ARTIFACT_ROOT="artifacts/migrations/${ARTIFACT_SLUG}"
ADAPTER_ROOT="${ARTIFACT_ROOT}/adapters"
VALIDATED_ADAPTER_ROOT="${ARTIFACT_ROOT}/adapters_validated"
CROSS_ROOT="${ARTIFACT_ROOT}/cross_templates"
RENDERED_ROOT="${ARTIFACT_ROOT}/rendered_cases"
RESULT_PREFIX="${ARTIFACT_ROOT}/results/run"
LOG_ROOT="${ARTIFACT_ROOT}/logs"
```

The following project layers continue to use their existing standard locations:

```text
knowledge_raw/
normalized_templates/
migration_candidates/
```

Historical root-level outputs such as `adapters_*`, `cross_templates_*`,
`rendered_cases_*`, and `runner/results/run_*` should be preserved for
reproducibility, but new PoC runs should prefer the grouped artifact layout.

## 1. Build Or Refresh RAG Knowledge

Use this when raw knowledge files have changed:

```bash
PYTHONPATH=. python3 -m knowledge.rag_builder
```

## 2. Validate The Normalized Template

```bash
PYTHONPATH=. python3 -m template_maker.validate_template \
  --root "$TEMPLATE_ROOT"
```

## 3. Generate Multi-Granularity Mask Reports

```bash
PYTHONPATH=. python3 -m template_maker.ast_mask_lite \
  --root "$TEMPLATE_ROOT"

PYTHONPATH=. python3 -m template_maker.ast_mask_select \
  --root "$TEMPLATE_ROOT"
```

Expected outputs:

```text
$TEMPLATE_ROOT/ast_mask_report.yaml
$TEMPLATE_ROOT/selected_mask_units.yaml
```

## 4. Candidate API Mapping

If a rule-based mapper exists for the template family, use it. Otherwise, create
`$CANDIDATE_DIR/candidates.yaml` manually using the same scoring dimensions:

```text
operation_family
function_behavior
parameter_structure
vulnerability_path
harness_feasibility
```

Candidate entries should explain:

- target library and API
- decision: `generate`, `needs_llm_review`, or `skip`
- preserved vulnerability-path features
- lost or weakened features
- harness feasibility

## 5. Collect RAG Evidence

```bash
PYTHONPATH=. python3 -m migration.evidence_collector \
  --candidates "$CANDIDATE_DIR/candidates.yaml" \
  --mask-report "$TEMPLATE_ROOT/mask_report.yaml" \
  --output "$CANDIDATE_DIR/candidates_with_evidence.yaml" \
  --top-k 5
```

Check that the generated YAML parses and that evidence queries are non-empty.

## 6. Generate Structured Adapters With LLM

Only run this stage when intentionally entering the LLM adapter-generation
phase:

```bash
PYTHONPATH=. python3 -m migration.adapter_filler \
  --candidates "$CANDIDATE_DIR/candidates_with_evidence.yaml" \
  --template-root "$TEMPLATE_ROOT" \
  --out-root "$ADAPTER_ROOT" \
  --use-llm
```

The exact flags may vary by adapter family. Keep adapter output structured and
reviewable.

## 7. Validate Adapters

```bash
PYTHONPATH=. python3 -m migration.adapter_validate \
  --adapter-root "$ADAPTER_ROOT" \
  --out-root "$VALIDATED_ADAPTER_ROOT"
```

Proceed only with validated adapters.

## 8. Generate Cross-Library Templates

```bash
PYTHONPATH=. python3 -m template_maker.cross_generator_from_adapters \
  --adapter-root "$VALIDATED_ADAPTER_ROOT" \
  --out-root "$CROSS_ROOT"
```

## 9. Render Concrete Cases

```bash
PYTHONPATH=. python3 -m template_maker.render_cases \
  --root "$CROSS_ROOT" \
  --out-root "$RENDERED_ROOT" \
  --max-cases 32
```

Check that C placeholders were rendered:

```bash
grep -R "\[[A-Z0-9_]\+\]" -n "$RENDERED_ROOT" --include="*.c" || \
  echo "OK: C placeholders rendered"
```

## 10. Compile And Run

```bash
PYTHONPATH=. python3 -m runner.compile_run \
  --input-root "$RENDERED_ROOT" \
  --result "${RESULT_PREFIX}.jsonl" \
  --keep-going
```

## 11. Analyze Per-Case Results

```bash
PYTHONPATH=. python3 -m runner.analyze_results \
  --input "${RESULT_PREFIX}.jsonl" \
  --output "${RESULT_PREFIX}.summary.json" \
  --case-output "${RESULT_PREFIX}.verdicts.jsonl"
```

## 12. Analyze Cross-Library Migration Results

```bash
PYTHONPATH=. python3 -m runner.analyze_cross_results \
  --input "${RESULT_PREFIX}.summary.json" \
  --output "${RESULT_PREFIX}.migration_summary.json" \
  --pair-output "${RESULT_PREFIX}.migration_pairs.jsonl" \
  --source-lib mbedtls \
  --target-lib openssl
```

### Migration Verdicts

Cross-library migration analysis can produce several meaningful outcomes:

- `migrated_bug_candidate`: the source-side behavior and target-side behavior
  indicate that the vulnerability pattern may have migrated to the target API.
- `migrated_safe`: both sides show safe behavior for the rendered cases, or the
  target safely rejects the migrated malformed input.
- `migration_needs_triage`: the available source/target verdict pair is not
  strong enough for an automatic migrated/safe classification.

Not every historical PoC should be expected to migrate into a target-library bug
candidate. A safe/safe result is a valid experimental result: it documents that
the target API preserved enough of the tested vulnerability path to be exercised
and did not reproduce the problematic behavior under the current oracle.

## 13. Print Result Statistics

```bash
python3 - <<'PY'
import json
from collections import Counter

prefix = "runner/results/run_<slug>"
s = json.load(open(prefix + ".summary.json", encoding="utf-8"))
m = json.load(open(prefix + ".migration_summary.json", encoding="utf-8"))

print("total_cases:", s.get("total_cases"))
print("raw_status_counts:", s.get("raw_status_counts"))
print("verdict_counts:", s.get("verdict_counts"))
print("total_pairs:", m.get("total_pairs"))
print("migration_verdict_counts:", m.get("migration_verdict_counts"))
PY
```

## Notes

- Keep generated adapters and candidates reviewable before running large batches.
- Do not treat all `bug_candidate` verdicts as crashes. Some families, such as
  DER pointer-consumption, use semantic oracles.
- Keep `runner/results/` artifacts unless intentionally regenerating an
  experiment result.
