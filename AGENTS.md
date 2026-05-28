# AGENTS.md

## Project Context

This repository is an academic research prototype for **cryptographic-library vulnerability-pattern migration**.

The goal is **not** coverage-guided AFL++ fuzzing.
The goal is to build a **pattern-guided API harness generation and migration-verification framework**.

The project focuses on:

1. Starting from real cryptographic-library PoC / PR / CVE / patch / regression test.
2. Reproducing or inspecting buggy and fixed behavioral differences.
3. Extracting the root cause, patch semantics, failure signal, mutation points, and oracle.
4. Building a reusable PoC Pattern Layer.
5. Generating source-library templates and mask reports from PoC patterns.
6. Using AST-lite masking to identify mutation-relevant source fragments.
7. Using RAG evidence to evaluate cross-library candidate APIs.
8. Letting the LLM fill structured `adapter.yaml`, rather than directly generating full C files.
9. Validating adapters with semantic checks before harness generation.
10. Generating target-library API harnesses from structured templates and adapters.
11. Validating migration results with ASAN / UBSAN / canary / return-code / output-state / pointer-consumption oracles.

This project focuses on **vulnerability-pattern migration**, not random fuzzing or coverage maximization.

The intended contribution is to explore whether historical cryptographic-library vulnerability patterns can be:

```text
real PoC / patch / root cause
    ↓
vulnerability pattern abstraction
    ↓
cross-library API candidate evaluation
    ↓
structured adapter generation
    ↓
template-based harness rendering
    ↓
oracle-based migration validation
```

---

## Important Design Rules

* Do not break existing CLI behavior.
* Keep existing plain-text output mode working.
* Add new options in a backward-compatible way.
* Prefer structured JSON / YAML outputs for downstream tools.
* Do not hard-code demo-only behavior when a generic implementation is possible.
* Do not introduce AFL++ as a dependency.
* Do not store API keys, tokens, credentials, or secrets in code.
* Do not commit secrets or API keys.
* Do not remove existing files unless explicitly asked.
* Do not change existing output directories unless explicitly asked.
* Do not silently drop existing fields in YAML / JSON outputs.
* Keep generated outputs deterministic when possible.
* Keep error messages readable and actionable.
* Avoid unnecessary dependencies.
* Do not run destructive commands unless the user explicitly approves.
* Do not use `git push --force`.
* Do not overwrite other collaborators' work.
* When working with generated directories, prefer removing only task-specific output roots.
* When adding a new PoC, separate **PoC-specific artifacts** from **family-level framework changes**.

---

## Academic Positioning

This repository should be treated as an academic research prototype.

The intended research contribution is not simply finding crashes.
The intended contribution is to explore whether historical cryptographic-library vulnerability patterns can be:

1. abstracted from real PoCs and patches,
2. represented as structured templates,
3. migrated across libraries using API semantics and RAG evidence,
4. validated through generated harnesses and explicit oracles.

The project should prioritize:

* semantic correctness,
* traceability,
* reproducibility,
* structured intermediate artifacts,
* explainable migration decisions,
* careful distinction between crash bugs, semantic differences, safe rejections, and triage cases.

---

## Current Architecture

Important modules and directories:

```text
knowledge/
  rag_builder.py
  rag_query.py

knowledge_raw/
  api_constraints/
  poc_patterns/
  unit_tests/
  cross_lib_equivalence/
  wycheproof_vectors/

data/pocs/core10/
  MBEDTLS-POC-0001/
  MBEDTLS-POC-0002/
  MBEDTLS-POC-0003/
  MBEDTLS-POC-0004/
  MBEDTLS-POC-0005/
  MBEDTLS-POC-0011/
  MBEDTLS-POC-0017/
  MBEDTLS-POC-0020/
  MBEDTLS-POC-0027/
  MBEDTLS-POC-0028/

datasets/openssl/
  artifact_summary.csv
  artifact_validation_results.jsonl
  poc_artifacts/

template_maker/
  mask.py
  normalize_enriched.py
  validate_template.py
  ast_mask_lite.py
  ast_mask_select.py
  render_cases.py
  cross_generator_from_candidates.py
  cross_generator_from_adapters.py

migration/
  candidate_mapper.py
  evidence_collector.py
  adapter_filler.py
  adapter_validate.py

runner/
  compile_run.py
  analyze_results.py
  analyze_cross_results.py

utils/
  path_resolver.py

docs/
  setup_local_paths.md
  full_migration_pipeline.md
  harness_family_design.md

generated_templates/
enriched_templates/
normalized_templates/
migration_candidates/
adapters*/
adapters*_validated/
cross_templates*/
rendered_cases*/
runner/results/
```

Directory roles:

```text
knowledge_raw/
  Raw knowledge layer, including API constraints, PoC patterns, local unit-test evidence,
  cross-library equivalence notes, and Wycheproof vectors.

normalized_templates/
  PoC-specific normalized source templates.
  Each template directory usually contains README.md, poc_original.c, tmpl_mbedtls.c,
  template_meta.yaml, mask_report.yaml, ast_mask_report.yaml, selected_mask_units.yaml.

migration_candidates/
  Candidate API mapping and RAG evidence layer.
  Usually contains candidates.yaml, candidates_with_evidence.yaml, and notes.md.

adapters*/
  LLM-generated or manually repaired structured adapter YAML.

adapters*_validated/
  Adapter outputs after adapter_validate semantic validation.

cross_templates*/
  Cross-library template outputs generated from validated adapters.

rendered_cases*/
  Concrete rendered C test cases.

runner/results/
  compile_run outputs, single-case verdicts, and cross-library migration summaries.
```

---

## Current Research Pipeline

The current intended pipeline is:

```text
Real crypto-library PoC / PR / CVE / patch / regression test
    ↓
Reproduce or inspect buggy/fixed behavior
    ↓
Extract root cause / patch semantics / mutation points / oracle
    ↓
Build PoC Pattern Knowledge
    ↓
Generate normalized source template: tmpl_mbedtls.c
    ↓
Define template_meta.yaml and mask_report.yaml
    ↓
Generate AST-lite mask report and selected mask units
    ↓
Run RAG-enhanced target API candidate mapping
    ↓
Produce candidates.yaml and candidates_with_evidence.yaml
    ↓
Generate structured adapter.yaml via LLM or manual repair
    ↓
Run adapter_validate semantic validation
    ↓
Generate cross-library harness templates
    ↓
Render concrete cases
    ↓
Compile and run cases
    ↓
Run analyze_results and analyze_cross_results
    ↓
Classify migration verdicts
```

The pipeline should remain template-based and oracle-based.
The LLM is used to fill structured adapters, not to directly produce final C harnesses.

---

## PoC-Specific vs Family-Level Changes

Each new PoC normally requires new **PoC-specific artifacts**:

```text
knowledge_raw/poc_patterns/...
normalized_templates/...
template_meta.yaml
mask_report.yaml
ast_mask_report.yaml
selected_mask_units.yaml
migration_candidates/.../candidates.yaml
migration_candidates/.../candidates_with_evidence.yaml
adapters*/
adapters*_validated/
cross_templates*/
rendered_cases*/
runner/results/*
```

But the following files should **not** be modified for every single PoC:

```text
migration/candidate_mapper.py
migration/adapter_validate.py
template_maker/cross_generator_from_adapters.py
template_maker/render_cases.py
runner/analyze_results.py
runner/analyze_cross_results.py
```

These files should only be extended when a new **harness family**, oracle type, or reusable semantic rule is introduced.

The intended rule is:

```text
If the new PoC belongs to an existing harness_family:
    add PoC-specific template / candidates / adapter / results only.

If the new PoC introduces a new vulnerability family:
    extend family-level registry once,
    then keep future PoCs in that family data-driven.
```

Avoid one-off hard-coded logic for a single PoC unless it is explicitly marked as temporary and documented as TODO.

---

## Harness Family Design

The framework should gradually converge around reusable `harness_family` values.

Current or planned harness families:

```text
buffer_canary_boundary
  Used for caller-provided buffer / explicit length / canary-after-buffer memory boundary patterns.

der_pointer_consumption
  Used for DER top-level trailing garbage and pointer-consumption semantic patterns.

x509_asn1_inner_boundary
  Used for X.509 / ASN.1 inner substructure boundary patterns.

return_code_outlen_semantic
  Used for APIs where an error return should leave output length / output state safe.

crash_sanitizer_oracle
  Used for ASAN / UBSAN / SEGV / sanitizer crash oracles.

object_state_lifecycle
  Used for object state transitions such as stale pointer / stale length / reuse-after-zero-length-update.

null_deref_dispatch
  Used for generic dispatch paths where a wrong object type can lead to NULL dereference.
```

Each harness family should define:

```yaml
harness_family:
oracle_type:
required_observables:
target_api_features:
source_api_features:
common_mutation_points:
safe_behavior:
bug_behavior:
triage_behavior:
```

Example for `return_code_outlen_semantic`:

```yaml
harness_family: return_code_outlen_semantic
oracle_type: invalid_padding_output_length_oracle
required_observables:
  - return_code
  - output_length
  - error_path_state
target_api_features:
  - finalization_api
  - invalid_padding_path
  - caller_visible_output_length
  - output_buffer_or_output_length_pointer
```

When adding a new harness family, update:

```text
docs/harness_family_design.md
template_maker/cross_generator_from_adapters.py
runner/analyze_results.py
runner/analyze_cross_results.py
migration/adapter_validate.py
migration/candidate_mapper.py, if automatic candidate mapping is available
```

Only extend these modules when the new family genuinely requires new reusable behavior.

---

## Current Case Studies

### MBEDTLS-POC-0020

```text
Pattern ID:
  MBEDTLS-POC-0020

Pattern:
  RSA DER top-level SEQUENCE trailing garbage

Source API:
  mbedtls_pk_parse_key
  mbedtls_rsa_parse_key
  mbedtls_rsa_parse_pubkey

Target APIs:
  OpenSSL d2i_RSAPrivateKey
  OpenSSL d2i_PrivateKey
  OpenSSL d2i_RSA_PUBKEY

harness_family:
  der_pointer_consumption

oracle_type:
  pointer_consumption_semantic_oracle

Oracle:
  Source safe behavior:
    mbedTLS rejects DER with trailing garbage.
  Target bug candidate:
    OpenSSL d2i_* returns success but consumed_len < der_len,
    meaning it parsed the first DER object and left trailing garbage unconsumed.

Result:
  migrated_bug_candidate observed for some OpenSSL d2i_* cases.

Important:
  This is not a crash.
  It is a semantic difference based on accepted prefix DER with unconsumed trailing garbage.
```

### MBEDTLS-POC-0017

```text
Pattern ID:
  MBEDTLS-POC-0017

Pattern:
  X.509 / ASN.1 inner substructure boundary

Source API:
  mbedtls_x509_crt_parse_der

Target API tested:
  OpenSSL d2i_X509

harness_family:
  x509_asn1_inner_boundary

oracle_type:
  inner_asn1_boundary_semantic_oracle

Historical commit-level oracle:
  buggy ret = -9186
  fixed ret = -9184

Current mbedTLS 4.1.0 runner behavior:
  ret = -96
  ret=-96 corresponds to MBEDTLS_ERR_ASN1_OUT_OF_DATA.
  This is ASN.1-layer safe rejection, not a crash.

OpenSSL d2i_X509 behavior:
  safe rejection for the current malformed DER cases.

Result:
  migrated_safe / safe-safe comparison.

Important:
  This result should not be reported as a vulnerability.
  It is a useful negative case showing that the framework can identify safe/safe migration outcomes.
```

### MBEDTLS-POC-0004

```text
Pattern ID:
  MBEDTLS-POC-0004

Pattern:
  invalid PKCS padding output length underflow

Source API:
  mbedtls_cipher_finish

Internal function:
  get_pkcs_padding / mbedtls_get_pkcs_padding

Root cause:
  get_pkcs_padding computed:
    *data_len = input_len - padding_len
  before rejecting invalid padding_len > input_len.
  This could underflow size_t and leave a huge caller-visible output length on the error path.

Planned target API:
  OpenSSL EVP_DecryptFinal_ex
  OpenSSL EVP_CipherFinal_ex

Planned harness_family:
  return_code_outlen_semantic

Planned oracle_type:
  invalid_padding_output_length_oracle

Oracle:
  bug behavior:
    invalid padding return code, but output length is nonzero or unsafe.
  safe behavior:
    invalid padding return code, and output length remains zero.
```

### Early Bignum Examples

Early bignum cases remain useful examples but are no longer the only current demo.

```text
MBEDTLS-POC-0001:
  Source API: mbedtls_mpi_write_string
  Pattern: negative MPI serialization + small caller-provided output buffer
  Oracle: canary corruption / sanitizer crash / safe return behavior

MBEDTLS-POC-0002:
  Source API: mbedtls_mpi_sub_abs
  Pattern: bignum subtraction and output limb boundary behavior
```

For `mbedtls_mpi_write_string`, examples include:

```text
OpenSSL BN_bn2binpad        → generate
OpenSSL BN_signed_bn2bin    → generate
OpenSSL BN_bn2hex           → skip / migration_not_applicable
OpenSSL BN_bn2dec           → skip / migration_not_applicable
```

Reason:

```text
BN_bn2binpad and BN_signed_bn2bin preserve:
- caller-provided output buffer
- explicit length parameter
- library write into caller memory

BN_bn2hex and BN_bn2dec return library-allocated strings.
They do not preserve the caller-buffer boundary vulnerability path.
```

---

## API Equivalence / Migration Scoring

Candidate APIs are **not** judged by simple name similarity.

They are scored by **vulnerability-path migration suitability**.

The scoring dimensions are:

### 1. `operation_family`

Whether the source and target APIs belong to the same abstract operation family.

Examples:

```text
bignum serialization
bignum subtraction
DER parsing
X.509 parsing
symmetric cipher finalization
AEAD setup
signature verification
PEM parsing
```

### 2. `function_behavior`

Whether the concrete behavior of the functions is similar.

Examples:

```text
Serialize a big integer.
Parse DER into an object.
Finalize decryption and check padding.
Verify a signature.
Set up an AEAD decrypt operation.
```

### 3. `parameter_structure`

Whether critical source parameters have target counterparts.

Examples:

```text
source output buffer maps to target output pointer
source buflen maps to target tolen
source DER pointer maps to target const unsigned char **ppin
source olen maps to target outl
source key context maps to target EVP_PKEY / X509 / RSA object
```

### 4. `vulnerability_path`

The most important dimension.

Whether the target API preserves the source vulnerability path.

Examples:

```text
caller-provided output buffer
explicit length parameter
library writes to caller memory
DER parser consumes a prefix but leaves trailing garbage
invalid padding error path updates output length incorrectly
wrong object type dispatch reaches internal type-specific logic
```

### 5. `harness_feasibility`

Whether a compilable and meaningful C API harness can be generated.

This includes:

```text
initialization
input construction
trigger call
oracle
cleanup
return-value observability
output-state observability
sanitizer observability
```

### 6. `oracle_observability`

Whether the target API exposes enough signal for an oracle.

Examples:

```text
return code
output length
consumed pointer
object pointer is NULL or non-NULL
sanitizer crash
canary corruption
error stack
```

---

## Default Weighted Score

```text
final_score =
  0.15 * operation_family
+ 0.20 * function_behavior
+ 0.20 * parameter_structure
+ 0.30 * vulnerability_path
+ 0.15 * harness_feasibility
```

Decision rule:

```python
if final_score >= 75 and vulnerability_path >= 70:
    decision = "generate"
elif final_score >= 55 and vulnerability_path >= 50:
    decision = "needs_llm_review"
else:
    decision = "skip / migration_not_applicable"
```

The term `skip` means the candidate is not suitable for **automatic migration generation**.
It does **not** mean the candidate is irrelevant for research.

---

## Family-Specific Candidate Features

### Bignum / Canary Boundary

Useful target API features:

```text
caller-provided output buffer
explicit output length
library writes to caller buffer
canary-after-buffer observability
return code or sanitizer observability
```

### DER Pointer Consumption

Useful target API features:

```text
DER parser
explicit input length
consumed pointer / ppin
object pointer return
trailing garbage observability
return code or pointer advancement oracle
```

### X.509 / ASN.1 Inner Boundary

Useful target API features:

```text
X.509 parser
ASN.1 parser
nested structure boundary
malformed DER rejection path
return-code observability
pointer-consumption observability, if available
```

### Return-Code + Output-Length Semantic

Useful target API features:

```text
finalization API
invalid padding path
caller-visible output length
output length pointer
error path should not pollute output state
```

### Crash / Sanitizer Oracle

Useful target API features:

```text
malformed input reaches memory-sensitive path
sanitizer-observable failure
no required external service
deterministic crash or deterministic safe rejection
```

---

## Candidate Mapper Rules

`migration/candidate_mapper.py` is responsible for candidate API / equivalent API mapping.

It should not only match by function name.
It should use:

```text
template_id
source_api
source_component
harness_family
oracle_type
mutation_points
required_observables
target API semantic tags
RAG evidence
```

Current state:

```text
candidate_mapper.py initially supported bignum-oriented paths.
For new families such as x509_asn1_inner_boundary or return_code_outlen_semantic,
manual candidates.yaml may be acceptable temporarily.
However, the corresponding rule should eventually be added to candidate_mapper.py.
```

Temporary hand-written candidates should include:

```yaml
target_library:
target_api:
decision:
migration_applicability:
scores:
reason:
parameter_mapping:
preserved_vulnerability_features:
lost_or_weakened_features:
```

---

## Important LLM Design Rule

The LLM should **not** directly generate complete C files as the main workflow.

Preferred design:

```text
RAG evidence
    ↓
LLM generates structured adapter.yaml
    ↓
adapter_validate checks adapter semantics
    ↓
Template renderer generates C harness
    ↓
Runner compiles and executes
```

Reason:

```text
Direct C generation is unstable.
It can break canary layout.
It can hallucinate API signatures.
It can silently change the vulnerability path.
Structured adapter YAML is easier to validate, repair, and trace.
```

The LLM should fill fields such as:

```yaml
target_library:
target_api:
include_headers:
type_mapping:
constant_mapping:
init_block:
input_construction_block:
trigger_block:
return_value_semantics:
oracle_strategy:
cleanup_block:
preserved_features:
lost_or_weakened_features:
```

---

## Adapter Validation Rules

`migration/adapter_validate.py` should validate not only YAML structure, but also target API semantics.

Examples:

### d2i_X509

A valid `d2i_X509` adapter should include:

```text
openssl/x509.h
X509 *x509 = NULL
const unsigned char *p = der
d2i_X509(NULL, &p, (long) der_len)
consumed_len = (long)(p - der)
X509_free(x509)
```

A `d2i_X509` adapter must reject bignum residue such as:

```text
BIGNUM
BN_new
BN_free
BN_set_word
BUFLEN
signed_value
magnitude
openssl/bn.h
```

### DER d2i APIs

A DER `d2i_*` adapter should generally expose:

```text
input DER pointer
input length
const unsigned char **ppin or equivalent
target object pointer
return success / failure
consumed pointer or object pointer oracle
cleanup function
```

### Return-Code + Output-Length APIs

A return-code + output-length adapter should expose:

```text
return code
output length pointer
output buffer, if needed
error-path behavior
cleanup of cipher context or equivalent object
```

If an LLM-generated adapter mixes skeletons from another family, it must be repaired or rejected.

---

## RAG Design Rule

RAG evidence should be structured whenever possible.

The preferred `knowledge.rag_query.py` JSON output should look like:

```json
{
  "query": "...",
  "top_k": 5,
  "results": [
    {
      "rank": 1,
      "score": 0.83,
      "distance": 0.20,
      "layer": "api_constraints",
      "source_file": "knowledge_raw/api_constraints/...",
      "text": "int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);",
      "metadata": {
        "library": "openssl",
        "api": "BN_signed_bn2bin"
      }
    }
  ]
}
```

Rules:

```text
Do not mix JSON output with normal log text.
Plain-text output mode must remain available for humans.
JSON output must be valid and machine-readable.
If ChromaDB returns distances, preserve distance.
If a score is easy to compute, use score = 1 / (1 + distance).
If metadata lacks layer or source_file, use an empty string rather than crashing.
Avoid empty RAG queries.
Prefer evidence from api_constraints, unit_tests, poc_patterns, and cross_lib_equivalence.
```

---

## Portable Local Paths

The project must not hard-code local paths such as:

```text
/home/wen/work/clean_sources
```

Use:

```text
${CLEAN_SOURCES_ROOT}
```

Path resolution rules:

```text
If CLEAN_SOURCES_ROOT is set:
    use it.

Otherwise:
    default to <project_root>/../clean_sources.
```

Recommended local directory layout:

```text
work/
  crypto-pattern-fuzz/
  clean_sources/
    mbedtls-4.1.0/
    mbedtls-3.6.4/
    openssl-3.5.5/
    botan-3.10.0/
```

The path resolver is:

```text
utils/path_resolver.py
```

It should support:

```text
${CLEAN_SOURCES_ROOT}
$CLEAN_SOURCES_ROOT
~
relative paths
project-relative paths
```

Do not write machine-specific absolute paths into:

```text
config/runner_config.yaml
config/libraries.yaml
config/rag_source_versions.yaml
docs/
scripts/
```

API keys must only be provided through environment variables, for example:

```text
ZHIPUAI_API_KEY
GLM_API_KEY
```

Never store API keys in code, config files, docs, scripts, or Git history.

---

## Result Verdicts

The analysis pipeline may produce several result types.

Common verdicts:

```text
safe_reject_behavior
  The library rejects malformed input safely.

bug_candidate
  The target library shows behavior consistent with the migrated vulnerability pattern.

normal_behavior_needs_triage
  The behavior is not clearly classifiable by the current oracle rules.

migrated_bug_candidate
  Cross-library pair indicates source safe behavior and target bug-like behavior.

migrated_safe
  Source and target both show safe behavior.

migration_needs_triage
  Pair needs manual review or stronger oracle.
```

Important rule:

```text
Not every PoC must produce a bug_candidate.
safe/safe results are valid experimental outcomes.
```

A safe/safe result can show that:

```text
The target API has stronger validation.
The source current version rejects earlier than the historical buggy/fixed oracle.
The pattern does not migrate to this target API.
The current harness does not reach the vulnerability path and needs triage.
```

Crash results must be supported by explicit evidence such as:

```text
ASAN report
UBSAN report
SEGV
exit code 139
heap-buffer-overflow
stack-buffer-overflow
use-after-free
```

A nonzero return code from a harness is not automatically a crash.
It may be an intentional oracle signal.

---

## Current Priority

The current priority is to migrate additional PoC patterns while reducing one-off framework changes.

Near-term tasks:

1. Finish documenting `MBEDTLS-POC-0017` `d2i_X509` safe/safe result.
2. Start `MBEDTLS-POC-0004`.
3. Add and document:

```text
harness_family: return_code_outlen_semantic
oracle_type: invalid_padding_output_length_oracle
```

4. Keep improving family-level registries:

```text
candidate_mapper.py
adapter_validate.py
cross_generator_from_adapters.py
render_cases.py
analyze_results.py
analyze_cross_results.py
```

5. Avoid modifying framework code for every single PoC when the family already exists.
6. Prefer data-driven family configuration over one-off hard-coded logic.
7. Keep 0020 and 0017 results reproducible.

---

## General Run Environment

Use:

```bash
cd ~/work/crypto-pattern-fuzz
source .venv/bin/activate
export PYTHONPATH=.
export CLEAN_SOURCES_ROOT="${CLEAN_SOURCES_ROOT:-$HOME/work/clean_sources}"
```

If using LLM adapter generation, set keys only in the shell environment:

```bash
export ZHIPUAI_API_KEY="..."
export GLM_API_KEY="$ZHIPUAI_API_KEY"
```

Do not print key contents.
Do not commit keys.
Do not write keys into repository files.

---

## Full Migration Command Template

Use variables for a new migration task:

```bash
POC_ID="MBEDTLS-POC-XXXX"
CATEGORY="<category>"
SLUG="<slug>"

TEMPLATE_ROOT="normalized_templates/${CATEGORY}/${SLUG}"
CANDIDATE_DIR="migration_candidates/${CATEGORY}/${SLUG}"
ADAPTER_ROOT="adapters_${SLUG}"
VALIDATED_ADAPTER_ROOT="adapters_${SLUG}_validated"
CROSS_ROOT="cross_templates_${SLUG}_from_validated_adapters"
RENDERED_ROOT="rendered_cases_${SLUG}_from_validated_adapters"
RESULT_PREFIX="runner/results/run_${SLUG}"

MASK_REPORT="${TEMPLATE_ROOT}/mask_report.yaml"
CANDIDATES="${CANDIDATE_DIR}/candidates.yaml"
CANDIDATES_WITH_EVIDENCE="${CANDIDATE_DIR}/candidates_with_evidence.yaml"
RESULT_JSONL="${RESULT_PREFIX}.jsonl"
SUMMARY_JSON="${RESULT_PREFIX}.summary.json"
VERDICTS_JSONL="${RESULT_PREFIX}.verdicts.jsonl"
MIGRATION_SUMMARY_JSON="${RESULT_PREFIX}.migration_summary.json"
MIGRATION_PAIRS_JSONL="${RESULT_PREFIX}.migration_pairs.jsonl"
```

Validate and mask template:

```bash
PYTHONPATH=. python3 -m template_maker.validate_template \
  --root "$TEMPLATE_ROOT"

PYTHONPATH=. python3 -m template_maker.ast_mask_lite \
  --root "$TEMPLATE_ROOT"

PYTHONPATH=. python3 -m template_maker.ast_mask_select \
  --root "$TEMPLATE_ROOT"
```

Collect evidence:

```bash
PYTHONPATH=. python3 -m migration.evidence_collector \
  --candidates "$CANDIDATES" \
  --mask-report "$MASK_REPORT" \
  --output "$CANDIDATES_WITH_EVIDENCE" \
  --top-k 5
```

Generate adapter with LLM:

```bash
PYTHONPATH=. python3 -m migration.adapter_filler \
  --mask-report "$MASK_REPORT" \
  --candidates-with-evidence "$CANDIDATES_WITH_EVIDENCE" \
  --out-root "$ADAPTER_ROOT" \
  --use-llm
```

Validate adapter:

```bash
PYTHONPATH=. python3 -m migration.adapter_validate \
  --adapter-root "$ADAPTER_ROOT" \
  --out-root "$VALIDATED_ADAPTER_ROOT"
```

Generate cross templates:

```bash
PYTHONPATH=. python3 -m template_maker.cross_generator_from_adapters \
  --adapter-root "$VALIDATED_ADAPTER_ROOT" \
  --out-root "$CROSS_ROOT"
```

Render concrete cases:

```bash
PYTHONPATH=. python3 -m template_maker.render_cases \
  --root "$CROSS_ROOT" \
  --out-root "$RENDERED_ROOT" \
  --max-cases 32
```

Check unresolved placeholders:

```bash
grep -R "\[.*\]" -n "$RENDERED_ROOT" --include="*.c" || echo "OK: C placeholders rendered"
```

Compile and run:

```bash
PYTHONPATH=. python3 -m runner.compile_run \
  --input-root "$RENDERED_ROOT" \
  --result "$RESULT_JSONL" \
  --keep-going
```

Analyze single-case results:

```bash
PYTHONPATH=. python3 -m runner.analyze_results \
  --input "$RESULT_JSONL" \
  --output "$SUMMARY_JSON" \
  --case-output "$VERDICTS_JSONL"
```

Analyze cross-library pairs:

```bash
PYTHONPATH=. python3 -m runner.analyze_cross_results \
  --input "$SUMMARY_JSON" \
  --output "$MIGRATION_SUMMARY_JSON" \
  --pair-output "$MIGRATION_PAIRS_JSONL" \
  --source-lib mbedtls \
  --target-lib openssl
```

Print summary:

```bash
python3 - <<PY
import json

s = json.load(open("${SUMMARY_JSON}", "r", encoding="utf-8"))
m = json.load(open("${MIGRATION_SUMMARY_JSON}", "r", encoding="utf-8"))

print("total_cases:", s.get("total_cases"))
print("raw_status_counts:", s.get("raw_status_counts"))
print("verdict_counts:", s.get("verdict_counts"))
print("total_pairs:", m.get("total_pairs"))
print("migration_verdict_counts:", m.get("migration_verdict_counts"))
PY
```

---

## Standard Checks Before Editing

Before making changes, inspect:

```bash
git status --short
git log --oneline -5
```

If there is a merge or rebase conflict, stop and ask the user.

Before committing or pushing, inspect:

```bash
git status --short
git diff --stat
git diff | grep -i "api_key\|apikey\|zhipu\|glm\|sk-" || echo "OK: no obvious API key in diff"
grep -R "/home/wen/work/clean_sources" -n config runner template_maker migration scripts docs 2>/dev/null || echo "OK: no hardcoded clean_sources path"
```

Do not run:

```bash
git push --force
```

---

## Notes for Coding Agents

When modifying code:

1. Inspect the existing implementation first.
2. Make the smallest backward-compatible change.
3. Preserve existing behavior unless explicitly asked.
4. Avoid demo-only hard-coding.
5. Add CLI flags rather than changing defaults.
6. Keep errors readable.
7. Do not introduce unnecessary dependencies.
8. Do not run destructive commands.
9. Do not commit secrets or API keys.
10. After edits, provide exact test commands and a short summary of changed files.
11. If a tool-generated file is semantically wrong but structurally valid, repair or improve validators rather than continuing blindly.
12. If an oracle produces an unexpected result, investigate before reclassifying it.
13. Do not turn a safe/safe result into a bug candidate without evidence.
14. Distinguish crash evidence from intentional harness exit codes.

---

## Preferred Response Format for Agents

After completing a coding task, respond with:

```text
Changed files:
- path/to/file.py

What changed:
- Short bullet describing change 1
- Short bullet describing change 2

How to test:
- exact command 1
- exact command 2

Notes:
- Any compatibility or limitation notes
```

If no file was changed, state clearly:

```text
No files were modified.
```

When reporting migration results, include:

```text
total_cases:
raw_status_counts:
verdict_counts:
total_pairs:
migration_verdict_counts:
crash evidence, if any:
semantic interpretation:
next recommended step:
```

---

## Non-Goals

This project should not be turned into:

* a random AFL++ fuzzing framework,
* a pure coverage-guided fuzzing project,
* a direct LLM-to-C-code generation demo,
* a one-off hard-coded proof-of-concept,
* a tool that only works for one API pair,
* a system that relies on hallucinated API signatures,
* a system that reports safe/safe behavior as a vulnerability,
* a system that treats every nonzero harness exit as a crash.

The core value is:

```text
PoC / patch / root cause
    ↓
vulnerability pattern abstraction
    ↓
cross-library API candidate evaluation
    ↓
structured adapter generation
    ↓
template-based harness rendering
    ↓
oracle-based migration validation
```

---

## Response Language

* Please respond to the user in Chinese.
* Keep code, file names, CLI flags, and error messages in their original English form.
* Summaries, explanations, and task reports should be written in Chinese.
