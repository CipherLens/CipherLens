# AGENTS.md

## Project Context

This repository is an academic research prototype for **cryptographic-library vulnerability-pattern migration**.

The goal is **not** coverage-guided AFL++ fuzzing.  
The goal is to build a **pattern-guided API harness generation and migration-verification framework**.

The project focuses on:

1. Starting from real cryptographic-library PoC / PR / CVE / patch / regression test.
2. Reproducing buggy and fixed behavioral differences.
3. Extracting the root cause, patch semantics, failure signal, mutation points, and oracle.
4. Building a reusable PoC Pattern Layer.
5. Generating mask reports from templates and PoC patterns.
6. Using RAG evidence to evaluate cross-library candidate APIs.
7. Letting the LLM fill structured adapter YAML.
8. Generating API harnesses from structured templates and adapters.
9. Validating migration results with ASAN / UBSAN / canary / return-code oracles.

This project focuses on **vulnerability-pattern migration**, not random fuzzing or coverage maximization.

---

## Important Design Rules

- Do not break existing CLI behavior.
- Keep existing plain-text output mode working.
- Add new options in a backward-compatible way.
- Prefer structured JSON outputs for downstream tools.
- Do not hard-code demo-only behavior when a generic implementation is possible.
- Do not introduce AFL++ as a dependency.
- Do not store API keys, tokens, credentials, or secrets in code.
- Do not remove existing files unless explicitly asked.
- Do not change existing output directories unless explicitly asked.
- Do not silently drop existing fields in YAML / JSON outputs.
- Keep generated outputs deterministic when possible.
- Keep error messages readable and actionable.
- Avoid unnecessary dependencies.
- Do not run destructive commands.
- Do not commit secrets or API keys.

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
  wycheproof_vectors/

template_maker/
  mask.py
  normalize_enriched.py
  render_cases.py
  validate_template.py
  cross_generator_from_candidates.py
  cross_generator_from_adapters.py

migration/
  candidate_mapper.py
  evidence_collector.py
  adapter_filler.py

runner/
  compile_run.py
  analyze_results.py
  analyze_cross_results.py

generated_templates/
enriched_templates/
normalized_templates/
migration_candidates/
cross_templates_from_candidates/
cross_templates_from_adapters/
rendered_cases_from_candidates/
rendered_cases_from_adapters/
adapters/
runner/results/
```

---

## Current Research Pipeline

The current intended pipeline is:

```text
Real crypto-library PoC / PR / CVE / patch
    ↓
Reproduce buggy/fixed behavior difference
    ↓
Extract root cause, patch semantics, failure signal, mutation points
    ↓
Build PoC Pattern Layer
    ↓
Generate mask_report.yaml
    ↓
Build RAG knowledge base
    ↓
Run candidate_mapper.py to score cross-library candidate APIs
    ↓
Run evidence_collector.py to collect RAG evidence for candidates
    ↓
Run adapter_filler.py to let LLM generate structured adapter.yaml
    ↓
Generate cross-library harness templates
    ↓
Render concrete cases
    ↓
Compile and run cases
    ↓
Analyze results and cross-library migration verdicts
```

---

## API Equivalence / Migration Scoring

Candidate APIs are **not** judged by simple name similarity.

They are scored by **vulnerability-path migration suitability**.

The current scoring dimensions are:

### 1. `operation_family`

Whether the source and target APIs belong to the same abstract operation family.

Examples:

- bignum serialization
- bignum subtraction
- AEAD decrypt
- signature verify

### 2. `function_behavior`

Whether the concrete behavior of the functions is similar.

Example:

- Serialize a big integer into binary or string form.

### 3. `parameter_structure`

Whether critical source parameters have target counterparts.

Example:

- source buffer maps to target output pointer
- `buflen` maps to `tolen`

### 4. `vulnerability_path`

The most important dimension.

Whether the target API preserves the source vulnerability path.

Example:

- caller-provided output buffer
- explicit length parameter
- library writes to that buffer

### 5. `harness_feasibility`

Whether a compilable and meaningful C API harness can be generated.

This includes:

- initialization
- trigger call
- oracle
- cleanup
- return-value observability

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

## Current Example

The current main demo pattern is:

```text
Pattern ID: MBEDTLS-POC-0001
Source API: mbedtls_mpi_write_string
Pattern: negative MPI serialization + small caller-provided output buffer
Root cause: negative sign '-' was written without decrementing buflen
Oracle: canary corruption / sanitizer crash / safe return behavior
```

For this pattern:

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

For `mbedtls_mpi_sub_abs`:

```text
OpenSSL BN_usub → skip / migration_not_applicable
OpenSSL BN_sub  → skip / migration_not_applicable
```

Reason:

```text
They are functionally related to bignum subtraction.

However, they do not preserve:
- manual output limb boundary control
- direct canary-after-output-limbs behavior
- the same memory-boundary vulnerability path
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
Template renderer generates C harness
    ↓
Validator checks adapter / C harness
    ↓
Runner compiles and executes
```

Reason:

- Direct C generation is unstable.
- It can break canary layout.
- It can hallucinate API signatures.
- It can silently change the vulnerability path.
- Structured adapter YAML is easier to validate, repair, and trace.

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

- Do not mix JSON output with normal log text.
- Plain-text output mode must remain available for humans.
- JSON output must be valid and machine-readable.
- If ChromaDB returns distances, preserve `distance`.
- If a score is easy to compute, use:

```python
score = 1 / (1 + distance)
```

- If metadata lacks `layer` or `source_file`, use an empty string rather than crashing.

---

## Current Priority

Upgrade `knowledge/rag_query.py` so it supports:

```text
--top-k N
--json
```

The old command must still work:

```bash
PYTHONPATH=. python3 -m knowledge.rag_query \
  --query "mbedtls_mpi_write_string negative sign missing buflen caller-provided output buffer"
```

The new command should work:

```bash
PYTHONPATH=. python3 -m knowledge.rag_query \
  --query "OpenSSL BN_signed_bn2bin unsigned char to int tolen" \
  --top-k 5 \
  --json
```

The JSON output should include:

```text
query
top_k
results
  rank
  score or distance
  layer
  source_file
  text
  metadata
```

Expected behavior:

- Old text mode still works.
- New JSON mode returns valid JSON.
- `results` is an array.
- Each result has `rank`, `text`, `metadata`, `layer`, and `source_file`.
- No plain logs are mixed into JSON output.

---

## Test Commands

After modifying `knowledge/rag_query.py`, run:

```bash
cd ~/work/crypto-pattern-fuzz
source .venv/bin/activate
export PYTHONPATH=.
```

Check CLI help:

```bash
PYTHONPATH=. python3 -m knowledge.rag_query --help
```

Old text mode:

```bash
PYTHONPATH=. python3 -m knowledge.rag_query \
  --query "mbedtls_mpi_write_string negative sign missing buflen caller-provided output buffer"
```

New JSON mode:

```bash
PYTHONPATH=. python3 -m knowledge.rag_query \
  --query "OpenSSL BN_signed_bn2bin unsigned char to int tolen" \
  --top-k 5 \
  --json
```

Validate JSON:

```bash
PYTHONPATH=. python3 -m knowledge.rag_query \
  --query "OpenSSL BN_signed_bn2bin unsigned char to int tolen" \
  --top-k 5 \
  --json | python3 -m json.tool | head -120
```

Expected results:

```text
- Old text mode still works.
- New JSON mode returns valid JSON.
- results is an array.
- Each result has rank, text, metadata, layer, and source_file.
- No plain logs are mixed into JSON output.
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

---

## Non-Goals

This project should not be turned into:

- a random AFL++ fuzzing framework
- a pure coverage-guided fuzzing project
- a direct LLM-to-C-code generation demo
- a one-off hard-coded proof-of-concept
- a tool that only works for one API pair
- a system that relies on hallucinated API signatures

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

## Academic Positioning

This repository should be treated as an academic research prototype.

The intended research contribution is not simply finding crashes.  
The intended contribution is to explore whether historical cryptographic-library vulnerability patterns can be:

1. abstracted from real PoCs and patches,
2. represented as structured templates,
3. migrated across libraries using API semantics and RAG evidence,
4. validated through generated harnesses and explicit oracles.

The project should prioritize:

- semantic correctness,
- traceability,
- reproducibility,
- structured intermediate artifacts,
- explainable migration decisions.


---

## Response Language

- Please respond to the user in Chinese.
- Keep code, file names, CLI flags, and error messages in their original English form.
- Summaries, explanations, and task reports should be written in Chinese.

---

## Current Priority Override: AST-lite Multi-Granularity Masking

The current task is to implement a lightweight role-aware multi-granularity masking report.

Do not implement full clang/tree-sitter AST yet.

Preferred module:

template_maker/ast_mask_lite.py

Input:

normalized_templates/*/*/mask_report.yaml
normalized_templates/*/*/template_meta.yaml
normalized_templates/*/*/tmpl_mbedtls.c

Output:

normalized_templates/*/*/ast_mask_report.yaml

The output should include mask units at these levels:

value
identifier
type
api_argument
function_call
statement
block

Each mask unit should include:

unit_id
mask_level
role
placeholder
code
source
reason
priority

Roles should include:

input_construction
input_preparation
trigger_call
oracle
cleanup
helper_function
mutation_point

Do not call GLM.
Do not require API keys.
Do not modify adapter_filler.py, adapter_validate.py, evidence_collector.py, or candidate_mapper.py.
Do not break existing mask_report.yaml.

