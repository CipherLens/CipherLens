#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
fi

export PYTHONPATH=.

ADAPTER_ROOT="adapters_rsa_validated"
CROSS_ROOT="cross_templates_rsa_from_validated_adapters"
RENDERED_ROOT="rendered_cases_rsa_from_validated_adapters"
RESULT_JSONL="runner/results/run_rsa_der_trailing_garbage_410.jsonl"
SUMMARY_JSON="runner/results/run_rsa_der_trailing_garbage_410.summary.json"
VERDICTS_JSONL="runner/results/run_rsa_der_trailing_garbage_410.verdicts.jsonl"
MIGRATION_JSON="runner/results/run_rsa_der_trailing_garbage_410.migration_summary.json"
MIGRATION_PAIRS_JSONL="runner/results/run_rsa_der_trailing_garbage_410.migration_pairs.jsonl"

echo "[STEP] Generate OpenSSL cross templates from validated RSA adapters"
python3 -m template_maker.cross_generator_from_adapters \
  --adapter-root "$ADAPTER_ROOT" \
  --out-root "$CROSS_ROOT"

echo "[STEP] Render concrete cases"
python3 -m template_maker.render_cases \
  --root "$CROSS_ROOT" \
  --out-root "$RENDERED_ROOT" \
  --max-cases 32

echo "[STEP] Check rendered C placeholders"
if grep -R "\[DER_KIND\]\|\[TRAILING_GARBAGE_BYTES\]\|\[TRAILING_GARBAGE_LEN\]\|\[PARSE_API_KIND\]\|\[EXPECT_RET\]" \
  -n "$RENDERED_ROOT" \
  --include="*.c"; then
  echo "[ERROR] Unrendered placeholders found in C output"
  exit 1
else
  echo "OK: C placeholders rendered"
fi

echo "[STEP] Compile and run rendered cases"
python3 -m runner.compile_run \
  --input-root "$RENDERED_ROOT" \
  --result "$RESULT_JSONL" \
  --keep-going

echo "[STEP] Analyze per-case results"
python3 -m runner.analyze_results \
  --input "$RESULT_JSONL" \
  --output "$SUMMARY_JSON" \
  --case-output "$VERDICTS_JSONL"

echo "[STEP] Analyze cross-library migration results"
python3 -m runner.analyze_cross_results \
  --input "$SUMMARY_JSON" \
  --output "$MIGRATION_JSON" \
  --pair-output "$MIGRATION_PAIRS_JSONL" \
  --source-lib mbedtls \
  --target-lib openssl

echo "[STEP] Print final summary"
python3 - <<'PY'
import json
from collections import Counter

result_path = "runner/results/run_rsa_der_trailing_garbage_410.jsonl"
summary_path = "runner/results/run_rsa_der_trailing_garbage_410.summary.json"
migration_path = "runner/results/run_rsa_der_trailing_garbage_410.migration_summary.json"

compile_codes = Counter()
with open(result_path, "r", encoding="utf-8") as f:
    for line in f:
        obj = json.loads(line)
        compile_codes[(obj.get("compile") or {}).get("returncode")] += 1

s = json.load(open(summary_path, "r", encoding="utf-8"))
m = json.load(open(migration_path, "r", encoding="utf-8"))

print("compile_returncodes:", dict(compile_codes))
print("total_cases:", s.get("total_cases"))
print("raw_status_counts:", s.get("raw_status_counts"))
print("verdict_counts:", s.get("verdict_counts"))
print("total_pairs:", m.get("total_pairs"))
print("migration_verdict_counts:", m.get("migration_verdict_counts"))
print("note: bug_candidate is a DER pointer-consumption semantic finding, not a crash.")
PY
