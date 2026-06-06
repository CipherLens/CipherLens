#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
fi

export PYTHONPATH=.

TEMPLATE_ROOT="normalized_templates/pk/pk_verify_ext_null_deref"
MASK_REPORT="${TEMPLATE_ROOT}/mask_report.yaml"
SELECTED_MASK_UNITS="${SELECTED_MASK_UNITS:-${TEMPLATE_ROOT}/selected_mask_units.yaml}"

SMOKE_ROOT="${SMOKE_ROOT:-smoke_outputs/pk_null_deref_dry}"
export SMOKE_ROOT
CANDIDATES="${SMOKE_ROOT}/candidates.yaml"
CANDIDATES_WITH_EVIDENCE="${SMOKE_ROOT}/candidates_with_evidence.yaml"
ADAPTER_ROOT="${SMOKE_ROOT}/adapters"
VALIDATED_ADAPTER_ROOT="${SMOKE_ROOT}/adapters_validated"
CROSS_ROOT="${SMOKE_ROOT}/cross_templates"
RENDERED_ROOT="${SMOKE_ROOT}/rendered_cases"
RESULT_JSONL="${SMOKE_ROOT}/run.jsonl"
SUMMARY_JSON="${SMOKE_ROOT}/summary.json"
VERDICTS_JSONL="${SMOKE_ROOT}/verdicts.jsonl"
MIGRATION_JSON="${SMOKE_ROOT}/migration_summary.json"
MIGRATION_PAIRS_JSONL="${SMOKE_ROOT}/migration_pairs.jsonl"

TARGET_LIBRARY="${TARGET_LIBRARY:-openssl}"
TARGET_API="${TARGET_API:-EVP_DigestVerify}"
MAX_CASES="${MAX_CASES:-16}"
TOP_K="${TOP_K:-5}"

mkdir -p "$SMOKE_ROOT"

echo "[INFO] smoke root: $SMOKE_ROOT"
echo "[INFO] target: ${TARGET_LIBRARY}.${TARGET_API}"
echo "[INFO] max cases: $MAX_CASES"
echo "[INFO] selected mask units: $SELECTED_MASK_UNITS"

echo "[STEP] Map target API candidates"
python3 -m migration.candidate_mapper \
  --mask-report "$MASK_REPORT" \
  --selected-mask-units "$SELECTED_MASK_UNITS" \
  --output "$CANDIDATES"

echo "[STEP] Collect RAG/raw-knowledge evidence"
python3 -m migration.evidence_collector \
  --candidates "$CANDIDATES" \
  --mask-report "$MASK_REPORT" \
  --selected-mask-units "$SELECTED_MASK_UNITS" \
  --output "$CANDIDATES_WITH_EVIDENCE" \
  --target-api "$TARGET_API" \
  --top-k "$TOP_K"

echo "[STEP] Fill structured adapter from recipe/defaults"
python3 -m migration.adapter_filler \
  --mask-report "$MASK_REPORT" \
  --selected-mask-units "$SELECTED_MASK_UNITS" \
  --candidates-with-evidence "$CANDIDATES_WITH_EVIDENCE" \
  --out-root "$ADAPTER_ROOT" \
  --target-library "$TARGET_LIBRARY" \
  --target-api "$TARGET_API" \
  --require-recipes \
  --include-non-generate

echo "[STEP] Validate adapter semantics"
python3 -m migration.adapter_validate \
  --adapter-root "$ADAPTER_ROOT" \
  --out-root "$VALIDATED_ADAPTER_ROOT"

echo "[STEP] Generate cross-library templates"
python3 -m template_maker.cross_generator_from_adapters \
  --adapter-root "$VALIDATED_ADAPTER_ROOT" \
  --out-root "$CROSS_ROOT"

echo "[STEP] Render concrete C cases"
python3 -m template_maker.render_cases \
  --root "$CROSS_ROOT" \
  --out-root "$RENDERED_ROOT" \
  --max-cases "$MAX_CASES"

echo "[STEP] Check rendered C placeholders"
python3 - <<'PY'
import os
from pathlib import Path
from template_maker.render_cases import unresolved_placeholders

root = Path(os.environ["SMOKE_ROOT"]) / "rendered_cases"
files = sorted(root.rglob("*.c"))
bad = []

for path in files:
    unresolved = unresolved_placeholders(
        path.read_text(encoding="utf-8", errors="ignore")
    )
    if unresolved:
        bad.append((path, unresolved))

print(f"checked_c_files: {len(files)}")
print(f"files_with_unresolved_placeholders: {len(bad)}")

for path, unresolved in bad[:20]:
    print(f"{path}: {unresolved}")

if bad:
    raise SystemExit(1)
PY

echo "[STEP] Dry-run compile commands without clean_sources"
python3 -m runner.compile_run \
  --input-root "$RENDERED_ROOT" \
  --result "$RESULT_JSONL" \
  --dry-run \
  --keep-going

echo "[STEP] Analyze per-case dry-run results"
python3 -m runner.analyze_results \
  --input "$RESULT_JSONL" \
  --output "$SUMMARY_JSON" \
  --case-output "$VERDICTS_JSONL"

echo "[STEP] Analyze cross-library dry-run pairs"
python3 -m runner.analyze_cross_results \
  --input "$SUMMARY_JSON" \
  --output "$MIGRATION_JSON" \
  --pair-output "$MIGRATION_PAIRS_JSONL" \
  --source-lib mbedtls \
  --target-lib openssl

echo "[STEP] Print final dry-run summary"
python3 - <<'PY'
import json
import os
from pathlib import Path

smoke_root = Path(os.environ["SMOKE_ROOT"])
summary_path = smoke_root / "summary.json"
migration_path = smoke_root / "migration_summary.json"

s = json.load(open(summary_path, "r", encoding="utf-8"))
m = json.load(open(migration_path, "r", encoding="utf-8"))

print("total_cases:", s.get("total_cases"))
print("raw_status_counts:", s.get("raw_status_counts"))
print("verdict_counts:", s.get("verdict_counts"))
print("harness_family_counts:", s.get("harness_family_counts"))
print("total_pairs:", m.get("total_pairs"))
print("migration_verdict_counts:", m.get("migration_verdict_counts"))
print("target_api_counts:", m.get("target_api_counts"))
print("note: dry-run does not compile or execute C cases; real compile/run needs clean_sources.")
PY
