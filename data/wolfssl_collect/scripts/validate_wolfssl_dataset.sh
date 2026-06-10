#!/usr/bin/env bash
set -euo pipefail

echo "[*] validating wolfSSL dataset"

echo "[*] checking required files"
test -f README.md
test -f inventory/wolfssl_poc_inventory.md
test -f inventory/wolfssl_poc_inventory.csv
test -f inventory/wolfssl_pattern_summary.md
test -f inventory/wolfssl_pattern_recipes.json
test -f inventory/wolfssl_dataset_statistics.md
test -f data/jsonl/README_dataset_schema.md
test -f data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl
test -f data/jsonl/wolfssl_code_localization_eval_v1.jsonl

echo "[*] checking JSON syntax"
python3 -m json.tool inventory/wolfssl_pattern_recipes.json >/dev/null

echo "[*] checking pattern prompt JSONL row count"
python3 - <<'PY'
import json
from pathlib import Path

p = Path("data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl")
rows = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

assert len(rows) == 10, f"expected 10 pattern prompt rows, got {len(rows)}"
assert {r["pattern_id"] for r in rows} == {f"Pattern-{i:02d}" for i in range(1, 11)}

print("[OK] pattern prompt JSONL rows:", len(rows))
PY

echo "[*] checking code localization JSONL"
python3 scripts/validate_wolfssl_code_localization_jsonl.py

echo "[*] checking manifest"
test -f inventory/wolfssl_artifact_manifest.txt
grep -q "^README.md$" inventory/wolfssl_artifact_manifest.txt
grep -q "data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl" inventory/wolfssl_artifact_manifest.txt
grep -q "data/jsonl/wolfssl_code_localization_eval_v1.jsonl" inventory/wolfssl_artifact_manifest.txt
grep -q "inventory/wolfssl_pattern_recipes.json" inventory/wolfssl_artifact_manifest.txt

echo "[OK] wolfSSL dataset validation passed"
