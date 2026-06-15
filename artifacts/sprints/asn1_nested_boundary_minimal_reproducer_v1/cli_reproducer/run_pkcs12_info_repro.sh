#!/usr/bin/env bash
set -u

SPRINT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BIN="${OPENSSL_BIN:-/home/wen/work/clean_sources/openssl-3.5.5/apps/openssl}"
SEED_FILE="${SEED_FILE:-/home/wen/work/crypto-pattern-fuzz/datasets/openssl/poc_artifacts/issue_30581/inputs/test.p12}"
SEED_STATUS="${SEED_STATUS:-only_placeholder_input_found}"

STDOUT_PATH="$SPRINT_ROOT/results/raw_stdout/pkcs12_info.stdout.txt"
STDERR_PATH="$SPRINT_ROOT/results/raw_stderr/pkcs12_info.stderr.txt"
EXIT_PATH="$SPRINT_ROOT/results/exit_codes/pkcs12_info.exit_code"

mkdir -p "$(dirname "$STDOUT_PATH")" "$(dirname "$STDERR_PATH")" "$(dirname "$EXIT_PATH")"

{
  echo "OPENSSL_BIN=$OPENSSL_BIN"
  echo "SEED_FILE=$SEED_FILE"
  echo "SEED_STATUS=$SEED_STATUS"
  if [ ! -x "$OPENSSL_BIN" ]; then
    echo "openssl_binary_missing"
    echo 2 > "$EXIT_PATH"
    exit 2
  fi
  "$OPENSSL_BIN" version -a
} > "$STDOUT_PATH" 2> "$STDERR_PATH"

if [ ! -f "$SEED_FILE" ]; then
  echo "seed_missing" >> "$STDERR_PATH"
  echo 3 > "$EXIT_PATH"
  exit 3
fi

if [ "$SEED_STATUS" != "real_input_seed_found" ]; then
  echo "seed_missing_or_placeholder: refusing to treat placeholder input as strict reproduction" >> "$STDERR_PATH"
  echo 3 > "$EXIT_PATH"
  exit 3
fi

"$OPENSSL_BIN" pkcs12 -info -in "$SEED_FILE" -noout -passin pass:any >> "$STDOUT_PATH" 2>> "$STDERR_PATH"
status=$?
echo "$status" > "$EXIT_PATH"
exit "$status"
