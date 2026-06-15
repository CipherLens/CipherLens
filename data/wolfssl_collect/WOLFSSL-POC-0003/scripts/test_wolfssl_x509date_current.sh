#!/usr/bin/env bash
set -euo pipefail

BASE=~/workplace/CryptoPoc/Builds/wolfssl_repro
POC_ROOT=~/workplace/CryptoPoc/Collect_Poc/wolfSSL_collect/WOLFSSL-POC-0003

BUILD_DIR="$BASE/wolfssl-current-asan-x509date"
LOGDIR="$POC_ROOT/logs/current_version/wolfssl-current-asan-x509date"

mkdir -p "$BASE"
mkdir -p "$LOGDIR"

echo "[*] Testing current wolfSSL"
echo "[*] Build dir: $BUILD_DIR"
echo "[*] Log dir: $LOGDIR"

cd "$BASE"

rm -rf "$BUILD_DIR"

git clone https://github.com/wolfSSL/wolfssl.git "$BUILD_DIR"

cd "$BUILD_DIR"

{
  echo "===== git describe ====="
  git describe --tags --always

  echo
  echo "===== commit hash ====="
  git rev-parse HEAD

  echo
  echo "===== latest commit ====="
  git log -1 --format="%h %ci %s"
} | tee "$LOGDIR/build_info.txt"

./autogen.sh

CFLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=address,undefined" \
./configure \
  --enable-debug \
  --enable-opensslextra \
  --enable-certgen \
  --enable-certreq

make -j"$(nproc)" src/libwolfssl.la || {
  echo "[!] make failed once, trying to remove -Werror from Makefile"
  cp Makefile Makefile.before_remove_werror || true

  python3 - <<'PY'
from pathlib import Path
p = Path("Makefile")
s = p.read_text()
s = s.replace(" -Werror ", " ")
s = s.replace(" -Werror\n", "\n")
p.write_text(s)
print("Removed -Werror from Makefile")
PY

  make -j"$(nproc)" src/libwolfssl.la
}

cd "$POC_ROOT"

BIN="$POC_ROOT/poc/poc_x509_date_min_current_asan"

gcc -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$BUILD_DIR" \
  -I"$BUILD_DIR/wolfssl" \
  "$POC_ROOT/poc/poc_x509_date_min.c" \
  -L"$BUILD_DIR/src/.libs" \
  -Wl,-rpath,"$BUILD_DIR/src/.libs" \
  -lwolfssl \
  -o "$BIN"

ldd "$BIN" | grep wolfssl | tee "$LOGDIR/ldd.txt"

set +e
set -o pipefail

for MODE in after before
do
  echo
  echo "[*] Running mode: $MODE"

  ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
  UBSAN_OPTIONS=print_stacktrace=1 \
  timeout 10s "$BIN" "$MODE" \
  2>&1 | tee "$LOGDIR/${MODE}_repro.log"

  STATUS="${PIPESTATUS[0]}"
  echo "$STATUS" > "$LOGDIR/${MODE}_exit_code.txt"
  echo "[*] $MODE exit code: $STATUS"
done

set -e

grep -RniE "ERROR: AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|WRITE of size|READ of size|SEGV|runtime error|ABORTING" "$LOGDIR" \
  | tee "$LOGDIR/asan_grep_result.txt" || true

echo
echo "[*] Precise crash signal check:"
grep -RniE "ERROR: AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|WRITE of size|READ of size|SEGV|runtime error|ABORTING" "$LOGDIR" \
  || echo "NO_CRASH_SIGNAL"

echo
echo "[*] Result summary for current wolfSSL:"
if grep -RqiE "ERROR: AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|WRITE of size|READ of size|SEGV|runtime error|ABORTING" "$LOGDIR"; then
  echo "VULNERABLE_OR_STILL_CRASHING"
else
  echo "NO_ASAN_CRASH_OBSERVED"
fi
