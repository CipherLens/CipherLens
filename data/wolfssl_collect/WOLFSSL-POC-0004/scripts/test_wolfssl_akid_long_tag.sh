#!/usr/bin/env bash
set -euo pipefail

TAG="$1"
ROLE="$2"

BASE=~/workplace/CryptoPoc/Builds/wolfssl_repro
POC_ROOT=~/workplace/CryptoPoc/Collect_Poc/wolfSSL_collect/WOLFSSL-POC-0004

BUILD_DIR="$BASE/wolfssl-${TAG}-asan-akid"
LOGDIR="$POC_ROOT/logs/${ROLE}_version/wolfssl-${TAG}-asan-akid"

mkdir -p "$BASE"
mkdir -p "$LOGDIR"
mkdir -p "$POC_ROOT/inputs/reconstructed"

echo "[*] Testing wolfSSL tag: $TAG"
echo "[*] Role: $ROLE"
echo "[*] Build dir: $BUILD_DIR"
echo "[*] Log dir: $LOGDIR"

cd "$BASE"

rm -rf "$BUILD_DIR"

git clone https://github.com/wolfSSL/wolfssl.git "$BUILD_DIR"

cd "$BUILD_DIR"

git checkout "$TAG"

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

CFLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -DWOLFSSL_AKID_NAME" \
LDFLAGS="-fsanitize=address,undefined" \
./configure \
  --enable-debug \
  --enable-opensslextra \
  --enable-certgen \
  --enable-certreq \
  --enable-certext

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

BIN="$POC_ROOT/poc/poc_akid_certfromx509_long_${TAG}_asan"
DER_OUT="$POC_ROOT/inputs/reconstructed/cve-2026-5447-akid-overflow-long.der"

gcc -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -DWOLFSSL_AKID_NAME \
  -I"$BUILD_DIR" \
  -I"$BUILD_DIR/wolfssl" \
  "$POC_ROOT/poc/poc_akid_certfromx509_long.c" \
  -L"$BUILD_DIR/src/.libs" \
  -Wl,-rpath,"$BUILD_DIR/src/.libs" \
  -lwolfssl \
  -o "$BIN"

ldd "$BIN" | grep wolfssl | tee "$LOGDIR/ldd.txt"

set +e
set -o pipefail

ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=print_stacktrace=1 \
timeout 10s "$BIN" "$DER_OUT" \
2>&1 | tee "$LOGDIR/akid_repro.log"

STATUS="${PIPESTATUS[0]}"
set -e

echo "$STATUS" > "$LOGDIR/akid_exit_code.txt"

echo "[*] exit code: $STATUS"

if [ -f "$DER_OUT" ]; then
  file "$DER_OUT" | tee "$LOGDIR/der_file.txt" || true
  sha256sum "$DER_OUT" | tee "$LOGDIR/der_sha256.txt" || true
fi

grep -RniE "ERROR: AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|WRITE of size|READ of size|SEGV|runtime error|ABORTING|Auth Key ID too large|BUFFER_E" "$LOGDIR" \
  | tee "$LOGDIR/asan_grep_result.txt" || true

echo
echo "[*] Precise crash signal check:"
grep -RniE "ERROR: AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|WRITE of size|READ of size|SEGV|runtime error|ABORTING" "$LOGDIR" \
  || echo "NO_CRASH_SIGNAL"

echo
echo "[*] Result summary for $TAG:"
if grep -RqiE "ERROR: AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|WRITE of size|READ of size|SEGV|runtime error|ABORTING" "$LOGDIR"; then
  echo "VULNERABLE_OR_STILL_CRASHING"
else
  echo "NO_ASAN_CRASH_OBSERVED"
fi
