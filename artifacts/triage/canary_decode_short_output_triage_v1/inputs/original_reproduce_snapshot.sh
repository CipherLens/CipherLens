#!/usr/bin/env bash
set -euo pipefail
OPENSSL_ROOT="/home/wen/work/install-openssl-3.5.5-asan"
gcc -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -I"$OPENSSL_ROOT/include" min_repro.c -L"$OPENSSL_ROOT/lib64" -Wl,-rpath,"$OPENSSL_ROOT/lib64" -lssl -lcrypto -ldl -pthread -o min_repro.bin
OPENSSL_MODULES="$OPENSSL_ROOT/lib64/ossl-modules" LD_LIBRARY_PATH="$OPENSSL_ROOT/lib64:${LD_LIBRARY_PATH:-}" ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./min_repro.bin
