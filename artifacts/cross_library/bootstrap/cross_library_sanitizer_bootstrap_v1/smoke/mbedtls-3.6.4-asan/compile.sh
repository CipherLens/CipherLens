#!/usr/bin/env bash
set -euo pipefail
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -I/home/wen/work/install-mbedtls-3.6.4-asan/include /home/wen/work/crypto-pattern-fuzz/artifacts/cross_library/bootstrap/cross_library_sanitizer_bootstrap_v1/smoke/mbedtls-3.6.4-asan/smoke.c -L/home/wen/work/install-mbedtls-3.6.4-asan/lib -Wl,-rpath,/home/wen/work/install-mbedtls-3.6.4-asan/lib -lmbedcrypto -o /home/wen/work/crypto-pattern-fuzz/artifacts/cross_library/bootstrap/cross_library_sanitizer_bootstrap_v1/smoke/mbedtls-3.6.4-asan/smoke.bin
