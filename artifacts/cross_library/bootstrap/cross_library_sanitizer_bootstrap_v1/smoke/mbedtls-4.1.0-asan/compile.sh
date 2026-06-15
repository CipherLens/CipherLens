#!/usr/bin/env bash
set -euo pipefail
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -I/home/wen/work/install-mbedtls-4.1.0-asan/include /home/wen/work/crypto-pattern-fuzz/artifacts/cross_library/bootstrap/cross_library_sanitizer_bootstrap_v1/smoke/mbedtls-4.1.0-asan/smoke.c -L/home/wen/work/install-mbedtls-4.1.0-asan/lib -Wl,-rpath,/home/wen/work/install-mbedtls-4.1.0-asan/lib -lmbedcrypto -o /home/wen/work/crypto-pattern-fuzz/artifacts/cross_library/bootstrap/cross_library_sanitizer_bootstrap_v1/smoke/mbedtls-4.1.0-asan/smoke.bin
