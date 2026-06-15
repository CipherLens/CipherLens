#!/usr/bin/env bash
set -euo pipefail
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -I/home/wen/work/install-openssl-3.5.5-asan/include /home/wen/work/crypto-pattern-fuzz/artifacts/cross_library/bootstrap/cross_library_sanitizer_bootstrap_v1/smoke/openssl-3.5.5-asan/smoke.c -L/home/wen/work/install-openssl-3.5.5-asan/lib64 -Wl,-rpath,/home/wen/work/install-openssl-3.5.5-asan/lib64 -lssl -lcrypto -ldl -pthread -o /home/wen/work/crypto-pattern-fuzz/artifacts/cross_library/bootstrap/cross_library_sanitizer_bootstrap_v1/smoke/openssl-3.5.5-asan/smoke.bin
