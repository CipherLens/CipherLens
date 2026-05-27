#!/usr/bin/env bash
set -u

echo "[*] Working directory: $(pwd)"
echo "[*] System OpenSSL version:"
openssl version -a || true

echo "[*] Compiling poc.c..."
gcc poc.c -o poc -g -O0 -Wall -Wextra -lssl -lcrypto > build.log 2>&1
compile_status=$?

if [ $compile_status -ne 0 ]; then
    echo "[!] Compile failed. See build.log"
    exit $compile_status
fi

echo "[*] Compilation finished."

echo "[*] Linked OpenSSL libraries:"
ldd ./poc | grep -E "ssl|crypto" || true

echo "[*] Running PoC normally..."
./poc > run.log 2>&1
run_status=$?
echo "[*] Normal run exit code: $run_status"

if command -v valgrind >/dev/null 2>&1; then
    echo "[*] Running PoC under Valgrind..."
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./poc > valgrind.log 2>&1
    vg_status=$?
    echo "[*] Valgrind exit code: $vg_status"
    echo "[*] Valgrind summary:"
    grep -E "ERROR SUMMARY|LEAK SUMMARY|definitely lost|indirectly lost|Invalid read|Invalid write|Conditional jump|uninitialised" valgrind.log || true
else
    echo "[!] Valgrind is not installed. Skip valgrind."
fi

exit 0
