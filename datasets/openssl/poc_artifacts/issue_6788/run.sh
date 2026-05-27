#!/usr/bin/env bash
set -u

INPUTS=("inputs/crl.pem")

echo "[*] Working directory: $(pwd)"
echo "[*] System OpenSSL:"
openssl version -a || true

echo "[*] Compiling poc.c..."
gcc -g -O0 -Wall -Wextra -Wno-deprecated-declarations poc.c -o poc -lssl -lcrypto > build.log 2>&1
if [ $? -ne 0 ]; then
    echo "[!] Compile failed. See build.log"
    exit 1
fi

echo "[*] Compilation finished."
echo "[*] Linked libraries:"
ldd ./poc | grep -E "ssl|crypto" || true

for input in "${INPUTS[@]}"; do
    if [ ! -f "$input" ]; then
        echo "[!] Missing input file: $input"
        echo "[!] Put the original PoC input under inputs/, then rerun."
        exit 2
    fi
done

echo "[*] Running C harness..."
./poc "${INPUTS[@]}" > run.log 2>&1
status=$?
echo "[*] Normal run exit code: $status"
echo "[*] Saved normal run output to run.log"

if command -v valgrind >/dev/null 2>&1; then
    echo "[*] Running under Valgrind..."
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./poc "${INPUTS[@]}" > valgrind.log 2>&1
    vg_status=$?
    echo "[*] Valgrind exit code: $vg_status"
    echo "[*] Saved Valgrind output to valgrind.log"
    echo "[*] Valgrind summary:"
    grep -E "ERROR SUMMARY|Invalid read|Invalid write|definitely lost|Conditional jump|uninitialised" valgrind.log || true
fi

exit 0
