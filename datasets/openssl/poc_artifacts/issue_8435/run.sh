#!/usr/bin/env bash
set -u

echo "[*] Working directory: $(pwd)"
echo "[*] System OpenSSL:"
openssl version -a || true

echo "[*] Compiling poc.c..."
gcc poc.c -o poc -g -O0 -Wall -Wextra -lssl -lcrypto > build.log 2>&1
if [ $? -ne 0 ]; then
    echo "[!] Compile failed. See build.log"
    exit 1
fi

echo "[*] Compilation finished."
echo "[*] Linked libraries:"
ldd ./poc | grep -E "ssl|crypto" || true

if [ ! -f inputs/sm2_bad.key ]; then
    echo "[!] Missing input file: inputs/sm2_bad.key"
    echo "[!] Put the original SM2 PoC private key here, then rerun."
    exit 2
fi

if [ ! -f inputs/message.txt ]; then
    echo "[!] Missing input file: inputs/message.txt"
    echo "[!] Put the original message file here, then rerun."
    exit 2
fi

echo "[*] Running C harness..."
./poc inputs/sm2_bad.key inputs/message.txt > run.log 2>&1
status=$?
echo "[*] Normal run exit code: $status"

if command -v valgrind >/dev/null 2>&1; then
    echo "[*] Running under Valgrind..."
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./poc inputs/sm2_bad.key inputs/message.txt > valgrind.log 2>&1
    vg_status=$?
    echo "[*] Valgrind exit code: $vg_status"
    echo "[*] Valgrind summary:"
    grep -E "ERROR SUMMARY|Invalid read|Invalid write|definitely lost|Conditional jump|uninitialised" valgrind.log || true
fi

exit 0
