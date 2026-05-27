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

if [ ! -f inputs/poc.pem ]; then
    echo "[!] Missing input file: inputs/poc.pem"
    echo "[!] Put the certificate PoC file here, then rerun:"
    echo "    data/openssl/poc_artifacts/issue_11567/inputs/poc.pem"
    exit 2
fi

echo "[*] Running C harness..."
./poc inputs/poc.pem > run.log 2>&1
status=$?
echo "[*] Normal run exit code: $status"

if command -v valgrind >/dev/null 2>&1; then
    echo "[*] Running under Valgrind..."
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./poc inputs/poc.pem > valgrind.log 2>&1
    echo "[*] Valgrind summary:"
    grep -E "ERROR SUMMARY|Invalid read|Invalid write|definitely lost|Conditional jump|uninitialised" valgrind.log || true
fi

exit 0
