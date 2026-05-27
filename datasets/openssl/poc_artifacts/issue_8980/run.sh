#!/bin/bash
set -euo pipefail

# 编译 C PoC
echo "[*] Compiling poc.c..."
gcc poc.c -o poc -lssl -lcrypto
echo "[*] Compilation finished."

# 使用 Valgrind 运行 PoC 并捕获内存错误
echo "[*] Running PoC under Valgrind..."
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./poc || true

# 直接运行 PoC 以捕获 crash（如果 valgrind 没显示）
echo "[*] Running PoC normally to catch segmentation faults..."
./poc || echo "[!] PoC triggered a crash or returned non-zero exit code"