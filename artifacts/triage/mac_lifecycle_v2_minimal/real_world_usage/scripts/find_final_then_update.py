from pathlib import Path
import sys

FINALS = ["EVP_MAC_final", "CMAC_Final"]
UPDATES = ["EVP_MAC_update", "CMAC_Update"]

root = Path(sys.argv[1])

for p in root.rglob("*"):
    if p.suffix.lower() not in [".c", ".cc", ".cpp", ".h", ".hpp"]:
        continue

    lines = p.read_text(errors="ignore").splitlines()

    for i, line in enumerate(lines):
        if any(f in line for f in FINALS):
            for j in range(i + 1, min(i + 100, len(lines))):
                if any(u in lines[j] for u in UPDATES):
                    print(f"\n== {p} ==")
                    print(f"final line {i+1}: {line.strip()}")
                    print(f"update line {j+1}: {lines[j].strip()}")
                    print("\ncontext:")
                    for k in range(max(0, i - 8), min(len(lines), j + 8)):
                        print(f"{k+1:5d}: {lines[k]}")
