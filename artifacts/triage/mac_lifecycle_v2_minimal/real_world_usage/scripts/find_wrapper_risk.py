from pathlib import Path
import sys
import re

root = Path(sys.argv[1])
final_terms = ["EVP_MAC_final", "CMAC_Final"]
update_terms = ["EVP_MAC_update", "CMAC_Update"]
state_terms = ["finalized", "finalised", "done", "closed", "finished", "state"]

for p in root.rglob("*"):
    if p.suffix.lower() not in [".c", ".cc", ".cpp", ".h", ".hpp"]:
        continue
    text = p.read_text(errors="ignore")
    has_final = any(x in text for x in final_terms)
    has_update = any(x in text for x in update_terms)
    if not (has_final and has_update):
        continue

    low = text.lower()
    has_state_guard_word = any(x in low for x in state_terms)

    print(f"\n== {p} ==")
    print("has_final=1")
    print("has_update=1")
    print(f"has_state_guard_word={int(has_state_guard_word)}")

    lines = text.splitlines()
    for i, line in enumerate(lines):
        if any(x in line for x in final_terms + update_terms):
            start = max(0, i - 4)
            end = min(len(lines), i + 5)
            print(f"\n-- context around line {i+1} --")
            for j in range(start, end):
                print(f"{j+1:5d}: {lines[j]}")
