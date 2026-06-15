import csv
import json
from pathlib import Path

root = Path(".")
inventory_dir = Path("inventory")
inventory_dir.mkdir(exist_ok=True)

csv_path = inventory_dir / "wolfssl_poc_inventory.csv"
md_path = inventory_dir / "wolfssl_poc_inventory.md"

poc_dirs = sorted(root.glob("WOLFSSL-POC-*"))

rows = []

for d in poc_dirs:
    if "rejected" in d.name.lower():
        continue

    meta_path = d / "metadata.json"
    if not meta_path.exists():
        continue

    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] failed to parse {meta_path}: {e}")
        continue

    rows.append({
        "poc_id": data.get("poc_id", d.name),
        "issue_or_cve": data.get("issue_or_cve", ""),
        "title": data.get("title", ""),
        "source_library": data.get("source_library", ""),
        "bug_class": data.get("bug_class", ""),
        "harness_family": data.get("harness_family", ""),
        "oracle_type": data.get("oracle_type", ""),
        "input_provenance": data.get("input_provenance", ""),
        "quality_level": data.get("quality_level", ""),
        "vulnerable_version_verified": str(data.get("vulnerable_version_verified", False)),
        "fixed_version_verified": str(data.get("fixed_version_verified", False)),
        "current_version_verified": str(data.get("current_version_verified", False)),
        "fixed_version": data.get("fixed_version", ""),
        "strict_reproduction": str(data.get("strict_reproduction", False)),
        "crash_signal": data.get("crash_signal", ""),
    })

fieldnames = [
    "poc_id",
    "issue_or_cve",
    "title",
    "source_library",
    "bug_class",
    "harness_family",
    "oracle_type",
    "input_provenance",
    "quality_level",
    "vulnerable_version_verified",
    "fixed_version_verified",
    "current_version_verified",
    "fixed_version",
    "strict_reproduction",
    "crash_signal",
]

with csv_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

lines = []
lines.append("# wolfSSL PoC Inventory")
lines.append("")
lines.append("| PoC ID | CVE / Issue | Bug Class | Input Provenance | Quality | Vulnerable | Fixed | Current |")
lines.append("|---|---|---|---|---|---|---|---|")

for r in rows:
    lines.append(
        "| {poc_id} | {issue_or_cve} | {bug_class} | {input_provenance} | {quality_level} | {vulnerable_version_verified} | {fixed_version_verified} | {current_version_verified} |".format(**r)
    )

lines.append("")
lines.append("## Summary")
lines.append("")
lines.append(f"- Total collected wolfSSL PoCs: {len(rows)}")
lines.append(f"- Q1 strict reproduction candidates: {sum(1 for r in rows if r['quality_level'] == 'Q1_strict_reproduction_candidate')}")
lines.append(f"- Vulnerable-version verified: {sum(1 for r in rows if r['vulnerable_version_verified'] == 'True')}")
lines.append(f"- Fixed-version verified: {sum(1 for r in rows if r['fixed_version_verified'] == 'True')}")
lines.append(f"- Current-version verified: {sum(1 for r in rows if r['current_version_verified'] == 'True')}")

md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"[OK] wrote {csv_path}")
print(f"[OK] wrote {md_path}")
print(f"[OK] total PoCs: {len(rows)}")
