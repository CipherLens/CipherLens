import json
from pathlib import Path

ROOT = Path(".")
RECIPE_PATH = ROOT / "inventory/wolfssl_pattern_recipes.json"
OUT_PATH = ROOT / "data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl"

PROMPT_MAP = {
    "Pattern-01": "prompts/pattern_01_x509_name_loc_overflow_prompt.md",
    "Pattern-02": "prompts/pattern_02_x509_text_off_by_one_prompt.md",
    "Pattern-03": "prompts/pattern_03_asn1_time_length_prompt.md",
    "Pattern-04": "prompts/pattern_04_akid_length_confusion_prompt.md",
    "Pattern-05": "prompts/pattern_05_dtls13_ack_length_truncation_prompt.md",
    "Pattern-06": "prompts/pattern_06_pkcs7_signedattrs_array_overflow_prompt.md",
    "Pattern-07": "prompts/pattern_07_pkcs7_ori_oid_stack_overflow_prompt.md",
    "Pattern-08": "prompts/pattern_08_tls13_pqc_keyshare_cleanup_uaf_prompt.md",
    "Pattern-09": "prompts/pattern_09_ssl_session_chain_count_overflow_prompt.md",
    "Pattern-10": "prompts/pattern_10_alpn_protocol_list_overread_prompt.md",
}

def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))

def load_text(path):
    return path.read_text(encoding="utf-8")

def load_metadata_for_poc(poc_id):
    p = ROOT / poc_id / "metadata.json"
    if not p.exists():
        return {}
    return load_json(p)

def main():
    recipes = load_json(RECIPE_PATH)
    rows = []

    for pattern in recipes.get("patterns", []):
        pattern_id = pattern["pattern_id"]
        related_pocs = pattern.get("related_pocs", [])
        primary_poc = related_pocs[0] if related_pocs else ""

        prompt_path = ROOT / PROMPT_MAP[pattern_id]
        prompt_text = load_text(prompt_path)

        poc_metadata = load_metadata_for_poc(primary_poc)

        sample = {
            "sample_id": f"wolfssl_{pattern_id.lower().replace('-', '_')}",
            "library": "wolfSSL",
            "task_type": "vulnerability_pattern_search",
            "pattern_id": pattern_id,
            "related_pocs": related_pocs,
            "prompt": prompt_text,
            "recipe": pattern,
            "poc_metadata": {
                "poc_id": poc_metadata.get("poc_id", primary_poc),
                "issue_or_cve": poc_metadata.get("issue_or_cve", ""),
                "title": poc_metadata.get("title", ""),
                "bug_class": poc_metadata.get("bug_class", ""),
                "input_provenance": poc_metadata.get("input_provenance", ""),
                "quality_level": poc_metadata.get("quality_level", ""),
                "vulnerable_version_verified": poc_metadata.get("vulnerable_version_verified", False),
                "fixed_version_verified": poc_metadata.get("fixed_version_verified", False),
                "current_version_verified": poc_metadata.get("current_version_verified", False),
                "strict_reproduction": poc_metadata.get("strict_reproduction", False),
                "crash_signal": poc_metadata.get("crash_signal", "")
            },
            "expected_output_schema": {
                "suspicious_regions": [
                    {
                        "function_name": "string",
                        "file_path": "string",
                        "relevant_variables": ["string"],
                        "guard_condition": "string",
                        "copy_or_write_operation": "string",
                        "destination_capacity": "string",
                        "matched_recipe_slots": ["string"],
                        "why_it_matches": "string",
                        "suggested_mutation": "string"
                    }
                ],
                "confidence": "low | medium | high"
            }
        }

        rows.append(sample)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUT_PATH.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[OK] wrote {OUT_PATH}")
    print(f"[OK] total samples: {len(rows)}")

if __name__ == "__main__":
    main()
