import json
import yaml
from pathlib import Path
from typing import Dict, Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "libraries.yaml"
OUT_DIR = PROJECT_ROOT / "knowledge_raw" / "wycheproof_vectors"


ALGO_FAMILY_MAP = {
    "aes_gcm": "AEADDecrypt",
    "aes_ccm": "AEADDecrypt",
    "chacha20_poly1305": "AEADDecrypt",
    "hmac": "MAC",
    "cmac": "MAC",
    "rsa": "SignatureVerify",
    "ecdsa": "SignatureVerify",
    "eddsa": "SignatureVerify",
    "ecdh": "KeyAgreement",
    "hkdf": "KDF",
    "pbkdf2": "KDF",
}


FOCUS_FILES = [
    "aes_gcm",
    "aes_ccm",
    "hmac_sha256",
    "rsa",
    "ecdsa",
]


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def guess_api_family(filename: str) -> str:
    name = filename.lower()
    for key, family in ALGO_FAMILY_MAP.items():
        if key in name:
            return family
    return "Unknown"


def should_import(filename: str) -> bool:
    name = filename.lower()
    return any(k in name for k in FOCUS_FILES)


def extract_params(test: Dict[str, Any]) -> Dict[str, Any]:
    skip = {"tcId", "comment", "result", "flags"}
    return {k: v for k, v in test.items() if k not in skip}


def expected_behavior(result: str) -> str:
    if result == "valid":
        return "accept"
    if result == "invalid":
        return "reject"
    return "acceptable"


def main():
    cfg = load_config()
    wp_dir = Path(cfg["wycheproof"]["testvectors_dir"])

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if not wp_dir.exists():
        raise FileNotFoundError(f"Wycheproof testvectors directory not found: {wp_dir}")

    json_files = sorted(wp_dir.glob("*.json"))
    json_files = [p for p in json_files if should_import(p.name)]

    print(f"[+] Found {len(json_files)} focused Wycheproof JSON files")

    total = 0

    for jf in json_files:
        api_family = guess_api_family(jf.name)
        out_path = OUT_DIR / f"{jf.stem}.jsonl"

        try:
            with jf.open("r", encoding="utf-8", errors="ignore") as f:
                obj = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load {jf}: {e}")
            continue

        algorithm = obj.get("algorithm", jf.stem)

        count = 0
        with out_path.open("w", encoding="utf-8") as out:
            for group in obj.get("testGroups", []):
                group_meta = {k: v for k, v in group.items() if k != "tests"}

                for test in group.get("tests", []):
                    item = {
                        "source": "wycheproof",
                        "file": jf.name,
                        "algorithm": algorithm,
                        "api_family": api_family,
                        "case_id": str(test.get("tcId", "")),
                        "comment": test.get("comment", ""),
                        "result": test.get("result", ""),
                        "expected_behavior": expected_behavior(test.get("result", "")),
                        "flags": test.get("flags", []),
                        "group": group_meta,
                        "params": extract_params(test),
                    }

                    out.write(json.dumps(item, ensure_ascii=False) + "\n")
                    total += 1
                    count += 1

        print(f"[+] {jf.name}: wrote {count} vectors -> {out_path.name}")

    print(f"[+] Total Wycheproof vector entries: {total}")


if __name__ == "__main__":
    main()
