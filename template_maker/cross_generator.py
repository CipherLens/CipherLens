import argparse
import copy
import json
import shutil
from pathlib import Path
from typing import Any, Dict

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def find_template_dirs(root: Path):
    return sorted(p.parent for p in root.rglob("template_meta.yaml"))


def openssl_bn2binpad_template() -> str:
    return r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define BUFLEN [BUFLEN]
#define CANARY_SIZE [CANARY_SIZE]
#define CANARY_BYTE 0xA5

static int canary_corrupted(unsigned char *buf)
{
    for (size_t i = 0; i < CANARY_SIZE; i++) {
        if (buf[BUFLEN + i] != CANARY_BYTE) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    BIGNUM *X = NULL;
    unsigned char buf[BUFLEN + CANARY_SIZE];
    int ret;
    long signed_value = [VALUE];
    unsigned long magnitude;

    memset(buf, 0x42, sizeof(buf));
    memset(buf + BUFLEN, CANARY_BYTE, CANARY_SIZE);

    X = BN_new();
    if (X == NULL) {
        printf("BN_new failed\n");
        return 2;
    }

    if (signed_value < 0) {
        magnitude = (unsigned long)(-signed_value);
    } else {
        magnitude = (unsigned long)signed_value;
    }

    if (!BN_set_word(X, magnitude)) {
        printf("BN_set_word failed\n");
        BN_free(X);
        return 2;
    }

    if (signed_value < 0) {
        BN_set_negative(X, 1);
    }

    /*
     * Migrated vulnerability pattern:
     * source: mbedtls_mpi_write_string(X, radix, buf, buflen, &olen)
     * target: BN_bn2binpad(X, buf, buflen)
     *
     * The exact radix parameter has no direct counterpart in BN_bn2binpad.
     * The migrated path focuses on caller-provided output buffer + length.
     */
    ret = BN_bn2binpad(X, buf, BUFLEN);

    printf("ret=%d\n", ret);
    printf("buf/canary prefix=");

    for (size_t i = 0; i < BUFLEN + 8 && i < sizeof(buf); i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {
            printf("%c", c);
        } else {
            printf("\\x%02x", c);
        }
    }
    printf("\n");

    if (canary_corrupted(buf)) {
        printf("[BUG] Canary corrupted: BN_bn2binpad wrote beyond caller buffer.\n");
        BN_free(X);
        return 1;
    }

    printf("[OK] Canary intact.\n");

    BN_free(X);
    return 0;
}
'''


def build_cross_mapping(meta: Dict[str, Any], mask_report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": {
            "library": "mbedtls",
            "api": "mbedtls_mpi_write_string",
            "template_id": meta.get("template_id", ""),
            "semantic_operation": meta.get("operation", {}).get("abstract", ""),
            "vulnerability_pattern": meta.get("operation", {}).get("bug_class", []),
        },
        "target": {
            "library": "openssl",
            "candidate_api": "BN_bn2binpad",
            "semantic_operation": "bignum_serialize_to_fixed_buffer",
        },
        "equivalence_assessment": {
            "semantic_equivalence": "medium",
            "parameter_structure_equivalence": "medium",
            "vulnerability_path_equivalence": "high",
            "migration_confidence": "medium",
        },
        "parameter_mapping": {
            "X": "BIGNUM *X",
            "[VALUE]": "BN_set_word(X, abs(VALUE)) + BN_set_negative",
            "[BUFLEN]": "BN_bn2binpad third argument tolen",
            "[CANARY_SIZE]": "same canary guard layout",
            "[RADIX]": "no direct counterpart in BN_bn2binpad; omitted in OpenSSL target template",
        },
        "preserved_roles": {
            "input_construction": [
                "construct BIGNUM from VALUE",
                "set negative flag when VALUE < 0",
            ],
            "trigger_call": [
                "ret = BN_bn2binpad(X, buf, BUFLEN);",
            ],
            "oracle": [
                "canary_corrupted(buf)",
                "ASAN/UBSAN runtime checks",
            ],
            "cleanup": [
                "BN_free(X)",
            ],
        },
        "source_context": {
            "rag_query_context": mask_report.get("rag_query_context", ""),
            "cross_generation_hints": mask_report.get("cross_generation_hints", {}),
        },
        "notes": [
            "This is vulnerability-path migration rather than full API semantic equivalence.",
            "The source radix parameter is not preserved because BN_bn2binpad serializes to big-endian binary.",
            "The caller-provided buffer and explicit length are preserved, which is the key boundary-risk path.",
        ],
    }


def generate_cross_template(template_dir: Path, root: Path, out_root: Path) -> bool:
    meta = load_yaml(template_dir / "template_meta.yaml")
    template_id = meta.get("template_id", "")

    if template_id != "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER":
        print(f"[SKIP] no cross rule for {template_id}")
        return False

    mask_report_path = template_dir / "mask_report.yaml"
    if not mask_report_path.exists():
        raise FileNotFoundError(f"missing mask_report.yaml: {mask_report_path}")

    mask_report = load_yaml(mask_report_path)

    rel = template_dir.relative_to(root)
    out_dir = out_root / rel
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy source files.
    for name in ["poc_original.c", "tmpl_mbedtls.c", "README.md", "mask_report.yaml", "rag_context.json", "llm_updates.json", "normalization_report.json"]:
        src = template_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)

    cross_meta = copy.deepcopy(meta)
    cross_meta["status"] = "cross_generated"
    cross_meta.setdefault("cross_library", {})
    cross_meta["cross_library"]["openssl"] = {
        "target_api": "BN_bn2binpad",
        "target_template": "tmpl_openssl.c",
        "semantic_equivalence": "medium",
        "parameter_structure_equivalence": "medium",
        "vulnerability_path_equivalence": "high",
        "migration_confidence": "medium",
        "note": "Migrates caller-provided output buffer boundary pattern; radix has no direct BN_bn2binpad counterpart.",
    }

    dump_yaml(out_dir / "template_meta.yaml", cross_meta)

    write_text(out_dir / "tmpl_openssl.c", openssl_bn2binpad_template())

    cross_mapping = build_cross_mapping(meta, mask_report)
    dump_yaml(out_dir / "cross_mapping.yaml", cross_mapping)

    readme = f"""# Cross-Library Template: mbedTLS to OpenSSL

## Source Pattern

- Source library: mbedTLS
- Source API: `mbedtls_mpi_write_string`
- Source template: `{template_id}`

## Target Candidate

- Target library: OpenSSL
- Target API: `BN_bn2binpad`

## Migration Meaning

This template migrates the vulnerability path rather than full API semantics.

The preserved risk pattern is:

1. construct a big integer value,
2. serialize it into a caller-provided output buffer,
3. use an explicit buffer length,
4. detect possible out-of-bounds writes with a canary oracle.

`RADIX` has no direct counterpart in `BN_bn2binpad`, so it is retained for the source mbedTLS template but omitted in the OpenSSL target template.

## Generated Files

- `tmpl_mbedtls.c`
- `tmpl_openssl.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
"""
    write_text(out_dir / "README.md", readme)

    print(f"[OK] cross-generated {template_dir} -> {out_dir}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate cross-library templates from source API harness templates.")
    parser.add_argument("--root", default="normalized_templates", help="Input template root.")
    parser.add_argument("--out-root", default="cross_templates", help="Output root.")
    args = parser.parse_args()

    root = Path(args.root)
    out_root = Path(args.out_root)

    if not root.exists():
        print(f"[ERROR] root not found: {root}")
        return 1

    if out_root.exists():
        shutil.rmtree(out_root)

    template_dirs = find_template_dirs(root)
    count = 0

    for td in template_dirs:
        if generate_cross_template(td, root, out_root):
            count += 1

    print("=" * 80)
    print(f"[SUMMARY] cross-generated templates: {count}")
    print(f"[SUMMARY] output root: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
