import argparse
import copy
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List

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


def sanitize_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s)


def copy_if_exists(src_dir: Path, out_dir: Path, names: List[str]) -> None:
    for name in names:
        src = src_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)


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
     * This preserves caller-provided output buffer + explicit length.
     * It does not preserve textual radix formatting.
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


def openssl_bn_signed_bn2bin_template() -> str:
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
     * source: mbedtls_mpi_write_string negative integer serialization
     * target: BN_signed_bn2bin signed binary serialization
     *
     * This preserves signed integer handling and caller-provided output buffer.
     * It does not preserve textual radix formatting.
     */
    ret = BN_signed_bn2bin(X, buf, BUFLEN);

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
        printf("[BUG] Canary corrupted: BN_signed_bn2bin wrote beyond caller buffer.\n");
        BN_free(X);
        return 1;
    }

    printf("[OK] Canary intact.\n");

    BN_free(X);
    return 0;
}
'''


def target_template_for(candidate: Dict[str, Any]) -> str:
    library = candidate.get("library")
    api = candidate.get("api")

    if library == "openssl" and api == "BN_bn2binpad":
        return openssl_bn2binpad_template()

    if library == "openssl" and api == "BN_signed_bn2bin":
        return openssl_bn_signed_bn2bin_template()

    raise ValueError(f"no target template rule for {library}:{api}")


def build_cross_mapping(
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
    candidate: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "source": {
            "library": source_meta.get("poc_source", {}).get("library"),
            "api": source_meta.get("poc_source", {}).get("api"),
            "template_id": source_meta.get("template_id"),
            "semantic_operation": source_meta.get("operation", {}).get("abstract"),
            "bug_class": source_meta.get("operation", {}).get("bug_class", []),
            "poc_pattern": mask_report.get("poc_pattern", {}),
        },
        "target": {
            "library": candidate.get("library"),
            "candidate_api": candidate.get("api"),
        },
        "equivalence_assessment": {
            "scores": candidate.get("scores", {}),
            "decision": candidate.get("decision"),
            "reason": candidate.get("reason"),
        },
        "parameter_mapping": candidate.get("parameter_mapping", {}),
        "preserved_vulnerability_features": candidate.get("preserved_vulnerability_features", []),
        "lost_or_weakened_features": candidate.get("lost_or_weakened_features", []),
        "source_context": {
            "rag_query_context": mask_report.get("rag_query_context", ""),
            "cross_generation_hints": mask_report.get("cross_generation_hints", {}),
        },
        "notes": [
            "Generated from migration candidate scoring rather than hard-coded target selection.",
            "This is vulnerability-path migration, not strict full API semantic equivalence.",
        ],
    }


def build_cross_meta(source_meta: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    cross_meta = copy.deepcopy(source_meta)
    cross_meta["status"] = "cross_generated_from_candidates"

    target_lib = candidate.get("library")
    target_api = candidate.get("api")

    base_template_id = source_meta.get("template_id", "UNKNOWN_TEMPLATE")
    target_suffix = sanitize_name(f"{target_lib}_{target_api}").upper()
    cross_meta["source_template_id"] = base_template_id
    cross_meta["template_id"] = f"{base_template_id}__{target_suffix}"

    cross_meta.setdefault("cross_library", {})
    cross_meta["cross_library"][target_lib] = {
        "target_api": target_api,
        "target_template": f"tmpl_{target_lib}.c",
        "scores": candidate.get("scores", {}),
        "decision": candidate.get("decision"),
        "reason": candidate.get("reason"),
        "parameter_mapping": candidate.get("parameter_mapping", {}),
        "preserved_vulnerability_features": candidate.get("preserved_vulnerability_features", []),
        "lost_or_weakened_features": candidate.get("lost_or_weakened_features", []),
    }

    return cross_meta


def generate_one_candidate(
    source_template_dir: Path,
    candidate_yaml: Path,
    candidate: Dict[str, Any],
    candidate_root: Path,
    out_root: Path,
) -> bool:
    if candidate.get("decision") != "generate":
        print(f"[SKIP] {candidate.get('library')} {candidate.get('api')} decision={candidate.get('decision')}")
        return False

    source_meta = load_yaml(source_template_dir / "template_meta.yaml")
    mask_report = load_yaml(source_template_dir / "mask_report.yaml")

    rel = candidate_yaml.parent.relative_to(candidate_root)
    target_dir_name = f"{candidate.get('library')}_{sanitize_name(candidate.get('api', 'unknown'))}"
    out_dir = out_root / rel / target_dir_name
    out_dir.mkdir(parents=True, exist_ok=True)

    copy_if_exists(
        source_template_dir,
        out_dir,
        [
            "poc_original.c",
            "tmpl_mbedtls.c",
            "README.md",
            "mask_report.yaml",
            "rag_context.json",
            "llm_updates.json",
            "normalization_report.json",
        ],
    )

    cross_meta = build_cross_meta(source_meta, candidate)
    dump_yaml(out_dir / "template_meta.yaml", cross_meta)

    target_lib = candidate.get("library")
    write_text(out_dir / f"tmpl_{target_lib}.c", target_template_for(candidate))

    cross_mapping = build_cross_mapping(source_meta, mask_report, candidate)
    dump_yaml(out_dir / "cross_mapping.yaml", cross_mapping)

    readme = f"""# Cross-Library Template Generated from Candidate Scoring

## Source

- Source template: `{source_meta.get("template_id")}`
- Source API: `{source_meta.get("poc_source", {}).get("api")}`
- Source library: `{source_meta.get("poc_source", {}).get("library")}`

## Target

- Target library: `{candidate.get("library")}`
- Target API: `{candidate.get("api")}`
- Candidate decision: `{candidate.get("decision")}`
- Final score: `{candidate.get("scores", {}).get("final")}`
- Vulnerability-path score: `{candidate.get("scores", {}).get("vulnerability_path")}`

## Reason

{candidate.get("reason")}

## Meaning

This template is generated because the candidate API preserves enough of the
source vulnerability path to support migration testing. This is not strict API
equivalence; it is vulnerability-path equivalence.

## Oracle

This migrated harness uses a memory-safety oracle inherited from the source PoC pattern.

The target API is executed with a caller-provided output buffer followed by a canary region. The oracle classifies the case as bug-like if the canary region is corrupted or if ASAN/UBSAN reports a memory-safety violation.

Expected safe behavior:

- the target API does not write beyond the provided output buffer;
- the canary region remains intact;
- no sanitizer crash is observed.

Bug candidate behavior:

- canary corruption;
- sanitizer crash;
- out-of-bounds write signal.

## Files

- `tmpl_mbedtls.c`
- `tmpl_{target_lib}.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
"""
    write_text(out_dir / "README.md", readme)

    print(f"[OK] generated {out_dir}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate cross-library templates from migration candidates."
    )
    parser.add_argument(
        "--template-root",
        default="normalized_templates",
        help="Root containing source templates.",
    )
    parser.add_argument(
        "--candidate-root",
        default="migration_candidates",
        help="Root containing candidates.yaml files.",
    )
    parser.add_argument(
        "--out-root",
        default="cross_templates_from_candidates",
        help="Output root.",
    )
    args = parser.parse_args()

    template_root = Path(args.template_root)
    candidate_root = Path(args.candidate_root)
    out_root = Path(args.out_root)

    if out_root.exists():
        shutil.rmtree(out_root)

    count = 0

    candidate_files = sorted(candidate_root.rglob("candidates.yaml"))
    if not candidate_files:
        print(f"[ERROR] no candidates.yaml found under {candidate_root}")
        return 1

    for cand_file in candidate_files:
        rel = cand_file.parent.relative_to(candidate_root)
        source_template_dir = template_root / rel

        if not source_template_dir.exists():
            print(f"[WARN] missing source template dir for {cand_file}: {source_template_dir}")
            continue

        obj = load_yaml(cand_file)
        candidates = obj.get("target_candidates", [])

        for candidate in candidates:
            try:
                if generate_one_candidate(
                    source_template_dir=source_template_dir,
                    candidate_yaml=cand_file,
                    candidate=candidate,
                    candidate_root=candidate_root,
                    out_root=out_root,
                ):
                    count += 1
            except Exception as e:
                print(f"[FAIL] {cand_file} {candidate.get('api')}: {e}")

    print("=" * 80)
    print(f"[SUMMARY] generated cross templates: {count}")
    print(f"[SUMMARY] output root: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
