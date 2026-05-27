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
    return re.sub(r"[^A-Za-z0-9_]+", "_", str(s))


def strip_code_fence(s: Any) -> str:
    text = str(s or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def indent_block(block: str, spaces: int = 4) -> str:
    block = strip_code_fence(block)
    if not block:
        return " " * spaces + "/* empty */"
    pad = " " * spaces
    return "\n".join(pad + line if line.strip() else "" for line in block.splitlines())


def normalize_init_block(block: str) -> str:
    block = strip_code_fence(block)
    # We declare BIGNUM *X = NULL in the harness. Avoid redeclaration.
    block = block.replace("BIGNUM *X = BN_new();", "X = BN_new();")
    block = block.replace("BIGNUM* X = BN_new();", "X = BN_new();")
    return block


def copy_if_exists(src_dir: Path, out_dir: Path, names: List[str]) -> None:
    for name in names:
        src = src_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)


def render_target_c_from_adapter(adapter: Dict[str, Any]) -> str:
    includes = adapter.get("include_headers") or []
    include_lines = []
    for h in includes:
        h = str(h).strip()
        if h:
            include_lines.append(f"#include <{h}>")

    if not include_lines:
        include_lines.append("#include <openssl/bn.h>")

    init_block = normalize_init_block(adapter.get("init_block", "X = BN_new();"))
    input_block = strip_code_fence(adapter.get("input_construction_block", ""))
    trigger_block = strip_code_fence(adapter.get("trigger_block", ""))
    cleanup_block = strip_code_fence(adapter.get("cleanup_block", "BN_free(X);"))

    target_api = adapter.get("target_api", "unknown_target_api")

    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{chr(10).join(include_lines)}

#define BUFLEN [BUFLEN]
#define CANARY_SIZE [CANARY_SIZE]
#define CANARY_BYTE 0xA5

static int canary_corrupted(unsigned char *buf)
{{
    for (size_t i = 0; i < CANARY_SIZE; i++) {{
        if (buf[BUFLEN + i] != CANARY_BYTE) {{
            return 1;
        }}
    }}
    return 0;
}}

int main(void)
{{
    BIGNUM *X = NULL;
    unsigned char buf[BUFLEN + CANARY_SIZE];
    int ret = 0;
    long signed_value = [VALUE];
    unsigned long magnitude = 0;

    memset(buf, 0x42, sizeof(buf));
    memset(buf + BUFLEN, CANARY_BYTE, CANARY_SIZE);

    if (signed_value < 0) {{
        magnitude = (unsigned long)(-signed_value);
    }} else {{
        magnitude = (unsigned long)signed_value;
    }}

    /*
     * Adapter-generated initialization.
     */
{indent_block(init_block, 4)}

    if (X == NULL) {{
        printf("target init failed\\n");
        return 2;
    }}

    /*
     * Adapter-generated input construction.
     */
{indent_block(input_block, 4)}

    /*
     * Adapter-generated trigger call.
     * target_api: {target_api}
     */
{indent_block(trigger_block, 4)}

    printf("ret=%d\\n", ret);
    printf("buf/canary prefix=");

    for (size_t i = 0; i < BUFLEN + 8 && i < sizeof(buf); i++) {{
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {{
            printf("%c", c);
        }} else {{
            printf("\\\\x%02x", c);
        }}
    }}
    printf("\\n");

    if (canary_corrupted(buf)) {{
        printf("[BUG] Canary corrupted: target API wrote beyond caller buffer.\\n");
{indent_block(cleanup_block, 8)}
        return 1;
    }}

    printf("[OK] Canary intact.\\n");

{indent_block(cleanup_block, 4)}
    return 0;
}}
'''


def build_cross_meta(source_meta: Dict[str, Any], adapter: Dict[str, Any]) -> Dict[str, Any]:
    cross_meta = copy.deepcopy(source_meta)
    cross_meta["status"] = "cross_generated_from_llm_adapter"

    target_lib = adapter.get("target_library")
    target_api = adapter.get("target_api")

    base_template_id = source_meta.get("template_id", "UNKNOWN_TEMPLATE")
    target_suffix = sanitize_name(f"{target_lib}_{target_api}").upper()
    cross_meta["source_template_id"] = base_template_id
    cross_meta["template_id"] = f"{base_template_id}__{target_suffix}"

    cross_meta.setdefault("cross_library", {})
    cross_meta["cross_library"][target_lib] = {
        "target_api": target_api,
        "target_template": f"tmpl_{target_lib}.c",
        "adapter_source": "llm_adapter_yaml",
        "applicability": adapter.get("applicability"),
        "preserved_features": adapter.get("preserved_features", []),
        "lost_or_weakened_features": adapter.get("lost_or_weakened_features", []),
        "llm_status": adapter.get("_llm_status"),
    }

    return cross_meta


def build_cross_mapping(
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
    adapter: Dict[str, Any],
    adapter_meta: Dict[str, Any],
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
            "library": adapter.get("target_library"),
            "candidate_api": adapter.get("target_api"),
        },
        "adapter": {
            "include_headers": adapter.get("include_headers", []),
            "type_mapping": adapter.get("type_mapping", {}),
            "constant_mapping": adapter.get("constant_mapping", {}),
            "init_block": adapter.get("init_block", ""),
            "input_construction_block": adapter.get("input_construction_block", ""),
            "trigger_block": adapter.get("trigger_block", ""),
            "return_value_semantics": adapter.get("return_value_semantics", ""),
            "oracle_strategy": adapter.get("oracle_strategy", {}),
            "cleanup_block": adapter.get("cleanup_block", ""),
            "llm_status": adapter.get("_llm_status"),
        },
        "candidate": adapter_meta.get("candidate", {}),
        "preserved_vulnerability_features": adapter.get("preserved_features", []),
        "lost_or_weakened_features": adapter.get("lost_or_weakened_features", []),
        "notes": [
            "Generated from LLM-filled structured adapter YAML.",
            "The C harness skeleton is fixed; the target-specific blocks come from adapter.yaml.",
            "This is vulnerability-path migration, not strict full API semantic equivalence.",
        ],
    }


def generate_one(adapter_file: Path, adapter_root: Path, out_root: Path) -> bool:
    adapter = load_yaml(adapter_file)
    adapter_meta = load_yaml(adapter_file.parent / "adapter_meta.yaml")

    source_files = adapter_meta.get("source_files", {})
    mask_report_path = Path(source_files.get("mask_report", ""))

    if not mask_report_path.exists():
        print(f"[FAIL] missing mask_report for adapter: {adapter_file}")
        return False

    source_template_dir = mask_report_path.parent
    source_meta = load_yaml(source_template_dir / "template_meta.yaml")
    mask_report = load_yaml(mask_report_path)

    rel = adapter_file.parent.relative_to(adapter_root)
    out_dir = out_root / rel
    out_dir.mkdir(parents=True, exist_ok=True)

    copy_if_exists(
        source_template_dir,
        out_dir,
        [
            "poc_original.c",
            "tmpl_mbedtls.c",
            "mask_report.yaml",
            "rag_context.json",
            "llm_updates.json",
            "normalization_report.json",
        ],
    )

    target_lib = adapter.get("target_library", "target")

    cross_meta = build_cross_meta(source_meta, adapter)
    dump_yaml(out_dir / "template_meta.yaml", cross_meta)

    write_text(out_dir / f"tmpl_{target_lib}.c", render_target_c_from_adapter(adapter))

    cross_mapping = build_cross_mapping(source_meta, mask_report, adapter, adapter_meta)
    dump_yaml(out_dir / "cross_mapping.yaml", cross_mapping)

    readme = f"""# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `{source_meta.get("template_id")}`
- Source API: `{source_meta.get("poc_source", {}).get("api")}`
- Source library: `{source_meta.get("poc_source", {}).get("library")}`

## Target API

- Target library: `{adapter.get("target_library")}`
- Target API: `{adapter.get("target_api")}`
- LLM status: `{adapter.get("_llm_status")}`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses a memory-safety oracle inherited from the source PoC pattern. The target API is executed with a caller-provided output buffer followed by a canary region.

Bug candidate behavior:

- canary corruption;
- sanitizer crash;
- out-of-bounds write signal.

Safe behavior:

- canary region remains intact;
- no sanitizer crash is observed.

## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

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
    parser = argparse.ArgumentParser(description="Generate cross-library templates from LLM adapter YAML.")
    parser.add_argument("--adapter-root", default="adapters")
    parser.add_argument("--out-root", default="cross_templates_from_adapters")
    args = parser.parse_args()

    adapter_root = Path(args.adapter_root)
    out_root = Path(args.out_root)

    if out_root.exists():
        shutil.rmtree(out_root)

    count = 0

    adapter_files = sorted(adapter_root.rglob("adapter.yaml"))
    if not adapter_files:
        print(f"[ERROR] no adapter.yaml found under {adapter_root}")
        return 1

    for af in adapter_files:
        try:
            if generate_one(af, adapter_root, out_root):
                count += 1
        except Exception as e:
            print(f"[FAIL] {af}: {e}")

    print("=" * 80)
    print(f"[SUMMARY] generated cross templates from adapters: {count}")
    print(f"[SUMMARY] output root: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
