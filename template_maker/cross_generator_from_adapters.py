import argparse
import copy
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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


def normalize_include_header(header: Any) -> str:
    h = str(header or "").strip()
    h = h.strip("<>\"")
    if h.startswith("include/"):
        h = h[len("include/"):]
    return h


def render_include_lines(adapter: Dict[str, Any], default_headers: List[str]) -> str:
    headers = []
    seen = set()

    for h in default_headers + list(adapter.get("include_headers") or []):
        h = normalize_include_header(h)
        if h and h not in seen:
            seen.add(h)
            headers.append(h)

    return "\n".join(f"#include <{h}>" for h in headers)


def copy_if_exists(src_dir: Path, out_dir: Path, names: List[str]) -> None:
    for name in names:
        src = src_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)


def infer_source_template_id(adapter: Dict[str, Any], adapter_file: Path, adapter_root: Path) -> Optional[str]:
    for key in ["source_template_id", "template_id"]:
        value = adapter.get(key)
        if value:
            return str(value)

    try:
        rel = adapter_file.parent.relative_to(adapter_root)
        if len(rel.parts) >= 2:
            return rel.parts[0]
    except ValueError:
        pass

    parent = adapter_file.parent.parent.name
    return parent or None


def find_normalized_template_dir(template_id: str, root: Path = Path("normalized_templates")) -> Optional[Path]:
    if not template_id or not root.exists():
        return None

    for meta_path in sorted(root.rglob("template_meta.yaml")):
        meta = load_yaml(meta_path)
        if meta.get("template_id") == template_id or meta.get("source_template_id") == template_id:
            return meta_path.parent

    return None


def load_or_infer_adapter_meta(
    adapter: Dict[str, Any],
    adapter_file: Path,
    adapter_root: Path,
) -> Dict[str, Any]:
    meta_path = adapter_file.parent / "adapter_meta.yaml"
    if meta_path.exists():
        return load_yaml(meta_path)

    template_id = infer_source_template_id(adapter, adapter_file, adapter_root)
    source_template_dir = find_normalized_template_dir(str(template_id or ""))
    if source_template_dir is None:
        raise FileNotFoundError(
            f"adapter_meta.yaml missing and no normalized template found for template_id={template_id!r}"
        )

    target_library = adapter.get("target_library")
    target_api = adapter.get("target_api")

    return {
        "candidate": {
            "target_api": target_api,
            "target_library": target_library,
        },
        "source_files": {
            "template_meta": str(source_template_dir / "template_meta.yaml"),
            "mask_report": str(source_template_dir / "mask_report.yaml"),
            "source_template": str(source_template_dir / "tmpl_mbedtls.c"),
        },
        "inferred_adapter_meta": True,
    }


def optional_path(value: Any) -> Optional[Path]:
    text = str(value or "").strip()
    if not text:
        return None
    return Path(text)


def render_buffer_canary_harness(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    include_lines = render_include_lines(adapter, ["openssl/bn.h"])

    init_block = normalize_init_block(adapter.get("init_block", "X = BN_new();"))
    input_block = strip_code_fence(adapter.get("input_construction_block", ""))
    trigger_block = strip_code_fence(adapter.get("trigger_block", ""))
    cleanup_block = strip_code_fence(adapter.get("cleanup_block", "BN_free(X);"))

    target_api = adapter.get("target_api", "unknown_target_api")

    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{include_lines}

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


def normalize_der_init_block(block: str) -> str:
    block = strip_code_fence(block)
    # The DER pointer-consumption skeleton owns these common oracle variables.
    patterns = [
        r"^\s*const\s+unsigned\s+char\s+\*p\s*=\s*NULL\s*;\s*$",
        r"^\s*long\s+consumed_len\s*=\s*0\s*;\s*$",
        r"^\s*size_t\s+consumed_len\s*=\s*0\s*;\s*$",
    ]
    lines = []
    for line in block.splitlines():
        if any(re.match(pat, line) for pat in patterns):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def extract_static_function(source: str, name: str) -> str:
    marker = f"{name}("
    idx = source.find(marker)
    if idx < 0:
        return ""

    start = source.rfind("static ", 0, idx)
    if start < 0:
        return ""

    brace = source.find("{", idx)
    if brace < 0:
        return ""

    depth = 0
    for pos in range(brace, len(source)):
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1].strip()

    return ""


def der_helper_fallback() -> str:
    return r'''static int hexval(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_to_bin(const char *hex,
                      unsigned char *out,
                      size_t out_size,
                      size_t *out_len)
{
    size_t n = 0;
    int hi = -1;

    while (*hex != '\0') {
        int v;

        if (isspace((unsigned char) *hex)) {
            hex++;
            continue;
        }

        v = hexval((unsigned char) *hex);
        if (v < 0) {
            return -1;
        }

        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_size) {
                return -2;
            }
            out[n++] = (unsigned char) ((hi << 4) | v);
            hi = -1;
        }

        hex++;
    }

    if (hi >= 0) {
        return -3;
    }

    *out_len = n;
    return 0;
}

static const char *select_base_der_hex(const char *der_kind)
{
    static const char *private_base_hex =
        "3063020100021100cc8ab070369ede72920e5a51523c8571"
        "02030100010211009a6318982a7231de1894c54aa4909201"
        "020900f3058fd8dc484d61020900d7770dbd8b78a2110209"
        "009471f14c26428401020813425f060c4b72210208052b93"
        "d01747a87c";
    static const char *public_base_hex =
        "308189028181009f091e6968b474f76f0e9c237c1d895996"
        "ae704b4f6d706acec8d2daac6209bf524aa3f658d0283a"
        "dba1077f6cbe92e425dcde52290b239cade91be86c884254"
        "34986806e85734e159768f3dfea932baaa9409d25bace8ee"
        "9dce0cdde0903207299de575ae60feccf0daf82334ab836"
        "38539b0da74072f253acea8afc8e66bb70203010001";

    if (strcmp(der_kind, "private") == 0) {
        return private_base_hex;
    }
    if (strcmp(der_kind, "public") == 0) {
        return public_base_hex;
    }
    return NULL;
}

static int build_der_with_trailing_garbage(const char *base_hex,
                                           const char *trailing_hex,
                                           unsigned char *der,
                                           size_t der_size,
                                           size_t *der_len,
                                           size_t *trailing_len)
{
    int ret;
    size_t base_len = 0;

    ret = hex_to_bin(base_hex, der, der_size, &base_len);
    if (ret != 0) {
        return ret;
    }

    ret = hex_to_bin(trailing_hex,
                     der + base_len,
                     der_size - base_len,
                     trailing_len);
    if (ret != 0) {
        return ret;
    }

    *der_len = base_len + *trailing_len;
    return 0;
}'''


def extract_der_helpers(source_template_dir: Path) -> str:
    source_path = source_template_dir / "tmpl_mbedtls.c"
    source = source_path.read_text(encoding="utf-8", errors="ignore") if source_path.exists() else ""
    names = [
        "hexval",
        "hex_to_bin",
        "select_base_der_hex",
        "build_der_with_trailing_garbage",
    ]
    helpers = [extract_static_function(source, name) for name in names]
    if all(helpers):
        return "\n\n".join(helpers)
    return der_helper_fallback()


def render_der_pointer_consumption_harness(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    extra_headers = []
    if adapter.get("target_api") in {"d2i_RSA_PUBKEY", "d2i_PUBKEY"}:
        extra_headers.append("openssl/x509.h")

    adapter_for_includes = dict(adapter)
    adapter_for_includes["include_headers"] = list(adapter.get("include_headers") or []) + extra_headers
    include_lines = render_include_lines(adapter_for_includes, [])
    helpers = extract_der_helpers(source_template_dir)

    init_block = normalize_der_init_block(adapter.get("init_block", ""))
    input_block = strip_code_fence(adapter.get("input_construction_block", ""))
    trigger_block = strip_code_fence(adapter.get("trigger_block", ""))
    cleanup_block = strip_code_fence(adapter.get("cleanup_block", ""))
    target_api = adapter.get("target_api", "unknown_target_api")

    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

{include_lines}

#define MAX_DER_SIZE 1024
#define TRAILING_GARBAGE_HEX "[TRAILING_GARBAGE_BYTES]"
#define TRAILING_GARBAGE_EXPECTED_LEN ((size_t) [TRAILING_GARBAGE_LEN])

{helpers}

int main(void)
{{
    const char *der_kind = "[DER_KIND]";
    const char *base_hex = NULL;
    unsigned char der[MAX_DER_SIZE];
    size_t der_len = 0;
    size_t trailing_len = 0;
    const unsigned char *p = NULL;
    long consumed_len = 0;
    int ret = 0;

    setbuf(stdout, NULL);
    memset(der, 0, sizeof(der));

    base_hex = select_base_der_hex(der_kind);
    if (base_hex == NULL) {{
        printf("[ERROR] unsupported DER_KIND: %s\\n", der_kind);
        return 2;
    }}

    ret = build_der_with_trailing_garbage(base_hex,
                                          TRAILING_GARBAGE_HEX,
                                          der,
                                          sizeof(der),
                                          &der_len,
                                          &trailing_len);
    if (ret != 0) {{
        printf("[ERROR] DER construction failed: %d\\n", ret);
        return 2;
    }}

    if (trailing_len != TRAILING_GARBAGE_EXPECTED_LEN) {{
        printf("[ERROR] trailing garbage length mismatch: got=%zu expected=%zu\\n",
               trailing_len, TRAILING_GARBAGE_EXPECTED_LEN);
        return 2;
    }}

    /*
     * Adapter-generated initialization.
     */
{indent_block(init_block, 4)}

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
    printf("der_len=%zu\\n", der_len);
    printf("consumed_len=%ld\\n", consumed_len);

    if (ret == 0 && consumed_len < (long) der_len) {{
        printf("[BUG] target decoded first DER object but left trailing garbage unconsumed.\\n");
{indent_block(cleanup_block, 8)}
        return 1;
    }}

    if (ret == 0 && consumed_len == (long) der_len) {{
        printf("[OK] target decoded and consumed full input exactly.\\n");
{indent_block(cleanup_block, 8)}
        return 0;
    }}

    printf("[OK] target rejected trailing-garbage input.\\n");
{indent_block(cleanup_block, 4)}
    return 0;
}}
'''


RENDERERS: Dict[str, Callable[[Dict[str, Any], Path, Dict[str, Any], Dict[str, Any]], str]] = {
    "buffer_canary_boundary": render_buffer_canary_harness,
    "der_pointer_consumption": render_der_pointer_consumption_harness,
}


def render_target_c_from_adapter(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    harness_family = source_meta.get("harness_family") or "buffer_canary_boundary"
    renderer = RENDERERS.get(harness_family)
    if renderer is None:
        known = ", ".join(sorted(RENDERERS))
        raise ValueError(f"unknown harness_family={harness_family!r}; known: {known}")
    return renderer(adapter, source_template_dir, source_meta, mask_report)


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
    adapter_meta = load_or_infer_adapter_meta(adapter, adapter_file, adapter_root)

    source_files = adapter_meta.get("source_files", {})
    template_meta_path = optional_path(source_files.get("template_meta"))
    mask_report_path = optional_path(source_files.get("mask_report"))

    if mask_report_path is None or not mask_report_path.exists():
        print(f"[FAIL] missing mask_report for adapter: {adapter_file}")
        return False

    if template_meta_path is not None and template_meta_path.exists():
        source_template_dir = template_meta_path.parent
        source_meta = load_yaml(template_meta_path)
    else:
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

    write_text(
        out_dir / f"tmpl_{target_lib}.c",
        render_target_c_from_adapter(adapter, source_template_dir, source_meta, mask_report),
    )

    cross_mapping = build_cross_mapping(source_meta, mask_report, adapter, adapter_meta)
    dump_yaml(out_dir / "cross_mapping.yaml", cross_mapping)

    harness_family = source_meta.get("harness_family") or "buffer_canary_boundary"
    if harness_family == "der_pointer_consumption":
        oracle_text = """The migrated harness uses a pointer-consumption semantic oracle for DER parsing.

Bug candidate behavior:

- target decoder returns success;
- `consumed_len < der_len`, meaning the first DER object was decoded while trailing garbage remained unconsumed.

Safe behavior:

- target decoder rejects the trailing-garbage input; or
- target decoder succeeds and `consumed_len == der_len`.
"""
    else:
        oracle_text = """The migrated harness uses a memory-safety oracle inherited from the source PoC pattern. The target API is executed with a caller-provided output buffer followed by a canary region.

Bug candidate behavior:

- canary corruption;
- sanitizer crash;
- out-of-bounds write signal.

Safe behavior:

- canary region remains intact;
- no sanitizer crash is observed.
"""

    readme = f"""# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `{source_meta.get("template_id")}`
- Source API: `{source_meta.get("poc_source", {}).get("api")}`
- Source library: `{source_meta.get("poc_source", {}).get("library")}`
- Harness family: `{harness_family}`

## Target API

- Target library: `{adapter.get("target_library")}`
- Target API: `{adapter.get("target_api")}`
- LLM status: `{adapter.get("_llm_status")}`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

{oracle_text}

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

    out_root.mkdir(parents=True, exist_ok=True)

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
