import argparse
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def replace_define(text: str, name: str, placeholder: str) -> str:
    pattern = rf"(^\s*#\s*define\s+{re.escape(name)}\s+)(.+?)\s*$"
    return re.sub(pattern, rf"\1{placeholder}", text, flags=re.M)


def mask_mpi_write_string(text: str) -> str:
    text = replace_define(text, "BUFLEN", "[BUFLEN]")
    text = replace_define(text, "CANARY_SIZE", "[CANARY_SIZE]")

    text = re.sub(
        r"mbedtls_mpi_lset\s*\(\s*&X\s*,\s*[-+]?\d+\s*\)",
        "mbedtls_mpi_lset(&X, [VALUE])",
        text,
    )

    text = re.sub(
        r"(&X\s*,\s*)2(\s*,\s*\(char\s*\*\)\s*buf\s*,\s*BUFLEN\s*,\s*&olen)",
        r"\1[RADIX]\2",
        text,
        flags=re.S,
    )

    return text


def mask_mpi_sub_abs(text: str) -> str:
    text = replace_define(text, "CANARY_SIZE", "[CANARY_SIZE]")

    text = re.sub(
        r'mbedtls_mpi_read_string\s*\(\s*&A\s*,\s*10\s*,\s*"5"\s*\)',
        'mbedtls_mpi_read_string(&A, [A_BASE], "[A_VALUE]")',
        text,
    )

    text = re.sub(
        r'mbedtls_mpi_read_string\s*\(\s*&B\s*,\s*16\s*,\s*"123456789abcdef01"\s*\)',
        'mbedtls_mpi_read_string(&B, [B_BASE], "[B_VALUE]")',
        text,
    )

    text = re.sub(
        r"prepare_output_with_canary\s*\(\s*&X\s*,\s*1\s*\)",
        "prepare_output_with_canary(&X, [X_LIMB_COUNT])",
        text,
    )

    return text


def mask_pk_verify_ext(text: str) -> str:
    text = replace_define(text, "KEY_BITS", "[KEY_BITS]")
    text = replace_define(text, "HASH_LEN", "[HASH_LEN]")
    text = replace_define(text, "SIG_LEN", "[SIG_LEN]")

    text = text.replace("MBEDTLS_RSA_SALT_LEN_ANY", "[EXPECTED_SALT_LEN]")

    # Replace digest algorithm after salt placeholder replacement.
    text = text.replace("MBEDTLS_MD_SHA256", "[MD_ALG]")

    text = re.sub(
        r"mbedtls_pk_verify_ext\s*\(\s*MBEDTLS_PK_RSASSA_PSS\s*,",
        "mbedtls_pk_verify_ext([PK_VERIFY_TYPE],",
        text,
    )

    return text


def common_meta(
    analysis: Dict[str, Any],
    template_id: str,
    template_name: str,
    operation_abstract: str,
    api_family: str,
    bug_class: List[str],
    mutation_points: List[Dict[str, Any]],
    oracle: Dict[str, Any],
    verdict: Dict[str, Any],
    generation_policy: Dict[str, Any],
    cross_library: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    trigger = analysis.get("trigger_call", {})
    source_file = Path(analysis["source_file"]).name

    meta = {
        "template_id": template_id,
        "template_name": template_name,
        "backend": "api_harness",
        "language": analysis.get("language", "c"),
        "status": "generated_by_mask",
        "poc_source": {
            "file": source_file,
            "library": analysis.get("library", "unknown"),
            "api": trigger.get("function", ""),
        },
        "operation": {
            "abstract": operation_abstract,
            "api_family": api_family,
            "bug_class": bug_class,
        },
        "source_api": {
            "library": analysis.get("library", "unknown"),
            "function": trigger.get("function", ""),
        },
        "mutation_points": mutation_points,
        "oracle": oracle,
        "verdict": verdict,
        "generation_policy": generation_policy,
        "rag_requirements": {
            "retrieve": [
                f"{trigger.get('function', '')} API constraints",
                "library unit-test call patterns",
                "cross-library candidate mappings",
                "related oracle knowledge",
            ]
        },
    }

    if cross_library is not None:
        meta["cross_library"] = cross_library

    return meta


def spec_for_trigger(trigger: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
    if trigger == "mbedtls_mpi_write_string":
        return {
            "out_dir": Path("bignum/mpi_write_string"),
            "mask_func": mask_mpi_write_string,
            "meta": common_meta(
                analysis,
                template_id="BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER",
                template_name="mbedtls_mpi_write_string negative small-buffer template",
                operation_abstract="bignum_serialize_to_string",
                api_family="BignumSerialize",
                bug_class=[
                    "output_buffer_boundary",
                    "negative_integer_serialization",
                    "canary_detected_oob_write",
                ],
                mutation_points=[
                    {"name": "VALUE", "placeholder": "[VALUE]", "type": "signed_integer", "default": -1},
                    {"name": "RADIX", "placeholder": "[RADIX]", "type": "enum", "default": 2},
                    {"name": "BUFLEN", "placeholder": "[BUFLEN]", "type": "size_t", "default": 4},
                    {"name": "CANARY_SIZE", "placeholder": "[CANARY_SIZE]", "type": "size_t", "default": 16},
                ],
                oracle={
                    "memory_safety": ["no_crash", "asan_clean", "canary_intact"],
                    "behavior": ["insufficient_buffer_should_fail", "output_length_should_be_reasonable"],
                },
                verdict={
                    "true_positive": {
                        "condition": "canary_corrupted == true",
                        "exit_code": 1,
                    },
                    "safe_behavior": {
                        "condition": "canary_corrupted == false",
                        "exit_code": 0,
                    },
                },
                generation_policy={
                    "max_cases": 64,
                    "priority": ["negative_values", "small_buffer_lengths", "radix_boundaries"],
                    "compile_with": ["asan", "ubsan"],
                },
            ),
        }

    if trigger == "mbedtls_mpi_sub_abs":
        return {
            "out_dir": Path("bignum/mpi_sub_abs"),
            "mask_func": mask_mpi_sub_abs,
            "meta": common_meta(
                analysis,
                template_id="BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY",
                template_name="mbedtls_mpi_sub_abs limb-boundary template",
                operation_abstract="bignum_subtract_absolute",
                api_family="BignumArithmetic",
                bug_class=[
                    "limb_boundary_oob_write",
                    "insufficient_output_limb_allocation",
                    "canary_detected_oob_write",
                ],
                mutation_points=[
                    {"name": "A_VALUE", "placeholder": "[A_VALUE]", "type": "string_number", "default": "5"},
                    {"name": "B_VALUE", "placeholder": "[B_VALUE]", "type": "string_hex", "default": "123456789abcdef01"},
                    {"name": "A_BASE", "placeholder": "[A_BASE]", "type": "enum", "default": 10},
                    {"name": "B_BASE", "placeholder": "[B_BASE]", "type": "enum", "default": 16},
                    {"name": "X_LIMB_COUNT", "placeholder": "[X_LIMB_COUNT]", "type": "size_t", "default": 1},
                    {"name": "CANARY_SIZE", "placeholder": "[CANARY_SIZE]", "type": "size_t", "default": 16},
                ],
                oracle={
                    "memory_safety": ["no_crash", "asan_clean", "canary_intact"],
                    "behavior": ["negative_result_should_be_rejected", "no_write_beyond_x_limbs"],
                },
                verdict={
                    "true_positive": {
                        "condition": "canary_corrupted == true",
                        "exit_code": 1,
                    },
                    "expected_rejection": {
                        "condition": "ret == MBEDTLS_ERR_MPI_NEGATIVE_VALUE && canary_corrupted == false",
                        "exit_code": 0,
                    },
                },
                generation_policy={
                    "max_cases": 128,
                    "priority": ["X_LIMB_COUNT_boundary", "B_VALUE_large_limb_count"],
                    "compile_with": ["asan", "ubsan"],
                },
                cross_library={
                    "openssl": {
                        "status": "candidate_mapping",
                        "api_family": "BignumArithmetic",
                        "candidate_api": "BN_usub",
                        "migration_confidence": "medium",
                    }
                },
            ),
        }

    if trigger == "mbedtls_pk_verify_ext":
        return {
            "out_dir": Path("pk/pk_verify_ext_null_deref"),
            "mask_func": mask_pk_verify_ext,
            "meta": common_meta(
                analysis,
                template_id="PK_VERIFY_EXT_OPAQUE_RSA_PSS_NULL_DEREF",
                template_name="mbedtls_pk_verify_ext opaque RSA-PSS null-deref template",
                operation_abstract="pk_verify_ext_opaque_key",
                api_family="SignatureVerify",
                bug_class=[
                    "null_pointer_dereference",
                    "opaque_key_type_confusion",
                    "missing_context_type_check",
                ],
                mutation_points=[
                    {"name": "KEY_BITS", "placeholder": "[KEY_BITS]", "type": "int", "default": 1024},
                    {"name": "HASH_LEN", "placeholder": "[HASH_LEN]", "type": "size_t", "default": 32},
                    {"name": "SIG_LEN", "placeholder": "[SIG_LEN]", "type": "size_t", "default": 128},
                    {"name": "MD_ALG", "placeholder": "[MD_ALG]", "type": "enum", "default": "MBEDTLS_MD_SHA256"},
                    {"name": "PK_VERIFY_TYPE", "placeholder": "[PK_VERIFY_TYPE]", "type": "enum", "default": "MBEDTLS_PK_RSASSA_PSS"},
                    {"name": "EXPECTED_SALT_LEN", "placeholder": "[EXPECTED_SALT_LEN]", "type": "enum", "default": "MBEDTLS_RSA_SALT_LEN_ANY"},
                ],
                oracle={
                    "memory_safety": ["no_crash", "asan_clean", "no_null_deref"],
                    "behavior": ["fixed_version_returns_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE"],
                },
                verdict={
                    "true_positive": {
                        "condition": "process_crash_or_asan_null_deref == true",
                        "exit_code": "nonzero_or_signal",
                    },
                    "fixed_behavior": {
                        "condition": "ret == MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE",
                        "exit_code": 0,
                    },
                },
                generation_policy={
                    "max_cases": 32,
                    "priority": ["PK_VERIFY_TYPE_RSASSA_PSS", "opaque_key_context"],
                    "compile_with": ["asan", "ubsan"],
                },
            ),
        }

    raise ValueError(f"Unsupported trigger API for masking: {trigger}")


def make_readme(meta: Dict[str, Any]) -> str:
    api = meta["poc_source"]["api"]
    bug_class = ", ".join(meta["operation"]["bug_class"])
    placeholders = "\n".join(
        f"- `{mp['placeholder']}`: {mp['name']} ({mp['type']})"
        for mp in meta["mutation_points"]
    )

    return f"""# Generated Template: {meta['template_name']}

## Source

Source PoC: `{meta['poc_source']['file']}`

## API

`{api}`

## Vulnerability Pattern

{bug_class}

## Mutation Points

{placeholders}

## Oracle

This generated template uses the oracle declared in `template_meta.yaml`, including memory-safety checks, return-code checks, and harness-specific conditions.

## Status

Generated by `template_maker/mask.py`. This output should be validated and compared with the corresponding golden template.
"""


def mask_one_analysis(analysis_path: Path, out_root: Path) -> Path:
    analysis = load_yaml(analysis_path)
    trigger = analysis.get("trigger_call", {}).get("function", "")

    spec = spec_for_trigger(trigger, analysis)

    poc_path = PROJECT_ROOT / analysis["source_file"]
    if not poc_path.exists():
        raise FileNotFoundError(f"PoC source not found: {poc_path}")

    original = read_text(poc_path)
    masked = spec["mask_func"](original)

    out_dir = out_root / spec["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(poc_path, out_dir / "poc_original.c")
    write_text(out_dir / "tmpl_mbedtls.c", masked)
    dump_yaml(out_dir / "template_meta.yaml", spec["meta"])
    write_text(out_dir / "README.md", make_readme(spec["meta"]))

    print(f"[OK] generated template: {out_dir}")
    return out_dir


def main():
    parser = argparse.ArgumentParser(description="Mask PoC files into C/C++ template skeletons.")
    parser.add_argument(
        "analysis_files",
        nargs="*",
        help="analysis/*.analysis.yaml files. If omitted, process all analysis/*.analysis.yaml",
    )
    parser.add_argument(
        "--out-root",
        default="generated_templates",
        help="Output root directory. Default: generated_templates",
    )
    args = parser.parse_args()

    out_root = Path(args.out_root)

    if args.analysis_files:
        analysis_files = [Path(p) for p in args.analysis_files]
    else:
        analysis_files = sorted(Path("analysis").glob("*.analysis.yaml"))

    if not analysis_files:
        print("[ERROR] no analysis files found")
        return 1

    for analysis_path in analysis_files:
        mask_one_analysis(analysis_path, out_root)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
