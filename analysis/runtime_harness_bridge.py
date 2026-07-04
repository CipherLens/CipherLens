#!/usr/bin/env python3
"""Bridge stage campaign plans into bounded runtime smoke compile/run reports."""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from analysis.card_contract_loader import DEFAULT_WOLFSSL_ROOT, load_yaml_file, target_runtime_status, wolfssl_preflight, write_yaml


SANITIZER_MARKERS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "runtime error:",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "SEGV",
]

WOLFSSL_RUNTIME_ALIASES = {
    "wolfssl-5.9.1": "wolfssl",
    "wolfssl-5.9.1-asan": "wolfssl",
    "wolfSSL-5.9.1": "wolfssl",
    "wolfSSL-5.9.1-asan": "wolfssl",
}

P1_RENDER_REQUIREMENTS = {
    "return_code_outlen_semantic": {
        "renderer_status": "preflight_supported_runtime_renderer_pending",
        "harness_template_id": "return_code_outlen_template",
        "required_fixture": "cipher_invalid_padding_input_output_buffer_fixture",
        "required_inputs": ["key", "iv", "ciphertext", "output_buffer", "output_length_pointer"],
        "expected_oracle": "invalid_padding_output_length_oracle",
        "must_not_route_to": ["der_pointer_consumption"],
    },
    "x509_asn1_inner_boundary": {
        "renderer_status": "preflight_supported_runtime_renderer_pending",
        "harness_template_id": "x509_inner_boundary_template",
        "required_fixture": "malformed_x509_der_seed",
        "required_inputs": ["der", "der_len", "mbedtls_x509_crt_context"],
        "expected_oracle": "inner_asn1_boundary_semantic_oracle",
        "must_not_route_to": ["der_pointer_consumption"],
    },
}


def _runtime_target_kind(target: str) -> str:
    return WOLFSSL_RUNTIME_ALIASES.get(target, target)


def _runtime_status_for_target(target: str) -> str:
    runtime_target = _runtime_target_kind(target)
    return target_runtime_status(runtime_target)


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _signal_name(returncode: int | None) -> str:
    if returncode is None or returncode >= 0:
        return ""
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIG{-returncode}"


def _sanitizer_summary(text: str) -> dict[str, Any]:
    markers = [marker for marker in SANITIZER_MARKERS if marker in text]
    kinds = []
    if "AddressSanitizer" in text:
        kinds.append("asan")
    if "UndefinedBehaviorSanitizer" in text or "runtime error:" in text:
        kinds.append("ubsan")
    if "LeakSanitizer" in text:
        kinds.append("lsan")
    return {
        "sanitizer_observed": bool(markers),
        "markers": sorted(set(markers)),
        "kinds": sorted(set(kinds)),
    }


def _bytes_c_array(data: bytes, indent: str = "    ") -> str:
    lines = []
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02x}" for b in data[i : i + 12])
        lines.append(indent + chunk)
    return ",\n".join(lines)


def _der_seed_root(path: Path) -> Path:
    candidates = [
        path.parent / "der_seeds",
        path / "der_seeds",
        Path("artifacts/cross_library/mainline/p0_der_payload_oracle_enrichment_v1/der_seeds"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _seed_for_case(case: dict[str, Any], out_dir: Path) -> tuple[Path, str]:
    seed_root = _der_seed_root(out_dir)
    target = str(case.get("target", ""))
    selected_api = str((case.get("slot_binding") or {}).get("selected_api") or "")
    runtime_target = _runtime_target_kind(target)
    if runtime_target == "wolfssl":
        if selected_api == "wc_RsaPublicKeyDecode":
            return seed_root / "rsa_pkcs1_public.der", "rsa_pkcs1_public.der"
        return seed_root / "rsa_pkcs1_private.der", "rsa_pkcs1_private.der"
    if _target_family(target) == "botan":
        if selected_api == "Botan::X509::load_key":
            return seed_root / "rsa_pkcs1_public.der", "rsa_pkcs1_public.der"
        return seed_root / "rsa_pkcs8_private.der", "rsa_pkcs8_private.der"
    return seed_root / "rsa_pkcs8_private.der", "rsa_pkcs8_private.der"


def _der_arrays(seed: Path) -> tuple[bytes, bytes]:
    clean = seed.read_bytes()
    trailing = clean + bytes([0x00, 0x01, 0x02, 0x03])
    return clean, trailing


def _target_family(target: str) -> str:
    if target.startswith("mbedtls"):
        return "mbedtls"
    if target.startswith("botan"):
        return "botan"
    if _runtime_target_kind(target) == "wolfssl":
        return "wolfssl"
    return target


def _write_der_case_source(path: Path, case: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    seed, seed_name = _seed_for_case(case, out_dir)
    clean, trailing = _der_arrays(seed)
    clean_array = _bytes_c_array(clean)
    trailing_array = _bytes_c_array(trailing)
    target = str(case.get("target", ""))
    target_family = _target_family(target)
    selected_api = str((case.get("slot_binding") or {}).get("selected_api") or "")
    metadata = {
        "uses_real_der_seed": True,
        "clean_der_seed": seed.as_posix(),
        "trailing_der_seed": seed.as_posix() + "+00010203",
        "clean_der_size": len(clean),
        "trailing_der_size": len(trailing),
        "selected_api": selected_api,
        "oracle_type": "parser_full_consumption_oracle",
    }
    if target_family == "mbedtls":
        parse_call = "mbedtls_pk_parse_key(&ctx, der, len, NULL, 0, NULL, NULL)"
        if target.startswith("mbedtls-4."):
            parse_call = "mbedtls_pk_parse_key(&ctx, der, len, NULL, 0)"
        path.write_text(
            f"""#include <mbedtls/pk.h>
#include <stdio.h>
#include <stddef.h>

static const unsigned char clean_der[] = {{
{clean_array}
}};
static const unsigned char trailing_der[] = {{
{trailing_array}
}};

static int parse_one(const unsigned char *der, size_t len) {{
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    int ret = {parse_call};
    mbedtls_pk_free(&ctx);
    return ret;
}}

int main(void) {{
    int clean_ret = parse_one(clean_der, sizeof(clean_der));
    int trailing_ret = parse_one(trailing_der, sizeof(trailing_der));
    printf("DER_ORACLE target={target} api={selected_api} seed={seed_name}\\n");
    printf("DER_ORACLE clean_len=%zu trailing_len=%zu clean_return=%d trailing_return=%d clean_consumed=-1 trailing_consumed=-1\\n",
           sizeof(clean_der), sizeof(trailing_der), clean_ret, trailing_ret);
    return 0;
}}
""",
            encoding="utf-8",
        )
        return metadata
    if target_family == "botan":
        path.write_text(
            f"""#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>

static const uint8_t clean_der[] = {{
{clean_array}
}};
static const uint8_t trailing_der[] = {{
{trailing_array}
}};

static int parse_one(const uint8_t *der, size_t len) {{
    try {{
        std::unique_ptr<Botan::Private_Key> key = Botan::PKCS8::load_key(std::span<const uint8_t>(der, len));
        return key ? 0 : 1;
    }} catch(...) {{
        return -1;
    }}
}}

int main() {{
    int clean_ret = parse_one(clean_der, sizeof(clean_der));
    int trailing_ret = parse_one(trailing_der, sizeof(trailing_der));
    std::printf("DER_ORACLE target={target} api={selected_api} seed={seed_name}\\n");
    std::printf("DER_ORACLE clean_len=%zu trailing_len=%zu clean_return=%d trailing_return=%d clean_consumed=-1 trailing_consumed=-1\\n",
                sizeof(clean_der), sizeof(trailing_der), clean_ret, trailing_ret);
    return 0;
}}
""",
            encoding="utf-8",
        )
        return metadata
    if target_family == "wolfssl":
        decode_call = "wc_RsaPrivateKeyDecode(der, &idx, &key, (word32)len)"
        if selected_api == "wc_RsaPublicKeyDecode":
            decode_call = "wc_RsaPublicKeyDecode(der, &idx, &key, (word32)len)"
        path.write_text(
            f"""#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/types.h>
#include <stdio.h>
#include <stddef.h>

static const unsigned char clean_der[] = {{
{clean_array}
}};
static const unsigned char trailing_der[] = {{
{trailing_array}
}};

static int parse_one(const unsigned char *der, size_t len, unsigned int *consumed) {{
    word32 idx = 0;
    int init_ret = 0;
    RsaKey *key = wc_NewRsaKey(NULL, INVALID_DEVID, &init_ret);
    if (key == NULL || init_ret != 0) {{
        *consumed = 0;
        return init_ret;
    }}
    int ret = {decode_call.replace('&key', 'key')};
    *consumed = (unsigned int)idx;
    wc_FreeRsaKey(key);
    return ret;
}}

int main(void) {{
    unsigned int clean_consumed = 0;
    unsigned int trailing_consumed = 0;
    int clean_ret = parse_one(clean_der, sizeof(clean_der), &clean_consumed);
    int trailing_ret = parse_one(trailing_der, sizeof(trailing_der), &trailing_consumed);
    printf("DER_ORACLE target={target} api={selected_api} seed={seed_name}\\n");
    printf("DER_ORACLE clean_len=%zu trailing_len=%zu clean_return=%d trailing_return=%d clean_consumed=%u trailing_consumed=%u\\n",
           sizeof(clean_der), sizeof(trailing_der), clean_ret, trailing_ret, clean_consumed, trailing_consumed);
    return 0;
}}
""",
            encoding="utf-8",
        )
        return metadata
    raise ValueError(f"unsupported_der_target:{target}")


def _source_suffix_for_case(case: dict[str, Any]) -> str:
    if case.get("framework_family") == "der_pointer_consumption" and _target_family(str(case.get("target", ""))) == "botan":
        return ".cpp"
    return ".c"


def _compiler_for_case(case: dict[str, Any]) -> str:
    if case.get("framework_family") == "der_pointer_consumption" and _target_family(str(case.get("target", ""))) == "botan":
        return shutil.which("c++") or shutil.which("g++") or shutil.which("clang++") or ""
    return shutil.which("cc") or shutil.which("gcc") or ""


def _write_case_source(path: Path, case: dict[str, Any], out_dir: Path | None = None) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    family = case.get("framework_family", "unknown_family")
    pattern = case.get("concrete_pattern", "unknown_pattern")
    target = case.get("target", "unknown_target")
    if family == "der_pointer_consumption" and out_dir is not None:
        return _write_der_case_source(path, case, out_dir)
    if _runtime_target_kind(target) == "wolfssl":
        path.write_text(
            "\n".join(
                [
                    "#include <wolfssl/options.h>",
                    "#include <wolfssl/ssl.h>",
                    "#include <stdio.h>",
                    "int main(void) {",
                    "    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {",
                    "        return 2;",
                    "    }",
                    f'    puts("runtime_smoke:{target}:{family}:{pattern}");',
                    "    wolfSSL_Cleanup();",
                    "    return 0;",
                    "}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return {}
    path.write_text(
        "\n".join(
            [
                "#include <stdio.h>",
                "int main(void) {",
                f'    puts("runtime_smoke:{target}:{family}:{pattern}");',
                "    return 0;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {}


def _sequence_items(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _sequence_text(value: Any) -> str:
    return " ".join(_sequence_items(value))


def render_readiness_for_slot_bindings(slot_bindings_doc: dict[str, Any]) -> dict[str, Any]:
    """Preflight slot bindings before runtime rendering without writing C files."""
    return registry_dispatch_preflight(
        slot_bindings_doc=slot_bindings_doc,
        family_registry={
            family: {
                "runtime_readiness_requirements": requirements,
                "harness_template_id": requirements.get("harness_template_id", ""),
            }
            for family, requirements in P1_RENDER_REQUIREMENTS.items()
        },
    )


def registry_dispatch_preflight(slot_bindings_doc: dict[str, Any], family_registry: dict[str, Any]) -> dict[str, Any]:
    """Classify slot bindings through a registry-shaped preflight contract."""
    bindings = slot_bindings_doc.get("bindings") or slot_bindings_doc.get("slot_bindings") or []
    items: list[dict[str, Any]] = []
    summary = {
        "binding_count": len(bindings) if isinstance(bindings, list) else 0,
        "bindings_enter_renderer": 0,
        "render_ready_now": 0,
        "needs_fixture_count": 0,
        "needs_call_sequence_normalization_count": 0,
        "unsupported_family_count": 0,
        "would_route_to_p0_der_renderer_count": 0,
        "would_use_internal_smoke_fallback_count": 0,
    }
    if not isinstance(bindings, list):
        bindings = []
    for index, binding in enumerate(bindings, start=1):
        if not isinstance(binding, dict):
            continue
        target = str(binding.get("target", ""))
        family = str(binding.get("framework_family", ""))
        selected_api = str(binding.get("selected_api", ""))
        family_record = family_registry.get(family) or {}
        requirements = family_record.get("runtime_readiness_requirements") or {}
        setup_items = _sequence_items(binding.get("setup_sequence"))
        call_items = _sequence_items(binding.get("call_sequence"))
        teardown_items = _sequence_items(binding.get("teardown_sequence"))
        call_text = _sequence_text(call_items)
        mutation_values = binding.get("mutation_values")
        evidence_paths = _sequence_items(binding.get("evidence_paths"))
        would_route_to_p0_der = family == "der_pointer_consumption"
        would_use_internal_smoke = requirements is None and family != "der_pointer_consumption"
        needs_call_sequence_normalization = False
        if family == "x509_asn1_inner_boundary":
            needs_call_sequence_normalization = (
                any(item in {"der", "der_len)"} for item in call_items)
                or "mbedtls_x509_crt_parse_der" not in call_text
            )
        elif family == "return_code_outlen_semantic":
            needs_call_sequence_normalization = (
                "mbedtls_cipher_finish" not in call_text
                or any("," in item and "mbedtls_" in item for item in setup_items + call_items)
            )
        render_ready_now = bool(
            requirements
            and selected_api
            and setup_items
            and call_items
            and teardown_items
            and isinstance(mutation_values, dict)
            and mutation_values
            and evidence_paths
            and not needs_call_sequence_normalization
        )
        if requirements:
            summary["bindings_enter_renderer"] += 1
            summary["needs_fixture_count"] += 1
        else:
            summary["unsupported_family_count"] += 1
        if render_ready_now:
            summary["render_ready_now"] += 1
        if needs_call_sequence_normalization:
            summary["needs_call_sequence_normalization_count"] += 1
        if would_route_to_p0_der:
            summary["would_route_to_p0_der_renderer_count"] += 1
        if would_use_internal_smoke:
            summary["would_use_internal_smoke_fallback_count"] += 1
        items.append(
            {
                "index": index,
                "target": target,
                "framework_family": family,
                "selected_api": selected_api,
                "harness_template_id": family_record.get("harness_template_id", ""),
                "renderer_status": (requirements or {}).get("renderer_status", "unsupported_family"),
                "can_enter_renderer": bool(requirements),
                "render_ready_now": render_ready_now,
                "required_fixture": (requirements or {}).get("required_fixture", ""),
                "required_inputs": (requirements or {}).get("required_inputs", []),
                "expected_oracle": (requirements or {}).get("expected_oracle", ""),
                "needs_input_output_buffer_fixture": family == "return_code_outlen_semantic",
                "needs_cert_der_seed": family == "x509_asn1_inner_boundary",
                "needs_call_sequence_normalization": needs_call_sequence_normalization,
                "would_route_to_p0_der_renderer": would_route_to_p0_der,
                "would_use_internal_smoke_fallback": would_use_internal_smoke,
                "notes": [
                    "preflight only; no C source was rendered",
                    "runtime renderer for this P1 family should be implemented before compile/run" if requirements else "family is not supported by P1 preflight",
                ],
            }
        )
    return {
        "schema": "runtime_harness_bridge_render_readiness_v1",
        "scope": "preflight_only_no_render_no_compile_no_run",
        "supported_p1_families": sorted(P1_RENDER_REQUIREMENTS),
        "items": items,
        "summary": summary,
    }


def _compile_command(cc: str, source: Path, binary: Path, case: dict[str, Any]) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    target = case.get("target", "")
    runtime_target = _runtime_target_kind(str(target))
    target_family = _target_family(str(target))
    env = os.environ.copy()
    metadata: dict[str, Any] = {}
    base = [cc, "-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined", str(source)]
    if case.get("framework_family") == "der_pointer_consumption" and target_family == "mbedtls":
        default_root = f"/home/wen/work/install-{target}-asan"
        root_var = "MBEDTLS36_ROOT" if str(target).startswith("mbedtls-3.6.4") else "MBEDTLS41_ROOT"
        root = Path(os.environ.get(root_var, os.environ.get("MBEDTLS_ROOT", default_root))).expanduser()
        include_dir = Path(os.environ.get("MBEDTLS_INCLUDE_DIR", root / "include")).expanduser()
        lib_dir = Path(os.environ.get("MBEDTLS_LIB_DIR", root / "lib")).expanduser()
        prior_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{prior_ld}" if prior_ld else str(lib_dir)
        metadata["mbedtls_runtime"] = {
            "install_root": str(root),
            "include_dir": str(include_dir),
            "lib_dir": str(lib_dir),
            "library": "mbedcrypto",
        }
        return (
            base
            + [
                f"-I{include_dir}",
                f"-L{lib_dir}",
                "-lmbedcrypto",
                f"-Wl,-rpath,{lib_dir}",
                "-o",
                str(binary),
            ],
            env,
            metadata,
        )
    if case.get("framework_family") == "der_pointer_consumption" and target_family == "botan":
        root = Path(os.environ.get("BOTAN_ROOT", "/home/wen/work/install-botan-3.10.0-asan")).expanduser()
        include_dir = Path(os.environ.get("BOTAN_INCLUDE_DIR", root / "include" / "botan-3")).expanduser()
        lib_dir = Path(os.environ.get("BOTAN_LIB_DIR", root / "lib")).expanduser()
        prior_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{prior_ld}" if prior_ld else str(lib_dir)
        metadata["botan_runtime"] = {
            "install_root": str(root),
            "include_dir": str(include_dir),
            "lib_dir": str(lib_dir),
            "library": "botan-3",
        }
        return (
            base
            + [
                "-std=c++20",
                f"-I{include_dir}",
                f"-L{lib_dir}",
                "-lbotan-3",
                f"-Wl,-rpath,{lib_dir}",
                "-o",
                str(binary),
            ],
            env,
            metadata,
        )
    if runtime_target == "wolfssl":
        wolf = wolfssl_preflight()
        include_dir = wolf.get("include_dir") or str(Path(DEFAULT_WOLFSSL_ROOT) / "include")
        lib_dir = wolf.get("lib_dir") or str(Path(DEFAULT_WOLFSSL_ROOT) / "lib")
        prior_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{prior_ld}" if prior_ld else lib_dir
        metadata["wolfssl_preflight"] = wolf
        return (
            base
            + [
                f"-I{include_dir}",
                f"-L{lib_dir}",
                "-lwolfssl",
                "-lpthread",
                f"-Wl,-rpath,{lib_dir}",
                "-o",
                str(binary),
            ],
            env,
            metadata,
        )
    return base + ["-o", str(binary)], env, metadata


def _select_runtime_cases(cases: list[dict[str, Any]], max_cases: int, per_target_family: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for case in cases:
        target = case.get("target", "")
        family = case.get("framework_family", "")
        runtime_status = case.get("target_runtime_status") or _runtime_status_for_target(str(target))
        if runtime_status != "runtime_ready":
            skipped.append(
                {
                    "case_id": case.get("case_id"),
                    "target": target,
                    "framework_family": family,
                    "reason": runtime_status,
                }
            )
            continue
        key = (target, family)
        if counts[key] >= per_target_family:
            skipped.append(
                {
                    "case_id": case.get("case_id"),
                    "target": target,
                    "framework_family": family,
                    "reason": "per_target_family_limit",
                }
            )
            continue
        if len(selected) >= max_cases:
            skipped.append(
                {
                    "case_id": case.get("case_id"),
                    "target": target,
                    "framework_family": family,
                    "reason": "max_cases_limit",
                }
            )
            continue
        selected.append(case)
        counts[key] += 1
    return selected, skipped


def _case_from_slot_binding(binding: dict[str, Any]) -> dict[str, Any]:
    target = str(binding.get("target", ""))
    family = str(binding.get("framework_family", ""))
    pattern = str(binding.get("concrete_pattern", ""))
    return {
        "case_id": f"{family}__{pattern}__{target}",
        "target": target,
        "framework_family": family,
        "concrete_pattern": pattern,
        "target_runtime_status": _runtime_status_for_target(target),
        "mapping_status": "usable_slot_binding",
        "render_source": "slot_validation_report",
        "binding_status": "usable",
        "slot_binding": binding,
    }


def _skipped_bindings_from_validation(slot_validation: dict[str, Any]) -> list[dict[str, Any]]:
    skipped: list[dict[str, Any]] = []
    for class_name, records in [
        ("needs_review_bindings", slot_validation.get("needs_review_binding_records", [])),
        ("invalid_bindings", slot_validation.get("invalid_binding_records", [])),
        ("blocked_bindings", slot_validation.get("blocked_binding_records", [])),
    ]:
        for record in records or []:
            if not isinstance(record, dict):
                continue
            skipped.append(
                {
                    "index": record.get("index"),
                    "target": record.get("target"),
                    "framework_family": record.get("framework_family"),
                    "concrete_pattern": record.get("concrete_pattern"),
                    "selected_api": record.get("selected_api"),
                    "binding_class": class_name,
                    "skip_reason": record.get("reason") or class_name,
                }
            )
    return skipped


def _parse_der_oracle_stdout(text: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for line in text.splitlines():
        if not line.startswith("DER_ORACLE "):
            continue
        for token in line.split()[1:]:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            parsed[key] = value
    for key in ["clean_len", "trailing_len", "clean_return", "trailing_return", "clean_consumed", "trailing_consumed"]:
        if key in parsed:
            try:
                parsed[key] = int(parsed[key])
            except ValueError:
                pass
    return parsed


def _classify_der_oracle(case: dict[str, Any], parsed: dict[str, Any], run_status: str, sanitizer: dict[str, Any], timed_out: bool, signal_name: str) -> dict[str, Any]:
    selected_api = str((case.get("slot_binding") or {}).get("selected_api", ""))
    target = str(case.get("target", ""))
    is_wolfssl_low_level_der_decode = (
        target.startswith("wolfssl")
        and selected_api in {"wc_RsaPrivateKeyDecode", "wc_RsaPublicKeyDecode"}
    )
    contract_note = ""
    if run_status != "run_success" or timed_out or signal_name or sanitizer.get("sanitizer_observed"):
        classification = "candidate_event"
        candidate_level = "runtime_failure_observation"
        next_action = "manual_review_runtime_failure_before_any_claim"
    elif not parsed:
        classification = "semantic_observation"
        candidate_level = "needs_more_oracle_specific_payload"
        next_action = "inspect_stdout_parser_or_rendered_case"
    else:
        clean_return = parsed.get("clean_return")
        trailing_return = parsed.get("trailing_return")
        clean_consumed = parsed.get("clean_consumed", -1)
        trailing_consumed = parsed.get("trailing_consumed", -1)
        trailing_len = parsed.get("trailing_len", -1)
        if (
            clean_return == 0
            and trailing_return == 0
            and isinstance(trailing_consumed, int)
            and isinstance(trailing_len, int)
            and trailing_consumed >= 0
            and trailing_len >= 0
            and trailing_consumed < trailing_len
        ):
            if is_wolfssl_low_level_der_decode:
                classification = "semantic_observation"
                candidate_level = "caller_full_consumption_check_required"
                next_action = "preserve_as_contract_observation_and_require_idx_equals_input_len_for_full_consumption"
                contract_note = "wolfssl_low_level_der_decode_ret_zero_only_means_one_asn1_item_decoded; caller_must_check_idx_equals_input_len_when_full_consumption_is_required"
            else:
                classification = "candidate_event"
                candidate_level = "parser_full_consumption_semantic_gap_candidate"
                next_action = "triage_consumed_length_semantics_against_target_api_contract"
        else:
            classification = "semantic_observation"
            candidate_level = "needs_more_oracle_specific_payload"
            next_action = "keep_as_observation_unless_differential_or_consumption_mismatch_is_confirmed"
    return {
        "case_id": case.get("case_id"),
        "target": case.get("target"),
        "selected_api": selected_api,
        "clean_der_seed": parsed.get("seed", ""),
        "trailing_der_seed": str(parsed.get("seed", "")) + "+00010203" if parsed.get("seed") else "",
        "clean_result": parsed.get("clean_return", ""),
        "trailing_result": parsed.get("trailing_return", ""),
        "clean_consumed": parsed.get("clean_consumed", ""),
        "trailing_consumed": parsed.get("trailing_consumed", ""),
        "clean_len": parsed.get("clean_len", ""),
        "trailing_len": parsed.get("trailing_len", ""),
        "oracle_classification": classification,
        "candidate_level": candidate_level,
        "overclaim_guard": "observation_only_no_validated_issue_claim" if is_wolfssl_low_level_der_decode else "runtime_observation_only_no_vulnerability_claim",
        "next_triage_action": next_action,
        "api_contract_note": contract_note,
        "full_consumption_required_check": "ret == 0 and consumed_idx == input_len" if is_wolfssl_low_level_der_decode else "",
    }


def run_runtime_harness_bridge(
    repo_root: Path,
    out_dir: Path,
    campaign_plan_path: Path,
    render_plan_path: Path,
    execution_mode: str,
    slot_bindings_path: Path | None = None,
    slot_validation_path: Path | None = None,
    max_cases: int = 20,
    max_compile_jobs: int = 20,
    timeout_seconds: int = 10,
    per_target_family: int = 2,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    campaign_plan = load_yaml_file(campaign_plan_path)
    render_plan = load_yaml_file(render_plan_path)
    slot_bindings_doc = load_yaml_file(slot_bindings_path) if slot_bindings_path else {}
    raw_slot_bindings = slot_bindings_doc.get("slot_bindings", []) if isinstance(slot_bindings_doc, dict) else []
    slot_validation = load_yaml_file(slot_validation_path) if slot_validation_path else {}
    usable_slot_bindings = (
        slot_validation.get("usable_slot_bindings", [])
        if isinstance(slot_validation, dict)
        else []
    )
    slot_bindings = usable_slot_bindings if slot_validation_path else raw_slot_bindings
    slot_index = {
        (item.get("target"), item.get("framework_family"), item.get("concrete_pattern")): item
        for item in slot_bindings
        if isinstance(item, dict)
    }
    cases = [_case_from_slot_binding(item) for item in slot_bindings if isinstance(item, dict)] if slot_bindings_path else campaign_plan.get("cases", [])
    target_status = campaign_plan.get("target_status", [])
    max_cases = min(max_cases, 20)
    max_compile_jobs = min(max_compile_jobs, 20)
    skipped_bindings = _skipped_bindings_from_validation(slot_validation) if slot_validation_path else []

    rendered_cases: list[dict[str, Any]] = []
    compile_results: list[dict[str, Any]] = []
    run_results: list[dict[str, Any]] = []
    runtime_analysis: list[dict[str, Any]] = []
    selected_cases, skipped_cases = _select_runtime_cases(cases, max_cases, per_target_family)
    if len(selected_cases) > max_compile_jobs:
        skipped_cases.extend(
            {
                "case_id": case.get("case_id"),
                "target": case.get("target"),
                "framework_family": case.get("framework_family"),
                "reason": "max_compile_jobs_limit",
            }
            for case in selected_cases[max_compile_jobs:]
        )
        selected_cases = selected_cases[:max_compile_jobs]

    default_cc = shutil.which("cc") or shutil.which("gcc")
    runtime_harness_executed = execution_mode == "runtime_smoke"
    render_root = out_dir / "rendered_cases"
    build_root = out_dir / "compiled_cases"
    log_root = out_dir / "logs"

    if slot_bindings_path and not slot_bindings:
        runtime_harness_executed = False
        rendered_manifest = {
            "schema": "rendered_cases_manifest_v1",
            "execution_mode": execution_mode,
            "render_plan_source": str(render_plan_path),
            "slot_bindings_source": str(slot_bindings_path),
            "slot_validation_source": str(slot_validation_path) if slot_validation_path else "",
            "render_plan_status": render_plan.get("status"),
            "status": "waiting_for_valid_slot_bindings",
            "reason": "no_usable_slot_bindings",
            "runtime_skip_reason": "no_usable_slot_bindings",
            "used_internal_smoke_fallback": False,
            "rendered_from_slot_bindings": False,
            "render_filter": {
                "source": "slot_validation_report.yaml" if slot_validation_path else "slot_bindings.yaml",
                "included_binding_class": "usable_bindings_only",
                "excluded_binding_classes": ["needs_review_bindings", "invalid_bindings", "blocked_bindings"],
            },
            "cases": [],
            "rendered_cases": [],
            "skipped_cases": [],
            "skipped_bindings": skipped_bindings,
            "summary": {"cases_rendered": 0, "cases_skipped": 0, "bindings_skipped": len(skipped_bindings)},
        }
        compile_report = {
            "schema": "compile_report_v1",
            "status": "waiting_for_valid_slot_bindings",
            "reason": "no_usable_slot_bindings",
            "runtime_harness_executed": False,
            "runtime_smoke": execution_mode == "runtime_smoke",
            "cc_path": default_cc or "",
            "compile_results": [],
            "summary": {"cases_compiled": 0, "compile_success": 0, "compile_failed": 0, "compile_skipped": 0},
        }
        run_report = {
            "schema": "run_report_v1",
            "status": "waiting_for_valid_slot_bindings",
            "reason": "no_usable_slot_bindings",
            "timeout_seconds": timeout_seconds,
            "run_results": [],
            "summary": {"cases_run": 0, "run_success": 0, "run_failed": 0, "timeout_count": 0, "crash_observation_count": 0, "sanitizer_observation_count": 0},
        }
        runtime_analyze_report = {
            "schema": "runtime_analyze_report_v1",
            "status": "waiting_for_valid_slot_bindings",
            "reason": "no_usable_slot_bindings",
            "runtime_harness_executed": False,
            "runtime_smoke": execution_mode == "runtime_smoke",
            "full_fuzzing": False,
            "targets_requested": [row.get("target") for row in target_status],
            "targets_executed": [],
            "targets_blocked": [],
            "targets_baseline_only": [],
            "families_executed": [],
            "cases_rendered": 0,
            "cases_compiled": 0,
            "cases_run": 0,
            "compile_success": 0,
            "compile_failed": 0,
            "run_success": 0,
            "run_failed": 0,
            "timeout_count": 0,
            "crash_observation_count": 0,
            "sanitizer_observation_count": 0,
            "semantic_observation_count": 0,
            "candidate_event_count": 0,
            "blocked_count": 0,
            "binary_artifacts_created": False,
            "binary_artifacts": [],
            "used_internal_smoke_fallback": False,
            "rendered_from_slot_bindings": False,
            "runtime_skip_reason": "no_usable_slot_bindings",
            "observations": [],
            "analysis": [],
            "notes": ["No runtime was executed because slot validation produced no usable bindings."],
        }
        write_yaml(out_dir / "rendered_cases_manifest.yaml", rendered_manifest)
        write_yaml(out_dir / "compile_report.yaml", compile_report)
        write_yaml(out_dir / "run_report.yaml", run_report)
        write_yaml(out_dir / "runtime_analyze_report.yaml", runtime_analyze_report)
        return runtime_analyze_report

    for index, case in enumerate(selected_cases, start=1):
        case_id = str(case.get("case_id") or f"runtime_smoke_{index}")
        safe_case_id = "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in case_id)
        source = render_root / f"{safe_case_id}{_source_suffix_for_case(case)}"
        binary = build_root / safe_case_id / "case_smoke.bin"
        compile_stdout = log_root / f"{safe_case_id}.compile.stdout.log"
        compile_stderr = log_root / f"{safe_case_id}.compile.stderr.log"
        run_stdout = log_root / f"{safe_case_id}.run.stdout.log"
        run_stderr = log_root / f"{safe_case_id}.run.stderr.log"
        render_metadata = _write_case_source(source, case, out_dir)
        slot_binding = slot_index.get((case.get("target"), case.get("framework_family"), case.get("concrete_pattern")), {})
        rendered_cases.append(
            {
                "case_id": case_id,
                "target": case.get("target"),
                "framework_family": case.get("framework_family"),
                "concrete_pattern": case.get("concrete_pattern"),
                "source": _rel(source, repo_root),
                "runtime_status": case.get("target_runtime_status"),
                "render_source": "slot_validation_report" if slot_validation_path else ("slot_bindings" if slot_binding else "campaign_plan"),
                "used_internal_smoke_fallback": False,
                "binding_status": "usable" if slot_binding else "",
                "selected_api": slot_binding.get("selected_api") if isinstance(slot_binding, dict) else "",
                "slot_binding": slot_binding,
                "render_metadata": render_metadata,
            }
        )

        compile_status = "not_attempted"
        compile_returncode: int | None = None
        compile_command: list[str] = []
        compile_env = os.environ.copy()
        compile_metadata: dict[str, Any] = {}
        cc = _compiler_for_case(case)
        if runtime_harness_executed and cc:
            binary.parent.mkdir(parents=True, exist_ok=True)
            compile_stdout.parent.mkdir(parents=True, exist_ok=True)
            compile_command, compile_env, compile_metadata = _compile_command(cc, source, binary, case)
            proc = subprocess.run(
                compile_command,
                cwd=repo_root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=compile_env,
            )
            compile_returncode = proc.returncode
            compile_stdout.write_text(proc.stdout, encoding="utf-8")
            compile_stderr.write_text(proc.stderr, encoding="utf-8")
            compile_status = "compile_success" if proc.returncode == 0 and binary.exists() else "compile_failed"
        else:
            compile_stdout.parent.mkdir(parents=True, exist_ok=True)
            compile_stdout.write_text("", encoding="utf-8")
            reason = "syntax_only_execution_mode" if execution_mode == "syntax_only" else "cc_not_found"
            compile_stderr.write_text(reason + "\n", encoding="utf-8")
            compile_status = "compile_skipped"

        compile_results.append(
            {
                "case_id": case_id,
                "target": case.get("target"),
                "framework_family": case.get("framework_family"),
                "source": _rel(source, repo_root),
                "binary_path": _rel(binary, repo_root),
                "compile_command": " ".join(compile_command),
                "compile_status": compile_status,
                "returncode": compile_returncode,
                "stdout_log": _rel(compile_stdout, repo_root),
                "stderr_log": _rel(compile_stderr, repo_root),
                "compile_metadata": compile_metadata,
            }
        )

        run_status = "not_run"
        returncode: int | None = None
        timed_out = False
        duration = 0.0
        if compile_status == "compile_success":
            start = time.monotonic()
            try:
                proc = subprocess.run(
                    [str(binary)],
                    cwd=repo_root,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_seconds,
                    check=False,
                    env={
                        **compile_env,
                        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    },
                )
                duration = round(time.monotonic() - start, 6)
                returncode = proc.returncode
                run_stdout.write_text(proc.stdout, encoding="utf-8")
                run_stderr.write_text(proc.stderr, encoding="utf-8")
                run_status = "run_success" if proc.returncode == 0 else "run_failed"
            except subprocess.TimeoutExpired as exc:
                duration = round(time.monotonic() - start, 6)
                timed_out = True
                returncode = None
                run_stdout.write_text((exc.stdout or "") if isinstance(exc.stdout, str) else "", encoding="utf-8")
                run_stderr.write_text((exc.stderr or "") if isinstance(exc.stderr, str) else "", encoding="utf-8")
                run_status = "timeout"
        else:
            run_stdout.parent.mkdir(parents=True, exist_ok=True)
            run_stdout.write_text("", encoding="utf-8")
            run_stderr.write_text("not run because compile did not succeed\n", encoding="utf-8")

        stderr_text = run_stderr.read_text(encoding="utf-8", errors="replace") if run_stderr.exists() else ""
        stdout_text = run_stdout.read_text(encoding="utf-8", errors="replace") if run_stdout.exists() else ""
        sanitizer = _sanitizer_summary(stdout_text + "\n" + stderr_text)
        sig = _signal_name(returncode)
        run_results.append(
            {
                "case_id": case_id,
                "target": case.get("target"),
                "framework_family": case.get("framework_family"),
                "binary_path": _rel(binary, repo_root),
                "run_status": run_status,
                "returncode": returncode,
                "timeout": timed_out,
                "signal": sig,
                "duration_seconds": duration,
                "stdout_log": _rel(run_stdout, repo_root),
                "stderr_log": _rel(run_stderr, repo_root),
                "sanitizer_summary": sanitizer,
            }
        )
        der_oracle = {}
        if case.get("framework_family") == "der_pointer_consumption":
            parsed_der = _parse_der_oracle_stdout(stdout_text)
            der_oracle = _classify_der_oracle(case, parsed_der, run_status, sanitizer, timed_out, sig)
            classification = der_oracle["oracle_classification"]
        else:
            classification = "semantic_observation" if run_status == "run_success" else "candidate_event"
            if timed_out:
                classification = "candidate_event"
            if sig or sanitizer["sanitizer_observed"]:
                classification = "candidate_event"
        runtime_analysis.append(
            {
                "case_id": case_id,
                "target": case.get("target"),
                "framework_family": case.get("framework_family"),
                "classification": classification,
                "observed_behavior": run_status,
                "candidate_level": der_oracle.get("candidate_level", "runtime_smoke_observation"),
                "overclaim_guard": der_oracle.get("overclaim_guard", "observation_only_no_validated_issue_claim"),
                "next_triage_action": der_oracle.get("next_triage_action", "manual_review_if_nonzero_timeout_signal_or_sanitizer"),
                "der_oracle": der_oracle,
            }
        )

    targets_executed = sorted({item["target"] for item in run_results if item["run_status"] != "not_run"})
    targets_baseline_only = sorted({row["target"] for row in target_status if row.get("runtime_status") == "baseline_only"})
    targets_blocked = [
        {
            "target": row.get("target"),
            "requested_target": row.get("requested_target"),
            "reason": row.get("runtime_status"),
        }
        for row in target_status
        if row.get("runtime_status") == "blocked_runtime"
    ]
    compile_success = sum(1 for item in compile_results if item["compile_status"] == "compile_success")
    compile_failed = sum(1 for item in compile_results if item["compile_status"] == "compile_failed")
    run_success = sum(1 for item in run_results if item["run_status"] == "run_success")
    run_failed = sum(1 for item in run_results if item["run_status"] == "run_failed")
    timeout_count = sum(1 for item in run_results if item["timeout"])
    crash_count = sum(1 for item in run_results if item["signal"])
    sanitizer_count = sum(1 for item in run_results if item["sanitizer_summary"]["sanitizer_observed"])
    semantic_count = sum(1 for item in runtime_analysis if item["classification"] == "semantic_observation")
    candidate_count = sum(1 for item in runtime_analysis if item["classification"] == "candidate_event")
    binaries = [item["binary_path"] for item in compile_results if item["compile_status"] == "compile_success"]

    rendered_manifest = {
        "schema": "rendered_cases_manifest_v1",
        "execution_mode": execution_mode,
        "render_plan_source": str(render_plan_path),
        "slot_bindings_source": str(slot_bindings_path) if slot_bindings_path else "",
        "slot_validation_source": str(slot_validation_path) if slot_validation_path else "",
        "render_plan_status": render_plan.get("status"),
        "used_internal_smoke_fallback": False,
        "rendered_from_slot_bindings": bool(slot_bindings),
        "render_filter": {
            "source": "slot_validation_report.yaml" if slot_validation_path else "slot_bindings.yaml",
            "included_binding_class": "usable_bindings_only" if slot_validation_path else "slot_bindings",
            "excluded_binding_classes": ["needs_review_bindings", "invalid_bindings", "blocked_bindings"] if slot_validation_path else [],
        },
        "cases": rendered_cases,
        "rendered_cases": rendered_cases,
        "skipped_cases": skipped_cases,
        "skipped_bindings": skipped_bindings,
        "summary": {"cases_rendered": len(rendered_cases), "cases_skipped": len(skipped_cases), "bindings_skipped": len(skipped_bindings)},
    }
    compile_report = {
        "schema": "compile_report_v1",
        "runtime_harness_executed": runtime_harness_executed,
        "runtime_smoke": execution_mode == "runtime_smoke",
        "cc_path": default_cc or "",
        "compile_results": compile_results,
        "summary": {
            "cases_compiled": len([item for item in compile_results if item["compile_status"] != "compile_skipped"]),
            "compile_success": compile_success,
            "compile_failed": compile_failed,
            "compile_skipped": sum(1 for item in compile_results if item["compile_status"] == "compile_skipped"),
        },
    }
    run_report = {
        "schema": "run_report_v1",
        "timeout_seconds": timeout_seconds,
        "run_results": run_results,
        "summary": {
            "cases_run": len([item for item in run_results if item["run_status"] != "not_run"]),
            "run_success": run_success,
            "run_failed": run_failed,
            "timeout_count": timeout_count,
            "crash_observation_count": crash_count,
            "sanitizer_observation_count": sanitizer_count,
        },
    }
    runtime_analyze_report = {
        "schema": "runtime_analyze_report_v1",
        "runtime_harness_executed": runtime_harness_executed,
        "runtime_smoke": execution_mode == "runtime_smoke",
        "full_fuzzing": False,
        "targets_requested": [row.get("target") for row in target_status],
        "targets_executed": targets_executed,
        "targets_blocked": targets_blocked,
        "targets_baseline_only": targets_baseline_only,
        "families_executed": sorted({item["framework_family"] for item in run_results if item["run_status"] != "not_run"}),
        "cases_rendered": len(rendered_cases),
        "cases_compiled": compile_success + compile_failed,
        "cases_run": run_success + run_failed + timeout_count,
        "compile_success": compile_success,
        "compile_failed": compile_failed,
        "run_success": run_success,
        "run_failed": run_failed,
        "timeout_count": timeout_count,
        "crash_observation_count": crash_count,
        "sanitizer_observation_count": sanitizer_count,
        "semantic_observation_count": semantic_count,
        "candidate_event_count": candidate_count,
        "blocked_count": len(targets_blocked),
        "binary_artifacts_created": bool(binaries),
        "binary_artifacts": binaries,
        "used_internal_smoke_fallback": False,
        "rendered_from_slot_bindings": bool(slot_bindings),
        "cleanup_policy": "temporary smoke binaries live under the task artifact out_dir and are not for broad commit",
        "observations": runtime_analysis,
        "analysis": runtime_analysis,
        "notes": [
            "Runtime smoke is bounded and not a fuzzing campaign.",
            "Runtime observations are triage inputs only.",
        ],
    }

    write_yaml(out_dir / "rendered_cases_manifest.yaml", rendered_manifest)
    write_yaml(out_dir / "compile_report.yaml", compile_report)
    write_yaml(out_dir / "run_report.yaml", run_report)
    write_yaml(out_dir / "runtime_analyze_report.yaml", runtime_analyze_report)
    der_cases = [item.get("der_oracle") for item in runtime_analysis if isinstance(item.get("der_oracle"), dict) and item.get("der_oracle")]
    if der_cases:
        der_summary = {
            "cases_run": len(der_cases),
            "clean_success": sum(1 for item in der_cases if item.get("clean_result") == 0),
            "trailing_success": sum(1 for item in der_cases if item.get("trailing_result") == 0),
            "semantic_observation_count": sum(1 for item in der_cases if item.get("oracle_classification") == "semantic_observation"),
            "candidate_event_count": sum(1 for item in der_cases if item.get("oracle_classification") == "candidate_event"),
            "crash_observation_count": crash_count,
            "sanitizer_observation_count": sanitizer_count,
            "timeout_count": timeout_count,
        }
        der_payload_oracle_report = {
            "schema": "p0_der_payload_oracle_report_v1",
            "runtime_harness_executed": runtime_harness_executed,
            "used_internal_smoke_fallback": False,
            "rendered_from_slot_bindings": bool(slot_bindings),
            "cases": der_cases,
            "summary": der_summary,
        }
        der_payload_runtime_report = {
            "schema": "p0_der_payload_runtime_report_v1",
            "runtime_harness_executed": runtime_harness_executed,
            "runtime_smoke": execution_mode == "runtime_smoke",
            "full_fuzzing": False,
            "targets_executed": targets_executed,
            "families_executed": runtime_analyze_report["families_executed"],
            "cases_rendered": len(rendered_cases),
            "cases_compiled": compile_success + compile_failed,
            "cases_run": run_success + run_failed + timeout_count,
            "compile_success": compile_success,
            "compile_failed": compile_failed,
            "run_success": run_success,
            "run_failed": run_failed,
            "timeout_count": timeout_count,
            "crash_observation_count": crash_count,
            "sanitizer_observation_count": sanitizer_count,
            "semantic_observation_count": der_summary["semantic_observation_count"],
            "candidate_event_count": der_summary["candidate_event_count"],
            "claim_policy": "runtime observation only; no vulnerability conclusion",
        }
        write_yaml(out_dir / "der_payload_oracle_report.yaml", der_payload_oracle_report)
        write_yaml(out_dir / "der_payload_runtime_report.yaml", der_payload_runtime_report)
    return runtime_analyze_report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--campaign-plan", required=True)
    parser.add_argument("--render-plan", required=True)
    parser.add_argument("--slot-bindings")
    parser.add_argument("--slot-validation")
    parser.add_argument("--execution-mode", choices=["syntax_only", "runtime_smoke"], default="syntax_only")
    parser.add_argument("--max-cases", type=int, default=20)
    parser.add_argument("--max-compile-jobs", type=int, default=20)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    args = parser.parse_args()
    report = run_runtime_harness_bridge(
        repo_root=Path(args.repo_root),
        out_dir=Path(args.out_dir),
        campaign_plan_path=Path(args.campaign_plan),
        render_plan_path=Path(args.render_plan),
        slot_bindings_path=Path(args.slot_bindings) if args.slot_bindings else None,
        slot_validation_path=Path(args.slot_validation) if args.slot_validation else None,
        execution_mode=args.execution_mode,
        max_cases=args.max_cases,
        max_compile_jobs=args.max_compile_jobs,
        timeout_seconds=args.timeout_seconds,
    )
    print(
        "runtime harness bridge:",
        "runtime_harness_executed=",
        report.get("runtime_harness_executed"),
        "cases_run=",
        report.get("cases_run"),
        "compile_success=",
        report.get("compile_success"),
    )


if __name__ == "__main__":
    main()
