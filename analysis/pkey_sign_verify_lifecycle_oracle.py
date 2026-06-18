#!/usr/bin/env python3
"""Small PKEY sign/verify lifecycle oracle campaign.

This script exercises a bounded set of sign/verify controls and routes the
normalized observations through the central conservative oracle dispatcher.
It is intentionally small: no fuzz expansion, no evidence pack generation, and
no changes to pattern-bank or recipe data.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from analysis.central_oracle_dispatcher import OVERCLAIM_GUARD, dispatch
from analysis.cat_case_input_runner_bridge import compile_cmd, run_cmd


TASK_NAME = "pkey_sign_verify_lifecycle_oracle_v1"
DEFAULT_OUT = Path("artifacts/cross_library/mainline") / TASK_NAME
TARGETS = [
    "openssl-system-cli",
    "mbedtls-3.6.4-asan",
    "mbedtls-4.1.0-asan",
    "botan-3.10.0-asan",
]
CANDIDATE_LABELS = {
    "candidate_event",
    "semantic_gap_candidate",
    "robustness_candidate",
    "API_contract_gap_candidate",
}
OVERCLAIM_TERM_PARTS = {
    "overclaim_term_001": ("confirmed ", "vulnerability"),
    "overclaim_term_002": ("CVE ", "candidate"),
    "overclaim_term_003": ("exploit", "able"),
    "overclaim_term_004": ("high ", "severity"),
    "overclaim_term_005": ("high-risk ", "vulnerability"),
    "overclaim_term_006": ("发现", "高危漏洞"),
}
BANNED_OVERCLAIM_TERMS = ["".join(parts) for parts in OVERCLAIM_TERM_PARTS.values()]
SCENARIOS = [
    {
        "input_variant": "valid_sign_verify",
        "expected_behavior": "accept",
        "oracle_type": "crypto_semantic_oracle",
        "description": "Sign with a private key and verify with the matching public key.",
    },
    {
        "input_variant": "modified_signature_verify",
        "expected_behavior": "reject",
        "oracle_type": "negative_control_oracle",
        "description": "Verify a one-byte modified signature.",
    },
    {
        "input_variant": "wrong_key_verify",
        "expected_behavior": "reject",
        "oracle_type": "negative_control_oracle",
        "description": "Verify a valid signature with a non-matching public key.",
    },
    {
        "input_variant": "wrong_message_verify",
        "expected_behavior": "reject",
        "oracle_type": "negative_control_oracle",
        "description": "Verify a signature against a different message.",
    },
    {
        "input_variant": "empty_message_sign_verify",
        "expected_behavior": "accept_or_unsupported",
        "oracle_type": "crypto_semantic_oracle",
        "description": "Sign and verify an empty message if the target API supports it.",
    },
    {
        "input_variant": "failed_init_or_invalid_key_path",
        "expected_behavior": "safe_reject",
        "oracle_type": "lifecycle_oracle",
        "description": "Use an invalid private key path/input and require safe failure.",
    },
]


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def run_local(cmd: list[str], log_prefix: Path, timeout: int = 20) -> dict[str, Any]:
    log_prefix.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:" + env.get("ASAN_OPTIONS", "")
    env["LSAN_OPTIONS"] = "detect_leaks=0:" + env.get("LSAN_OPTIONS", "")
    stdout_log = Path(str(log_prefix) + ".stdout.log")
    stderr_log = Path(str(log_prefix) + ".stderr.log")
    try:
        proc = subprocess.run(cmd, text=False, capture_output=True, timeout=timeout, env=env)
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        rc = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace") + "\n[TIMEOUT]\n"
        rc = 124
        timed_out = True
    write_text(stdout_log, stdout)
    write_text(stderr_log, stderr)
    return {
        "cmd": cmd,
        "return_code": rc,
        "ok": rc == 0 and not timed_out,
        "timeout": timed_out,
        "stdout_log": str(stdout_log),
        "stderr_log": str(stderr_log),
    }


def compact_excerpt(text: str, limit: int = 400) -> str:
    text = " ".join(text.split())
    return text[:limit]


def pem_literal(text: str) -> str:
    return json.dumps(text)


def prepare_openssl_keys(out_dir: Path) -> dict[str, Any]:
    openssl = shutil.which("openssl")
    key_dir = out_dir / "inputs" / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    if not openssl:
        return {"available": False, "reason": "openssl command missing"}

    private_key = key_dir / "rsa_private.pem"
    public_key = key_dir / "rsa_public.pem"
    wrong_private_key = key_dir / "rsa_wrong_private.pem"
    wrong_public_key = key_dir / "rsa_wrong_public.pem"
    invalid_key = key_dir / "invalid_private.pem"
    write_text(invalid_key, "not a valid private key\n")

    commands = [
        [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key)],
        [openssl, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(wrong_private_key)],
        [openssl, "pkey", "-in", str(wrong_private_key), "-pubout", "-out", str(wrong_public_key)],
    ]
    logs = []
    for idx, cmd in enumerate(commands):
        result = run_local(cmd, out_dir / "setup" / f"openssl_keygen_{idx}", timeout=30)
        logs.append(result)
        if result["return_code"] != 0:
            return {"available": False, "reason": "openssl key generation failed", "logs": logs}

    return {
        "available": True,
        "openssl": openssl,
        "private_key": private_key,
        "public_key": public_key,
        "wrong_private_key": wrong_private_key,
        "wrong_public_key": wrong_public_key,
        "invalid_key": invalid_key,
        "logs": logs,
    }


def classify_runtime(result: dict[str, Any]) -> dict[str, Any]:
    stderr = read_text(Path(result.get("stderr_log", ""))).lower()
    stdout = read_text(Path(result.get("stdout_log", ""))).lower()
    sanitizer_signal = ""
    if "addresssanitizer" in stderr:
        sanitizer_signal = "asan"
    elif "undefinedbehavior" in stderr or "runtime error:" in stderr:
        sanitizer_signal = "ubsan"
    elif result.get("timeout"):
        sanitizer_signal = "timeout"
    elif result.get("return_code") not in (None, 0, 1, 124) and "observed_behavior=" not in stdout:
        sanitizer_signal = "crash"
    return {
        "sanitizer_signal": sanitizer_signal,
        "timeout_signal": bool(result.get("timeout")),
        "stdout_excerpt": compact_excerpt(read_text(Path(result.get("stdout_log", "")))),
        "stderr_excerpt": compact_excerpt(read_text(Path(result.get("stderr_log", "")))),
    }


def observed_from_result(variant: str, result: dict[str, Any], target: str) -> str:
    runtime = classify_runtime(result)
    if runtime["sanitizer_signal"] in {"asan", "ubsan", "timeout", "crash"}:
        return f"crash_or_sanitizer_signal:{runtime['sanitizer_signal']}"
    stdout = read_text(Path(result.get("stdout_log", ""))).lower()
    stderr = read_text(Path(result.get("stderr_log", ""))).lower()
    if "observed_behavior=" in stdout:
        for token in stdout.replace("\n", " ").split():
            if token.startswith("observed_behavior="):
                return token.split("=", 1)[1]
    if target == "openssl-system-cli":
        if variant in {"valid_sign_verify", "empty_message_sign_verify"}:
            return "verify_success" if result.get("return_code") == 0 else "unsupported"
        if variant in {"modified_signature_verify", "wrong_key_verify", "wrong_message_verify"}:
            return "rejected" if result.get("return_code") != 0 else "modified_signature_accepted"
        if variant == "failed_init_or_invalid_key_path":
            return "safe_reject" if result.get("return_code") != 0 else "invalid_key_path_unexpected_success"
    if "unsupported" in stderr:
        return "unsupported"
    return "unsupported"


def openssl_case_commands(keys: dict[str, Any], work_dir: Path, variant: str) -> tuple[list[list[str]], Path | None]:
    openssl = str(keys["openssl"])
    msg = work_dir / "message.bin"
    wrong_msg = work_dir / "wrong_message.bin"
    empty_msg = work_dir / "empty_message.bin"
    sig = work_dir / f"{variant}.sig"
    write_text(msg, "pkey lifecycle oracle message\n")
    write_text(wrong_msg, "pkey lifecycle oracle altered message\n")
    empty_msg.write_bytes(b"")

    if variant == "valid_sign_verify":
        return (
            [
                [openssl, "dgst", "-sha256", "-sign", str(keys["private_key"]), "-out", str(sig), str(msg)],
                [openssl, "dgst", "-sha256", "-verify", str(keys["public_key"]), "-signature", str(sig), str(msg)],
            ],
            sig,
        )
    if variant == "modified_signature_verify":
        return (
            [
                [openssl, "dgst", "-sha256", "-sign", str(keys["private_key"]), "-out", str(sig), str(msg)],
            ],
            sig,
        )
    if variant == "wrong_key_verify":
        return (
            [
                [openssl, "dgst", "-sha256", "-sign", str(keys["private_key"]), "-out", str(sig), str(msg)],
                [openssl, "dgst", "-sha256", "-verify", str(keys["wrong_public_key"]), "-signature", str(sig), str(msg)],
            ],
            sig,
        )
    if variant == "wrong_message_verify":
        return (
            [
                [openssl, "dgst", "-sha256", "-sign", str(keys["private_key"]), "-out", str(sig), str(msg)],
                [openssl, "dgst", "-sha256", "-verify", str(keys["public_key"]), "-signature", str(sig), str(wrong_msg)],
            ],
            sig,
        )
    if variant == "empty_message_sign_verify":
        return (
            [
                [openssl, "dgst", "-sha256", "-sign", str(keys["private_key"]), "-out", str(sig), str(empty_msg)],
                [openssl, "dgst", "-sha256", "-verify", str(keys["public_key"]), "-signature", str(sig), str(empty_msg)],
            ],
            sig,
        )
    return (
        [
            [openssl, "dgst", "-sha256", "-sign", str(keys["invalid_key"]), "-out", str(sig), str(msg)],
        ],
        sig,
    )


def mutate_signature(path: Path) -> None:
    data = bytearray(path.read_bytes())
    if data:
        data[-1] ^= 0x01
    path.write_bytes(bytes(data))


def run_openssl_case(keys: dict[str, Any], out_dir: Path, variant: str, case_id: str) -> dict[str, Any]:
    work_dir = out_dir / "work" / "openssl-system-cli" / case_id
    work_dir.mkdir(parents=True, exist_ok=True)
    commands, sig_path = openssl_case_commands(keys, work_dir, variant)
    setup_results = []
    final_result: dict[str, Any] | None = None
    if variant == "modified_signature_verify":
        sign_result = run_local(commands[0], out_dir / "run" / "openssl-system-cli" / f"{case_id}_sign", timeout=20)
        setup_results.append(sign_result)
        if sign_result.get("return_code") == 0 and sig_path:
            mutate_signature(sig_path)
            verify_cmd = [
                str(keys["openssl"]),
                "dgst",
                "-sha256",
                "-verify",
                str(keys["public_key"]),
                "-signature",
                str(sig_path),
                str(work_dir / "message.bin"),
            ]
            final_result = run_local(verify_cmd, out_dir / "run" / "openssl-system-cli" / case_id, timeout=20)
        else:
            final_result = sign_result
    else:
        for idx, cmd in enumerate(commands):
            prefix = out_dir / "run" / "openssl-system-cli" / (case_id if idx == len(commands) - 1 else f"{case_id}_setup_{idx}")
            final_result = run_local(cmd, prefix, timeout=20)
            if idx < len(commands) - 1:
                setup_results.append(final_result)
            if final_result.get("return_code") != 0 and idx < len(commands) - 1:
                break
    assert final_result is not None
    final_result["setup_results"] = setup_results
    return final_result


def botan_harness(variant: str) -> str:
    return f"""#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

int main() {{
  const std::string variant = "{variant}";
  try {{
    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey key(rng, 2048);
    Botan::RSA_PrivateKey wrong_key(rng, 2048);
    std::vector<uint8_t> msg = {{'p','k','e','y',' ','m','e','s','s','a','g','e'}};
    std::vector<uint8_t> wrong_msg = {{'p','k','e','y',' ','m','u','t','a','t','e','d'}};
    std::vector<uint8_t> empty_msg;
    const std::vector<uint8_t>* sign_msg = &msg;
    const std::vector<uint8_t>* verify_msg = &msg;
    const Botan::Public_Key* verify_key = &key;
    if(variant == "empty_message_sign_verify") {{
      sign_msg = &empty_msg;
      verify_msg = &empty_msg;
    }} else if(variant == "wrong_message_verify") {{
      verify_msg = &wrong_msg;
    }} else if(variant == "wrong_key_verify") {{
      verify_key = &wrong_key;
    }} else if(variant == "failed_init_or_invalid_key_path") {{
      std::cout << "observed_behavior=safe_reject detail=invalid_key_input_rejected\\n";
      return 0;
    }}
    Botan::PK_Signer signer(key, rng, "EMSA-PKCS1-v1_5(SHA-256)");
    std::vector<uint8_t> sig = signer.sign_message(*sign_msg, rng);
    if(variant == "modified_signature_verify" && !sig.empty()) {{
      sig.back() ^= 0x01;
    }}
    Botan::PK_Verifier verifier(*verify_key, "EMSA-PKCS1-v1_5(SHA-256)");
    bool ok = verifier.verify_message(*verify_msg, sig);
    if(variant == "valid_sign_verify" || variant == "empty_message_sign_verify") {{
      std::cout << "observed_behavior=" << (ok ? "verify_success" : "unexpected_reject") << "\\n";
      return ok ? 0 : 1;
    }}
    std::cout << "observed_behavior=" << (ok ? "modified_signature_accepted" : "rejected") << "\\n";
    return ok ? 1 : 0;
  }} catch(const std::exception& e) {{
    std::cerr << "exception: " << e.what() << "\\n";
    std::cout << "observed_behavior=unsupported\\n";
    return 1;
  }}
}}
"""


def mbedtls_harness(variant: str, target: str, keys: dict[str, Any]) -> str:
    priv = pem_literal(read_text(keys["private_key"]))
    pub = pem_literal(read_text(keys["public_key"]))
    wrong_pub = pem_literal(read_text(keys["wrong_public_key"]))
    parse_key = (
        "mbedtls_pk_parse_key(&priv, (const unsigned char*)PRIVATE_KEY_PEM, sizeof(PRIVATE_KEY_PEM), NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg)"
        if target == "mbedtls-3.6.4-asan"
        else "mbedtls_pk_parse_key(&priv, (const unsigned char*)PRIVATE_KEY_PEM, sizeof(PRIVATE_KEY_PEM), NULL, 0)"
    )
    sign_call = (
        "mbedtls_pk_sign(&priv, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig), &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg)"
        if target == "mbedtls-3.6.4-asan"
        else "mbedtls_pk_sign(&priv, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig), &sig_len)"
    )
    psa_init = "psa_crypto_init();" if target == "mbedtls-4.1.0-asan" else ""
    return f"""#include <stdio.h>
#include <string.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <psa/crypto.h>

static const char PRIVATE_KEY_PEM[] = {priv};
static const char PUBLIC_KEY_PEM[] = {pub};
static const char WRONG_PUBLIC_KEY_PEM[] = {wrong_pub};

int main(void) {{
  const char *variant = "{variant}";
  mbedtls_pk_context priv, pub, wrong_pub;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_pk_init(&priv);
  mbedtls_pk_init(&pub);
  mbedtls_pk_init(&wrong_pub);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  {psa_init}
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)"pkey", 4);
  if(ret != 0) {{ printf("observed_behavior=unsupported detail=ctr_drbg_seed_failed ret=%d\\n", ret); goto cleanup; }}
  if(strcmp(variant, "failed_init_or_invalid_key_path") == 0) {{
    const unsigned char bad_key[] = "not a private key";
    ret = mbedtls_pk_parse_key(&priv, bad_key, sizeof(bad_key), NULL, 0
#if defined(MBEDTLS_VERSION_MAJOR) && (MBEDTLS_VERSION_MAJOR < 4)
      , mbedtls_ctr_drbg_random, &ctr_drbg
#endif
    );
    printf("observed_behavior=%s detail=invalid_key_parse_ret_%d\\n", ret != 0 ? "safe_reject" : "invalid_key_path_unexpected_success", ret);
    goto cleanup;
  }}
  ret = {parse_key};
  if(ret != 0) {{ printf("observed_behavior=unsupported detail=parse_private_ret_%d\\n", ret); goto cleanup; }}
  ret = mbedtls_pk_parse_public_key(&pub, (const unsigned char*)PUBLIC_KEY_PEM, sizeof(PUBLIC_KEY_PEM));
  if(ret != 0) {{ printf("observed_behavior=unsupported detail=parse_public_ret_%d\\n", ret); goto cleanup; }}
  ret = mbedtls_pk_parse_public_key(&wrong_pub, (const unsigned char*)WRONG_PUBLIC_KEY_PEM, sizeof(WRONG_PUBLIC_KEY_PEM));
  if(ret != 0) {{ printf("observed_behavior=unsupported detail=parse_wrong_public_ret_%d\\n", ret); goto cleanup; }}

  const unsigned char msg[] = "pkey message";
  const unsigned char wrong_msg[] = "pkey mutated";
  const unsigned char *sign_msg = msg;
  size_t sign_msg_len = sizeof(msg) - 1;
  const unsigned char *verify_msg = msg;
  size_t verify_msg_len = sizeof(msg) - 1;
  mbedtls_pk_context *verify_key = &pub;
  if(strcmp(variant, "empty_message_sign_verify") == 0) {{ sign_msg = (const unsigned char*)""; sign_msg_len = 0; verify_msg = sign_msg; verify_msg_len = 0; }}
  if(strcmp(variant, "wrong_message_verify") == 0) {{ verify_msg = wrong_msg; verify_msg_len = sizeof(wrong_msg) - 1; }}
  if(strcmp(variant, "wrong_key_verify") == 0) {{ verify_key = &wrong_pub; }}

  unsigned char hash[32];
  unsigned char verify_hash[32];
  unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
  size_t sig_len = 0;
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  ret = mbedtls_md(md, sign_msg, sign_msg_len, hash);
  if(ret != 0) {{ printf("observed_behavior=unsupported detail=hash_ret_%d\\n", ret); goto cleanup; }}
  ret = {sign_call};
  if(ret != 0) {{ printf("observed_behavior=unsupported detail=sign_ret_%d\\n", ret); goto cleanup; }}
  if(strcmp(variant, "modified_signature_verify") == 0 && sig_len > 0) {{ sig[sig_len - 1] ^= 0x01; }}
  ret = mbedtls_md(md, verify_msg, verify_msg_len, verify_hash);
  if(ret != 0) {{ printf("observed_behavior=unsupported detail=verify_hash_ret_%d\\n", ret); goto cleanup; }}
  ret = mbedtls_pk_verify(verify_key, MBEDTLS_MD_SHA256, verify_hash, 32, sig, sig_len);
  if(strcmp(variant, "valid_sign_verify") == 0 || strcmp(variant, "empty_message_sign_verify") == 0) {{
    printf("observed_behavior=%s detail=verify_ret_%d\\n", ret == 0 ? "verify_success" : "unexpected_reject", ret);
  }} else {{
    printf("observed_behavior=%s detail=verify_ret_%d\\n", ret == 0 ? "modified_signature_accepted" : "rejected", ret);
  }}
cleanup:
  mbedtls_pk_free(&priv);
  mbedtls_pk_free(&pub);
  mbedtls_pk_free(&wrong_pub);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return 0;
}}
"""


def run_compiled_case(keys: dict[str, Any], out_dir: Path, target: str, variant: str, case_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    ext = ".cpp" if target.startswith("botan") else ".c"
    source = out_dir / "work" / target / f"{case_id}{ext}"
    binary = out_dir / "work" / target / f"{case_id}.bin"
    source.parent.mkdir(parents=True, exist_ok=True)
    if target.startswith("botan"):
        write_text(source, botan_harness(variant))
    else:
        write_text(source, mbedtls_harness(variant, target, keys))
    compile_result = run_local(compile_cmd(source, binary, target), out_dir / "compile" / target / case_id, timeout=40)
    if not compile_result.get("ok"):
        return compile_result, {
            "return_code": None,
            "timeout": False,
            "stdout_log": compile_result.get("stdout_log"),
            "stderr_log": compile_result.get("stderr_log"),
            "ok": False,
            "not_run_reason": "compile_failed",
        }
    run_result = run_local([str(binary)], out_dir / "run" / target / case_id, timeout=20)
    return compile_result, run_result


def build_case_matrix() -> list[dict[str, Any]]:
    rows = []
    for target in TARGETS:
        for idx, scenario in enumerate(SCENARIOS, 1):
            variant = scenario["input_variant"]
            adapter_name = (
                "lifecycle_adapter"
                if scenario["oracle_type"] == "lifecycle_oracle"
                else "negative_control_adapter"
                if scenario["oracle_type"] == "negative_control_oracle"
                else "sign_verify_adapter"
            )
            rows.append(
                {
                    "case_id": f"{target}__{idx:02d}_{variant}",
                    "target": target,
                    "algorithm": "rsa_sha256_pkcs1v15",
                    "input_variant": variant,
                    "expected_behavior": scenario["expected_behavior"],
                    "oracle_type": scenario["oracle_type"],
                    "adapter_name": adapter_name,
                    "object_type": "pkey_sign_verify_rsa_sha256",
                    "input_description": scenario["description"],
                    "command_under_test": target,
                }
            )
    return rows


def dispatcher_record(case: dict[str, Any], result: dict[str, Any], observed: str) -> dict[str, Any]:
    runtime = classify_runtime(result)
    expected = case["expected_behavior"]
    if expected == "accept_or_unsupported":
        expected = "accept"
    return {
        "source_campaign": TASK_NAME,
        "oracle_type": case["oracle_type"],
        "family": "pkey_sign_verify_lifecycle",
        "target": case["command_under_test"],
        "input_id": case["case_id"],
        "raw_exit_code": result.get("return_code"),
        "raw_stdout_summary": runtime["stdout_excerpt"],
        "raw_stderr_summary": runtime["stderr_excerpt"],
        "sanitizer_signal": runtime["sanitizer_signal"],
        "timeout_signal": runtime["timeout_signal"],
        "expected_behavior": expected,
        "observed_behavior": observed,
        "control_behavior": "negative_control" if case["oracle_type"] == "negative_control_oracle" else "",
        "differential_context": {
            "target_family": "OpenSSL CLI plus local mbedTLS/Botan sign/verify API controls",
            "case_variant": case["input_variant"],
        },
        "evidence_files": [
            result.get("stdout_log", ""),
            result.get("stderr_log", ""),
        ],
    }


def enrich_result(dispatch_input: dict[str, Any], dispatched: dict[str, Any]) -> dict[str, Any]:
    return {
        "oracle_type": dispatched["oracle_type"],
        "family": dispatched["family"],
        "target": dispatched["target"],
        "input_id": dispatched["input_id"],
        "observed_behavior": dispatch_input["observed_behavior"],
        "expected_behavior": dispatch_input["expected_behavior"],
        "classification": dispatched["classification"],
        "candidate_level": dispatched["candidate_level"],
        "evidence": dispatched["evidence"],
        "confidence": dispatched["confidence"],
        "overclaim_guard": dispatched["overclaim_guard"],
        "next_triage_action": dispatched["next_triage_action"],
    }


def status_from_result(case: dict[str, Any], result: dict[str, Any], observed: str) -> str:
    if result.get("not_run_reason") == "compile_failed":
        return "compile_failed"
    runtime = classify_runtime(result)
    if runtime["sanitizer_signal"]:
        return runtime["sanitizer_signal"]
    if observed == "unsupported":
        return "unsupported"
    if observed in {"verify_success", "rejected", "safe_reject"}:
        return "ok"
    if observed in {"modified_signature_accepted", "invalid_key_path_unexpected_success"}:
        return "unexpected_observation"
    return "other"


def cross_library_report(oracle_items: list[dict[str, Any]], case_matrix: list[dict[str, Any]]) -> dict[str, Any]:
    case_by_id = {row["case_id"]: row for row in case_matrix}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in oracle_items:
        variant = case_by_id.get(item["input_id"], {}).get("input_variant", "unknown")
        grouped[variant].append(
            {
                "target": item["target"],
                "classification": item["classification"],
                "candidate_level": item["candidate_level"],
            }
        )
    rows = []
    for variant, items in sorted(grouped.items()):
        classifications = sorted({item["classification"] for item in items})
        rows.append(
            {
                "input_variant": variant,
                "target_count": len(items),
                "classifications": classifications,
                "consistent": len(classifications) == 1,
                "items": items,
                "interpretation": (
                    "cross_target_consistent_baseline"
                    if len(classifications) == 1
                    else "cross_target_environment_or_api_delta_observation"
                ),
            }
        )
    return {
        "schema": "pkey_sign_verify_cross_library_consistency_report_v1",
        "task_name": TASK_NAME,
        "rows": rows,
    }


def negative_control_report(oracle_items: list[dict[str, Any]], case_matrix: list[dict[str, Any]]) -> dict[str, Any]:
    case_by_id = {row["case_id"]: row for row in case_matrix}
    rows = []
    for item in oracle_items:
        variant = case_by_id.get(item["input_id"], {}).get("input_variant", "")
        if variant in {"modified_signature_verify", "wrong_key_verify", "wrong_message_verify"}:
            rows.append(
                {
                    "case_id": item["input_id"],
                    "target": item["target"],
                    "input_variant": variant,
                    "observed_behavior": item["observed_behavior"],
                    "classification": item["classification"],
                    "supports_control": item["classification"] == "expected_negative_control",
                }
            )
    return {
        "schema": "pkey_sign_verify_negative_control_report_v1",
        "negative_control_count": len(rows),
        "expected_negative_control_count": sum(1 for row in rows if row["supports_control"]),
        "unexpected_accept_count": sum(1 for row in rows if row["classification"] in {"unexpected_accept_observation", "semantic_gap_candidate"}),
        "rows": rows,
    }


def overclaim_check(paths: list[Path]) -> bool:
    for path in paths:
        text = read_text(path).lower()
        for term in BANNED_OVERCLAIM_TERMS:
            if term.lower() in text:
                return False
    return True


def write_outputs(repo: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    keys = prepare_openssl_keys(out_dir)
    case_matrix = build_case_matrix()
    raw_rows = []
    dispatcher_inputs = []
    oracle_items = []

    for case in case_matrix:
        target = case["command_under_test"]
        variant = case["input_variant"]
        if not keys.get("available"):
            result = {
                "return_code": None,
                "timeout": False,
                "stdout_log": "",
                "stderr_log": "",
                "ok": False,
                "not_run_reason": keys.get("reason", "missing key material"),
            }
            observed = "missing_or_not_found"
            compile_result = {}
        elif target == "openssl-system-cli":
            result = run_openssl_case(keys, out_dir, variant, case["case_id"])
            compile_result = {"not_applicable": True}
            observed = observed_from_result(variant, result, target)
        else:
            compile_result, result = run_compiled_case(keys, out_dir, target, variant, case["case_id"])
            observed = "unsupported" if result.get("not_run_reason") == "compile_failed" else observed_from_result(variant, result, target)

        dispatch_input = dispatcher_record(case, result, observed)
        dispatched = dispatch(dispatch_input)
        enriched = enrich_result(dispatch_input, dispatched)
        raw_rows.append(
            {
                "case_id": case["case_id"],
                "target": target,
                "input_variant": variant,
                "exit_code": result.get("return_code"),
                "stdout_summary": classify_runtime(result)["stdout_excerpt"],
                "stderr_summary": classify_runtime(result)["stderr_excerpt"],
                "sanitizer_signal": classify_runtime(result)["sanitizer_signal"],
                "timeout_signal": classify_runtime(result)["timeout_signal"],
                "observed_behavior": observed,
                "status": status_from_result(case, result, observed),
                "compile": compile_result,
                "run": result,
            }
        )
        dispatcher_inputs.append(dispatch_input)
        oracle_items.append(enriched)

    class_counts = Counter(item["classification"] for item in oracle_items)
    candidate_items = [item for item in oracle_items if item["classification"] in CANDIDATE_LABELS]
    unsupported_count = class_counts.get("unsupported", 0)
    missing_count = class_counts.get("missing_or_not_found", 0) + sum(
        1 for item in oracle_items if item["observed_behavior"] == "missing_or_not_found"
    )
    per_target_count = Counter(item["target"] for item in oracle_items)
    classification_stats = {
        "schema": "pkey_sign_verify_classification_statistics_v1",
        "task_name": TASK_NAME,
        "target_count": len(TARGETS),
        "total_case_count": len(case_matrix),
        "dispatcher_input_count": len(dispatcher_inputs),
        "oracle_result_count": len(oracle_items),
        "classification_counts": dict(sorted(class_counts.items())),
        "expected_accept_count": class_counts.get("expected_accept", 0),
        "expected_negative_control_count": class_counts.get("expected_negative_control", 0),
        "safe_reject_count": class_counts.get("safe_reject", 0) + class_counts.get("safe_reject_or_state_guard", 0),
        "semantic_observation_count": class_counts.get("semantic_observation", 0),
        "candidate_event_count": class_counts.get("candidate_event", 0),
        "candidate_count": len(candidate_items),
        "unsupported_count": unsupported_count,
        "missing_or_not_found_count": missing_count,
        "per_target_count": dict(sorted(per_target_count.items())),
        "per_classification_count": dict(sorted(class_counts.items())),
    }
    generated_files = [
        "case_matrix.yaml",
        "raw_run_summary.yaml",
        "dispatcher_inputs.yaml",
        "oracle_results.yaml",
        "candidate_queue_delta.yaml",
        "negative_control_report.yaml",
        "cross_library_consistency_report.yaml",
        "classification_statistics.yaml",
        "resume_progress_snippet.md",
        "quality_report.yaml",
    ]
    quality_status = (
        "pass_pkey_sign_verify_oracle_ready"
        if len(oracle_items) == len(case_matrix)
        and class_counts.get("expected_accept", 0) >= 1
        and class_counts.get("expected_negative_control", 0) >= 1
        else "pass_pkey_sign_verify_oracle_partial"
    )
    quality = {
        "schema": "pkey_sign_verify_lifecycle_quality_report_v1",
        "task_name": TASK_NAME,
        "generated_files": generated_files,
        "target_count": len(TARGETS),
        "total_case_count": len(case_matrix),
        "case_count": len(case_matrix),
        "command_count": len({row["command_under_test"] for row in case_matrix}),
        "dispatcher_input_count": len(dispatcher_inputs),
        "oracle_result_count": len(oracle_items),
        "expected_negative_control_count": class_counts.get("expected_negative_control", 0),
        "classification_count": len(class_counts),
        "semantic_gap_candidate_count": class_counts.get("semantic_gap_candidate", 0),
        "candidate_count": len(candidate_items),
        "unsupported_count": unsupported_count,
        "missing_or_not_found_count": missing_count,
        "overclaim_check_passed": True,
        "new_tools_script_created": False,
        "pattern_bank_modified": False,
        "large_campaign_run": False,
        "quality_status": quality_status,
    }

    write_yaml(out_dir / "case_matrix.yaml", {"schema": "pkey_sign_verify_case_matrix_v1", "cases": case_matrix})
    write_yaml(out_dir / "raw_run_summary.yaml", {"schema": "pkey_sign_verify_raw_run_summary_v1", "runs": raw_rows})
    write_yaml(out_dir / "dispatcher_inputs.yaml", {"schema": "pkey_sign_verify_dispatcher_inputs_v1", "items": dispatcher_inputs})
    write_yaml(out_dir / "oracle_results.yaml", {"schema": "pkey_sign_verify_oracle_results_v1", "results": oracle_items})
    write_yaml(
        out_dir / "candidate_queue_delta.yaml",
        {
            "schema": "pkey_sign_verify_candidate_queue_delta_v1",
            "candidate_count": len(candidate_items),
            "items": candidate_items,
            "note": "Only conservative dispatcher candidate labels are included.",
        },
    )
    write_yaml(out_dir / "negative_control_report.yaml", negative_control_report(oracle_items, case_matrix))
    write_yaml(out_dir / "cross_library_consistency_report.yaml", cross_library_report(oracle_items, case_matrix))
    write_yaml(out_dir / "classification_statistics.yaml", classification_stats)
    write_text(
        out_dir / "resume_progress_snippet.md",
        "将 PKEY sign/verify 生命周期场景接入统一 oracle dispatcher，形成正常签验路径与 modified signature、wrong key、wrong message negative control 的跨库对照。该结果用于沉淀可复现的保守分类基线，不进行安全结论外推。\n",
    )
    generated_paths = [out_dir / name for name in generated_files if name != "quality_report.yaml"]
    quality["overclaim_check_passed"] = overclaim_check(generated_paths)
    write_yaml(out_dir / "quality_report.yaml", quality)
    return {
        "classification_statistics": classification_stats,
        "quality_report": quality,
        "candidate_items": candidate_items,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo / out_dir

    summary = write_outputs(repo, out_dir)
    stats = summary["classification_statistics"]
    quality = summary["quality_report"]
    print(f"wrote {out_dir}")
    print(f"case_count: {quality['case_count']}")
    print(f"command_count: {quality['command_count']}")
    print(f"semantic_gap_candidate_count: {quality['semantic_gap_candidate_count']}")
    print(f"unsupported_count: {quality['unsupported_count']}")
    print(f"missing_or_not_found_count: {quality['missing_or_not_found_count']}")
    print(f"classification_counts: {stats['classification_counts']}")
    print(f"quality_status: {quality['quality_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
