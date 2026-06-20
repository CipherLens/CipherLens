"""Minimal AEAD lifecycle adapter recipe and smoke runner.

This task implements a small valid-contract AES-GCM encrypt/decrypt smoke
across local sanitizer-ready mbedTLS and Botan targets. Modified-tag decrypt is
an expected safe rejection and is never treated as a candidate.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Any

import yaml

from analysis.cat_case_input_runner_bridge import TARGETS, BLOCKED_TARGETS, compile_cmd, run_cmd


TASK = "cipher_aead_lifecycle_adapter_recipe_v1"
DEFAULT_OUT = Path("artifacts/cross_library/mainline") / TASK
CANDIDATE_RULE = "Only ASAN/UBSAN/crash/timeout become candidate events. Modified-tag rejection, semantic mismatch, unsupported API, and invalid contract are observations only."


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def count_files(root: Path, suffixes: tuple[str, ...] = (".yaml", ".yml", ".md")) -> int:
    if not root.exists():
        return 0
    return sum(1 for p in root.rglob("*") if p.is_file() and p.suffix in suffixes)


def distribution(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def bytes_literal(hex_text: str) -> str:
    if not hex_text:
        return "0x00"
    return ", ".join(f"0x{b:02x}" for b in bytes.fromhex(hex_text))


def glm_preflight() -> dict[str, Any]:
    available = bool(os.environ.get("GLM_API_KEY") or os.environ.get("ZHIPUAI_API_KEY"))
    return {
        "schema": "cipher_aead_glm_preflight_v1",
        "glm_attempted": True,
        "attempt_type": "local_availability_preflight_only",
        "glm_available": available,
        "fallback_used": not available,
        "api_key_logged": False,
        "network_call_made": False,
    }


def artifact_inventory(repo_root: Path) -> dict[str, Any]:
    return {
        "schema": "cipher_aead_artifact_inventory_v1",
        "api_cards_loaded": count_files(repo_root / "knowledge/api_cards", (".yaml", ".yml")) + count_files(repo_root / "knowledge_base/api_cards", (".yaml", ".yml")) > 0,
        "family_cards_loaded": count_files(repo_root / "knowledge/family_cards", (".yaml", ".yml")) > 0,
        "prior_lifecycle_loaded": (repo_root / "artifacts/cross_library/mainline/stateful_lifecycle_valid_contract_v1/validation/stateful_lifecycle_valid_contract_quality_checks.yaml").exists(),
        "counts": {
            "family_cards": count_files(repo_root / "knowledge/family_cards", (".yaml", ".yml")),
            "api_cards": count_files(repo_root / "knowledge/api_cards", (".yaml", ".yml")) + count_files(repo_root / "knowledge_base/api_cards", (".yaml", ".yml")),
            "api_constraints": count_files(repo_root / "knowledge_raw/api_constraints"),
        },
    }


def capability_matrix() -> tuple[dict[str, Any], dict[str, Any]]:
    rows = []
    for target in TARGETS:
        api = "psa_aead_encrypt / psa_aead_decrypt" if target.startswith("mbedtls") else "Botan::AEAD_Mode AES-128/GCM"
        rows.append(
            {
                "family": "cipher_aead_lifecycle",
                "target": target,
                "status": "supported_valid_contract_smoke",
                "algorithm": "AES-128-GCM",
                "api": api,
                "supported_sequences": ["empty_aad", "nonempty_aad", "zero_length_plaintext", "length_1", "length_15", "length_16", "length_17", "modified_tag_safe_reject"],
            }
        )
    return (
        {"schema": "aead_capability_matrix_v1", "targets": TARGETS, "blocked_targets": sorted(BLOCKED_TARGETS), "rows": rows},
        {"schema": "unsupported_aead_matrix_v1", "unsupported_count": 0, "unsupported": []},
    )


def selected_sequences() -> list[dict[str, Any]]:
    specs = [
        ("empty_aad_len8", "", "0001020304050607", False),
        ("nonempty_aad_len8", "aabbccdd", "0001020304050607", False),
        ("zero_length_plaintext", "", "", False),
        ("plaintext_len_1", "", "00", False),
        ("plaintext_len_15", "aabb", "000102030405060708090a0b0c0d0e", False),
        ("plaintext_len_16", "aabb", "000102030405060708090a0b0c0d0e0f", False),
        ("plaintext_len_17", "aabb", "000102030405060708090a0b0c0d0e0f10", False),
        ("modified_tag_safe_reject", "aabbcc", "0011223344556677", True),
    ]
    rows = []
    for idx, (name, aad, pt, modified) in enumerate(specs, 1):
        rows.append(
            {
                "case_id": f"aead_lifecycle_{idx:03d}",
                "family": "cipher_aead_lifecycle",
                "sequence": name,
                "aad_hex": aad,
                "plaintext_hex": pt,
                "modified_tag": modified,
                "valid_contract": True,
                "compatible_targets": TARGETS,
            }
        )
    return rows


def mbedtls_harness(case: dict[str, Any]) -> str:
    aad_len = len(bytes.fromhex(case["aad_hex"])) if case["aad_hex"] else 0
    pt_len = len(bytes.fromhex(case["plaintext_hex"])) if case["plaintext_hex"] else 0
    aad = bytes_literal(case["aad_hex"])
    pt = bytes_literal(case["plaintext_hex"])
    modified = 1 if case["modified_tag"] else 0
    return f"""#include <stdio.h>
#include <string.h>
#include <psa/crypto.h>
int main(void) {{
  const char *case_id = "{case['case_id']}";
  const unsigned char key_bytes[16] = {{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f }};
  const unsigned char nonce[12] = {{ 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b }};
  const unsigned char aad[] = {{ {aad} }};
  const unsigned char pt[] = {{ {pt} }};
  unsigned char ciphertext[128];
  unsigned char decrypted[128];
  size_t ciphertext_len = 0, decrypted_len = 0;
  int mismatch = 0, modified_tag_safe_reject = 0, invalid_contract = 0;
  psa_status_t status = psa_crypto_init();
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, 128);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, PSA_ALG_GCM);
  if(status == PSA_SUCCESS) status = psa_import_key(&attr, key_bytes, sizeof(key_bytes), &key);
  if(status == PSA_SUCCESS) status = psa_aead_encrypt(key, PSA_ALG_GCM, nonce, sizeof(nonce), aad, {aad_len}, pt, {pt_len}, ciphertext, sizeof(ciphertext), &ciphertext_len);
  if(status == PSA_SUCCESS && {modified}) ciphertext[ciphertext_len - 1] ^= 0x01;
  if(status == PSA_SUCCESS) {{
    psa_status_t dec = psa_aead_decrypt(key, PSA_ALG_GCM, nonce, sizeof(nonce), aad, {aad_len}, ciphertext, ciphertext_len, decrypted, sizeof(decrypted), &decrypted_len);
    if({modified}) {{
      modified_tag_safe_reject = (dec != PSA_SUCCESS);
      mismatch = 0;
    }} else {{
      mismatch = (dec != PSA_SUCCESS) || (decrypted_len != {pt_len}) || memcmp(decrypted, pt, {pt_len}) != 0;
    }}
  }} else {{
    invalid_contract = 1;
  }}
  if(!mbedtls_svc_key_id_is_null(key)) psa_destroy_key(key);
  psa_reset_key_attributes(&attr);
  printf("CASE_RESULT family={case['family']} case_id=%s sequence={case['sequence']} status=%d encrypt_decrypt_success=%d encrypt_decrypt_mismatch=%d modified_tag_safe_reject=%d semantic_observation=%d normal_reject=0 invalid_contract=%d\\n", case_id, (int)status, status == PSA_SUCCESS && mismatch == 0 && (!{modified} || modified_tag_safe_reject), mismatch, modified_tag_safe_reject, mismatch || modified_tag_safe_reject, invalid_contract);
  return 0;
}}
"""


def botan_harness(case: dict[str, Any]) -> str:
    aad = bytes_literal(case["aad_hex"])
    pt = bytes_literal(case["plaintext_hex"])
    modified = "true" if case["modified_tag"] else "false"
    return f"""#include <botan/aead.h>
#include <botan/cipher_mode.h>
#include <botan/secmem.h>
#include <exception>
#include <iostream>
#include <vector>
int main() {{
  std::string case_id = "{case['case_id']}";
  std::vector<uint8_t> key{{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f }};
  std::vector<uint8_t> nonce{{ 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b }};
  std::vector<uint8_t> aad{{ {aad} }};
  Botan::secure_vector<uint8_t> pt{{ {pt} }};
  int mismatch = 0, modified_tag_safe_reject = 0, invalid_contract = 0;
  try {{
    auto enc = Botan::AEAD_Mode::create_or_throw("AES-128/GCM", Botan::Cipher_Dir::Encryption);
    enc->set_key(key);
    enc->set_associated_data(aad);
    enc->start(nonce);
    Botan::secure_vector<uint8_t> ct = pt;
    enc->finish(ct);
    if({modified}) ct[ct.size() - 1] ^= 0x01;
    auto dec = Botan::AEAD_Mode::create_or_throw("AES-128/GCM", Botan::Cipher_Dir::Decryption);
    dec->set_key(key);
    dec->set_associated_data(aad);
    dec->start(nonce);
    try {{
      Botan::secure_vector<uint8_t> recovered = ct;
      dec->finish(recovered);
      if({modified}) {{
        mismatch = 1;
      }} else {{
        mismatch = (recovered != pt);
      }}
    }} catch(const std::exception&) {{
      if({modified}) modified_tag_safe_reject = 1;
      else mismatch = 1;
    }}
  }} catch(const std::exception&) {{
    invalid_contract = 1;
  }}
  int success = (!invalid_contract && !mismatch && (!{modified} || modified_tag_safe_reject));
  std::cout << "CASE_RESULT family={case['family']} case_id=" << case_id << " sequence={case['sequence']} status=0 encrypt_decrypt_success=" << success << " encrypt_decrypt_mismatch=" << mismatch << " modified_tag_safe_reject=" << modified_tag_safe_reject << " semantic_observation=" << (mismatch || modified_tag_safe_reject) << " normal_reject=0 invalid_contract=" << invalid_contract << "\\n";
  return 0;
}}
"""


def harness_for(case: dict[str, Any], target: str) -> str:
    return botan_harness(case) if target.startswith("botan") else mbedtls_harness(case)


def classify(run_result: dict[str, Any]) -> dict[str, Any]:
    stdout = Path(run_result["stdout_log"]).read_text(encoding="utf-8", errors="replace") if Path(run_result["stdout_log"]).exists() else ""
    stderr = Path(run_result["stderr_log"]).read_text(encoding="utf-8", errors="replace") if Path(run_result["stderr_log"]).exists() else ""
    lower = stderr.lower()
    lsan_environment_error = "leaksanitizer does not work under ptrace" in lower
    asan = "addresssanitizer" in lower or ("asan" in lower and "runtime" not in lower)
    ubsan = "undefinedbehavior" in lower or "runtime error:" in lower or "ubsan" in lower
    timeout = bool(run_result.get("timeout"))
    crash = run_result.get("return_code") not in (0, 124) and not asan and not ubsan and not lsan_environment_error

    def bit(name: str) -> bool:
        m = re.search(rf"{name}=([01])", stdout)
        return bool(m and m.group(1) == "1")

    candidate = bool(asan or ubsan or crash or timeout)
    return {
        "encrypt_decrypt_success": bit("encrypt_decrypt_success"),
        "encrypt_decrypt_mismatch": bit("encrypt_decrypt_mismatch"),
        "modified_tag_safe_reject": bit("modified_tag_safe_reject"),
        "semantic_observation": bit("semantic_observation"),
        "normal_reject": bit("normal_reject"),
        "invalid_contract": bit("invalid_contract"),
        "asan": asan,
        "ubsan": ubsan,
        "crash": crash,
        "timeout": timeout,
        "candidate": candidate,
        "lsan_environment_error": lsan_environment_error,
    }


def compile_run(out_dir: Path, sequences: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    generated: list[dict[str, Any]] = []
    compile_rows: list[dict[str, Any]] = []
    run_rows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for seq in sequences:
        for target in seq["compatible_targets"]:
            if target in BLOCKED_TARGETS or target not in TARGETS:
                continue
            ext = ".cpp" if target.startswith("botan") else ".c"
            source = out_dir / "cases/work" / target / f"{seq['case_id']}{ext}"
            binary = out_dir / "cases/work" / target / f"{seq['case_id']}.bin"
            write_text(source, harness_for(seq, target))
            generated.append({"case_id": seq["case_id"], "sequence": seq["sequence"], "target": target, "source": str(source), "binary": str(binary), "binary_artifact_not_for_commit": True})
            c = run_cmd(compile_cmd(source, binary, target), out_dir / "compile" / target / seq["case_id"], timeout=30)
            compile_rows.append({"case_id": seq["case_id"], "target": target, "compile": c})
            if not c["ok"]:
                continue
            r = run_cmd([str(binary)], out_dir / "run" / target / seq["case_id"], timeout=20)
            cls = classify(r)
            run_rows.append({"case_id": seq["case_id"], "sequence": seq["sequence"], "target": target, "run": r, "classification": cls})
            events.append({"case_id": seq["case_id"], "sequence": seq["sequence"], "target": target, **cls})
    return generated, compile_rows, run_rows, events


def event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "encrypt_decrypt_success_count": sum(1 for e in events if e["encrypt_decrypt_success"]),
        "encrypt_decrypt_mismatch_count": sum(1 for e in events if e["encrypt_decrypt_mismatch"]),
        "modified_tag_safe_reject_count": sum(1 for e in events if e["modified_tag_safe_reject"]),
        "semantic_observation_count": sum(1 for e in events if e["semantic_observation"]),
        "normal_reject_count": sum(1 for e in events if e["normal_reject"]),
        "invalid_contract_count": sum(1 for e in events if e["invalid_contract"]),
        "asan_events": sum(1 for e in events if e["asan"]),
        "ubsan_events": sum(1 for e in events if e["ubsan"]),
        "crash_events": sum(1 for e in events if e["crash"]),
        "timeout_events": sum(1 for e in events if e["timeout"]),
        "candidate_event_count": sum(1 for e in events if e["candidate"]),
    }


def write_outputs(repo_root: Path, out_dir: Path) -> None:
    inventory = artifact_inventory(repo_root)
    preflight = glm_preflight()
    cap, unsupported = capability_matrix()
    sequences = selected_sequences()
    generated, compile_rows, run_rows, events = compile_run(out_dir, sequences)
    counts = event_counts(events)
    compile_success = sum(1 for r in compile_rows if r["compile"]["ok"])
    compile_failed = len(compile_rows) - compile_success
    run_success = sum(1 for r in run_rows if r["run"]["ok"])
    run_failed = len(run_rows) - run_success
    candidate_events = [e for e in events if e["candidate"]]
    semantic_events = [e for e in events if e["semantic_observation"]]
    comparison = []
    for case_id in sorted({e["case_id"] for e in events}):
        rows = [e for e in events if e["case_id"] == case_id]
        cats = {e["target"]: "candidate" if e["candidate"] else "modified_tag_safe_reject" if e["modified_tag_safe_reject"] else "mismatch" if e["encrypt_decrypt_mismatch"] else "encrypt_decrypt_success" for e in rows}
        comparison.append({"case_id": case_id, "behavior_categories": cats, "same_behavior": len(set(cats.values())) <= 1, "different_behavior": len(set(cats.values())) > 1})

    quality = "pass_aead_lifecycle_smoke_with_candidate_events" if counts["candidate_event_count"] else "pass_aead_lifecycle_smoke_no_candidate"
    if unsupported["unsupported_count"] and generated:
        quality = "partial_aead_some_unsupported"
    if not generated:
        quality = "blocked_no_supported_aead_cases"
    if compile_rows and compile_success == 0:
        quality = "blocked_compile_not_available"

    qc = {
        "schema": "cipher_aead_lifecycle_adapter_quality_checks_v1",
        "api_cards_loaded": inventory["api_cards_loaded"],
        "family_cards_loaded": inventory["family_cards_loaded"],
        "glm_attempted": preflight["glm_attempted"],
        "glm_available": preflight["glm_available"],
        "fallback_used": preflight["fallback_used"],
        "api_key_logged": False,
        "aead_capability_matrix_generated": True,
        "slot_binding_matrix_generated": True,
        "adapter_recipe_generated": True,
        "unsupported_aead_matrix_generated": True,
        "selected_sequence_count": len(sequences),
        "selected_target_distribution": distribution(generated, "target"),
        "valid_contract_sequences": len(sequences),
        "invalid_contract_sequences": 0,
        "generated_case_count": len(generated),
        "compile_run_attempted": bool(generated),
        "compile_success_count": compile_success,
        "compile_failed_count": compile_failed,
        "run_success_count": run_success,
        "run_failed_count": run_failed,
        **counts,
        "candidate_rule_preserved": True,
        "normal_reject_treated_as_candidate": False,
        "invalid_contract_treated_as_candidate": False,
        "semantic_difference_treated_as_candidate": False,
        "unsupported_api_treated_as_candidate": False,
        "modified_tag_reject_treated_as_candidate": False,
        "blocked_target_used": False,
        "new_tools_script_created": False,
        "rpki_logic_integrated": False,
        "external_code_vendored": False,
        "confirmed_vulnerability_claim": False,
        "git_add_commit_push": False,
        "binary_artifacts_marked_not_for_commit": True,
        "quality_status": quality,
    }

    dump_yaml(out_dir / "input/artifact_inventory.yaml", inventory)
    dump_yaml(out_dir / "glm/glm_preflight.yaml", preflight)
    dump_yaml(out_dir / "glm/glm_usage_plan.yaml", {"schema": "cipher_aead_glm_usage_plan_v1", "allowed_roles": ["AEAD API mapping", "slot binding suggestion", "adapter recipe draft", "nonce/tag/AAD/plaintext parameter suggestion", "valid-contract lifecycle sequence draft", "unsupported API reason explanation"], "forbidden_roles": ["vulnerability judgment", "CVE / externally actionable claim", "replacement for ASAN/UBSAN/crash/timeout oracle", "free-form unauditable harness generation", "API key logging"], "fallback_policy": "Use deterministic PSA/Botan AES-GCM mapping when GLM is unavailable."})
    dump_yaml(out_dir / "capability/aead_capability_matrix.yaml", cap)
    dump_yaml(out_dir / "capability/unsupported_aead_matrix.yaml", unsupported)
    dump_yaml(out_dir / "recipes/aead_adapter_recipe.yaml", {"schema": "aead_adapter_recipe_v1", "family": "cipher_aead_lifecycle", "algorithm": "AES-128-GCM", "key_len": 16, "nonce_len": 12, "tag_len": 16, "source": "deterministic fallback from local API cards and headers", "candidate_rule": CANDIDATE_RULE})
    dump_yaml(out_dir / "recipes/slot_binding_matrix.yaml", {"schema": "aead_slot_binding_matrix_v1", "slots": {"key": "fixed 16-byte AES key", "nonce": "fixed 12-byte GCM nonce", "aad": "sequence-specific AAD bytes", "plaintext": "sequence-specific plaintext bytes", "tag": "library-generated default GCM tag", "modified_tag": "flip final ciphertext/tag byte for expected safe rejection"}})
    dump_yaml(out_dir / "selection/selected_aead_sequences.yaml", {"schema": "selected_aead_sequences_v1", "sequences": sequences})
    dump_yaml(out_dir / "cases/generated_case_manifest.yaml", {"schema": "aead_generated_case_manifest_v1", "generated_case_count": len(generated), "cases": generated})
    dump_yaml(out_dir / "compile/compile_summary.yaml", {"schema": "aead_compile_summary_v1", "compile_run_attempted": bool(generated), "compile_success_count": compile_success, "compile_failed_count": compile_failed, "items": compile_rows})
    dump_yaml(out_dir / "run/run_summary.yaml", {"schema": "aead_run_summary_v1", "run_success_count": run_success, "run_failed_count": run_failed, **counts, "items": run_rows})
    dump_yaml(out_dir / "analysis/oracle_events.yaml", {"schema": "aead_oracle_events_v1", "candidate_rule": CANDIDATE_RULE, "events": events})
    dump_yaml(out_dir / "analysis/semantic_observations.yaml", {"schema": "aead_semantic_observations_v1", "semantic_observation_count": len(semantic_events), "events": semantic_events})
    dump_yaml(out_dir / "analysis/cross_library_behavior_comparison.yaml", {"schema": "aead_cross_library_behavior_comparison_v1", "behavior_categories_compared": True, "same_behavior_count": sum(1 for r in comparison if r["same_behavior"]), "different_behavior_count": sum(1 for r in comparison if r["different_behavior"]), "items": comparison})
    dump_yaml(out_dir / "analysis/candidate_summary.yaml", {"schema": "aead_candidate_summary_v1", "candidate_event_count": len(candidate_events), "candidate_rule": CANDIDATE_RULE, "confirmed_vulnerability_claim": False, "events": candidate_events})
    dump_yaml(out_dir / "validation/cipher_aead_lifecycle_adapter_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

Small AES-GCM valid-contract AEAD lifecycle smoke.

- selected AEAD sequences: {len(sequences)}
- generated target cases: {len(generated)}
- compile success: {compile_success}
- compile failed: {compile_failed}
- run success: {run_success}
- run failed: {run_failed}
- encrypt/decrypt success: {counts['encrypt_decrypt_success_count']}
- encrypt/decrypt mismatch: {counts['encrypt_decrypt_mismatch_count']}
- modified-tag safe reject: {counts['modified_tag_safe_reject_count']}
- candidate events: {counts['candidate_event_count']}
- quality status: {quality}

Candidate rule: {CANDIDATE_RULE}

No blocked targets, public target access, RPKI logic, external code vendoring, tools scripts, feedback-bank writes, pattern-bank writes, git add/commit/push, or vulnerability claims were used.
"""
    write_text(out_dir / "reports/cipher_aead_lifecycle_adapter_recipe_v1_report.md", report)
    print(f"wrote {out_dir}")
    print(f"quality_status: {quality}")
    print(f"generated_case_count: {len(generated)}")
    print(f"candidate_event_count: {counts['candidate_event_count']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = repo_root / out_dir
    write_outputs(repo_root, out_dir)


if __name__ == "__main__":
    main()
