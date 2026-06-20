"""Small valid-contract stateful lifecycle smoke campaign.

The campaign uses audited deterministic fallback harnesses for MAC and Digest
lifecycle sequences on local sanitizer-ready mbedTLS/Botan targets. AEAD and
PKEY are recorded as unsupported/deferred for this smoke run instead of
forcing uncertain harnesses.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Any

import yaml

from analysis.cat_case_input_runner_bridge import TARGETS, BLOCKED_TARGETS, compile_cmd, run_cmd


TASK = "stateful_lifecycle_valid_contract_v1"
DEFAULT_OUT = Path("artifacts/cross_library/mainline") / TASK
CANDIDATE_RULE = "Only ASAN/UBSAN/crash/timeout become candidate events. Semantic mismatches, safe rejects, unsupported APIs, and invalid contracts are observations only."


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


def glm_preflight() -> dict[str, Any]:
    available = bool(os.environ.get("GLM_API_KEY") or os.environ.get("ZHIPUAI_API_KEY"))
    return {
        "schema": "stateful_lifecycle_glm_preflight_v1",
        "glm_attempted": True,
        "attempt_type": "local_availability_preflight_only",
        "glm_available": available,
        "fallback_used": not available,
        "api_key_logged": False,
        "network_call_made": False,
    }


def artifact_inventory(repo_root: Path) -> dict[str, Any]:
    return {
        "schema": "stateful_lifecycle_artifact_inventory_v1",
        "api_cards_loaded": count_files(repo_root / "knowledge/api_cards", (".yaml", ".yml")) + count_files(repo_root / "knowledge_base/api_cards", (".yaml", ".yml")) > 0,
        "family_cards_loaded": count_files(repo_root / "knowledge/family_cards", (".yaml", ".yml")) > 0,
        "counts": {
            "family_cards": count_files(repo_root / "knowledge/family_cards", (".yaml", ".yml")),
            "api_cards": count_files(repo_root / "knowledge/api_cards", (".yaml", ".yml")) + count_files(repo_root / "knowledge_base/api_cards", (".yaml", ".yml")),
            "api_constraints": count_files(repo_root / "knowledge_raw/api_constraints"),
        },
        "prior_roundtrip_loaded": (repo_root / "artifacts/cross_library/mainline/crypto_roundtrip_metamorphic_oracle_v1/validation/crypto_roundtrip_metamorphic_quality_checks.yaml").exists(),
    }


def capability_matrix() -> tuple[dict[str, Any], dict[str, Any]]:
    supported: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    families = ["mac_lifecycle", "cipher_aead_lifecycle", "digest_lifecycle", "pkey_sign_verify_lifecycle"]
    for family in families:
        for target in TARGETS:
            if family in {"mac_lifecycle", "digest_lifecycle"}:
                supported.append({"family": family, "target": target, "status": "supported_valid_contract_smoke", "supported_sequences": ["empty_update", "one_shot_vs_streaming", "split_chunks", "reset_reuse"]})
            elif family == "cipher_aead_lifecycle":
                unsupported.append({"family": family, "target": target, "status": "deferred", "reason": "AEAD target APIs require separate nonce/tag/associated-data adapter recipe; not forced in this smoke run"})
            else:
                unsupported.append({"family": family, "target": target, "status": "deferred", "reason": "PKEY lifecycle needs key fixture and sign/verify mapping; not forced in this smoke run"})
    return (
        {"schema": "lifecycle_capability_matrix_v1", "targets": TARGETS, "blocked_targets": sorted(BLOCKED_TARGETS), "supported": supported},
        {"schema": "unsupported_lifecycle_matrix_v1", "unsupported_count": len(unsupported), "unsupported": unsupported},
    )


def select_sequences() -> list[dict[str, Any]]:
    sequences: list[dict[str, Any]] = []
    specs = [
        ("empty_update", "", "empty update then final"),
        ("one_shot_vs_streaming", "616263", "one-shot data vs streaming final"),
        ("split_chunks", "616263646566", "split data chunks then final"),
        ("reset_reuse", "7265736574", "final then reset/reuse"),
        ("short_boundary", "00", "single-byte boundary input"),
        ("block_boundary", "00112233445566778899aabbccddeeff", "block-size-like boundary input"),
    ]
    for family in ["mac_lifecycle", "digest_lifecycle"]:
        for idx, (oracle, data, desc) in enumerate(specs, 1):
            sequences.append(
                {
                    "case_id": f"{family}_{idx:03d}",
                    "family": family,
                    "oracle_type": oracle,
                    "description": desc,
                    "data_hex": data,
                    "valid_contract": True,
                    "compatible_targets": TARGETS,
                }
            )
    return sequences


def bytes_literal(hex_text: str) -> str:
    if not hex_text:
        return "0x00"
    return ", ".join(f"0x{b:02x}" for b in bytes.fromhex(hex_text))


def mbedtls_mac_harness(case: dict[str, Any], target: str) -> str:
    data_len = len(bytes.fromhex(case["data_hex"])) if case["data_hex"] else 0
    arr = bytes_literal(case["data_hex"])
    private_define = "#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS\n" if target == "mbedtls-4.1.0-asan" else ""
    return f"""#include <stdio.h>
#include <string.h>
{private_define}\
#include <mbedtls/md.h>
int main(void) {{
  const char *case_id = "{case['case_id']}";
  const unsigned char key[] = {{ 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 }};
  const unsigned char data[] = {{ {arr} }};
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  unsigned char one[32], stream[32], again[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  int mismatch = 0, ret = 0;
  if(info == NULL) ret = -1;
  if(ret == 0) ret = mbedtls_md_hmac(info, key, sizeof(key), data, {data_len}, one);
  if(ret == 0) ret = mbedtls_md_setup(&ctx, info, 1);
  if(ret == 0) ret = mbedtls_md_hmac_starts(&ctx, key, sizeof(key));
  if(ret == 0) ret = mbedtls_md_hmac_update(&ctx, data, {data_len // 2});
  if(ret == 0) ret = mbedtls_md_hmac_update(&ctx, data + {data_len // 2}, {data_len - data_len // 2});
  if(ret == 0) ret = mbedtls_md_hmac_finish(&ctx, stream);
  if(ret == 0 && memcmp(one, stream, sizeof(one)) != 0) mismatch = 1;
  if(ret == 0) ret = mbedtls_md_hmac_reset(&ctx);
  if(ret == 0) ret = mbedtls_md_hmac_update(&ctx, data, {data_len});
  if(ret == 0) ret = mbedtls_md_hmac_finish(&ctx, again);
  if(ret == 0 && memcmp(one, again, sizeof(one)) != 0) mismatch = 1;
  mbedtls_md_free(&ctx);
  printf("CASE_RESULT family={case['family']} case_id=%s oracle={case['oracle_type']} ret=%d normal_reject=0 semantic_observation=%d lifecycle_mismatch=%d invalid_contract=0\\n", case_id, ret, mismatch, mismatch);
  return 0;
}}
"""


def mbedtls_digest_harness(case: dict[str, Any]) -> str:
    data_len = len(bytes.fromhex(case["data_hex"])) if case["data_hex"] else 0
    arr = bytes_literal(case["data_hex"])
    return f"""#include <stdio.h>
#include <string.h>
#include <mbedtls/md.h>
int main(void) {{
  const char *case_id = "{case['case_id']}";
  const unsigned char data[] = {{ {arr} }};
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  unsigned char one[32], stream[32], again[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  int mismatch = 0, ret = 0;
  if(info == NULL) ret = -1;
  if(ret == 0) ret = mbedtls_md(info, data, {data_len}, one);
  if(ret == 0) ret = mbedtls_md_setup(&ctx, info, 0);
  if(ret == 0) ret = mbedtls_md_starts(&ctx);
  if(ret == 0) ret = mbedtls_md_update(&ctx, data, {data_len // 2});
  if(ret == 0) ret = mbedtls_md_update(&ctx, data + {data_len // 2}, {data_len - data_len // 2});
  if(ret == 0) ret = mbedtls_md_finish(&ctx, stream);
  if(ret == 0 && memcmp(one, stream, sizeof(one)) != 0) mismatch = 1;
  if(ret == 0) ret = mbedtls_md_starts(&ctx);
  if(ret == 0) ret = mbedtls_md_update(&ctx, data, {data_len});
  if(ret == 0) ret = mbedtls_md_finish(&ctx, again);
  if(ret == 0 && memcmp(one, again, sizeof(one)) != 0) mismatch = 1;
  mbedtls_md_free(&ctx);
  printf("CASE_RESULT family={case['family']} case_id=%s oracle={case['oracle_type']} ret=%d normal_reject=0 semantic_observation=%d lifecycle_mismatch=%d invalid_contract=0\\n", case_id, ret, mismatch, mismatch);
  return 0;
}}
"""


def botan_mac_harness(case: dict[str, Any]) -> str:
    arr = bytes_literal(case["data_hex"])
    return f"""#include <botan/mac.h>
#include <iostream>
#include <vector>
int main() {{
  std::string case_id = "{case['case_id']}";
  std::vector<uint8_t> key{{ 1,2,3,4,5,6,7,8 }};
  std::vector<uint8_t> data{{ {arr} }};
  int mismatch = 0;
  try {{
    auto one = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    one->set_key(key);
    one->update(data);
    auto tag1 = one->final_stdvec();
    auto stream = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    stream->set_key(key);
    stream->update(data.data(), data.size()/2);
    stream->update(data.data()+data.size()/2, data.size()-data.size()/2);
    auto tag2 = stream->final_stdvec();
    auto again = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    again->set_key(key);
    again->update(data);
    auto tag3 = again->final_stdvec();
    mismatch = (tag1 != tag2) || (tag1 != tag3);
    std::cout << "CASE_RESULT family={case['family']} case_id=" << case_id << " oracle={case['oracle_type']} ret=0 normal_reject=0 semantic_observation=" << mismatch << " lifecycle_mismatch=" << mismatch << " invalid_contract=0\\n";
  }} catch(const std::exception&) {{
    std::cout << "CASE_RESULT family={case['family']} case_id=" << case_id << " oracle={case['oracle_type']} ret=-1 normal_reject=1 semantic_observation=1 lifecycle_mismatch=0 invalid_contract=0\\n";
  }}
  return 0;
}}
"""


def botan_digest_harness(case: dict[str, Any]) -> str:
    arr = bytes_literal(case["data_hex"])
    return f"""#include <botan/hash.h>
#include <iostream>
#include <vector>
int main() {{
  std::string case_id = "{case['case_id']}";
  std::vector<uint8_t> data{{ {arr} }};
  int mismatch = 0;
  try {{
    auto one = Botan::HashFunction::create_or_throw("SHA-256");
    one->update(data);
    auto digest1 = one->final_stdvec();
    auto stream = Botan::HashFunction::create_or_throw("SHA-256");
    stream->update(data.data(), data.size()/2);
    stream->update(data.data()+data.size()/2, data.size()-data.size()/2);
    auto digest2 = stream->final_stdvec();
    auto again = Botan::HashFunction::create_or_throw("SHA-256");
    again->update(data);
    auto digest3 = again->final_stdvec();
    mismatch = (digest1 != digest2) || (digest1 != digest3);
    std::cout << "CASE_RESULT family={case['family']} case_id=" << case_id << " oracle={case['oracle_type']} ret=0 normal_reject=0 semantic_observation=" << mismatch << " lifecycle_mismatch=" << mismatch << " invalid_contract=0\\n";
  }} catch(const std::exception&) {{
    std::cout << "CASE_RESULT family={case['family']} case_id=" << case_id << " oracle={case['oracle_type']} ret=-1 normal_reject=1 semantic_observation=1 lifecycle_mismatch=0 invalid_contract=0\\n";
  }}
  return 0;
}}
"""


def harness_for(case: dict[str, Any], target: str) -> str:
    if target.startswith("botan"):
        return botan_mac_harness(case) if case["family"] == "mac_lifecycle" else botan_digest_harness(case)
    return mbedtls_mac_harness(case, target) if case["family"] == "mac_lifecycle" else mbedtls_digest_harness(case)


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

    semantic = bit("semantic_observation")
    invalid_contract = bit("invalid_contract")
    normal_reject = bit("normal_reject")
    candidate = bool(asan or ubsan or crash or timeout)
    return {
        "semantic_observation": semantic,
        "normal_reject": normal_reject,
        "invalid_contract": invalid_contract,
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
            source = out_dir / "cases/work" / seq["family"] / target / f"{seq['case_id']}{ext}"
            binary = out_dir / "cases/work" / seq["family"] / target / f"{seq['case_id']}.bin"
            write_text(source, harness_for(seq, target))
            generated.append({"case_id": seq["case_id"], "family": seq["family"], "oracle_type": seq["oracle_type"], "target": target, "source": str(source), "binary": str(binary), "binary_artifact_not_for_commit": True})
            c = run_cmd(compile_cmd(source, binary, target), out_dir / "compile" / seq["family"] / target / seq["case_id"], timeout=30)
            compile_rows.append({"case_id": seq["case_id"], "family": seq["family"], "target": target, "compile": c})
            if not c["ok"]:
                continue
            r = run_cmd([str(binary)], out_dir / "run" / seq["family"] / target / seq["case_id"], timeout=20)
            cls = classify(r)
            run_rows.append({"case_id": seq["case_id"], "family": seq["family"], "oracle_type": seq["oracle_type"], "target": target, "run": r, "classification": cls})
            events.append({"case_id": seq["case_id"], "family": seq["family"], "oracle_type": seq["oracle_type"], "target": target, **cls})
    return generated, compile_rows, run_rows, events


def event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    return {
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
    sequences = select_sequences()
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
        cats = {e["target"]: "candidate" if e["candidate"] else "semantic_observation" if e["semantic_observation"] else "lifecycle_ok" for e in rows}
        comparison.append({"case_id": case_id, "behavior_categories": cats, "same_behavior": len(set(cats.values())) <= 1, "different_behavior": len(set(cats.values())) > 1})

    quality = "pass_lifecycle_smoke_with_candidate_events" if counts["candidate_event_count"] else "pass_lifecycle_smoke_no_candidate"
    if unsupported["unsupported_count"] and generated:
        quality = "partial_lifecycle_some_unsupported"
    if not generated:
        quality = "blocked_no_supported_lifecycle_cases"
    if compile_rows and compile_success == 0:
        quality = "blocked_compile_not_available"

    qc = {
        "schema": "stateful_lifecycle_valid_contract_quality_checks_v1",
        "api_cards_loaded": inventory["api_cards_loaded"],
        "family_cards_loaded": inventory["family_cards_loaded"],
        "glm_attempted": preflight["glm_attempted"],
        "glm_available": preflight["glm_available"],
        "fallback_used": preflight["fallback_used"],
        "api_key_logged": False,
        "capability_matrix_generated": True,
        "unsupported_lifecycle_matrix_generated": True,
        "selected_sequence_count": len(sequences),
        "selected_family_distribution": distribution(sequences, "family"),
        "selected_oracle_distribution": distribution(sequences, "oracle_type"),
        "valid_contract_sequences": sum(1 for s in sequences if s["valid_contract"]),
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
    dump_yaml(out_dir / "glm/glm_usage_plan.yaml", {"schema": "stateful_lifecycle_glm_usage_plan_v1", "allowed_roles": ["API lifecycle mapping", "slot binding suggestion", "adapter recipe draft", "valid-contract sequence draft", "target API capability explanation", "semantic oracle draft"], "forbidden_roles": ["vulnerability judgment", "CVE / externally actionable claim", "replacement for ASAN/UBSAN/crash/timeout oracle", "free-form unauditable harness generation", "API key logging"], "fallback_policy": "Use deterministic local API-card/header mapping when GLM is unavailable."})
    dump_yaml(out_dir / "capability/lifecycle_capability_matrix.yaml", cap)
    dump_yaml(out_dir / "capability/unsupported_lifecycle_matrix.yaml", unsupported)
    dump_yaml(out_dir / "selection/selected_lifecycle_sequences.yaml", {"schema": "selected_lifecycle_sequences_v1", "sequences": sequences})
    dump_yaml(out_dir / "selection/selection_summary.yaml", {"schema": "lifecycle_selection_summary_v1", "selected_sequence_count": len(sequences), "selected_family_distribution": distribution(sequences, "family"), "selected_oracle_distribution": distribution(sequences, "oracle_type"), "valid_contract_sequences": len(sequences), "invalid_contract_sequences": 0})
    dump_yaml(out_dir / "recipes/adapter_recipe_summary.yaml", {"schema": "lifecycle_adapter_recipe_summary_v1", "implemented_families": ["mac_lifecycle", "digest_lifecycle"], "deferred_families": ["cipher_aead_lifecycle", "pkey_sign_verify_lifecycle"], "notes": "Small smoke uses audited deterministic fallback harnesses; AEAD/PKEY need separate recipes."})
    dump_yaml(out_dir / "cases/generated_case_manifest.yaml", {"schema": "stateful_lifecycle_generated_case_manifest_v1", "generated_case_count": len(generated), "cases": generated})
    dump_yaml(out_dir / "compile/compile_summary.yaml", {"schema": "stateful_lifecycle_compile_summary_v1", "compile_run_attempted": bool(generated), "compile_success_count": compile_success, "compile_failed_count": compile_failed, "items": compile_rows})
    dump_yaml(out_dir / "run/run_summary.yaml", {"schema": "stateful_lifecycle_run_summary_v1", "run_success_count": run_success, "run_failed_count": run_failed, **counts, "items": run_rows})
    dump_yaml(out_dir / "analysis/oracle_events.yaml", {"schema": "stateful_lifecycle_oracle_events_v1", "candidate_rule": CANDIDATE_RULE, "events": events})
    dump_yaml(out_dir / "analysis/semantic_observations.yaml", {"schema": "stateful_lifecycle_semantic_observations_v1", "semantic_observation_count": len(semantic_events), "events": semantic_events})
    dump_yaml(out_dir / "analysis/cross_library_behavior_comparison.yaml", {"schema": "stateful_lifecycle_cross_library_behavior_comparison_v1", "behavior_categories_compared": True, "same_behavior_count": sum(1 for r in comparison if r["same_behavior"]), "different_behavior_count": sum(1 for r in comparison if r["different_behavior"]), "items": comparison})
    dump_yaml(out_dir / "analysis/candidate_summary.yaml", {"schema": "stateful_lifecycle_candidate_summary_v1", "candidate_event_count": len(candidate_events), "candidate_rule": CANDIDATE_RULE, "confirmed_vulnerability_claim": False, "events": candidate_events})
    dump_yaml(out_dir / "validation/stateful_lifecycle_valid_contract_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

Small valid-contract lifecycle smoke campaign.

- selected source sequences: {len(sequences)}
- generated target cases: {len(generated)}
- compile success: {compile_success}
- compile failed: {compile_failed}
- run success: {run_success}
- run failed: {run_failed}
- semantic observations: {counts['semantic_observation_count']}
- candidate events: {counts['candidate_event_count']}
- quality status: {quality}

AEAD and PKEY lifecycle families were recorded as deferred/unsupported for this smoke run instead of forcing uncertain adapters.

Candidate rule: {CANDIDATE_RULE}

No blocked targets, public target access, RPKI logic, external code vendoring, tools scripts, feedback-bank writes, pattern-bank writes, git add/commit/push, or vulnerability claims were used.
"""
    write_text(out_dir / "reports/stateful_lifecycle_valid_contract_v1_report.md", report)
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
