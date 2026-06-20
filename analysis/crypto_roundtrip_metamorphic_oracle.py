"""Small crypto-aware roundtrip/metamorphic oracle campaign.

This script runs a compact smoke campaign across local sanitizer-ready targets.
It prioritizes valid-contract bignum roundtrip cases and records degraded
parse/raw observations for PKCS and X.509 where portable export APIs are not
available in the current local target set.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from analysis.cat_case_input_runner_bridge import TARGETS, BLOCKED_TARGETS, compile_cmd, run_cmd


TASK = "crypto_roundtrip_metamorphic_oracle_v1"
BASE = Path("artifacts/cross_library")
DEFAULT_OUT = BASE / "mainline" / TASK
FAMILIES = ["bignum_serialization_boundary", "pkcs_container_parsing", "x509_asn1_inner_boundary"]
CANDIDATE_RULE = "Only ASAN/UBSAN/crash/timeout become candidate events. Normal reject, semantic difference, invalid contract, and unsupported API are observations only."


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


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
    data = bytes.fromhex(hex_text)
    return ", ".join(f"0x{b:02x}" for b in data) or "0x00"


def glm_preflight() -> dict[str, Any]:
    available = bool(os.environ.get("GLM_API_KEY") or os.environ.get("ZHIPUAI_API_KEY"))
    return {
        "schema": "crypto_roundtrip_glm_preflight_v1",
        "glm_attempted": True,
        "attempt_type": "local_availability_preflight_only",
        "glm_available": available,
        "fallback_used": not available,
        "api_key_logged": False,
        "network_call_made": False,
    }


def artifact_inventory(repo_root: Path) -> dict[str, Any]:
    artifacts = {
        "mainline_relaunch": repo_root / "artifacts/cross_library/strategy/glm_crypto_mainline_relaunch_v1/validation/glm_crypto_mainline_relaunch_quality_checks.yaml",
        "cat_runner_bridge": repo_root / "artifacts/cross_library/seed_enrichment/cat_case_input_runner_bridge_v1/validation/runner_bridge_quality_checks.yaml",
        "cat_targeted_expansion": repo_root / "artifacts/cross_library/seed_enrichment/cat_targeted_operator_expansion_v1/validation/targeted_operator_expansion_quality_checks.yaml",
        "pkcs_bignum_replay": repo_root / "artifacts/cross_library/replay/pkcs_bignum_cross_library_adapter_and_replay_v1/validation/pkcs_bignum_cross_library_adapter_and_replay_quality_checks.yaml",
        "novel_behavior": repo_root / "artifacts/cross_library/behavior_guided/novel_behavior_triage_and_expansion_v1/validation/novel_behavior_triage_and_expansion_quality_checks.yaml",
        "mapping": repo_root / "artifacts/cross_library/mapping/cross_library_api_cards_and_mapping_v1/validation/cross_library_api_cards_and_mapping_quality_checks.yaml",
        "target_libraries": repo_root / "config/target_libraries.yaml",
        "sanitizer_profiles": repo_root / "config/sanitizer_profiles.yaml",
    }
    loaded = {name: path.exists() for name, path in artifacts.items()}
    return {
        "schema": "crypto_roundtrip_artifact_inventory_v1",
        "artifacts_loaded": loaded,
        "mainline_relaunch_loaded": loaded["mainline_relaunch"],
        "api_cards_loaded": count_files(repo_root / "knowledge/api_cards", (".yaml", ".yml")) + count_files(repo_root / "knowledge_base/api_cards", (".yaml", ".yml")) > 0,
        "family_cards_loaded": count_files(repo_root / "knowledge/family_cards", (".yaml", ".yml")) > 0,
        "counts": {
            "family_cards": count_files(repo_root / "knowledge/family_cards", (".yaml", ".yml")),
            "api_cards": count_files(repo_root / "knowledge/api_cards", (".yaml", ".yml")) + count_files(repo_root / "knowledge_base/api_cards", (".yaml", ".yml")),
            "api_constraints": count_files(repo_root / "knowledge_raw/api_constraints"),
        },
    }


def capability_matrix() -> tuple[dict[str, Any], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    for family in FAMILIES:
        for target in TARGETS:
            if family == "bignum_serialization_boundary":
                status = "supported_roundtrip"
                oracle = "from_bytes-to_bytes-from_bytes consistency"
                reason = "bignum read/write APIs are available in local mbedTLS/Botan targets"
            elif family == "pkcs_container_parsing":
                status = "degraded_parse_observation"
                oracle = "key import parse observation"
                reason = "portable import/export/import key roundtrip is not available for all selected local targets"
                unsupported.append({"family": family, "target": target, "missing_capability": "portable key export for roundtrip", "degraded_to": oracle, "reason": reason})
            else:
                status = "degraded_parse_observation"
                oracle = "cert parse/raw-stability observation"
                reason = "portable certificate DER export is not available for all selected local targets"
                unsupported.append({"family": family, "target": target, "missing_capability": "portable cert DER export for roundtrip", "degraded_to": oracle, "reason": reason})
            rows.append({"family": family, "target": target, "status": status, "oracle": oracle, "reason": reason})
    return (
        {"schema": "api_roundtrip_capability_matrix_v1", "targets": TARGETS, "blocked_targets": sorted(BLOCKED_TARGETS), "rows": rows},
        {"schema": "unsupported_api_matrix_v1", "unsupported_count": len(unsupported), "rows": unsupported},
    )


def select_cases() -> list[dict[str, Any]]:
    bignum_inputs = ["00", "01", "7f", "80", "0001"]
    pkcs_inputs = ["3000", "3003020101", "3006020101040100", "300806032a0304050100", "3010020101300b06092a864886f70d010101"]
    x509_inputs = ["3000", "3003020102", "30060201013001", "300a020101300506032a0304", "3010a00302010230090603551d130101ff"]
    cases: list[dict[str, Any]] = []
    for idx, hex_text in enumerate(bignum_inputs, 1):
        cases.append({"case_id": f"bignum_roundtrip_{idx:03d}", "family": "bignum_serialization_boundary", "oracle_type": "roundtrip_consistency", "bytes_hex": hex_text, "valid_contract": True, "degraded": False, "compatible_targets": TARGETS})
    for idx, hex_text in enumerate(pkcs_inputs, 1):
        cases.append({"case_id": f"pkcs_parse_observation_{idx:03d}", "family": "pkcs_container_parsing", "oracle_type": "degraded_parse_observation", "bytes_hex": hex_text, "valid_contract": True, "degraded": True, "compatible_targets": TARGETS})
    for idx, hex_text in enumerate(x509_inputs, 1):
        cases.append({"case_id": f"x509_parse_observation_{idx:03d}", "family": "x509_asn1_inner_boundary", "oracle_type": "degraded_parse_observation", "bytes_hex": hex_text, "valid_contract": True, "degraded": True, "compatible_targets": TARGETS})
    return cases


def mbedtls_bignum_harness(case: dict[str, Any], target: str) -> str:
    header = "mbedtls/bignum.h" if target == "mbedtls-3.6.4-asan" else "mbedtls/private/bignum.h"
    private_define = "#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS\n" if target == "mbedtls-4.1.0-asan" else ""
    arr = bytes_literal(case["bytes_hex"])
    return f"""#include <stdio.h>
#include <string.h>
{private_define}\
#include <{header}>
int main(void) {{
  const char *case_id = "{case['case_id']}";
  const unsigned char input[] = {{ {arr} }};
  unsigned char out1[sizeof(input) ? sizeof(input) : 1];
  unsigned char out2[sizeof(input) ? sizeof(input) : 1];
  mbedtls_mpi a, b;
  mbedtls_mpi_init(&a);
  mbedtls_mpi_init(&b);
  int ret1 = mbedtls_mpi_read_binary(&a, input, sizeof(input));
  int ret2 = 0, ret3 = 0, mismatch = 0;
  if(ret1 == 0) {{
    ret2 = mbedtls_mpi_write_binary(&a, out1, sizeof(out1));
    if(ret2 == 0) {{
      ret3 = mbedtls_mpi_read_binary(&b, out1, sizeof(out1));
      if(ret3 == 0) {{
        int ret4 = mbedtls_mpi_write_binary(&b, out2, sizeof(out2));
        if(ret4 != 0 || memcmp(out1, out2, sizeof(out1)) != 0) mismatch = 1;
      }} else mismatch = 1;
    }} else mismatch = 1;
  }}
  mbedtls_mpi_free(&a);
  mbedtls_mpi_free(&b);
  printf("CASE_RESULT family={case['family']} case_id=%s oracle=roundtrip ret=%d normal_reject=%d roundtrip_success=%d roundtrip_mismatch=%d semantic_observation=%d invalid_contract=0 degraded_oracle=0\\n", case_id, ret1, ret1 != 0, ret1 == 0 && ret2 == 0 && ret3 == 0 && mismatch == 0, mismatch, mismatch);
  return 0;
}}
"""


def botan_bignum_harness(case: dict[str, Any]) -> str:
    arr = bytes_literal(case["bytes_hex"])
    return f"""#include <botan/bigint.h>
#include <iostream>
#include <vector>
int main() {{
  std::string case_id = "{case['case_id']}";
  std::vector<uint8_t> input{{ {arr} }};
  int mismatch = 0;
  try {{
    Botan::BigInt a = Botan::BigInt::from_bytes(input);
    std::vector<uint8_t> out1 = a.serialize<std::vector<uint8_t>>(input.size());
    Botan::BigInt b = Botan::BigInt::from_bytes(out1);
    std::vector<uint8_t> out2 = b.serialize<std::vector<uint8_t>>(input.size());
    mismatch = (out1 != out2);
    std::cout << "CASE_RESULT family={case['family']} case_id=" << case_id << " oracle=roundtrip ret=0 normal_reject=0 roundtrip_success=" << (mismatch ? 0 : 1) << " roundtrip_mismatch=" << mismatch << " semantic_observation=" << mismatch << " invalid_contract=0 degraded_oracle=0\\n";
  }} catch(const std::exception&) {{
    std::cout << "CASE_RESULT family={case['family']} case_id=" << case_id << " oracle=roundtrip ret=-1 normal_reject=1 roundtrip_success=0 roundtrip_mismatch=0 semantic_observation=0 invalid_contract=0 degraded_oracle=0\\n";
  }}
  return 0;
}}
"""


def parse_harness(case: dict[str, Any], target: str) -> str:
    arr = bytes_literal(case["bytes_hex"])
    family = case["family"]
    if target.startswith("botan"):
        if family == "pkcs_container_parsing":
            return f"""#include <botan/pkcs8.h>
#include <botan/data_src.h>
#include <exception>
#include <iostream>
#include <vector>
int main() {{
  std::string case_id = "{case['case_id']}";
  std::vector<unsigned char> input{{ {arr} }};
  int normal_reject = 0;
  try {{
    Botan::DataSource_Memory src(input.data(), input.size());
    auto key = Botan::PKCS8::load_key(src);
    (void)key;
  }} catch(const std::exception&) {{
    normal_reject = 1;
  }}
  std::cout << "CASE_RESULT family={family} case_id=" << case_id << " oracle=degraded_parse ret=0 normal_reject=" << normal_reject << " roundtrip_success=0 roundtrip_mismatch=0 semantic_observation=1 invalid_contract=0 degraded_oracle=1\\n";
  return 0;
}}
"""
        return f"""#include <botan/x509cert.h>
#include <exception>
#include <iostream>
#include <vector>
int main() {{
  std::string case_id = "{case['case_id']}";
  std::vector<unsigned char> input{{ {arr} }};
  int normal_reject = 0;
  try {{
    Botan::X509_Certificate cert(input);
    (void)cert;
  }} catch(const std::exception&) {{
    normal_reject = 1;
  }}
  std::cout << "CASE_RESULT family={family} case_id=" << case_id << " oracle=degraded_parse ret=0 normal_reject=" << normal_reject << " roundtrip_success=0 roundtrip_mismatch=0 semantic_observation=1 invalid_contract=0 degraded_oracle=1\\n";
  return 0;
}}
"""
    if family == "pkcs_container_parsing":
        call = "mbedtls_pk_parse_key(&pk, input, sizeof(input), NULL, 0, NULL, NULL)" if target == "mbedtls-3.6.4-asan" else "mbedtls_pk_parse_key(&pk, input, sizeof(input), NULL, 0)"
        return f"""#include <stdio.h>
#include <mbedtls/pk.h>
int main(void) {{
  const char *case_id = "{case['case_id']}";
  const unsigned char input[] = {{ {arr} }};
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ret = {call};
  int normal_reject = (ret != 0);
  mbedtls_pk_free(&pk);
  printf("CASE_RESULT family={family} case_id=%s oracle=degraded_parse ret=%d normal_reject=%d roundtrip_success=0 roundtrip_mismatch=0 semantic_observation=1 invalid_contract=0 degraded_oracle=1\\n", case_id, ret, normal_reject);
  return 0;
}}
"""
    return f"""#include <stdio.h>
#include <mbedtls/x509_crt.h>
int main(void) {{
  const char *case_id = "{case['case_id']}";
  const unsigned char input[] = {{ {arr} }};
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  int ret = mbedtls_x509_crt_parse_der(&crt, input, sizeof(input));
  int normal_reject = (ret != 0);
  mbedtls_x509_crt_free(&crt);
  printf("CASE_RESULT family={family} case_id=%s oracle=degraded_parse ret=%d normal_reject=%d roundtrip_success=0 roundtrip_mismatch=0 semantic_observation=1 invalid_contract=0 degraded_oracle=1\\n", case_id, ret, normal_reject);
  return 0;
}}
"""


def harness_for(case: dict[str, Any], target: str) -> str:
    if case["family"] == "bignum_serialization_boundary":
        return botan_bignum_harness(case) if target.startswith("botan") else mbedtls_bignum_harness(case, target)
    return parse_harness(case, target)


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

    normal_reject = bit("normal_reject")
    roundtrip_success = bit("roundtrip_success")
    roundtrip_mismatch = bit("roundtrip_mismatch")
    semantic_observation = bit("semantic_observation") or roundtrip_mismatch
    invalid_contract = bit("invalid_contract")
    degraded_oracle = bit("degraded_oracle")
    candidate = bool(asan or ubsan or crash or timeout)
    return {
        "normal_reject": normal_reject,
        "roundtrip_success": roundtrip_success,
        "roundtrip_mismatch": roundtrip_mismatch,
        "semantic_observation": semantic_observation,
        "invalid_contract": invalid_contract,
        "degraded_oracle_only": degraded_oracle,
        "asan": asan,
        "ubsan": ubsan,
        "crash": crash,
        "timeout": timeout,
        "candidate": candidate,
        "lsan_environment_error": lsan_environment_error,
    }


def compile_run(out_dir: Path, cases: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    generated: list[dict[str, Any]] = []
    compile_rows: list[dict[str, Any]] = []
    run_rows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for case in cases:
        for target in case["compatible_targets"]:
            if target in BLOCKED_TARGETS or target not in TARGETS:
                continue
            ext = ".cpp" if target.startswith("botan") else ".c"
            source = out_dir / "cases/work" / case["family"] / target / f"{case['case_id']}{ext}"
            binary = out_dir / "cases/work" / case["family"] / target / f"{case['case_id']}.bin"
            write_text(source, harness_for(case, target))
            generated.append({"case_id": case["case_id"], "family": case["family"], "oracle_type": case["oracle_type"], "target": target, "source": str(source), "binary": str(binary), "binary_artifact_not_for_commit": True})
            c = run_cmd(compile_cmd(source, binary, target), out_dir / "compile" / case["family"] / target / case["case_id"], timeout=30)
            compile_rows.append({"case_id": case["case_id"], "family": case["family"], "target": target, "compile": c})
            if not c["ok"]:
                continue
            r = run_cmd([str(binary)], out_dir / "run" / case["family"] / target / case["case_id"], timeout=20)
            cls = classify(r)
            run_rows.append({"case_id": case["case_id"], "family": case["family"], "oracle_type": case["oracle_type"], "target": target, "run": r, "classification": cls})
            events.append({"case_id": case["case_id"], "family": case["family"], "oracle_type": case["oracle_type"], "target": target, **cls})
    return generated, compile_rows, run_rows, events


def counts(events: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "roundtrip_success_count": sum(1 for e in events if e["roundtrip_success"]),
        "roundtrip_mismatch_count": sum(1 for e in events if e["roundtrip_mismatch"]),
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
    usage = {
        "schema": "crypto_roundtrip_glm_usage_plan_v1",
        "allowed_roles": ["API capability mapping", "roundtrip oracle draft", "adapter recipe draft", "slot binding suggestion", "unsupported API reason explanation", "campaign summary explanation"],
        "forbidden_roles": ["vulnerability judgment", "CVE / externally actionable claim", "replacement for ASAN/UBSAN/crash/timeout oracle", "free-form unauditable harness generation", "API key logging"],
        "fallback_policy": "Use deterministic API-card and local-header based mapping when GLM is unavailable.",
    }
    cap, unsupported = capability_matrix()
    selected = select_cases()
    generated, compile_rows, run_rows, events = compile_run(out_dir, selected)
    event_counts = counts(events)
    compile_success = sum(1 for row in compile_rows if row["compile"]["ok"])
    compile_failed = len(compile_rows) - compile_success
    run_success = sum(1 for row in run_rows if row["run"]["ok"])
    run_failed = len(run_rows) - run_success
    candidate_events = [e for e in events if e["candidate"]]
    semantic_events = [e for e in events if e["semantic_observation"]]

    comparison_rows = []
    for case_id in sorted({e["case_id"] for e in events}):
        rows = [e for e in events if e["case_id"] == case_id]
        cats = {e["target"]: ("candidate" if e["candidate"] else "roundtrip_success" if e["roundtrip_success"] else "normal_reject" if e["normal_reject"] else "semantic_observation") for e in rows}
        comparison_rows.append({"case_id": case_id, "behavior_categories": cats, "same_behavior": len(set(cats.values())) <= 1, "different_behavior": len(set(cats.values())) > 1})

    quality = "pass_roundtrip_smoke_with_candidate_events" if event_counts["candidate_event_count"] else "pass_roundtrip_smoke_no_candidate"
    if unsupported["unsupported_count"] and generated:
        quality = "partial_roundtrip_some_unsupported"
    if not generated:
        quality = "blocked_no_supported_roundtrip_cases"
    if compile_rows and compile_success == 0:
        quality = "blocked_compile_not_available"

    qc = {
        "schema": "crypto_roundtrip_metamorphic_quality_checks_v1",
        "mainline_relaunch_loaded": inventory["mainline_relaunch_loaded"],
        "api_cards_loaded": inventory["api_cards_loaded"],
        "family_cards_loaded": inventory["family_cards_loaded"],
        "glm_attempted": preflight["glm_attempted"],
        "glm_available": preflight["glm_available"],
        "fallback_used": preflight["fallback_used"],
        "api_key_logged": False,
        "capability_matrix_generated": True,
        "unsupported_api_matrix_generated": True,
        "selected_case_count": len(selected),
        "selected_family_distribution": distribution(selected, "family"),
        "selected_oracle_distribution": distribution(selected, "oracle_type"),
        "generated_case_count": len(generated),
        "compile_run_attempted": bool(generated),
        "compile_success_count": compile_success,
        "compile_failed_count": compile_failed,
        "run_success_count": run_success,
        "run_failed_count": run_failed,
        **event_counts,
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
    dump_yaml(out_dir / "glm/glm_usage_plan.yaml", usage)
    dump_yaml(out_dir / "capability/api_roundtrip_capability_matrix.yaml", cap)
    dump_yaml(out_dir / "capability/unsupported_api_matrix.yaml", unsupported)
    dump_yaml(out_dir / "selection/selected_roundtrip_cases.yaml", {"schema": "selected_roundtrip_cases_v1", "cases": selected})
    dump_yaml(out_dir / "selection/selection_summary.yaml", {"schema": "roundtrip_selection_summary_v1", "selected_case_count": len(selected), "selected_family_distribution": distribution(selected, "family"), "selected_oracle_distribution": distribution(selected, "oracle_type"), "valid_contract_count": sum(1 for c in selected if c["valid_contract"]), "degraded_case_count": sum(1 for c in selected if c["degraded"])})
    dump_yaml(out_dir / "cases/generated_case_manifest.yaml", {"schema": "crypto_roundtrip_generated_case_manifest_v1", "generated_case_count": len(generated), "cases": generated})
    dump_yaml(out_dir / "compile/compile_summary.yaml", {"schema": "crypto_roundtrip_compile_summary_v1", "compile_run_attempted": bool(generated), "compile_success_count": compile_success, "compile_failed_count": compile_failed, "items": compile_rows})
    dump_yaml(out_dir / "run/run_summary.yaml", {"schema": "crypto_roundtrip_run_summary_v1", "run_success_count": run_success, "run_failed_count": run_failed, **event_counts, "items": run_rows})
    dump_yaml(out_dir / "analysis/oracle_events.yaml", {"schema": "crypto_roundtrip_oracle_events_v1", "candidate_rule": CANDIDATE_RULE, "events": events})
    dump_yaml(out_dir / "analysis/semantic_observations.yaml", {"schema": "crypto_roundtrip_semantic_observations_v1", "semantic_observation_count": len(semantic_events), "events": semantic_events})
    dump_yaml(out_dir / "analysis/cross_library_behavior_comparison.yaml", {"schema": "cross_library_behavior_comparison_v1", "behavior_categories_compared": True, "same_behavior_count": sum(1 for r in comparison_rows if r["same_behavior"]), "different_behavior_count": sum(1 for r in comparison_rows if r["different_behavior"]), "items": comparison_rows})
    dump_yaml(out_dir / "analysis/candidate_summary.yaml", {"schema": "crypto_roundtrip_candidate_summary_v1", "candidate_event_count": len(candidate_events), "candidate_rule": CANDIDATE_RULE, "confirmed_vulnerability_claim": False, "events": candidate_events})
    dump_yaml(out_dir / "validation/crypto_roundtrip_metamorphic_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

Small smoke roundtrip/metamorphic oracle campaign.

- selected source cases: {len(selected)}
- generated target cases: {len(generated)}
- compile success: {compile_success}
- compile failed: {compile_failed}
- run success: {run_success}
- run failed: {run_failed}
- roundtrip success: {event_counts['roundtrip_success_count']}
- roundtrip mismatch: {event_counts['roundtrip_mismatch_count']}
- semantic observations: {event_counts['semantic_observation_count']}
- normal reject: {event_counts['normal_reject_count']}
- candidate events: {event_counts['candidate_event_count']}
- quality status: {quality}

Candidate rule: {CANDIDATE_RULE}

No blocked targets, public target access, RPKI logic, external code vendoring, tools scripts, feedback-bank writes, pattern-bank writes, git add/commit/push, or vulnerability claims were used.
"""
    write_text(out_dir / "reports/crypto_roundtrip_metamorphic_oracle_v1_report.md", report)
    print(f"wrote {out_dir}")
    print(f"quality_status: {quality}")
    print(f"generated_case_count: {len(generated)}")
    print(f"candidate_event_count: {event_counts['candidate_event_count']}")


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
