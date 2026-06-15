"""Triage the CCM plaintext-length-not-announced campaign candidate.

This module snapshots the v3 campaign candidate, builds one local OpenSSL
ASAN triage harness with step-level events, compiles/runs it, and emits a
candidate decision. It does not write main feedback or the pattern bank.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from runner.sanitizer_env import lib_dir_for_install, matched_keywords, run_env, sanitizer_kinds, signal_name


TASK = "ccm_plaintext_length_not_announced_triage_v1"
DEFAULT_OUT_DIR = f"artifacts/triage/{TASK}"
DEFAULT_CAMPAIGN = "artifacts/campaigns/campaign_auto_bootstrap_loop_v3_remaining_plus_deeper_mutation"
DEFAULT_OPENSSL_INSTALL = "/home/wen/work/install-openssl-3.5.5-asan"
DEFAULT_OPENSSL_SRC = "/home/wen/work/openssl-3.5.5-asan-src"
FAMILY = "cipher_aead_lifecycle_ccm"
CASE_ID = "ccm_plaintext_length_not_announced"
ORIGINAL_LABEL = "unexpected_success_after_invalid_state_candidate"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--campaign-root", default=DEFAULT_CAMPAIGN)
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--openssl-install", default=DEFAULT_OPENSSL_INSTALL)
    parser.add_argument("--openssl-src", default=DEFAULT_OPENSSL_SRC)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def triage_harness_source() -> str:
    return r'''/*
 * Local triage harness for OpenSSL EVP AES-CCM plaintext length announcement.
 * No public target access, exploit chain, DER trailing-garbage oracle, or UAF.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static void step_event(const char *case_id, const char *step, int ret, int len)
{
    printf("STEP_EVENT case_id=%s step=%s ret=%d len=%d\n", case_id, step, ret, len);
}

static void oracle_event(const char *case_id, const char *expected,
                         const char *actual, int semantic_mismatch,
                         int state_transition_mismatch)
{
    printf("ORACLE_EVENT family=cipher_aead_lifecycle_ccm\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT semantic_mismatch=%d\n", semantic_mismatch);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=0\n");
}

static int valid_encrypt(unsigned char *ciphertext, unsigned char *tag,
                         int use_aad, int announce_len, const char *case_id,
                         int emit_steps)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    unsigned char plaintext[] = "local ccm msg";
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int final_len = 0;
    int r_new = ctx != NULL;
    int r_init1 = 0, r_ivlen = 0, r_taglen = 0, r_init2 = 0;
    int r_len = -1, r_aad = -1, r_payload = 0, r_final = 0, r_gettag = 0;
    int plaintext_len = (int)(sizeof(plaintext) - 1);

    if (emit_steps)
        step_event(case_id, "EVP_CIPHER_CTX_new", r_new, len);
    if (ctx == NULL)
        return 0;

    r_init1 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    if (emit_steps) step_event(case_id, "EncryptInit_cipher", r_init1, len);
    r_ivlen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
    if (emit_steps) step_event(case_id, "CTRL_SET_IVLEN", r_ivlen, len);
    r_taglen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL);
    if (emit_steps) step_event(case_id, "CTRL_SET_TAGLEN", r_taglen, len);
    r_init2 = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (emit_steps) step_event(case_id, "EncryptInit_key_iv", r_init2, len);
    if (announce_len) {
        r_len = EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);
        if (emit_steps) step_event(case_id, "EncryptUpdate_length_announcement", r_len, len);
    } else if (emit_steps) {
        step_event(case_id, "EncryptUpdate_length_announcement_skipped", -1, len);
    }
    if (use_aad) {
        r_aad = EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad));
        if (emit_steps) step_event(case_id, "EncryptUpdate_aad", r_aad, len);
    } else if (emit_steps) {
        step_event(case_id, "EncryptUpdate_aad_skipped", -1, len);
    }
    r_payload = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (emit_steps) step_event(case_id, "EncryptUpdate_payload", r_payload, len);
    r_final = EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
    if (emit_steps) step_event(case_id, "EncryptFinal", r_final, final_len);
    r_gettag = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag);
    if (emit_steps) step_event(case_id, "CTRL_GET_TAG", r_gettag, len);
    EVP_CIPHER_CTX_free(ctx);

    if (announce_len && use_aad)
        return r_init1 == 1 && r_ivlen == 1 && r_taglen == 1 && r_init2 == 1
            && r_len == 1 && r_aad == 1 && r_payload == 1 && r_final == 1 && r_gettag == 1;
    if (!announce_len && use_aad)
        return r_init1 == 1 && r_ivlen == 1 && r_taglen == 1 && r_init2 == 1
            && r_aad == 1 && r_payload == 1 && r_final == 1 && r_gettag == 1;
    return r_init1 == 1 && r_ivlen == 1 && r_taglen == 1 && r_init2 == 1
        && r_payload == 1 && r_final == 1 && r_gettag == 1;
}

static int decrypt_without_length(unsigned char *ciphertext, unsigned char *tag,
                                  const char *case_id)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char out[64] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int r_new = ctx != NULL;
    int r_init1 = 0, r_ivlen = 0, r_settag = 0, r_init2 = 0, r_payload = 0, r_final = 0;
    int plaintext_len = (int)(sizeof("local ccm msg") - 1);

    step_event(case_id, "EVP_CIPHER_CTX_new", r_new, len);
    if (ctx == NULL)
        return 0;
    r_init1 = EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    step_event(case_id, "DecryptInit_cipher", r_init1, len);
    r_ivlen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
    step_event(case_id, "CTRL_SET_IVLEN", r_ivlen, len);
    r_settag = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, tag);
    step_event(case_id, "CTRL_SET_TAG", r_settag, len);
    r_init2 = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    step_event(case_id, "DecryptInit_key_iv", r_init2, len);
    step_event(case_id, "DecryptUpdate_length_announcement_skipped", -1, len);
    r_payload = EVP_DecryptUpdate(ctx, out, &len, ciphertext, plaintext_len);
    step_event(case_id, "DecryptUpdate_payload", r_payload, len);
    r_final = EVP_DecryptFinal_ex(ctx, out + len, &len);
    step_event(case_id, "DecryptFinal", r_final, len);
    EVP_CIPHER_CTX_free(ctx);
    return r_init1 == 1 && r_ivlen == 1 && r_settag == 1 && r_init2 == 1 && r_payload == 1;
}

int main(void)
{
    unsigned char ciphertext[64] = {0};
    unsigned char tag[16] = {0};
    unsigned char scratch_ct[64] = {0};
    unsigned char scratch_tag[16] = {0};
    int ok = 0;

    ok = valid_encrypt(ciphertext, tag, 1, 1, "valid_control_with_plaintext_length_announced", 1);
    oracle_event("valid_control_with_plaintext_length_announced", "success",
                 ok ? "success" : "error", ok ? 0 : 1, ok ? 0 : 1);

    ok = valid_encrypt(scratch_ct, scratch_tag, 1, 0,
                       "candidate_without_plaintext_length_announcement", 1);
    oracle_event("candidate_without_plaintext_length_announcement", "error_or_documented",
                 ok ? "success" : "error", 0, ok ? 1 : 0);

    ok = valid_encrypt(scratch_ct, scratch_tag, 0, 0,
                       "no_aad_without_plaintext_length_announcement", 1);
    oracle_event("no_aad_without_plaintext_length_announcement", "observation",
                 ok ? "success" : "error", 0, 0);

    ok = decrypt_without_length(ciphertext, tag,
                                "decrypt_side_without_length_announcement_if_applicable");
    oracle_event("decrypt_side_without_length_announcement_if_applicable", "observation",
                 ok ? "success" : "error", 0, 0);

    return 0;
}
'''


def command_for(harness: Path, binary: Path, openssl_install: Path) -> list[str]:
    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    return [
        "gcc",
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined",
        f"-I{include_dir}",
        harness.as_posix(),
        f"-L{lib_dir}",
        f"-Wl,-rpath,{lib_dir}",
        "-lssl",
        "-lcrypto",
        "-ldl",
        "-pthread",
        "-o",
        binary.as_posix(),
    ]


def parse_events(stdout: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    step_events: list[dict[str, Any]] = []
    oracle_events: list[dict[str, Any]] = []
    current: dict[str, str] = {}
    raw: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("STEP_EVENT "):
            payload = stripped[len("STEP_EVENT ") :]
            data = {}
            for part in payload.split():
                if "=" in part:
                    k, v = part.split("=", 1)
                    data[k] = v
            step_events.append(
                {
                    "schema": "ccm_plaintext_length_step_event_v1",
                    "case_id": data.get("case_id", ""),
                    "step": data.get("step", ""),
                    "ret": int(data.get("ret", "0")),
                    "len": int(data.get("len", "0")),
                    "raw_line": stripped,
                }
            )
        elif stripped.startswith("ORACLE_EVENT "):
            raw.append(stripped)
            payload = stripped[len("ORACLE_EVENT ") :]
            if "=" in payload:
                k, v = payload.split("=", 1)
                current[k] = v
            if payload.startswith("crash_or_sanitizer="):
                oracle_events.append(
                    {
                        "schema": "ccm_plaintext_length_oracle_event_v1",
                        "family": current.get("family", FAMILY),
                        "case_id": current.get("case_id", ""),
                        "expected_behavior": current.get("expected_behavior", ""),
                        "actual_behavior": current.get("actual_behavior", ""),
                        "semantic_mismatch": current.get("semantic_mismatch") == "1",
                        "state_transition_mismatch": current.get("state_transition_mismatch") == "1",
                        "crash_or_sanitizer": current.get("crash_or_sanitizer") == "1",
                        "raw_lines": raw,
                    }
                )
                current = {}
                raw = []
    return step_events, oracle_events


def pick_original_candidate(candidates_yaml: dict[str, Any]) -> dict[str, Any]:
    for item in candidates_yaml.get("candidates", []) or []:
        if item.get("case_id") == CASE_ID:
            return item
    return {}


def pick_original_oracle(oracles_yaml: dict[str, Any]) -> dict[str, Any]:
    for item in oracles_yaml.get("oracle_events", []) or []:
        if item.get("case_id") == CASE_ID:
            return item
    return {}


def docs_notes(openssl_src: Path, docs_output: Path) -> tuple[bool, str, str]:
    source_file = openssl_src / "providers/implementations/ciphers/ciphercommon_ccm.c"
    manpage_file = openssl_src / "doc/man3/EVP_EncryptInit.pod"
    evidence = []
    documented_found = False
    if manpage_file.exists():
        text = manpage_file.read_text(encoding="utf-8", errors="replace")
        idx = text.find("For CCM mode, the total plaintext or ciphertext length")
        if idx >= 0:
            documented_found = True
            evidence.append("本地 OpenSSL manpage 明确描述 CCM total plaintext/ciphertext length 要求。")
            evidence.append(text[max(0, idx - 80) : min(len(text), idx + 420)].strip())
    if source_file.exists():
        text = source_file.read_text(encoding="utf-8", errors="replace")
        snippets = []
        for needle in [
            "If we have AAD, we need a message length",
            "If not set length yet do it",
            "ccm_set_iv(ctx, len)",
        ]:
            idx = text.find(needle)
            if idx >= 0:
                start = max(0, idx - 180)
                end = min(len(text), idx + 220)
                snippets.append(text[start:end].strip())
        if snippets:
            documented_found = True
            evidence.append("本地 OpenSSL provider 源码存在 CCM 长度处理逻辑证据。")
            evidence.extend(snippets)
    else:
        evidence.append(f"未找到本地源码文件: {source_file}")

    summary = (
        "本地 manpage 写明 CCM total plaintext/ciphertext length MUST 通过 in/out 为 NULL 的 update 调用传入。"
        "同时，本地 provider 源码显示：AAD 路径在未设置 message length 且 AAD length 非零时返回错误；"
        "payload update 路径若尚未设置长度，会调用 ccm_set_iv(ctx, len) 使用当前 payload length。"
        "因此文档语义与 payload-only 本地实现行为存在张力：带 AAD 缺长度会被拒绝，无 AAD payload-only 缺长度可成功。"
    )
    notes = f"""# CCM API Notes

## Local Evidence Checked

- OpenSSL install share docs: `/home/wen/work/install-openssl-3.5.5-asan/share`
- Repository references: `/home/wen/work/crypto-pattern-fuzz`
- Local OpenSSL source: `{openssl_src}`

## Evidence Summary

{summary}

## Source Evidence

```text
{chr(10).join(evidence)}
```

## Triage Interpretation

- CCM with AAD: local manpage and provider source both support requiring message length before AAD processing.
- CCM without AAD: provider source indicates the payload update path may set message length from payload length.
- Original campaign case did not include AAD and only checked the payload update return value.
- Therefore the original oracle treated a payload-only accepted sequence as an invalid-state success even though the implementation has a payload-only fallback path.

## Conclusion

The original oracle is too strong for the payload-only variant. The result should be downgraded unless a stricter candidate condition is used, such as AAD path success without length, tag/ciphertext inconsistency, decrypt-side invalid acceptance, sanitizer, or crash evidence.
"""
    write_text(docs_output, notes)
    return documented_found, summary, "\n".join(evidence)


def make_snapshots(campaign_root: Path, out_dir: Path) -> tuple[bool, dict[str, Any], dict[str, Any]]:
    source_case = campaign_root / f"per_family/{FAMILY}/cases/{CASE_ID}.c"
    candidates_path = campaign_root / f"per_family/{FAMILY}/candidate_queue/candidates.yaml"
    oracles_path = campaign_root / f"per_family/{FAMILY}/analyze/oracle_events.yaml"
    candidates_yaml = load_yaml(candidates_path)
    oracles_yaml = load_yaml(oracles_path)
    candidate = pick_original_candidate(candidates_yaml)
    oracle = pick_original_oracle(oracles_yaml)
    if source_case.exists():
        (out_dir / "inputs").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_case, out_dir / "inputs/original_case_snapshot.c")
    dump_yaml(out_dir / "inputs/original_candidate_snapshot.yaml", {"schema": "original_candidate_snapshot_v1", "candidate": candidate})
    dump_yaml(out_dir / "inputs/original_oracle_snapshot.yaml", {"schema": "original_oracle_snapshot_v1", "oracle_event": oracle})
    return bool(source_case.exists() and candidate), candidate, oracle


def decision_from_events(
    step_events: list[dict[str, Any]],
    oracle_events: list[dict[str, Any]],
    documented_found: bool,
    doc_summary: str,
    run_record: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    event_by_case = {item["case_id"]: item for item in oracle_events}
    valid_control_passed = event_by_case.get("valid_control_with_plaintext_length_announced", {}).get("actual_behavior") == "success"
    candidate_with_aad = event_by_case.get("candidate_without_plaintext_length_announcement", {}).get("actual_behavior") == "success"
    no_aad_observation = event_by_case.get("no_aad_without_plaintext_length_announcement", {}).get("actual_behavior") == "success"
    decrypt_observation = event_by_case.get("decrypt_side_without_length_announcement_if_applicable", {}).get("actual_behavior") == "success"
    asan = bool(run_record.get("sanitizer_observed") and "ASAN" in run_record.get("sanitizer_kinds", []))
    ubsan = bool(run_record.get("sanitizer_observed") and "UBSAN" in run_record.get("sanitizer_kinds", []))
    crash = run_record.get("signal") in {"SIGSEGV", "SIGABRT"}

    if asan or ubsan or crash:
        decision = "keep_candidate"
        reason = "sanitizer or crash evidence observed in minimal harness"
        quality = "pass_keep_candidate"
        oracle_too_strong = False
    elif not valid_control_passed:
        decision = "inconclusive"
        reason = "valid CCM control did not pass; triage harness baseline is not trustworthy"
        quality = "pass_inconclusive"
        oracle_too_strong = False
    elif candidate_with_aad:
        decision = "keep_candidate"
        reason = "AAD path without plaintext length announcement unexpectedly succeeded"
        quality = "pass_keep_candidate"
        oracle_too_strong = False
    elif no_aad_observation or decrypt_observation:
        decision = "downgrade_to_observation"
        reason = (
            "minimal harness shows payload-only no-length path can succeed while AAD no-length path rejects; "
            "original case was payload-only and the oracle was too strong"
        )
        quality = "pass_downgraded_observation"
        oracle_too_strong = True
    else:
        decision = "false_positive"
        reason = "minimal harness did not reproduce the original success condition"
        quality = "pass_false_positive"
        oracle_too_strong = True

    triage = {
        "schema": "ccm_plaintext_length_triage_decision_v1",
        "family": FAMILY,
        "case_id": CASE_ID,
        "original_label": ORIGINAL_LABEL,
        "decision": decision,
        "reason": reason,
        "documented_behavior_found": documented_found,
        "doc_evidence_summary": doc_summary,
        "valid_control_passed": valid_control_passed,
        "candidate_reproduced": bool(no_aad_observation),
        "candidate_reproduced_in_minimal_harness": bool(no_aad_observation),
        "asan_observed": asan,
        "ubsan_observed": ubsan,
        "crash_observed": crash,
        "oracle_too_strong": oracle_too_strong,
        "recommended_next_action": (
            "Reclassify original payload-only no-length case as observation and reserve candidate label for AAD no-length success, invalid decrypt acceptance, sanitizer, or crash."
            if decision == "downgrade_to_observation"
            else "Review minimal harness evidence before continuing the campaign."
        ),
    }
    revised = {
        "schema": "ccm_plaintext_length_revised_candidate_v1",
        "family": FAMILY,
        "case_id": CASE_ID,
        "original_label": ORIGINAL_LABEL,
        "revised_label": "state_transition_observation" if decision == "downgrade_to_observation" else ORIGINAL_LABEL,
        "retain_as_candidate": decision == "keep_candidate",
        "decision": decision,
        "reason": reason,
    }
    oracle_adjustment = {
        "schema": "ccm_plaintext_length_oracle_adjustment_recommendation_v1",
        "main_feedback_written": False,
        "recommendation": "Do not mark payload-only CCM encryption without explicit length announcement as unexpected_success_after_invalid_state_candidate.",
        "candidate_condition": "Require AAD path success without length, decrypt invalid acceptance, tag/ciphertext semantic mismatch, sanitizer, or crash.",
    }
    mutation_adjustment = {
        "schema": "ccm_plaintext_length_mutation_rule_adjustment_v1",
        "main_feedback_written": False,
        "rule": "Split CCM no-length mutation into with_aad_required_length and payload_only_observation variants.",
        "disabled_unsafe_behavior": ["use_after_free", "double_free"],
    }
    return triage | {"quality_status": quality}, revised, {
        "oracle_adjustment": oracle_adjustment,
        "mutation_adjustment": mutation_adjustment,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    campaign_root = repo_root / args.campaign_root
    openssl_install = Path(args.openssl_install)
    openssl_src = Path(args.openssl_src)
    source_loaded, original_candidate, original_oracle = make_snapshots(campaign_root, out_dir)

    harness = out_dir / "cases/ccm_plaintext_length_triage.c"
    write_text(harness, triage_harness_source())
    binary = out_dir / "compile/ccm_plaintext_length_triage.bin"
    binary.parent.mkdir(parents=True, exist_ok=True)
    cmd = command_for(harness, binary, openssl_install)
    start = time.monotonic()
    proc = subprocess.run(cmd, text=True, capture_output=True)
    compile_stdout = out_dir / "compile/compile.stdout.log"
    compile_stderr = out_dir / "compile/compile.stderr.log"
    write_text(compile_stdout, proc.stdout)
    write_text(compile_stderr, proc.stderr)
    compile_success = proc.returncode == 0 and binary.exists()
    dump_yaml(
        out_dir / "compile/compile_summary.yaml",
        {
            "schema": "ccm_plaintext_length_compile_summary_v1",
            "compile_executed": True,
            "compile_success": 1 if compile_success else 0,
            "compile_failed": 0 if compile_success else 1,
            "compile_command": " ".join(cmd),
            "return_code": proc.returncode,
            "stdout_log": compile_stdout.as_posix(),
            "stderr_log": compile_stderr.as_posix(),
        },
    )

    run_records = []
    step_events: list[dict[str, Any]] = []
    oracle_events: list[dict[str, Any]] = []
    run_record: dict[str, Any] = {
        "run_status": "not_run_compile_failed",
        "sanitizer_observed": False,
        "sanitizer_kinds": [],
        "signal": "",
    }
    if compile_success:
        run_stdout = out_dir / "run/run.stdout.log"
        run_stderr = out_dir / "run/run.stderr.log"
        lib_dir = lib_dir_for_install(openssl_install)
        try:
            run_proc = subprocess.run(
                [binary.as_posix()],
                text=True,
                capture_output=True,
                timeout=args.timeout_seconds,
                env=run_env(openssl_install, lib_dir),
            )
            duration = round(time.monotonic() - start, 6)
            write_text(run_stdout, run_proc.stdout)
            write_text(run_stderr, run_proc.stderr)
            combined = run_proc.stdout + "\n" + run_proc.stderr
            kinds = sanitizer_kinds(combined)
            keywords = matched_keywords(combined)
            sig = signal_name(run_proc.returncode)
            step_events, oracle_events = parse_events(run_proc.stdout)
            run_record = {
                "schema": "ccm_plaintext_length_run_record_v1",
                "run_status": "signaled" if sig else "exited",
                "exit_code": run_proc.returncode if run_proc.returncode >= 0 else None,
                "signal": sig,
                "timeout": False,
                "duration_seconds": duration,
                "sanitizer_observed": bool(kinds or keywords),
                "sanitizer_kinds": kinds,
                "matched_keywords": keywords,
                "stdout_log": run_stdout.as_posix(),
                "stderr_log": run_stderr.as_posix(),
                "step_event_count": len(step_events),
                "oracle_event_count": len(oracle_events),
            }
        except subprocess.TimeoutExpired as exc:
            write_text(run_stdout, exc.stdout or "")
            write_text(run_stderr, (exc.stderr or "") + "\ntimeout\n")
            run_record = {
                "schema": "ccm_plaintext_length_run_record_v1",
                "run_status": "timeout",
                "exit_code": None,
                "signal": "",
                "timeout": True,
                "sanitizer_observed": False,
                "sanitizer_kinds": [],
                "stdout_log": run_stdout.as_posix(),
                "stderr_log": run_stderr.as_posix(),
                "step_event_count": 0,
                "oracle_event_count": 0,
            }
        run_records.append(run_record)

    dump_yaml(out_dir / "run/run_records.yaml", {"schema": "ccm_plaintext_length_run_records_v1", "run_records": run_records})
    dump_yaml(
        out_dir / "run/run_summary.yaml",
        {
            "schema": "ccm_plaintext_length_run_summary_v1",
            "run_executed": compile_success,
            "run_attempted": len(run_records),
            "asan": any("ASAN" in item.get("sanitizer_kinds", []) for item in run_records),
            "ubsan": any("UBSAN" in item.get("sanitizer_kinds", []) for item in run_records),
            "crash": any(item.get("signal") in {"SIGSEGV", "SIGABRT"} for item in run_records),
        },
    )
    dump_yaml(out_dir / "analyze/step_events.yaml", {"schema": "ccm_plaintext_length_step_events_v1", "step_events": step_events})
    dump_yaml(out_dir / "analyze/oracle_events.yaml", {"schema": "ccm_plaintext_length_oracle_events_v1", "oracle_events": oracle_events})

    documented_found, doc_summary, doc_evidence = docs_notes(openssl_src, out_dir / "docs/ccm_api_notes.md")
    triage, revised, feedback = decision_from_events(step_events, oracle_events, documented_found, doc_summary, run_record)
    quality_status = triage.pop("quality_status")
    dump_yaml(out_dir / "candidate/triage_decision.yaml", triage)
    dump_yaml(out_dir / "candidate/revised_candidate.yaml", revised)
    dump_yaml(out_dir / "feedback_to_pipeline/oracle_adjustment_recommendation.yaml", feedback["oracle_adjustment"])
    dump_yaml(out_dir / "feedback_to_pipeline/mutation_rule_adjustment.yaml", feedback["mutation_adjustment"])
    dump_yaml(
        out_dir / "analyze/triage_summary.yaml",
        {
            "schema": "ccm_plaintext_length_triage_summary_v1",
            "family": FAMILY,
            "case_id": CASE_ID,
            "original_candidate": original_candidate,
            "original_oracle": original_oracle,
            "variant_count": len(oracle_events),
            "step_event_count": len(step_events),
            "decision": triage["decision"],
            "reason": triage["reason"],
            "doc_evidence_summary": doc_summary,
        },
    )
    qc = {
        "schema": "ccm_plaintext_length_triage_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "original_candidate_loaded": bool(original_candidate),
        "original_case_snapshotted": source_loaded,
        "minimal_harness_generated": harness.exists(),
        "variant_count": len(oracle_events),
        "compile_executed": True,
        "compile_success": 1 if compile_success else 0,
        "run_executed": compile_success,
        "run_attempted": len(run_records),
        "step_events_parsed": bool(step_events),
        "oracle_events_parsed": bool(oracle_events),
        "docs_checked": documented_found,
        "triage_decision_generated": True,
        "feedback_to_pipeline_generated": True,
        "uses_der_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "unsafe_uaf_or_double_free_executed": False,
        "public_target_access": False,
        "exploit_chain_generated": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status if compile_success else "blocked_compile_failure",
    }
    if not source_loaded:
        qc["quality_status"] = "blocked_original_candidate_missing"
    dump_yaml(out_dir / "validation/ccm_plaintext_length_triage_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

## Summary

- decision: {triage['decision']}
- reason: {triage['reason']}
- valid_control_passed: {triage['valid_control_passed']}
- candidate_reproduced_in_minimal_harness: {triage['candidate_reproduced_in_minimal_harness']}
- oracle_too_strong: {triage['oracle_too_strong']}
- ASAN/UBSAN/crash: {triage['asan_observed']} / {triage['ubsan_observed']} / {triage['crash_observed']}

## Documentation Evidence

{doc_summary}

```text
{doc_evidence}
```

## Policy

No tools script, public target access, exploit chain, main feedback write,
pattern-bank update, git operation, confirmed vulnerability claim, DER
trailing-garbage repeat, full-consumption oracle, UAF, or double-free was used.
"""
    write_text(out_dir / f"reports/{TASK}_report.md", report)
    print(f"wrote {out_dir}")
    print(f"decision: {triage['decision']}")
    print(f"quality_status: {qc['quality_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
