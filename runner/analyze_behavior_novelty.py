"""Behavior novelty analyzer v0.

This module clusters existing runner JSONL and app-level command matrices into
coarse discovery labels. It is intentionally conservative: nonzero harness exits
are not treated as crashes unless sanitizer or SEGV evidence is present.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


CRASH_PATTERNS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "SEGV",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "runtime error:",
)


def _read_jsonl(path: Optional[Path]) -> Iterable[Dict[str, Any]]:
    if not path:
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _read_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "accepted"}


def _text_tags(text: str) -> List[str]:
    tags: List[str] = []
    lowered = text.lower()
    if "-----begin" in lowered:
        tags.append("pem_object")
    if "fingerprint=" in lowered or "sha1 fingerprint" in lowered:
        tags.append("fingerprint")
    if "public key" in lowered or "-----begin public key" in lowered:
        tags.append("public_key")
    if "certificate request" in lowered:
        tags.append("csr_text")
    if "certificate revocation list" in lowered or "last update" in lowered:
        tags.append("crl_text")
    if "[bug]" in lowered:
        tags.append("oracle_bug_marker")
    if "[ok]" in lowered:
        tags.append("oracle_ok_marker")
    return tags


def _sanitizer_signal(exit_code: Optional[int], stdout: str, stderr: str) -> str:
    combined = f"{stdout}\n{stderr}"
    for pattern in CRASH_PATTERNS:
        if pattern in combined:
            return pattern
    if exit_code == 139:
        return "exit_139_segv"
    return ""


def _extract_int(pattern: str, text: str) -> Optional[int]:
    match = re.search(pattern, text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _case_id_from_source(source: str) -> str:
    path = Path(source)
    for part in reversed(path.parts):
        if part.startswith("mac_lifecycle_"):
            return part
    stem = path.stem
    match = re.search(r"(mac_lifecycle_\d+)", stem)
    return match.group(1) if match else stem


def _find_manifest_for_source(source: str, manifest_by_case_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    path = Path(source)
    adjacent = path.parent / "render_matrix_case_manifest.yaml"
    if adjacent.exists():
        try:
            return _read_yaml(adjacent)
        except OSError:
            pass
    case_id = _case_id_from_source(source)
    return manifest_by_case_id.get(case_id, {})


def _index_manifests(root: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if not root:
        return {}
    manifests: Dict[str, Dict[str, Any]] = {}
    if not root.exists():
        return manifests
    for path in root.rglob("render_matrix_case_manifest.yaml"):
        try:
            data = _read_yaml(path)
        except OSError:
            continue
        case_id = str(data.get("case_id") or path.parent.name)
        if case_id:
            manifests[case_id] = data
    return manifests


def _skipped_manifest_paths(root: Optional[Path]) -> List[Path]:
    if not root:
        return []
    candidates = [
        root / "render_matrix_skipped_cases.yaml",
        root.parent / "render_matrix_skipped_cases.yaml",
        root.parent / "expanded_cross_templates" / "render_matrix_skipped_cases.yaml",
    ]
    seen = set()
    paths: List[Path] = []
    for path in candidates:
        if path.exists() and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _has_nonzero_failure_outlen(stdout: str) -> bool:
    for match in re.finditer(r"returned\s+0\s+outl=(\d+)", stdout):
        try:
            if int(match.group(1)) != 0:
                return True
        except ValueError:
            continue
    return False


def _openssl_second_final_success(stdout: str) -> bool:
    return bool(re.search(r"second\s+EVP_MAC_final\s+returned\s+1\s+outl=16", stdout))


def _mbedtls_second_finish_reject(stdout: str) -> bool:
    return bool(re.search(r"second\s+psa_mac_sign_finish\s+status=-(?:\d+)", stdout))


def _expected_has(expected_candidate_types: List[Any], value: str) -> bool:
    return value in {str(item) for item in expected_candidate_types}


def _openssl_cmac_update_after_final_accept(stdout: str) -> bool:
    return (
        "second EVP_MAC_update after final returned 1" in stdout
        or "update after final accepted or unexpected state" in stdout
    )


def _openssl_cmac_third_final_accept(stdout: str) -> bool:
    return bool(
        re.search(r"second\s+EVP_MAC_final\s+returned\s+1\s+outl=\d+", stdout)
        and re.search(r"third\s+EVP_MAC_final\s+returned\s+1\s+outl=\d+", stdout)
    )


def _openssl_cmac_update_after_second_final_accept(stdout: str) -> bool:
    return (
        "EVP_MAC_update after second final returned 1" in stdout
        or "update after second final accepted or unexpected state" in stdout
    )


def _mbedtls_update_after_finish_reject(stdout: str) -> bool:
    return bool(re.search(r"psa_mac_update after finish\s+status=-(?:\d+)", stdout))


def _mbedtls_update_after_second_finish_reject(stdout: str) -> bool:
    return bool(re.search(r"psa_mac_update after second finish\s+status=-(?:\d+)", stdout))


def _classify_runner_case(obj: Dict[str, Any]) -> Tuple[str, str]:
    status = str(obj.get("status") or obj.get("raw_status") or "")
    verdict = str(obj.get("verdict") or "")
    stdout = str((obj.get("run") or {}).get("stdout") or obj.get("stdout") or "")
    stderr = str((obj.get("run") or {}).get("stderr") or obj.get("stderr") or "")
    exit_code = (obj.get("run") or {}).get("returncode", obj.get("exit_code"))
    compile_stderr = str((obj.get("compile") or {}).get("stderr") or "")
    sanitizer = _sanitizer_signal(exit_code, stdout, stderr)

    if sanitizer:
        return "crash_candidate", f"crash signal: {sanitizer}"
    if "compile_error" in status or (obj.get("compile") or {}).get("returncode") not in (None, 0):
        if "undefined reference" in compile_stderr or "ld:" in compile_stderr:
            return "harness_error", "link-like compile failure"
        return "harness_error", "compile failure"
    if "render_error" in status or "template_render_error" in status:
        return "harness_error", "template render failure"
    if verdict in {"safe_reject_behavior", "migrated_safe"}:
        return "safe_negative", verdict
    if verdict in {"bug_candidate", "migrated_bug_candidate"}:
        if "consumed_len" in stdout and "der_len" in stdout:
            return "low_level_d2i_prefix_parse", "pointer-consumption oracle"
        return "semantic_candidate", verdict
    if "normal_behavior_needs_triage" in verdict or "triage" in verdict:
        return "unknown_needs_triage", verdict
    if status == "run_ok":
        return "safe_negative", "run_ok without novelty marker"
    return "unknown_needs_triage", status or verdict or "unclassified"


def _classify_manifest_runner_case(
    obj: Dict[str, Any], manifest: Dict[str, Any]
) -> Tuple[str, str, Dict[str, Any]]:
    stdout = str((obj.get("run") or {}).get("stdout") or obj.get("stdout") or "")
    stderr = str((obj.get("run") or {}).get("stderr") or obj.get("stderr") or "")
    exit_code = (obj.get("run") or {}).get("returncode", obj.get("exit_code"))
    sanitizer = _sanitizer_signal(exit_code, stdout, stderr)
    if sanitizer:
        return "crash_candidate", f"crash signal: {sanitizer}", {"sanitizer_signal": sanitizer}

    unsupported_dimensions = manifest.get("unsupported_dimensions") or []
    expected_candidate_types = list(manifest.get("expected_candidate_types") or [])
    signature_mutation = str(manifest.get("signature_mutation") or "")
    verify_api = str(manifest.get("verify_api") or "")
    if signature_mutation or verify_api:
        extra = {
            "case_id": str(manifest.get("case_id") or ""),
            "verify_api": verify_api,
            "key_type": str(manifest.get("key_type") or ""),
            "signature_mutation": signature_mutation,
            "digest_mutation": str(manifest.get("digest_mutation") or ""),
            "key_mutation": str(manifest.get("key_mutation") or ""),
            "padding_mutation": str(manifest.get("padding_mutation") or ""),
            "expected_candidate_types": expected_candidate_types,
            "unsupported_dimensions": unsupported_dimensions,
            "needs_doc_review": False,
            "follow_up": "",
        }
        if unsupported_dimensions or manifest.get("unsupported_combo") or manifest.get("skipped"):
            return "projection_limitation", "unsupported PKEY verify projection", extra
        if "[BUG] unexpected verification success" in stdout:
            extra["follow_up"] = "minimize invalid verification material and confirm this is not harness misuse"
            return "unexpected_success_candidate", "invalid PKEY verification material was accepted", extra
        if "[SAFE] rejected invalid signature" in stdout:
            return "safe_negative", "invalid PKEY verification material was rejected", extra
        if "[OK] baseline valid signature accepted" in stdout:
            return "safe_negative", "baseline valid PKEY signature was accepted", extra
        if "HARNESS_ERROR:" in stdout or "HARNESS_ERROR:" in stderr:
            return "harness_error", "controlled PKEY verify harness setup failed", extra
        if "[TRIAGE]" in stdout:
            return "unknown_needs_triage", "controlled PKEY verify case needs triage", extra

    lifecycle = str(manifest.get("lifecycle_sequence") or "")
    mac_algorithm = str(manifest.get("mac_algorithm") or "")
    digest_or_cipher = str(manifest.get("digest_or_cipher") or "")
    library = str(obj.get("library") or "")
    extra = {
        "case_id": str(manifest.get("case_id") or ""),
        "mac_algorithm": mac_algorithm,
        "digest_or_cipher": digest_or_cipher,
        "lifecycle_sequence": lifecycle,
        "expected_candidate_types": expected_candidate_types,
        "unsupported_dimensions": unsupported_dimensions,
        "needs_doc_review": False,
        "follow_up": "",
    }

    if unsupported_dimensions or manifest.get("unsupported_combo") or manifest.get("skipped"):
        return "projection_limitation", "unsupported MAC lifecycle projection", extra

    if mac_algorithm == "HMAC" and _has_nonzero_failure_outlen(stdout):
        return "failure_path_output_state_triage", "HMAC failure path left nonzero outl", extra

    if library == "openssl" and mac_algorithm == "CMAC" and digest_or_cipher.startswith("AES-"):
        if lifecycle == "update_after_final" and _openssl_cmac_update_after_final_accept(stdout):
            extra["needs_doc_review"] = True
            extra["follow_up"] = "check update-after-final and final-after-update behavior"
            return (
                "lifecycle_semantic_divergence_candidate",
                "OpenSSL CMAC accepted update after final; requires documentation review",
                extra,
            )
        if lifecycle == "third_final" and _openssl_cmac_third_final_accept(stdout):
            extra["needs_doc_review"] = True
            extra["follow_up"] = "check whether OpenSSL CMAC repeated final is documented legacy semantics"
            if _expected_has(expected_candidate_types, "allowed_legacy_semantics"):
                return (
                    "allowed_legacy_semantics",
                    "OpenSSL CMAC repeated final matched documented allowed legacy semantics",
                    extra,
                )
            return (
                "allowed_legacy_semantics_needs_review",
                "OpenSSL CMAC repeated final succeeded; documentation review needed",
                extra,
            )
        if (
            lifecycle == "update_after_second_final"
            and _openssl_cmac_update_after_second_final_accept(stdout)
        ):
            extra["needs_doc_review"] = True
            extra["follow_up"] = "check update-after-second-final continuation behavior"
            return (
                "lifecycle_semantic_divergence_candidate",
                "OpenSSL CMAC accepted update after second final; requires documentation review",
                extra,
            )

    if "[OK]" in stdout:
        if "safe_reject_projection" in stdout or "safe_negative" in expected_candidate_types:
            return "safe_negative", "manifest-backed safe rejection", extra
        if _expected_has(expected_candidate_types, "allowed_legacy_semantics"):
            return "allowed_legacy_semantics", "manifest-backed allowed lifecycle behavior", extra
        return "safe_negative", "manifest-backed OK marker", extra

    if _expected_has(expected_candidate_types, "allowed_legacy_semantics_needs_review"):
        extra["needs_doc_review"] = True
        return (
            "allowed_legacy_semantics_needs_review",
            "allowed legacy class produced non-OK behavior",
            extra,
        )
    if _expected_has(expected_candidate_types, "allowed_legacy_semantics"):
        return "allowed_legacy_semantics", "manifest-backed allowed lifecycle behavior", extra
    return _classify_runner_case(obj)[0], "manifest present but no MAC-specific rule matched", extra


def _command_has_issue_grade_output(row: Dict[str, Any]) -> bool:
    name = str(row.get("command_name") or "").lower()
    command = str(row.get("command") or "").lower()
    if any(token in name for token in ("fingerprint", "export", "convert", "pubout", "pubkey", "text")):
        return True
    if any(token in command for token in ("-fingerprint", "-outform pem", "-pubout", "-pubkey", "-text")):
        return True
    return _bool(row.get("output_file_nonempty")) or _bool(row.get("stdout_nonempty"))


def _read_command_rows(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _classify_command_rows(rows: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    groups: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        groups[(str(row.get("input_kind") or ""), str(row.get("command_name") or ""))][
            str(row.get("input_case") or "")
        ] = row

    group_classes: Dict[Tuple[str, str], str] = {}
    for key, cases in groups.items():
        baseline = cases.get("baseline")
        tail = cases.get("tail")
        malformed = cases.get("malformed_only")
        baseline_ok = bool(baseline) and _bool(baseline.get("accepted", baseline.get("accepted_rejected")))
        tail_ok = bool(tail) and _bool(tail.get("accepted", tail.get("accepted_rejected")))
        malformed_rejected = bool(malformed) and not _bool(
            malformed.get("accepted", malformed.get("accepted_rejected"))
        )
        if baseline_ok and tail_ok and malformed_rejected:
            if tail and _command_has_issue_grade_output(tail):
                group_classes[key] = "real_app_level_validation_gap_candidate"
            else:
                group_classes[key] = "app_level_accepts_valid_prefix_with_malformed_tail"
        elif tail_ok:
            group_classes[key] = "app_command_accepts_malformed_tail"
        elif baseline_ok and malformed_rejected:
            group_classes[key] = "safe_negative"
        else:
            group_classes[key] = "unknown_needs_triage"
    return group_classes


def _case_from_command_row(
    row: Dict[str, Any], artifact: str, group_class: str
) -> Dict[str, Any]:
    stdout_tags = ["stdout_nonempty"] if _bool(row.get("stdout_nonempty")) else []
    stderr_tags = ["stderr_nonempty"] if _bool(row.get("stderr_nonempty")) else []
    if row.get("stderr_excerpt"):
        stderr_tags.extend(_text_tags(str(row.get("stderr_excerpt"))))
    input_case = str(row.get("input_case") or "")
    row_verdict = str(row.get("verdict") or "")
    if input_case == "tail" and group_class == "real_app_level_validation_gap_candidate":
        verdict = group_class
    elif input_case == "tail" and group_class == "app_level_accepts_valid_prefix_with_malformed_tail":
        verdict = group_class
    elif row_verdict:
        verdict = row_verdict
    else:
        verdict = group_class
    return {
        "case_id": str(row.get("command_id") or ""),
        "artifact": artifact,
        "library": "openssl",
        "api_or_command": str(row.get("command_name") or row.get("command") or ""),
        "input_kind": str(row.get("input_kind") or ""),
        "mutation": input_case,
        "exit_code": int(row.get("exit_code") or 0),
        "verdict": verdict,
        "migration_verdict": "",
        "stdout_tags": stdout_tags,
        "stderr_tags": stderr_tags,
        "sanitizer_signal": "",
        "consumed_len": None,
        "trailing_len": None,
        "caller_accept": _bool(row.get("accepted", row.get("accepted_rejected"))),
        "output_file_created": _bool(row.get("output_file_created")),
        "output_file_nonempty": _bool(row.get("output_file_nonempty")),
    }


def _case_from_runner_obj(
    obj: Dict[str, Any], artifact: str, manifest: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    stdout = str((obj.get("run") or {}).get("stdout") or obj.get("stdout") or "")
    stderr = str((obj.get("run") or {}).get("stderr") or obj.get("stderr") or "")
    exit_code = (obj.get("run") or {}).get("returncode", obj.get("exit_code"))
    reason = ""
    manifest_extra: Dict[str, Any] = {}
    if manifest:
        classification, reason, manifest_extra = _classify_manifest_runner_case(obj, manifest)
    else:
        classification, reason = _classify_runner_case(obj)
    consumed_len = _extract_int(r"consumed_len=(\d+)", stdout)
    der_len = _extract_int(r"der_len=(\d+)", stdout)
    trailing_len = None
    if consumed_len is not None and der_len is not None:
        trailing_len = max(der_len - consumed_len, 0)
    case_id = str(manifest_extra.get("case_id") or _case_id_from_source(str(obj.get("relative_source") or obj.get("source") or "")))
    case = {
        "case_id": case_id,
        "artifact": artifact,
        "library": str(obj.get("library") or ""),
        "api_or_command": str(obj.get("target_api") or (obj.get("template") or {}).get("target_api") or ""),
        "input_kind": str((obj.get("mutation_mapping") or {}).get("[DER_KIND]") or ""),
        "mutation": str((obj.get("mutation_mapping") or {}).get("[TRAILING_GARBAGE_BYTES]") or ""),
        "exit_code": exit_code,
        "verdict": classification,
        "migration_verdict": str(obj.get("migration_verdict") or ""),
        "stdout_tags": _text_tags(stdout),
        "stderr_tags": _text_tags(stderr),
        "sanitizer_signal": _sanitizer_signal(exit_code, stdout, stderr),
        "consumed_len": consumed_len,
        "trailing_len": trailing_len,
        "caller_accept": classification not in {"safe_negative", "harness_error"},
        "output_file_created": False,
        "output_file_nonempty": False,
        "reason": reason,
        "_stdout": stdout,
    }
    for key in (
        "mac_algorithm",
        "digest_or_cipher",
        "lifecycle_sequence",
        "expected_candidate_types",
        "unsupported_dimensions",
        "needs_doc_review",
        "follow_up",
    ):
        if key in manifest_extra:
            case[key] = manifest_extra[key]
    return case


def _case_from_skipped_manifest(manifest: Dict[str, Any], artifact: str) -> Dict[str, Any]:
    return {
        "case_id": str(manifest.get("case_id") or ""),
        "artifact": artifact,
        "library": "",
        "api_or_command": "",
        "input_kind": "",
        "mutation": str(manifest.get("lifecycle_sequence") or ""),
        "exit_code": None,
        "verdict": "projection_limitation",
        "migration_verdict": "",
        "stdout_tags": [],
        "stderr_tags": [],
        "sanitizer_signal": "",
        "consumed_len": None,
        "trailing_len": None,
        "caller_accept": False,
        "output_file_created": False,
        "output_file_nonempty": False,
        "mac_algorithm": str(manifest.get("mac_algorithm") or ""),
        "digest_or_cipher": str(manifest.get("digest_or_cipher") or ""),
        "lifecycle_sequence": str(manifest.get("lifecycle_sequence") or ""),
        "expected_candidate_types": list(manifest.get("expected_candidate_types") or ["projection_limitation"]),
        "unsupported_dimensions": manifest.get("unsupported_dimensions") or [],
        "needs_doc_review": False,
        "reason": "skipped render-matrix case: unsupported projection",
    }


def _refine_mac_lifecycle_pairs(cases: List[Dict[str, Any]]) -> None:
    grouped: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for case in cases:
        case_id = str(case.get("case_id") or "")
        library = str(case.get("library") or "")
        if case_id and library:
            grouped[case_id][library] = case

    for pair in grouped.values():
        openssl = pair.get("openssl")
        mbedtls = pair.get("mbedtls")
        if not openssl or not mbedtls:
            continue
        lifecycle = str(openssl.get("lifecycle_sequence") or "")
        openssl_stdout = str(openssl.get("_stdout") or "")
        mbedtls_stdout = str(mbedtls.get("_stdout") or "")
        if openssl.get("mac_algorithm") != "CMAC":
            continue
        if not str(openssl.get("digest_or_cipher") or "").startswith("AES-"):
            continue
        if lifecycle in {"setup_final_final", "setup_update_final_final"}:
            peer_rejects = (
                _openssl_second_final_success(openssl_stdout)
                and _mbedtls_second_finish_reject(mbedtls_stdout)
            )
            if not peer_rejects:
                continue
            openssl["verdict"] = "lifecycle_semantic_divergence_candidate"
            openssl["needs_doc_review"] = True
            openssl["reason"] = "OpenSSL CMAC second final succeeded while mbedTLS PSA rejected second finish"
            openssl["follow_up"] = "check repeated-final behavior against OpenSSL documentation"
            openssl["peer_library"] = "mbedtls"
            openssl["peer_verdict"] = str(mbedtls.get("verdict") or "")
            mbedtls["verdict"] = "safe_negative"
            mbedtls["reason"] = "mBedTLS PSA rejected repeated finish in CMAC double-final pair"
            continue
        if lifecycle == "update_after_final":
            peer_rejects = (
                _openssl_cmac_update_after_final_accept(openssl_stdout)
                and _mbedtls_update_after_finish_reject(mbedtls_stdout)
            )
            if peer_rejects:
                openssl["verdict"] = "lifecycle_semantic_divergence_candidate"
                openssl["needs_doc_review"] = True
                openssl["reason"] = "OpenSSL CMAC accepted update after final while mbedTLS PSA rejected update after finish"
                openssl["follow_up"] = "check update-after-final and final-after-update behavior"
                openssl["peer_library"] = "mbedtls"
                openssl["peer_verdict"] = str(mbedtls.get("verdict") or "")
                mbedtls["verdict"] = "safe_negative"
                mbedtls["reason"] = "mBedTLS PSA rejected update after finish in CMAC lifecycle pair"
            continue
        if lifecycle == "third_final":
            peer_rejects = (
                _openssl_cmac_third_final_accept(openssl_stdout)
                and _mbedtls_second_finish_reject(mbedtls_stdout)
            )
            if peer_rejects:
                openssl["verdict"] = "allowed_legacy_semantics_needs_review"
                openssl["needs_doc_review"] = True
                openssl["reason"] = "OpenSSL CMAC repeated final succeeded while mbedTLS PSA rejected repeated finish"
                openssl["follow_up"] = "check whether OpenSSL CMAC repeated final is documented legacy semantics"
                openssl["peer_library"] = "mbedtls"
                openssl["peer_verdict"] = str(mbedtls.get("verdict") or "")
                mbedtls["verdict"] = "safe_negative"
                mbedtls["reason"] = "mBedTLS PSA rejected repeated finish in CMAC lifecycle pair"
            continue
        if lifecycle == "update_after_second_final":
            peer_rejects = (
                _openssl_cmac_update_after_second_final_accept(openssl_stdout)
                and _mbedtls_update_after_second_finish_reject(mbedtls_stdout)
            )
            if peer_rejects:
                openssl["verdict"] = "lifecycle_semantic_divergence_candidate"
                openssl["needs_doc_review"] = True
                openssl["reason"] = "OpenSSL CMAC accepted update after second final while mbedTLS PSA rejected update after second finish"
                openssl["follow_up"] = "check update-after-second-final continuation behavior"
                openssl["peer_library"] = "mbedtls"
                openssl["peer_verdict"] = str(mbedtls.get("verdict") or "")
                mbedtls["verdict"] = "safe_negative"
                mbedtls["reason"] = "mBedTLS PSA rejected update after second finish in CMAC lifecycle pair"


def analyze(args: argparse.Namespace) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    cases: List[Dict[str, Any]] = []
    manifest_by_case_id = _index_manifests(args.case_manifest_root)

    verdict_by_case: Dict[str, Dict[str, Any]] = {}
    if args.verdicts_jsonl:
        for obj in _read_jsonl(args.verdicts_jsonl):
            key = str(obj.get("relative_source") or obj.get("source") or "")
            if key:
                verdict_by_case[key] = obj

    if args.run_jsonl:
        for obj in _read_jsonl(args.run_jsonl):
            key = str(obj.get("relative_source") or obj.get("source") or "")
            manifest = _find_manifest_for_source(
                str(obj.get("source") or obj.get("relative_source") or ""), manifest_by_case_id
            )
            if key and key in verdict_by_case:
                merged = dict(obj)
                verdict_obj = verdict_by_case[key]
                for field in ("verdict", "migration_verdict", "reason", "raw_status"):
                    if field in verdict_obj:
                        merged[field] = verdict_obj[field]
                cases.append(_case_from_runner_obj(merged, str(args.run_jsonl), manifest))
            else:
                cases.append(_case_from_runner_obj(obj, str(args.run_jsonl), manifest))
    elif args.verdicts_jsonl:
        for obj in verdict_by_case.values():
            manifest = _find_manifest_for_source(
                str(obj.get("source") or obj.get("relative_source") or ""), manifest_by_case_id
            )
            cases.append(_case_from_runner_obj(obj, str(args.verdicts_jsonl), manifest))

    if args.command_matrix_csv:
        rows = _read_command_rows(args.command_matrix_csv)
        group_classes = _classify_command_rows(rows)
        for row in rows:
            key = (str(row.get("input_kind") or ""), str(row.get("command_name") or ""))
            cases.append(_case_from_command_row(row, str(args.command_matrix_csv), group_classes[key]))

    if args.case_manifest_root:
        for skipped_path in _skipped_manifest_paths(args.case_manifest_root):
            skipped = _read_yaml(skipped_path).get("skipped_cases") or []
            if isinstance(skipped, list):
                for manifest in skipped:
                    if isinstance(manifest, dict):
                        cases.append(_case_from_skipped_manifest(manifest, str(skipped_path)))

    _refine_mac_lifecycle_pairs(cases)
    for case in cases:
        case.pop("_stdout", None)

    verdict_counts = Counter(str(case.get("verdict") or "unknown_needs_triage") for case in cases)
    summary = {
        "inputs": {
            "run_jsonl": str(args.run_jsonl) if args.run_jsonl else "",
            "verdicts_jsonl": str(args.verdicts_jsonl) if args.verdicts_jsonl else "",
            "command_matrix_csv": str(args.command_matrix_csv) if args.command_matrix_csv else "",
            "case_manifest_root": str(args.case_manifest_root) if args.case_manifest_root else "",
        },
        "total_cases": len(cases),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "has_crash_candidate": verdict_counts.get("crash_candidate", 0) > 0,
        "has_real_app_level_validation_gap_candidate": verdict_counts.get(
            "real_app_level_validation_gap_candidate", 0
        )
        > 0,
    }
    return summary, cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze behavior novelty from existing results.")
    parser.add_argument("--run-jsonl", type=Path)
    parser.add_argument("--verdicts-jsonl", type=Path)
    parser.add_argument("--command-matrix-csv", type=Path)
    parser.add_argument("--case-manifest-root", type=Path)
    parser.add_argument("--out-summary", type=Path, required=True)
    parser.add_argument("--out-cases", type=Path, required=True)
    args = parser.parse_args()

    if not any((args.run_jsonl, args.verdicts_jsonl, args.command_matrix_csv)):
        parser.error("provide at least one input: --run-jsonl, --verdicts-jsonl, or --command-matrix-csv")

    summary, cases = analyze(args)
    args.out_summary.parent.mkdir(parents=True, exist_ok=True)
    args.out_cases.parent.mkdir(parents=True, exist_ok=True)
    args.out_summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with args.out_cases.open("w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
