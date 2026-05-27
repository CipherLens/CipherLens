import argparse
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


def weighted_score(scores: Dict[str, int]) -> int:
    return round(
        0.15 * scores.get("operation_family", 0)
        + 0.20 * scores.get("function_behavior", 0)
        + 0.20 * scores.get("parameter_structure", 0)
        + 0.30 * scores.get("vulnerability_path", 0)
        + 0.15 * scores.get("harness_feasibility", 0)
    )


def decide(scores: Dict[str, int]) -> str:
    final = weighted_score(scores)
    vuln_path = scores.get("vulnerability_path", 0)

    if final >= 75 and vuln_path >= 70:
        return "generate"
    if final >= 55 and vuln_path >= 50:
        return "needs_llm_review"
    return "skip"


def migration_applicability_for_candidate(
    decision: str,
    scores: Dict[str, int],
    reason: str,
    lost: List[str],
) -> Dict[str, str]:
    if decision == "generate":
        return {
            "migration_applicability": "applicable",
            "migration_reason": "Candidate preserves the required vulnerability path well enough for automatic migration generation.",
        }

    if decision == "skip":
        lost_set = set(lost or [])
        if {
            "manual_output_limb_boundary_control",
            "direct_canary_after_output_limbs",
        } & lost_set:
            migration_reason = (
                "Functionally related but migration_not_applicable for automatic generation: "
                "vulnerability-path mismatch; missing manual output limb boundary control; "
                "missing direct canary after output limbs."
            )
        else:
            migration_reason = (
                "migration_not_applicable for automatic generation because the candidate "
                "does not preserve the required vulnerability path."
            )

        return {
            "migration_applicability": "migration_not_applicable",
            "migration_reason": migration_reason,
        }

    return {}


def make_candidate(
    library: str,
    api: str,
    scores: Dict[str, int],
    reason: str,
    parameter_mapping: Dict[str, Any],
    preserved: List[str],
    lost: List[str],
) -> Dict[str, Any]:
    final = weighted_score(scores)
    decision = decide(scores)
    applicability = migration_applicability_for_candidate(
        decision=decision,
        scores={**scores, "final": final},
        reason=reason,
        lost=lost,
    )
    return {
        "library": library,
        "api": api,
        "scores": {
            **scores,
            "final": final,
        },
        "decision": decision,
        "reason": reason,
        **applicability,
        "parameter_mapping": parameter_mapping,
        "preserved_vulnerability_features": preserved,
        "lost_or_weakened_features": lost,
    }


def candidates_for_mpi_write_string(mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        make_candidate(
            library="openssl",
            api="BN_bn2binpad",
            scores={
                "operation_family": 80,
                "function_behavior": 65,
                "parameter_structure": 60,
                "vulnerability_path": 90,
                "harness_feasibility": 85,
            },
            reason=(
                "BN_bn2binpad serializes a BIGNUM into a caller-provided output "
                "buffer with an explicit length. It preserves the key boundary-risk "
                "path, although it does not preserve radix-based text formatting."
            ),
            parameter_mapping={
                "[VALUE]": "BN_set_word(X, abs(VALUE)) plus BN_set_negative(X, 1) for negative values",
                "[BUFLEN]": "BN_bn2binpad third argument: tolen",
                "[CANARY_SIZE]": "same canary region after caller buffer",
                "[RADIX]": "no direct counterpart; target serializes big-endian binary",
                "X": "BIGNUM *X",
                "buf": "unsigned char *to",
            },
            preserved=[
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
            lost=[
                "radix_parameter",
                "textual_sign_byte_before_digits",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_signed_bn2bin",
            scores={
                "operation_family": 80,
                "function_behavior": 75,
                "parameter_structure": 70,
                "vulnerability_path": 85,
                "harness_feasibility": 80,
            },
            reason=(
                "BN_signed_bn2bin is closer to the negative integer serialization path "
                "because it preserves signed binary encoding and caller-provided output "
                "buffer length. It is a strong candidate if the target OpenSSL version "
                "supports this API."
            ),
            parameter_mapping={
                "[VALUE]": "BN_set_word plus BN_set_negative",
                "[BUFLEN]": "BN_signed_bn2bin third argument: tolen",
                "[CANARY_SIZE]": "same canary guard layout",
                "[RADIX]": "no direct counterpart; signed binary encoding",
                "X": "BIGNUM *X",
                "buf": "unsigned char *to",
            },
            preserved=[
                "negative_integer_path",
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
            lost=[
                "radix_parameter",
                "textual radix string representation",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_bn2hex",
            scores={
                "operation_family": 75,
                "function_behavior": 45,
                "parameter_structure": 30,
                "vulnerability_path": 20,
                "harness_feasibility": 80,
            },
            reason=(
                "BN_bn2hex performs bignum serialization, but returns a "
                "library-allocated string. It does not preserve the caller-provided "
                "small output buffer boundary path."
            ),
            parameter_mapping={
                "[VALUE]": "BIGNUM construction possible",
                "[RADIX]": "hex output is fixed",
                "[BUFLEN]": "no caller-provided buffer length counterpart",
                "[CANARY_SIZE]": "canary oracle not naturally applicable",
            },
            preserved=[
                "bignum_serialization",
            ],
            lost=[
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_bn2dec",
            scores={
                "operation_family": 75,
                "function_behavior": 45,
                "parameter_structure": 30,
                "vulnerability_path": 20,
                "harness_feasibility": 80,
            },
            reason=(
                "BN_bn2dec is semantically related to decimal serialization, but "
                "it returns a library-allocated string and does not expose caller-controlled "
                "output buffer length."
            ),
            parameter_mapping={
                "[VALUE]": "BIGNUM construction possible",
                "[RADIX]": "decimal output is fixed",
                "[BUFLEN]": "no caller-provided buffer length counterpart",
                "[CANARY_SIZE]": "canary oracle not naturally applicable",
            },
            preserved=[
                "bignum_serialization",
            ],
            lost=[
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
        ),
    ]


def candidates_for_mpi_sub_abs(mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        make_candidate(
            library="openssl",
            api="BN_usub",
            scores={
                "operation_family": 85,
                "function_behavior": 70,
                "parameter_structure": 60,
                "vulnerability_path": 45,
                "harness_feasibility": 70,
            },
            reason=(
                "BN_usub is functionally related to unsigned bignum subtraction, "
                "but OpenSSL generally manages BIGNUM expansion internally. The source "
                "pattern depends on output limb boundary control, so vulnerability-path "
                "equivalence is uncertain."
            ),
            parameter_mapping={
                "[A_VALUE]": "BIGNUM *A",
                "[B_VALUE]": "BIGNUM *B",
                "[X_LIMB_COUNT]": "no direct public counterpart for forcing result limb capacity",
                "[CANARY_SIZE]": "not directly applicable unless internal buffer control is exposed",
            },
            preserved=[
                "bignum_subtraction",
                "A_B_operand_relation",
            ],
            lost=[
                "manual_output_limb_boundary_control",
                "direct_canary_after_output_limbs",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_sub",
            scores={
                "operation_family": 85,
                "function_behavior": 75,
                "parameter_structure": 60,
                "vulnerability_path": 40,
                "harness_feasibility": 75,
            },
            reason=(
                "BN_sub supports signed subtraction behavior, but the original "
                "mbedtls_mpi_sub_abs pattern is tied to output limb allocation and "
                "negative-result boundary checks. The migration should be reviewed "
                "rather than directly generated."
            ),
            parameter_mapping={
                "[A_VALUE]": "BIGNUM *A",
                "[B_VALUE]": "BIGNUM *B",
                "[X_LIMB_COUNT]": "no direct public equivalent",
                "[CANARY_SIZE]": "not naturally applicable",
            },
            preserved=[
                "bignum_subtraction",
                "signed_result_behavior",
            ],
            lost=[
                "manual_output_limb_boundary_control",
                "direct_canary_after_output_limbs",
            ],
        ),
    ]


def map_candidates(mask_report: Dict[str, Any]) -> Dict[str, Any]:
    template_id = mask_report.get("template_id", "")
    source_api = mask_report.get("source_api", "")
    poc_pattern = mask_report.get("poc_pattern", {})

    if template_id == "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER":
        candidates = candidates_for_mpi_write_string(mask_report)
    elif template_id == "BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY":
        candidates = candidates_for_mpi_sub_abs(mask_report)
    else:
        candidates = []

    return {
        "template_id": template_id,
        "source": {
            "library": mask_report.get("source_library", ""),
            "api": source_api,
            "pattern_id": poc_pattern.get("pattern_id"),
            "root_cause_summary": poc_pattern.get("root_cause", {}).get("summary"),
            "vulnerability_path_features": poc_pattern.get("vulnerability_path_features", {}),
            "migration_guidance": poc_pattern.get("migration_guidance", {}),
        },
        "scoring_policy": {
            "operation_family": 0.15,
            "function_behavior": 0.20,
            "parameter_structure": 0.20,
            "vulnerability_path": 0.30,
            "harness_feasibility": 0.15,
            "decision_rule": {
                "generate": "final >= 75 and vulnerability_path >= 70",
                "needs_llm_review": "final >= 55 and vulnerability_path >= 50",
                "skip": "otherwise",
            },
        },
        "target_candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Map and score cross-library API migration candidates."
    )
    parser.add_argument(
        "--mask-report",
        default="normalized_templates/bignum/mpi_write_string/mask_report.yaml",
        help="Input mask_report.yaml",
    )
    parser.add_argument(
        "--output",
        default="migration_candidates/bignum/mpi_write_string/candidates.yaml",
        help="Output candidates.yaml",
    )
    args = parser.parse_args()

    mask_report = load_yaml(Path(args.mask_report))
    result = map_candidates(mask_report)
    dump_yaml(Path(args.output), result)

    print(f"[OK] candidates written to {args.output}")
    print(f"[INFO] template_id: {result['template_id']}")

    if not result["target_candidates"]:
        print("[WARN] no target candidates generated")

    for c in result["target_candidates"]:
        print(
            c["library"],
            c["api"],
            "decision=",
            c["decision"],
            "final=",
            c["scores"]["final"],
            "vuln_path=",
            c["scores"]["vulnerability_path"],
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
