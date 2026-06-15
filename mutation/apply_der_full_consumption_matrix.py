from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import yaml


DEFAULT_OUT = Path("artifacts/sprints/der_full_consumption_v2")
DEFAULT_SEED_ROOT = Path("artifacts/triage/ossl_store_full_consumption/minimal_reproducer/inputs")


TARGETS = {
    "openssl_app_x509": {
        "seed_dir": "x509_der",
        "command": ["x509", "-inform", "DER", "-in", "input.der", "-outform", "PEM", "-out", "out.pem"],
    },
    "openssl_app_pkey": {
        "seed_dir": "pubkey_der",
        "command": ["pkey", "-pubin", "-inform", "DER", "-in", "input.der", "-pubout", "-out", "out.pem"],
    },
    "openssl_app_pkcs8": {
        "seed_dir": "pkcs8_der",
        "command": ["pkcs8", "-inform", "DER", "-in", "input.der", "-nocrypt", "-outform", "PEM", "-out", "out.pem"],
    },
}


TRAILING_CONTENTS = [
    "all_zero",
    "random",
    "malformed_asn1_tag",
    "malformed_asn1_length",
    "valid_der_null",
    "valid_der_sequence",
    "duplicate_prefix_object",
]


TRAILING_LENGTHS = [0, 1, 16, 255, 1024]


INPUT_SHAPES = [
    "valid_der_only",
    "malformed_only",
    "valid_der_plus_malformed_tail",
    "valid_der_plus_valid_der_object",
    "valid_der_plus_duplicate_object",
]


def deterministic_random(length: int, seed: str) -> bytes:
    state = sum(seed.encode("utf-8")) & 0xFF
    out = bytearray()
    for idx in range(length):
        state = (state * 1103515245 + 12345 + idx) & 0x7FFFFFFF
        out.append((state >> 8) & 0xFF)
    return bytes(out)


def repeat_to_length(data: bytes, length: int) -> bytes:
    if length <= 0:
        return b""
    if not data:
        data = b"\x00"
    repeats = (length + len(data) - 1) // len(data)
    return (data * repeats)[:length]


def tail_bytes(content: str, length: int, seed: str, baseline: bytes) -> bytes:
    if length <= 0:
        return b""
    if content == "all_zero":
        return b"\x00" * length
    if content == "random":
        return deterministic_random(length, seed)
    if content == "malformed_asn1_tag":
        return repeat_to_length(b"\xff\x00", length)
    if content == "malformed_asn1_length":
        return repeat_to_length(bytes.fromhex("30 82 10 00"), length)
    if content == "valid_der_null":
        return repeat_to_length(bytes.fromhex("05 00"), length)
    if content == "valid_der_sequence":
        return repeat_to_length(bytes.fromhex("30 00"), length)
    if content == "duplicate_prefix_object":
        return repeat_to_length(baseline, length)
    raise ValueError(f"unknown trailing_content: {content}")


def expected_for_shape(shape: str) -> str:
    if shape == "valid_der_only":
        return "valid_baseline_success"
    if shape == "malformed_only":
        return "malformed_baseline_reject"
    if shape == "valid_der_plus_malformed_tail":
        return "strict_reject_or_app_level_validation_gap_candidate"
    return "expected_prefix_accept_behavior_or_manual_triage"


def build_matrix() -> dict[str, Any]:
    cases = []
    idx = 1
    malformed_combos = [
        (1, "malformed_asn1_tag"),
        (1, "all_zero"),
        (16, "malformed_asn1_length"),
        (16, "random"),
        (255, "malformed_asn1_tag"),
        (255, "malformed_asn1_length"),
        (1024, "all_zero"),
        (1024, "random"),
        (16, "all_zero"),
        (255, "random"),
    ]
    valid_object_combos = [
        (1, "valid_der_null"),
        (16, "valid_der_sequence"),
        (255, "valid_der_null"),
        (1024, "valid_der_sequence"),
        (16, "duplicate_prefix_object"),
        (255, "duplicate_prefix_object"),
        (1024, "duplicate_prefix_object"),
    ]
    duplicate_combos = [
        (1, "duplicate_prefix_object"),
        (16, "duplicate_prefix_object"),
        (255, "duplicate_prefix_object"),
        (1024, "duplicate_prefix_object"),
        (16, "valid_der_sequence"),
        (255, "valid_der_null"),
    ]
    for target in TARGETS:
        for shape in INPUT_SHAPES:
            if shape in {"valid_der_only", "malformed_only"}:
                cases.append(
                    {
                        "case_id": f"derv2_{idx:03d}",
                        "parser_target": target,
                        "input_shape": shape,
                        "trailing_length": 0,
                        "trailing_content": "none",
                        "expected_baseline": expected_for_shape(shape),
                    }
                )
                idx += 1
                continue
            if shape == "valid_der_plus_malformed_tail":
                combos = malformed_combos
            elif shape == "valid_der_plus_valid_der_object":
                combos = valid_object_combos
            else:
                combos = duplicate_combos
            for length, content in combos:
                cases.append(
                    {
                        "case_id": f"derv2_{idx:03d}",
                        "parser_target": target,
                        "input_shape": shape,
                        "trailing_length": length,
                        "trailing_content": content,
                        "expected_baseline": expected_for_shape(shape),
                    }
                )
                idx += 1
    return {
        "pattern_id": "MBEDTLS-POC-0020",
        "family": "der_full_consumption",
        "oracle_type": "app_level_full_consumption_semantic_oracle",
        "renderer": "controlled_app_level_wrapper",
        "cases": cases,
    }


def write_case_py(path: Path, command: list[str]) -> None:
    script = """from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


case_dir = Path(__file__).resolve().parent
manifest = json.loads((case_dir / "case_manifest.json").read_text(encoding="utf-8"))
openssl_env = os.environ.get("OPENSSL_APP", "").strip()
openssl = Path(openssl_env) if openssl_env else None
if openssl is None:
    clean_sources = Path(os.environ.get("CLEAN_SOURCES_ROOT", str(Path.home() / "work/clean_sources")))
    openssl = clean_sources / "openssl-3.5.5" / "apps" / "openssl"

cmd = [str(openssl)] + manifest["openssl_command"]
proc = subprocess.run(
    cmd,
    cwd=case_dir,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    errors="replace",
    check=False,
)
out_path = case_dir / "out.pem"
result = {
    "case_id": manifest["case_id"],
    "command": cmd,
    "exit_code": proc.returncode,
    "stdout": proc.stdout,
    "stderr": proc.stderr,
    "output_artifact_created": out_path.exists(),
    "output_artifact_nonempty": bool(out_path.exists() and out_path.stat().st_size > 0),
    "input_size": (case_dir / "input.der").stat().st_size,
}
(case_dir / "run_result.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
raise SystemExit(0)
"""
    path.write_text(script, encoding="utf-8")


def render_cases(matrix: dict[str, Any], seed_root: Path, rendered_root: Path) -> None:
    rendered_root.mkdir(parents=True, exist_ok=True)
    for case in matrix["cases"]:
        target_cfg = TARGETS[case["parser_target"]]
        seed_dir = seed_root / target_cfg["seed_dir"]
        baseline = (seed_dir / "baseline_valid.der").read_bytes()
        malformed = (seed_dir / "malformed_only.der").read_bytes()
        shape = case["input_shape"]
        if shape == "valid_der_only":
            data = baseline
        elif shape == "malformed_only":
            data = malformed
        else:
            content = case["trailing_content"]
            if shape == "valid_der_plus_valid_der_object" and content == "duplicate_prefix_object":
                content = "valid_der_sequence"
            if shape == "valid_der_plus_duplicate_object":
                content = "duplicate_prefix_object"
            data = baseline + tail_bytes(content, int(case["trailing_length"]), case["case_id"], baseline)

        case_dir = rendered_root / case["case_id"]
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "input.der").write_bytes(data)
        manifest = {
            **case,
            "seed_dir": str(seed_dir),
            "openssl_command": target_cfg["command"],
            "input_size": len(data),
        }
        (case_dir / "case_manifest.yaml").write_text(
            yaml.safe_dump(manifest, sort_keys=False),
            encoding="utf-8",
        )
        (case_dir / "case_manifest.json").write_text(
            __import__("json").dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        write_case_py(case_dir / "case.py", target_cfg["command"])


def write_mutation_plan(out_root: Path, matrix: dict[str, Any]) -> None:
    plan = {
        "pattern_id": "MBEDTLS-POC-0020",
        "family": "der_full_consumption",
        "sprint": "der_full_consumption_v2",
        "mode": "controlled_app_level_wrapper",
        "mutation_dimensions": {
            "parser_target": list(TARGETS),
            "input_shape": INPUT_SHAPES,
            "trailing_length": TRAILING_LENGTHS,
            "trailing_content": TRAILING_CONTENTS,
        },
        "oracle": {
            "valid_der_only": "must succeed",
            "malformed_only": "must reject",
            "valid_der_plus_malformed_tail": "success with output artifact is app_level_validation_gap_candidate",
            "valid_der_plus_valid_der_object": "manual triage / expected prefix ambiguity",
            "valid_der_plus_duplicate_object": "manual triage / expected prefix ambiguity",
        },
        "total_cases": len(matrix["cases"]),
    }
    (out_root / "mutation_plan.yaml").write_text(
        yaml.safe_dump(plan, sort_keys=False),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed-root", type=Path, default=DEFAULT_SEED_ROOT)
    parser.add_argument("--rendered-dir-name", default="rendered_cases")
    args = parser.parse_args()

    matrix = build_matrix()
    args.out_root.mkdir(parents=True, exist_ok=True)
    write_mutation_plan(args.out_root, matrix)
    matrix_path = args.out_root / "render_matrix.yaml"
    matrix_path.write_text(yaml.safe_dump(matrix, sort_keys=False), encoding="utf-8")
    render_cases(matrix, args.seed_root, args.out_root / args.rendered_dir_name)

    print(f"[OK] wrote {args.out_root / 'mutation_plan.yaml'}")
    print(f"[OK] wrote {matrix_path}")
    print(f"[OK] rendered cases: {len(matrix['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
