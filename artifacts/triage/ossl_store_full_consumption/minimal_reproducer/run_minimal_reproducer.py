import csv
import json
import os
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


REPRO = Path("artifacts/triage/ossl_store_full_consumption/minimal_reproducer")
INPUTS_DIR = REPRO / "inputs"
OUTPUTS_DIR = REPRO / "outputs"
LOGS_DIR = REPRO / "logs"
RESULTS_DIR = REPRO / "results"
CORPUS = Path("artifacts/triage/ossl_store_full_consumption/inputs")
MALFORMED_TAIL = bytes.fromhex("30 82 10 00")


def input_path(kind, case):
    names = {
        "baseline": "baseline_valid.der",
        "tail": "valid_plus_malformed_tail.der",
        "malformed_only": "malformed_only.der",
    }
    return INPUTS_DIR / kind / names[case]


def main():
    for directory in [INPUTS_DIR, OUTPUTS_DIR, LOGS_DIR, RESULTS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)

    objects = {
        "x509_der": {
            "baseline_src": CORPUS / "x509_der_baseline_empty.der",
            "tail_src": CORPUS / "x509_der_malformed_partial_sequence.der",
        },
        "pkcs8_der": {
            "baseline_src": CORPUS / "pkcs8_der_baseline_empty.der",
            "tail_src": CORPUS / "pkcs8_der_malformed_partial_sequence.der",
        },
        "pubkey_der": {
            "baseline_src": CORPUS / "pubkey_der_baseline_empty.der",
            "tail_src": CORPUS / "pubkey_der_malformed_partial_sequence.der",
        },
    }

    input_manifest = {}
    for kind, cfg in objects.items():
        kind_dir = INPUTS_DIR / kind
        kind_dir.mkdir(parents=True, exist_ok=True)
        baseline = kind_dir / "baseline_valid.der"
        tail = kind_dir / "valid_plus_malformed_tail.der"
        malformed_only = kind_dir / "malformed_only.der"
        shutil.copyfile(cfg["baseline_src"], baseline)
        shutil.copyfile(cfg["tail_src"], tail)
        malformed_only.write_bytes(MALFORMED_TAIL)
        input_manifest[kind] = {
            "baseline_valid": str(baseline),
            "valid_plus_malformed_tail": str(tail),
            "malformed_only": str(malformed_only),
            "baseline_len": baseline.stat().st_size,
            "malformed_tail_len": tail.stat().st_size,
            "malformed_only_len": malformed_only.stat().st_size,
        }

    clean_sources = Path(os.environ.get("CLEAN_SOURCES_ROOT", str(Path.home() / "work/clean_sources")))
    openssl = clean_sources / "openssl-3.5.5" / "apps" / "openssl"
    version = subprocess.run(
        [str(openssl), "version", "-a"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
    )
    (RESULTS_DIR / "openssl_version.txt").write_text(version.stdout + version.stderr, encoding="utf-8")

    commands = []
    for case in ["baseline", "tail", "malformed_only"]:
        file_path = input_path("x509_der", case)
        commands.append(
            (
                "x509_der",
                case,
                "x509_fingerprint",
                [str(openssl), "x509", "-inform", "DER", "-in", str(file_path), "-fingerprint", "-noout"],
                None,
            )
        )
        commands.append(
            (
                "x509_der",
                case,
                "x509_export_pem",
                [str(openssl), "x509", "-inform", "DER", "-in", str(file_path), "-outform", "PEM", "-out"],
                OUTPUTS_DIR / f"x509_{case}.pem",
            )
        )

    for case in ["baseline", "tail", "malformed_only"]:
        file_path = input_path("pkcs8_der", case)
        commands.append(
            (
                "pkcs8_der",
                case,
                "pkey_pubout",
                [str(openssl), "pkey", "-inform", "DER", "-in", str(file_path), "-pubout", "-out"],
                OUTPUTS_DIR / f"pkey_{case}_pub.pem",
            )
        )
        commands.append(
            (
                "pkcs8_der",
                case,
                "pkcs8_convert_pem",
                [
                    str(openssl),
                    "pkcs8",
                    "-inform",
                    "DER",
                    "-in",
                    str(file_path),
                    "-nocrypt",
                    "-outform",
                    "PEM",
                    "-out",
                ],
                OUTPUTS_DIR / f"pkcs8_{case}.pem",
            )
        )

    for case in ["baseline", "tail", "malformed_only"]:
        file_path = input_path("pubkey_der", case)
        commands.append(
            (
                "pubkey_der",
                case,
                "pubkey_pubout",
                [str(openssl), "pkey", "-pubin", "-inform", "DER", "-in", str(file_path), "-pubout", "-out"],
                OUTPUTS_DIR / f"pubkey_{case}.pem",
            )
        )

    rows = []
    for idx, (kind, case, command_name, argv, output_file) in enumerate(commands, start=1):
        command = list(argv)
        if output_file is not None:
            if output_file.exists():
                output_file.unlink()
            command.append(str(output_file))
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            check=False,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        log_base = LOGS_DIR / f"{idx:02d}_{kind}_{case}_{command_name}"
        log_base.with_suffix(".stdout.txt").write_text(stdout, encoding="utf-8")
        log_base.with_suffix(".stderr.txt").write_text(stderr, encoding="utf-8")
        output_created = bool(output_file and output_file.exists())
        output_nonempty = bool(output_created and output_file.stat().st_size > 0)
        accepted = proc.returncode == 0
        if case == "baseline":
            verdict = "baseline_success" if accepted else "baseline_failed"
        elif case == "tail":
            verdict = (
                "app_level_accepts_valid_prefix_with_malformed_tail"
                if accepted
                else "app_level_rejects_valid_prefix_with_malformed_tail"
            )
        else:
            verdict = "malformed_only_unexpected_success" if accepted else "malformed_only_rejected"
        rows.append(
            {
                "command_id": idx,
                "command": " ".join(command),
                "input_kind": kind,
                "input_case": case,
                "command_name": command_name,
                "exit_code": proc.returncode,
                "stdout_nonempty": bool(stdout.strip()),
                "stderr_nonempty": bool(stderr.strip()),
                "output_file_created": output_created,
                "output_file_nonempty": output_nonempty,
                "accepted_rejected": "accepted" if accepted else "rejected",
                "verdict": verdict,
                "stderr_excerpt": " ".join(stderr.split())[:240],
            }
        )

    matrix = RESULTS_DIR / "minimal_command_matrix.csv"
    with matrix.open("w", newline="", encoding="utf-8") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    tail_lines = []
    for kind in objects:
        baseline = INPUTS_DIR / kind / "baseline_valid.der"
        tail = INPUTS_DIR / kind / "valid_plus_malformed_tail.der"
        malformed_only = INPUTS_DIR / kind / "malformed_only.der"
        baseline_bytes = baseline.read_bytes()
        tail_bytes = tail.read_bytes()
        tail_lines.extend(
            [
                f"[{kind}]",
                f"baseline={baseline}",
                f"valid_plus_malformed_tail={tail}",
                f"malformed_only={malformed_only}",
                f"baseline_len={len(baseline_bytes)}",
                f"malformed_tail_len={len(tail_bytes)}",
                f"malformed_only_len={malformed_only.stat().st_size}",
                "tail_last_4=" + " ".join(f"{byte:02x}" for byte in tail_bytes[-4:]),
                f"tail_matches_30_82_10_00={tail_bytes[-4:] == MALFORMED_TAIL}",
                f"tail_prefix_equals_baseline={tail_bytes[:-4] == baseline_bytes}",
                "",
            ]
        )
    (RESULTS_DIR / "input_tail_hex.txt").write_text("\n".join(tail_lines), encoding="utf-8")

    by_case = defaultdict(list)
    by_kind = defaultdict(list)
    by_command = defaultdict(list)
    for row in rows:
        by_case[row["input_case"]].append(row)
        by_kind[row["input_kind"]].append(row)
        by_command[row["command_name"]].append(row)

    summary = {
        "openssl_path": str(openssl),
        "repro_root": str(REPRO),
        "input_manifest": input_manifest,
        "tail_bytes": "30 82 10 00",
        "total_commands": len(rows),
        "baseline_success": sum(
            row["input_case"] == "baseline" and row["accepted_rejected"] == "accepted" for row in rows
        ),
        "baseline_total": sum(row["input_case"] == "baseline" for row in rows),
        "malformed_tail_accepted": sum(
            row["input_case"] == "tail" and row["accepted_rejected"] == "accepted" for row in rows
        ),
        "malformed_tail_total": sum(row["input_case"] == "tail" for row in rows),
        "malformed_only_rejected": sum(
            row["input_case"] == "malformed_only" and row["accepted_rejected"] == "rejected" for row in rows
        ),
        "malformed_only_total": sum(row["input_case"] == "malformed_only" for row in rows),
        "verdict_counts": dict(Counter(row["verdict"] for row in rows)),
        "by_input_kind": {},
        "by_command_name": {},
    }
    summary["classification"] = (
        "app_level_accepts_valid_prefix_with_malformed_tail"
        if all(row["accepted_rejected"] == "accepted" for row in by_case["baseline"])
        and all(row["accepted_rejected"] == "accepted" for row in by_case["tail"])
        and all(row["accepted_rejected"] == "rejected" for row in by_case["malformed_only"])
        else "needs_triage"
    )

    for key, values in by_kind.items():
        summary["by_input_kind"][key] = {
            "total": len(values),
            "baseline_success": sum(
                row["input_case"] == "baseline" and row["accepted_rejected"] == "accepted" for row in values
            ),
            "malformed_tail_accepted": sum(
                row["input_case"] == "tail" and row["accepted_rejected"] == "accepted" for row in values
            ),
            "malformed_only_rejected": sum(
                row["input_case"] == "malformed_only" and row["accepted_rejected"] == "rejected"
                for row in values
            ),
        }
    for key, values in by_command.items():
        summary["by_command_name"][key] = {
            "total": len(values),
            "baseline_success": sum(
                row["input_case"] == "baseline" and row["accepted_rejected"] == "accepted" for row in values
            ),
            "malformed_tail_accepted": sum(
                row["input_case"] == "tail" and row["accepted_rejected"] == "accepted" for row in values
            ),
            "malformed_only_rejected": sum(
                row["input_case"] == "malformed_only" and row["accepted_rejected"] == "rejected"
                for row in values
            ),
            "tail_output_file_nonempty": sum(
                row["input_case"] == "tail" and row["output_file_nonempty"] for row in values
            ),
            "tail_stdout_nonempty": sum(
                row["input_case"] == "tail" and row["stdout_nonempty"] for row in values
            ),
        }

    (RESULTS_DIR / "minimal_command_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
