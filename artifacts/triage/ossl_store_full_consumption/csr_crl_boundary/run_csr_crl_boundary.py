import csv
import json
import os
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path("artifacts/triage/ossl_store_full_consumption/csr_crl_boundary")
INPUTS = ROOT / "inputs"
OUTPUTS = ROOT / "outputs"
LOGS = ROOT / "logs"
RESULTS = ROOT / "results"
WORK = ROOT / "work"
TAIL = bytes.fromhex("30 82 10 00")


def run(command, stdout_file=None, stderr_file=None):
    proc = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        check=False,
    )
    if stdout_file is not None:
        stdout_file.write_bytes(proc.stdout)
    if stderr_file is not None:
        stderr_file.write_bytes(proc.stderr)
    return proc


def run_text(command):
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
    )


def write_tail_set(kind, baseline_path):
    kind_dir = INPUTS / kind
    kind_dir.mkdir(parents=True, exist_ok=True)
    baseline = kind_dir / "baseline_valid.der"
    tail = kind_dir / "valid_plus_malformed_tail.der"
    malformed_only = kind_dir / "malformed_only.der"
    data = baseline_path.read_bytes()
    baseline.write_bytes(data)
    tail.write_bytes(data + TAIL)
    malformed_only.write_bytes(TAIL)
    return {
        "baseline_valid": str(baseline),
        "valid_plus_malformed_tail": str(tail),
        "malformed_only": str(malformed_only),
        "baseline_len": baseline.stat().st_size,
        "malformed_tail_len": tail.stat().st_size,
        "malformed_only_len": malformed_only.stat().st_size,
    }


def create_ca_config(ca_dir):
    config = ca_dir / "openssl-ca.cnf"
    certs = ca_dir / "certs"
    newcerts = ca_dir / "newcerts"
    certs.mkdir(parents=True, exist_ok=True)
    newcerts.mkdir(parents=True, exist_ok=True)
    (ca_dir / "index.txt").write_text("", encoding="utf-8")
    (ca_dir / "serial").write_text("1000\n", encoding="utf-8")
    (ca_dir / "crlnumber").write_text("1000\n", encoding="utf-8")
    config.write_text(
        f"""[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {ca_dir.resolve()}
certs = $dir/certs
new_certs_dir = $dir/newcerts
database = $dir/index.txt
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = $dir/ca_cert.pem
private_key = $dir/ca_key.pem
default_md = sha256
default_crl_days = 30
default_days = 365
policy = policy_any
x509_extensions = usr_cert
copy_extensions = none

[ policy_any ]
commonName = supplied

[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = Test CA

[ usr_cert ]
basicConstraints = CA:false

""",
        encoding="utf-8",
    )
    return config


def create_req_config(work_dir, common_name):
    config = work_dir / f"openssl-req-{common_name.lower().replace(' ', '-')}.cnf"
    config.write_text(
        f"""[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = {common_name}

""",
        encoding="utf-8",
    )
    return config


def generate_inputs(openssl):
    WORK.mkdir(parents=True, exist_ok=True)

    csr_key = WORK / "csr_key.pem"
    csr_der = WORK / "csr.der"
    csr_config = create_req_config(WORK, "DER Tail CSR Boundary")
    run_text(
        [
            str(openssl),
            "req",
            "-new",
            "-config",
            str(csr_config),
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=DER Tail CSR Boundary",
            "-keyout",
            str(csr_key),
            "-outform",
            "DER",
            "-out",
            str(csr_der),
        ]
    )

    manifest = {"csr_der": write_tail_set("csr_der", csr_der)}
    manifest["_csr_config"] = str(csr_config)

    ca_dir = WORK / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_key = ca_dir / "ca_key.pem"
    ca_cert = ca_dir / "ca_cert.pem"
    crl_pem = WORK / "crl.pem"
    crl_der = WORK / "crl.der"
    config = create_ca_config(ca_dir)
    ca_req_config = create_req_config(WORK, "DER Tail Test CA")
    run_text(
        [
            str(openssl),
            "req",
            "-x509",
            "-config",
            str(ca_req_config),
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=DER Tail Test CA",
            "-days",
            "1",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
        ]
    )
    crl_proc = run(
        [str(openssl), "ca", "-gencrl", "-config", str(config), "-out", str(crl_pem)],
        LOGS / "crl_generation.stdout.bin",
        LOGS / "crl_generation.stderr.bin",
    )
    crl_status = {
        "attempted": True,
        "exit_code": crl_proc.returncode,
        "stderr_excerpt": crl_proc.stderr.decode("utf-8", errors="replace").replace("\n", " ")[:240],
    }
    if crl_proc.returncode == 0 and crl_pem.exists() and crl_pem.stat().st_size > 0:
        convert_proc = run(
            [
                str(openssl),
                "crl",
                "-in",
                str(crl_pem),
                "-outform",
                "DER",
                "-out",
                str(crl_der),
            ],
            LOGS / "crl_der_conversion.stdout.bin",
            LOGS / "crl_der_conversion.stderr.bin",
        )
        crl_status["conversion_exit_code"] = convert_proc.returncode
    if crl_der.exists() and crl_der.stat().st_size > 0:
        manifest["crl_der"] = write_tail_set("crl_der", crl_der)
        crl_status["tested"] = True
    else:
        crl_status["tested"] = False
        crl_status["reason"] = "not_tested_due_to_generation_cost"
    return manifest, crl_status


def input_path(kind, case):
    names = {
        "baseline": "baseline_valid.der",
        "tail": "valid_plus_malformed_tail.der",
        "malformed_only": "malformed_only.der",
    }
    return INPUTS / kind / names[case]


def run_matrix(openssl, manifest):
    commands = []
    csr_config = manifest.get("_csr_config")
    for case in ["baseline", "tail", "malformed_only"]:
        file_path = input_path("csr_der", case)
        commands.extend(
            [
                (
                    "csr_der",
                    case,
                    "req_noout",
                    [str(openssl), "req", "-config", csr_config, "-inform", "DER", "-in", str(file_path), "-noout"],
                    None,
                ),
                (
                    "csr_der",
                    case,
                    "req_text_noout",
                    [str(openssl), "req", "-config", csr_config, "-inform", "DER", "-in", str(file_path), "-text", "-noout"],
                    None,
                ),
                (
                    "csr_der",
                    case,
                    "req_pubkey_noout",
                    [str(openssl), "req", "-config", csr_config, "-inform", "DER", "-in", str(file_path), "-pubkey", "-noout"],
                    None,
                ),
            ]
        )
    if "crl_der" in manifest:
        for case in ["baseline", "tail", "malformed_only"]:
            file_path = input_path("crl_der", case)
            commands.extend(
                [
                    (
                        "crl_der",
                        case,
                        "crl_noout",
                        [str(openssl), "crl", "-inform", "DER", "-in", str(file_path), "-noout"],
                        None,
                    ),
                    (
                        "crl_der",
                        case,
                        "crl_text_noout",
                        [str(openssl), "crl", "-inform", "DER", "-in", str(file_path), "-text", "-noout"],
                        None,
                    ),
                ]
            )

    rows = []
    for idx, (kind, case, command_name, command, output_file) in enumerate(commands, start=1):
        proc = run_text(command)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        log_base = LOGS / f"{idx:02d}_{kind}_{case}_{command_name}"
        log_base.with_suffix(".stdout.txt").write_text(stdout, encoding="utf-8")
        log_base.with_suffix(".stderr.txt").write_text(stderr, encoding="utf-8")
        accepted = proc.returncode == 0
        if case == "baseline":
            verdict = "baseline_success" if accepted else "baseline_failed"
        elif case == "tail":
            verdict = (
                "app_level_accepts_valid_prefix_with_malformed_tail"
                if accepted
                else "app_level_rejects_malformed_tail"
            )
        else:
            verdict = "input_generation_or_oracle_error" if accepted else "malformed_only_rejected"
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
                "output_file_created": bool(output_file and output_file.exists()),
                "accepted": accepted,
                "verdict": verdict,
                "stderr_excerpt": " ".join(stderr.split())[:240],
            }
        )

    matrix = RESULTS / "csr_crl_command_matrix.csv"
    with matrix.open("w", newline="", encoding="utf-8") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def write_tail_hex(manifest):
    lines = []
    for kind in ["csr_der", "crl_der"]:
        if kind not in manifest:
            lines.extend([f"[{kind}]", "tested=False", ""])
            continue
        baseline = input_path(kind, "baseline")
        tail = input_path(kind, "tail")
        malformed_only = input_path(kind, "malformed_only")
        baseline_bytes = baseline.read_bytes()
        tail_bytes = tail.read_bytes()
        lines.extend(
            [
                f"[{kind}]",
                f"baseline={baseline}",
                f"valid_plus_malformed_tail={tail}",
                f"malformed_only={malformed_only}",
                f"baseline_len={len(baseline_bytes)}",
                f"malformed_tail_len={len(tail_bytes)}",
                f"malformed_only_len={malformed_only.stat().st_size}",
                "tail_last_4=" + " ".join(f"{byte:02x}" for byte in tail_bytes[-4:]),
                f"tail_matches_30_82_10_00={tail_bytes[-4:] == TAIL}",
                f"tail_prefix_equals_baseline={tail_bytes[:-4] == baseline_bytes}",
                "",
            ]
        )
    (RESULTS / "input_tail_hex.txt").write_text("\n".join(lines), encoding="utf-8")


def summarize(rows, manifest, crl_status, openssl):
    by_kind = defaultdict(list)
    for row in rows:
        by_kind[row["input_kind"]].append(row)
    summary = {
        "openssl_path": str(openssl),
        "boundary_root": str(ROOT),
        "tail_bytes": "30 82 10 00",
        "input_manifest": manifest,
        "crl_generation": crl_status,
        "total_commands": len(rows),
        "verdict_counts": dict(Counter(row["verdict"] for row in rows)),
        "by_input_kind": {},
    }
    for kind, values in by_kind.items():
        baseline_total = sum(row["input_case"] == "baseline" for row in values)
        tail_total = sum(row["input_case"] == "tail" for row in values)
        malformed_total = sum(row["input_case"] == "malformed_only" for row in values)
        baseline_success = sum(
            row["input_case"] == "baseline" and row["accepted"] for row in values
        )
        tail_accepted = sum(row["input_case"] == "tail" and row["accepted"] for row in values)
        malformed_rejected = sum(
            row["input_case"] == "malformed_only" and not row["accepted"] for row in values
        )
        if baseline_success == baseline_total and tail_accepted == tail_total and malformed_rejected == malformed_total:
            classification = "app_level_accepts_valid_prefix_with_malformed_tail"
        elif baseline_success == baseline_total and tail_accepted == 0:
            classification = "app_level_rejects_malformed_tail"
        elif malformed_rejected != malformed_total:
            classification = "input_generation_or_oracle_error"
        else:
            classification = "needs_triage"
        summary["by_input_kind"][kind] = {
            "tested": True,
            "total": len(values),
            "baseline_success": baseline_success,
            "baseline_total": baseline_total,
            "malformed_tail_accepted": tail_accepted,
            "malformed_tail_total": tail_total,
            "malformed_only_rejected": malformed_rejected,
            "malformed_only_total": malformed_total,
            "classification": classification,
        }
    if "crl_der" not in summary["by_input_kind"]:
        summary["by_input_kind"]["crl_der"] = {
            "tested": False,
            "classification": "not_tested_due_to_generation_cost",
        }
    (RESULTS / "csr_crl_command_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary


def write_readme(summary):
    csr = summary["by_input_kind"].get("csr_der", {})
    crl = summary["by_input_kind"].get("crl_der", {})
    text = f"""# CSR / CRL DER Malformed Tail Boundary

This artifact checks whether the app-level DER malformed-tail behavior observed
for x509/pkey/pkcs8 extends to `openssl req` and `openssl crl`.

OpenSSL command:

```text
{summary['openssl_path']}
```

Malformed tail:

```text
30 82 10 00
```

## Results

CSR:

```text
tested={csr.get('tested')}
baseline_success={csr.get('baseline_success')}/{csr.get('baseline_total')}
malformed_tail_accepted={csr.get('malformed_tail_accepted')}/{csr.get('malformed_tail_total')}
malformed_only_rejected={csr.get('malformed_only_rejected')}/{csr.get('malformed_only_total')}
classification={csr.get('classification')}
```

CRL:

```text
tested={crl.get('tested')}
baseline_success={crl.get('baseline_success')}
malformed_tail_accepted={crl.get('malformed_tail_accepted')}
malformed_only_rejected={crl.get('malformed_only_rejected')}
classification={crl.get('classification')}
```

Detailed files:

```text
results/csr_crl_command_matrix.csv
results/csr_crl_command_summary.json
results/input_tail_hex.txt
logs/
```

Interpretation:

- `app_level_accepts_valid_prefix_with_malformed_tail` means baseline succeeds,
  valid-prefix plus malformed tail succeeds, and malformed-only fails.
- This is a semantic validation-gap candidate, not a crash and not a confirmed CVE.
"""
    (ROOT / "README.md").write_text(text, encoding="utf-8")


def main():
    for directory in [INPUTS, OUTPUTS, LOGS, RESULTS, WORK]:
        directory.mkdir(parents=True, exist_ok=True)
    clean_sources = Path(os.environ.get("CLEAN_SOURCES_ROOT", str(Path.home() / "work/clean_sources")))
    openssl = clean_sources / "openssl-3.5.5" / "apps" / "openssl"
    manifest, crl_status = generate_inputs(openssl)
    rows = run_matrix(openssl, manifest)
    write_tail_hex(manifest)
    summary = summarize(rows, manifest, crl_status, openssl)
    write_readme(summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
