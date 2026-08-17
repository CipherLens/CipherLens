from __future__ import annotations

import argparse
import hashlib
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from caller_audit.external_caller_discovery import GitHubSourceProvider
from caller_audit.impactlift_router import (
    DeterministicImpactProvider,
    load_mock_external_provider,
    run_impactlift_router,
)
from caller_audit.io_utils import write_yaml


PROPOSAL_SCHEMA = "cipherlens_frozen_demo_proposal_v1"
SUMMARY_SCHEMA = "cipherlens_demo_replay_summary_v1"
GENERATED_BY = "caller_audit.demo_replay_pipeline"
DEFAULT_TEMPLATE_ID = "openssl_evp_mac_cmac_lifecycle_replay_v1"
FORBIDDEN_PROPOSAL_MARKERS = ("lua-openssl", "zhaozg", "issue #410", "issue_410")
StageEventCallback = Callable[[dict[str, Any]], None]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_list(value: Any) -> list[str]:
    items: list[str] = []
    for item in _as_list(value):
        text = _as_text(item)
        if text and text not in items:
            items.append(text)
    return items


def _slugify(value: str) -> str:
    import re

    slug = re.sub(r"[^A-Za-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "demo"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def validate_frozen_proposal(proposal: dict[str, Any]) -> None:
    if proposal.get("schema") != PROPOSAL_SCHEMA:
        raise ValueError(f"unsupported frozen proposal schema: {proposal.get('schema', 'missing')}")
    required = [
        "proposal_id",
        "family",
        "target_library",
        "generated_by",
        "generation_mode",
        "source_rag_artifacts",
        "template_id",
        "slots",
        "validated",
        "validator",
    ]
    missing = [field for field in required if proposal.get(field) in (None, "", [], {})]
    if missing:
        raise ValueError(f"frozen proposal missing required fields: {', '.join(missing)}")
    if proposal["template_id"] != DEFAULT_TEMPLATE_ID:
        raise ValueError(f"unsupported demo template_id: {proposal['template_id']}")
    if proposal.get("validated") is not True:
        raise ValueError("frozen proposal must be pre-validated")
    slots = proposal.get("slots")
    if not isinstance(slots, dict):
        raise ValueError("frozen proposal slots must be a mapping")
    for field in ("mac_algorithm", "cipher", "key_hex", "prefix_message", "post_final_message"):
        if not _as_text(slots.get(field)):
            raise ValueError(f"frozen proposal slots.{field} is required")
    apis = _string_list(slots.get("apis"))
    for api in ("EVP_MAC_update", "EVP_MAC_final"):
        if api not in apis:
            raise ValueError(f"frozen proposal slots.apis must include {api}")
    text = yaml.safe_dump(proposal, sort_keys=False, allow_unicode=True).lower()
    for marker in FORBIDDEN_PROPOSAL_MARKERS:
        if marker in text:
            raise ValueError(f"frozen proposal contains forbidden downstream marker: {marker}")


def _hex_bytes_literal(hex_text: str) -> str:
    clean = "".join(ch for ch in hex_text.strip() if ch not in " :\n\t")
    if len(clean) % 2:
        raise ValueError("hex slot must have an even number of digits")
    int(clean or "00", 16)
    return ", ".join(f"0x{clean[i:i+2]}" for i in range(0, len(clean), 2))


def render_openssl_evp_mac_harness(proposal: dict[str, Any]) -> str:
    slots = proposal["slots"]
    key_literal = _hex_bytes_literal(slots["key_hex"])
    algorithm = _as_text(slots["mac_algorithm"])
    cipher = _as_text(slots["cipher"])
    prefix = _as_text(slots["prefix_message"])
    post = _as_text(slots["post_final_message"])
    return f"""#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const unsigned char *buf, size_t len) {{
    printf("%s=", label);
    for (size_t i = 0; i < len; ++i) {{
        printf("%02x", buf[i]);
    }}
    printf("\\n");
}}

int main(void) {{
    unsigned char key[] = {{{key_literal}}};
    const unsigned char prefix[] = "{prefix}";
    const unsigned char post[] = "{post}";
    unsigned char out1[64] = {{0}};
    unsigned char out2[64] = {{0}};
    unsigned char out3[64] = {{0}};
    size_t outl1 = sizeof(out1);
    size_t outl2 = sizeof(out2);
    size_t outl3 = sizeof(out3);

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "{algorithm}", NULL);
    if (mac == NULL) {{
        printf("fetch_ok=0\\n");
        return 2;
    }}
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {{
        EVP_MAC_free(mac);
        printf("ctx_ok=0\\n");
        return 2;
    }}

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "{cipher}", 0);
    params[1] = OSSL_PARAM_construct_end();

    int init_ret = EVP_MAC_init(ctx, key, sizeof(key), params);
    int update1_ret = init_ret ? EVP_MAC_update(ctx, prefix, strlen((const char *)prefix)) : 0;
    int first_final_ret = update1_ret ? EVP_MAC_final(ctx, out1, &outl1, sizeof(out1)) : 0;
    int second_final_ret = first_final_ret ? EVP_MAC_final(ctx, out2, &outl2, sizeof(out2)) : 0;
    int update_after_final_ret = second_final_ret ? EVP_MAC_update(ctx, post, strlen((const char *)post)) : 0;
    int third_final_ret = update_after_final_ret ? EVP_MAC_final(ctx, out3, &outl3, sizeof(out3)) : 0;

    printf("fetch_ok=1\\n");
    printf("ctx_ok=1\\n");
    printf("init_ret=%d\\n", init_ret);
    printf("update1_ret=%d\\n", update1_ret);
    printf("first_final_ret=%d\\n", first_final_ret);
    printf("second_final_ret=%d\\n", second_final_ret);
    printf("update_after_final_ret=%d\\n", update_after_final_ret);
    printf("third_final_ret=%d\\n", third_final_ret);
    printf("outl1=%zu\\n", outl1);
    printf("outl2=%zu\\n", outl2);
    printf("outl3=%zu\\n", outl3);
    print_hex("out1_hex", out1, outl1);
    print_hex("out2_hex", out2, outl2);
    print_hex("out3_hex", out3, outl3);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return 0;
}}
"""


def render_harness(proposal: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    render_dir = out_dir / "render"
    source_path = render_dir / "cmac_lifecycle_replay.c"
    source = render_openssl_evp_mac_harness(proposal)
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source, encoding="utf-8")
    artifact = {
        "schema": "cipherlens_demo_render_report_v1",
        "template_id": proposal["template_id"],
        "rendered_harness": str(source_path),
        "rendered_from_frozen_proposal": True,
        "rendered_source_sha256": _sha256(source_path),
    }
    write_yaml(render_dir / "render_report.yaml", artifact)
    return artifact


def _openssl_compile_flags() -> list[str]:
    proc = subprocess.run(
        ["pkg-config", "--cflags", "--libs", "openssl"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return shlex.split(proc.stdout.strip())
    return ["-lcrypto"]


def compile_harness(source_path: Path, out_dir: Path) -> dict[str, Any]:
    compile_dir = out_dir / "compile"
    binary_path = compile_dir / "cmac_lifecycle_replay.bin"
    stdout_path = compile_dir / "compile.stdout.log"
    stderr_path = compile_dir / "compile.stderr.log"
    compile_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["cc", str(source_path), "-o", str(binary_path), *_openssl_compile_flags()]
    proc = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    artifact = {
        "schema": "cipherlens_demo_compile_report_v1",
        "command": cmd,
        "returncode": proc.returncode,
        "status": "completed" if proc.returncode == 0 and binary_path.exists() else "failed",
        "binary": str(binary_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }
    write_yaml(compile_dir / "compile_report.yaml", artifact)
    return artifact


def run_harness(binary_path: Path, out_dir: Path, *, timeout_seconds: int) -> dict[str, Any]:
    run_dir = out_dir / "runtime"
    stdout_path = run_dir / "runtime.stdout.log"
    stderr_path = run_dir / "runtime.stderr.log"
    run_dir.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            [str(binary_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        duration = round(time.monotonic() - start, 6)
        timed_out = False
        returncode = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        duration = round(time.monotonic() - start, 6)
        timed_out = True
        returncode = None
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    artifact = {
        "schema": "cipherlens_demo_runtime_report_v1",
        "status": "timeout" if timed_out else "completed",
        "returncode": returncode,
        "timeout": timed_out,
        "duration_seconds": duration,
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }
    write_yaml(run_dir / "runtime_report.yaml", artifact)
    return artifact


def _parse_key_values(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def run_oracle(runtime_report: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    oracle_dir = out_dir / "oracle"
    stdout_path = Path(runtime_report["stdout"])
    parsed = _parse_key_values(stdout_path.read_text(encoding="utf-8"))
    repeated_final_allowed = parsed.get("second_final_ret") == "1"
    update_after_final_allowed = parsed.get("update_after_final_ret") == "1"
    repeated_final_after_update_allowed = parsed.get("third_final_ret") == "1"
    behavior = []
    if update_after_final_allowed:
        behavior.append("update_after_final_allowed")
    if repeated_final_allowed:
        behavior.append("repeated_final_allowed")
    if repeated_final_after_update_allowed:
        behavior.append("repeated_final_after_update_allowed")
    classification = "semantic_gap_candidate" if behavior else "semantic_observation"
    artifact = {
        "schema": "cipherlens_demo_oracle_result_v1",
        "oracle_type": "mac_lifecycle_state_transition_oracle",
        "status": "completed",
        "classification": classification,
        "candidate_level": "manual_review_required" if classification.endswith("_candidate") else "observation",
        "observed_behavior": behavior,
        "runtime_values": parsed,
        "claim_policy": {
            "vulnerability": "not_assessed",
            "cve": "not_assessed",
            "security_impact": "not_assessed",
        },
    }
    write_yaml(oracle_dir / "oracle_result.yaml", artifact)
    return artifact


def write_candidate(
    proposal: dict[str, Any],
    proposal_path: Path,
    render_report: dict[str, Any],
    compile_report: dict[str, Any],
    runtime_report: dict[str, Any],
    oracle_result: dict[str, Any],
    out_dir: Path,
) -> Path:
    candidate_dir = out_dir / "candidate"
    candidate_path = candidate_dir / "cmac_lifecycle_candidate.yaml"
    slots = proposal["slots"]
    candidate = {
        "schema": "cipherlens_demo_runtime_candidate_v1",
        "candidate_id": "openssl-evp-mac-update-evp-mac-final-mac-lifecycle-semantic-divergence",
        "library": "OpenSSL",
        "version": "runtime-linked-openssl",
        "family": "mac_lifecycle_semantic_divergence",
        "api": ["EVP_MAC_update", "EVP_MAC_final"],
        "api_or_function": "EVP_MAC_update, EVP_MAC_final",
        "semantic_type": oracle_result["classification"],
        "classification": oracle_result["classification"],
        "candidate_level": oracle_result["candidate_level"],
        "trigger_condition": "init -> update -> final -> repeated final / update after final",
        "behavior": oracle_result["observed_behavior"],
        "observed_behavior": {
            "algorithm": slots["mac_algorithm"],
            "cipher": slots["cipher"],
            "oracle_behavior": oracle_result["observed_behavior"],
            "runtime_values": oracle_result["runtime_values"],
        },
        "oracle_type": oracle_result["oracle_type"],
        "oracle_evidence": [str(out_dir / "oracle" / "oracle_result.yaml")],
        "source_artifacts": [
            str(proposal_path),
            str(Path(render_report["rendered_harness"])),
            str(out_dir / "compile" / "compile_report.yaml"),
            str(out_dir / "runtime" / "runtime_report.yaml"),
            str(out_dir / "oracle" / "oracle_result.yaml"),
        ],
        "claim_policy": {
            "vulnerability": "not_assessed",
            "cve": "not_assessed",
            "security_impact": "not_assessed",
        },
    }
    write_yaml(candidate_path, candidate)
    return candidate_path


def _stage(status: str, artifact: str = "") -> dict[str, str]:
    return {"status": status, "artifact": artifact}


def _emit_stage(
    callback: StageEventCallback | None,
    stage: str,
    status: str,
    message: str,
    artifact: str = "",
) -> None:
    if callback is None:
        return
    callback(
        {
            "timestamp": _utc_now(),
            "stage": stage,
            "status": status,
            "message": message,
            "artifact": artifact,
        }
    )


def run_demo_replay(
    proposal_path: Path,
    *,
    output_root: Path,
    workspace: Path,
    mock_external_search_results: Path | None = None,
    github_search: bool = False,
    timeout_seconds: int = 10,
    stage_callback: StageEventCallback | None = None,
) -> dict[str, Any]:
    proposal_path = proposal_path.expanduser().resolve()
    output_root = output_root.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    _emit_stage(stage_callback, "family", "completed", "Demo family selected.")
    _emit_stage(stage_callback, "proposal", "running", "Loading frozen proposal.", str(proposal_path))
    proposal = load_yaml(proposal_path)
    validate_frozen_proposal(proposal)
    write_yaml(output_root / "proposal_loaded.yaml", proposal)
    _emit_stage(stage_callback, "proposal", "completed", "Frozen proposal loaded.", str(output_root / "proposal_loaded.yaml"))

    _emit_stage(stage_callback, "validation", "running", "Validating proposal schema and required slots.")
    validation_report = {
        "schema": "cipherlens_demo_proposal_validation_v1",
        "status": "completed",
        "validated": True,
        "validator": GENERATED_BY,
        "proposal": str(proposal_path),
        "proposal_sha256": _sha256(proposal_path),
        "llm_called": False,
    }
    write_yaml(output_root / "proposal_validation.yaml", validation_report)
    _emit_stage(stage_callback, "validation", "completed", "Proposal validation passed.", str(output_root / "proposal_validation.yaml"))

    _emit_stage(stage_callback, "render", "running", "Rendering deterministic C harness from proposal slots.")
    render_report = render_harness(proposal, output_root)
    _emit_stage(stage_callback, "render", "completed", "Harness rendered.", str(output_root / "render" / "render_report.yaml"))
    _emit_stage(stage_callback, "compile", "running", "Compiling rendered harness.")
    compile_report = compile_harness(Path(render_report["rendered_harness"]), output_root)
    if compile_report["status"] != "completed":
        _emit_stage(stage_callback, "compile", "failed", "Harness compilation failed.", str(output_root / "compile" / "compile_report.yaml"))
        raise RuntimeError("demo harness compile failed")
    _emit_stage(stage_callback, "compile", "completed", "Harness compilation completed.", str(output_root / "compile" / "compile_report.yaml"))
    _emit_stage(stage_callback, "runtime", "running", "Executing compiled harness.")
    runtime_report = run_harness(Path(compile_report["binary"]), output_root, timeout_seconds=timeout_seconds)
    runtime_status = "failed" if runtime_report["status"] not in {"completed"} else "completed"
    _emit_stage(stage_callback, "runtime", runtime_status, "Runtime execution completed.", str(output_root / "runtime" / "runtime_report.yaml"))
    _emit_stage(stage_callback, "oracle", "running", "Analyzing runtime output with lifecycle oracle.")
    oracle_result = run_oracle(runtime_report, output_root)
    _emit_stage(stage_callback, "oracle", "completed", "Oracle analysis completed.", str(output_root / "oracle" / "oracle_result.yaml"))
    _emit_stage(stage_callback, "candidate", "running", "Writing candidate artifact from oracle result.")
    candidate_path = write_candidate(
        proposal,
        proposal_path,
        render_report,
        compile_report,
        runtime_report,
        oracle_result,
        output_root,
    )
    _emit_stage(stage_callback, "candidate", "completed", "Candidate artifact generated.", str(candidate_path))

    if github_search and mock_external_search_results:
        raise ValueError("github_search and mock_external_search_results are mutually exclusive")
    if github_search:
        external_provider = GitHubSourceProvider.from_environment()
    elif mock_external_search_results:
        external_provider = load_mock_external_provider(mock_external_search_results)
    else:
        external_provider = None

    impactlift_root = output_root / "impactlift"
    _emit_stage(stage_callback, "impactlift", "running", "Running ImpactLift Router and caller discovery.")
    impactlift_result = run_impactlift_router(
        candidate_path,
        output_root=impactlift_root,
        workspace=workspace,
        impact_provider=DeterministicImpactProvider(),
        external_provider=external_provider,
        evidence_roots=[],
        workspace_roots=[],
    )
    impactlift_summary = Path(impactlift_result["summary_path"])
    _emit_stage(stage_callback, "impactlift", impactlift_result["summary"]["status"], "ImpactLift Router completed.", str(impactlift_summary))

    summary = {
        "schema": SUMMARY_SCHEMA,
        "generated_by": GENERATED_BY,
        "run_id": f"{_slugify(proposal['proposal_id'])}-{hashlib.sha256(str(output_root).encode('utf-8')).hexdigest()[:12]}",
        "family": proposal["family"],
        "target_library": proposal["target_library"],
        "mode": "regression_replay",
        "status": "completed",
        "stages": {
            "family": _stage("completed", ""),
            "proposal": _stage("completed", str(output_root / "proposal_loaded.yaml")),
            "validation": _stage("completed", str(output_root / "proposal_validation.yaml")),
            "render": _stage("completed", str(output_root / "render" / "render_report.yaml")),
            "compile": _stage(compile_report["status"], str(output_root / "compile" / "compile_report.yaml")),
            "runtime": _stage(runtime_report["status"], str(output_root / "runtime" / "runtime_report.yaml")),
            "oracle": _stage(oracle_result["status"], str(output_root / "oracle" / "oracle_result.yaml")),
            "candidate": _stage("completed", str(candidate_path)),
            "impactlift": _stage(impactlift_result["summary"]["status"], str(impactlift_summary)),
        },
        "artifacts": {
            "proposal": str(proposal_path),
            "rendered_harness": render_report["rendered_harness"],
            "runtime_result": str(output_root / "runtime" / "runtime_report.yaml"),
            "oracle_result": str(output_root / "oracle" / "oracle_result.yaml"),
            "candidate": str(candidate_path),
            "impactlift_run_summary": str(impactlift_summary),
        },
        "claim_policy": {
            "vulnerability": "not_assessed",
            "cve": "not_assessed",
            "security_impact": "not_assessed",
        },
    }
    summary_path = output_root / "demo_run_summary.yaml"
    write_yaml(summary_path, summary)
    return {"summary": summary, "summary_path": summary_path, "candidate": candidate_path, "impactlift_summary": impactlift_summary}


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a frozen demo proposal through render/runtime/oracle/candidate/ImpactLift.")
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--out-root", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--mock-external-search-results", type=Path)
    parser.add_argument("--github-search", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=10)
    args = parser.parse_args()

    result = run_demo_replay(
        args.proposal,
        output_root=args.out_root,
        workspace=args.workspace,
        mock_external_search_results=args.mock_external_search_results,
        github_search=args.github_search,
        timeout_seconds=args.timeout_seconds,
    )
    print(f"[OK] Demo replay: {result['summary_path']}")
    print(f"[CANDIDATE] {result['candidate']}")
    print(f"[IMPACTLIFT] {result['impactlift_summary']}")


if __name__ == "__main__":
    main()
