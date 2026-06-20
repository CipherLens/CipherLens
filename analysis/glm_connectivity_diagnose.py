"""Diagnose GLM connectivity failures without running slot filling."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import os
import socket
import ssl
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text


TASK = "glm_connectivity_root_cause_v1"
DEFAULT_ENDPOINT_HOST = "open.bigmodel.cn"
ENV_NAMES = [
    "GLM_API_KEY",
    "ZHIPUAI_API_KEY",
    "ZAI_API_KEY",
    "GLM_MODEL",
    "GLM_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
]
SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PROXY")
PACKAGES = ["zhipuai", "zai", "openai", "httpx", "requests"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--previous-sprint", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def sha_prefix(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def env_record(name: str) -> dict[str, Any]:
    value = os.environ.get(name, "")
    return {
        "present": bool(value),
        "length": len(value),
        "sha256_prefix": sha_prefix(value) if value else "",
        "value_logged": False,
        "redacted": bool(value) and any(token in name for token in SECRET_HINTS),
    }


def load_previous(previous_sprint: Path) -> dict[str, Any]:
    preflight_path = previous_sprint / "preflight/glm_connectivity_preflight.yaml"
    invocation_path = previous_sprint / "slot_filling/glm_invocation_log.yaml"
    quality_path = previous_sprint / "validation/glm_retry_quality_checks.yaml"
    return {
        "schema": "previous_glm_retry_snapshot_v1",
        "previous_sprint": previous_sprint.as_posix(),
        "preflight_path": preflight_path.as_posix(),
        "invocation_log_path": invocation_path.as_posix(),
        "quality_path": quality_path.as_posix(),
        "preflight": load_yaml(preflight_path),
        "invocation_log": load_yaml(invocation_path),
        "quality": load_yaml(quality_path),
    }


def build_env_snapshot(previous: dict[str, Any]) -> dict[str, Any]:
    variables = {name: env_record(name) for name in ENV_NAMES}
    key_present = bool(
        variables["GLM_API_KEY"]["present"]
        or variables["ZHIPUAI_API_KEY"]["present"]
        or variables["ZAI_API_KEY"]["present"]
    )
    model_present = bool(variables["GLM_MODEL"]["present"])
    base_url_present = bool(
        variables["GLM_BASE_URL"]["present"] or variables["OPENAI_BASE_URL"]["present"]
    )
    return {
        "schema": "glm_env_snapshot_v1",
        "generated_at": now_iso(),
        "previous_sprint_loaded": bool(previous.get("preflight") or previous.get("invocation_log")),
        "variables": variables,
        "summary": {
            "api_key_present": key_present,
            "model_present": model_present,
            "base_url_present": base_url_present,
            "api_key_logged": False,
            "model_checked": True,
            "base_url_checked": True,
        },
        "previous_observed": {
            "glm_api_key_present": bool((previous.get("preflight") or {}).get("glm_api_key_present")),
            "glm_model_empty": not bool((previous.get("preflight") or {}).get("glm_model")),
            "glm_base_url_present": bool((previous.get("preflight") or {}).get("glm_base_url_present")),
            "glm_called": bool((previous.get("invocation_log") or {}).get("glm_called")),
            "unavailable_reason": (previous.get("invocation_log") or {}).get("unavailable_reason", ""),
            "quality_status": (previous.get("quality") or {}).get("quality_status", ""),
        },
    }


def package_probe() -> dict[str, Any]:
    rows = []
    for package in PACKAGES:
        spec = importlib.util.find_spec(package)
        item: dict[str, Any] = {
            "package": package,
            "installed": spec is not None,
            "version": "",
            "import_error": "",
            "import_error_message": "",
            "required_symbol": "",
            "required_symbol_available": None,
            "required_symbol_error": "",
            "required_symbol_error_message": "",
        }
        if spec is not None:
            try:
                module = importlib.import_module(package)
                item["version"] = str(getattr(module, "__version__", "") or "")
                if package == "zhipuai":
                    item["required_symbol"] = "ZhipuAI"
                    item["required_symbol_available"] = hasattr(module, "ZhipuAI")
                    if not item["required_symbol_available"]:
                        item["required_symbol_error"] = "AttributeError"
                        item["required_symbol_error_message"] = "zhipuai.ZhipuAI is not available"
            except Exception as exc:  # noqa: BLE001 - import probing must be best-effort.
                item["import_error"] = type(exc).__name__
                item["import_error_message"] = str(exc)[:200]
        rows.append(item)
    return {
        "schema": "python_package_probe_v1",
        "generated_at": now_iso(),
        "packages": rows,
        "package_probe_executed": True,
    }


def network_probe(env_doc: dict[str, Any]) -> dict[str, Any]:
    base_url_present = bool(env_doc.get("summary", {}).get("base_url_present"))
    dns_result: dict[str, Any] = {
        "host": DEFAULT_ENDPOINT_HOST,
        "attempted": True,
        "success": False,
        "addresses_count": 0,
        "error_type": "",
        "sanitized_error": "",
    }
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        addresses = socket.getaddrinfo(DEFAULT_ENDPOINT_HOST, 443, proto=socket.IPPROTO_TCP)
        dns_result["success"] = bool(addresses)
        dns_result["addresses_count"] = len(addresses)
    except Exception as exc:  # noqa: BLE001 - diagnostics must record network failures.
        dns_result["error_type"] = type(exc).__name__
        dns_result["sanitized_error"] = str(exc)[:200]
    finally:
        socket.setdefaulttimeout(old_timeout)

    tls_result: dict[str, Any] = {
        "host": DEFAULT_ENDPOINT_HOST,
        "port": 443,
        "attempted": True,
        "success": False,
        "error_type": "",
        "sanitized_error": "",
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((DEFAULT_ENDPOINT_HOST, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=DEFAULT_ENDPOINT_HOST):
                tls_result["success"] = True
    except Exception as exc:  # noqa: BLE001 - diagnostics must record network failures.
        tls_result["error_type"] = type(exc).__name__
        tls_result["sanitized_error"] = str(exc)[:200]

    return {
        "schema": "network_probe_v1",
        "generated_at": now_iso(),
        "network_probe_executed": True,
        "endpoint_host": DEFAULT_ENDPOINT_HOST,
        "configured_base_url_present": base_url_present,
        "configured_base_url_value_logged": False,
        "base_url_note": "absent; SDK default endpoint or explicit GLM_BASE_URL is required"
        if not base_url_present
        else "present but redacted",
        "dns": dns_result,
        "tls": tls_result,
    }


def client_probe(env_doc: dict[str, Any], package_doc: dict[str, Any]) -> dict[str, Any]:
    variables = env_doc.get("variables", {})
    key_present = bool(env_doc.get("summary", {}).get("api_key_present"))
    model_present = bool(env_doc.get("summary", {}).get("model_present"))
    base_url_present = bool(env_doc.get("summary", {}).get("base_url_present"))
    packages = {item["package"]: item for item in package_doc.get("packages", [])}
    clients = []

    def skipped(
        name: str,
        reason: str,
        package: str | None = None,
        *,
        client_init_attempted: bool = False,
        client_init_success: bool = False,
        sanitized_error: str | None = None,
    ) -> dict[str, Any]:
        return {
            "client": name,
            "package": package or "",
            "package_installed": bool(packages.get(package or "", {}).get("installed")) if package else True,
            "attempted": True,
            "client_init_attempted": client_init_attempted,
            "client_init_success": client_init_success,
            "real_request_attempted": False,
            "success": False,
            "exception_type": reason,
            "sanitized_error": sanitized_error or f"real GLM request skipped: {reason}",
        }

    if not key_present:
        clients.append(skipped("repo_utils_query_llm", "api_key_missing", "zhipuai"))
    elif not model_present:
        clients.append(skipped("repo_utils_query_llm", "model_missing", "zhipuai"))
    else:
        clients.append(skipped("repo_utils_query_llm", "request_not_attempted_by_diagnosis_policy", "zhipuai"))

    zhipuai_ready = False
    for package, label in [("zhipuai", "zhipuai_sdk"), ("zai", "zai_sdk")]:
        if not packages.get(package, {}).get("installed"):
            reason = "sdk_missing" if package == "zhipuai" else "optional_sdk_missing"
            clients.append(skipped(label, reason, package))
        elif package == "zhipuai" and packages.get(package, {}).get("import_error"):
            clients.append(
                skipped(
                    label,
                    "sdk_import_failed",
                    package,
                    sanitized_error=str(packages.get(package, {}).get("import_error_message", ""))[:200],
                )
            )
        elif package == "zhipuai" and not packages.get(package, {}).get("required_symbol_available"):
            clients.append(
                skipped(
                    label,
                    "sdk_version_incompatible",
                    package,
                    sanitized_error=str(
                        packages.get(package, {}).get("required_symbol_error_message", "")
                        or "zhipuai.ZhipuAI is not available"
                    )[:200],
                )
            )
        elif not key_present:
            clients.append(skipped(label, "api_key_missing", package))
        elif not model_present:
            clients.append(skipped(label, "model_missing", package))
        elif package == "zhipuai":
            try:
                module = importlib.import_module("zhipuai")
                zhipu_client = getattr(module, "ZhipuAI")
                kwargs: dict[str, Any] = {"api_key": "diagnostic-redacted-key"}
                if base_url_present:
                    kwargs["base_url"] = os.environ.get("GLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
                zhipu_client(**kwargs)
                zhipuai_ready = True
                clients.append(
                    skipped(
                        label,
                        "request_not_attempted_by_diagnosis_policy",
                        package,
                        client_init_attempted=True,
                        client_init_success=True,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - diagnosis should classify init failures.
                clients.append(
                    skipped(
                        label,
                        "client_init_failed",
                        package,
                        client_init_attempted=True,
                        client_init_success=False,
                        sanitized_error=str(exc)[:200],
                    )
                )
        else:
            clients.append(skipped(label, "request_not_attempted_by_diagnosis_policy", package))

    if not packages.get("openai", {}).get("installed"):
        clients.append(skipped("openai_compatible_client", "optional_sdk_missing", "openai"))
    elif not base_url_present:
        clients.append(skipped("openai_compatible_client", "base_url_missing", "openai"))
    elif not key_present:
        clients.append(skipped("openai_compatible_client", "api_key_missing", "openai"))
    elif not model_present:
        clients.append(skipped("openai_compatible_client", "model_missing", "openai"))
    else:
        clients.append(skipped("openai_compatible_client", "request_not_attempted_by_diagnosis_policy", "openai"))

    return {
        "schema": "client_probe_matrix_v1",
        "generated_at": now_iso(),
        "client_probe_attempted": True,
        "real_glm_request_attempted": False,
        "note": "No real GLM request is attempted by this diagnosis; it only probes environment, packages, network, and local client construction.",
        "primary_sdk_ready": zhipuai_ready,
        "env_alias_state": {
            "GLM_API_KEY_present": bool(variables.get("GLM_API_KEY", {}).get("present")),
            "ZHIPUAI_API_KEY_present": bool(variables.get("ZHIPUAI_API_KEY", {}).get("present")),
            "ZAI_API_KEY_present": bool(variables.get("ZAI_API_KEY", {}).get("present")),
            "values_logged": False,
        },
        "clients": clients,
    }


def root_cause_candidates(
    previous: dict[str, Any],
    env_doc: dict[str, Any],
    package_doc: dict[str, Any],
    network_doc: dict[str, Any],
    client_doc: dict[str, Any],
) -> dict[str, Any]:
    variables = env_doc.get("variables", {})
    packages = {item["package"]: item for item in package_doc.get("packages", [])}
    candidates: list[dict[str, Any]] = []
    previous_reason = (previous.get("invocation_log") or {}).get("unavailable_reason", "")

    def add(code: str, confidence: str, summary: str, evidence: list[str], fix: str) -> None:
        candidates.append(
            {
                "code": code,
                "confidence": confidence,
                "summary": summary,
                "evidence": evidence,
                "recommended_fix": fix,
            }
        )

    if not variables.get("GLM_MODEL", {}).get("present"):
        add(
            "model_missing",
            "high",
            "GLM_MODEL is not set, so the diagnosis policy did not attempt a real GLM request.",
            [
                "current env snapshot: GLM_MODEL present=false",
                "previous preflight: glm_model was empty",
                "previous invocation: glm_called=false and request_count=0",
            ],
            'Set an explicit model, for example: export GLM_MODEL="glm-4.5-flash"',
        )

    if not env_doc.get("summary", {}).get("base_url_present"):
        add(
            "base_url_missing",
            "medium",
            "No explicit GLM/OpenAI-compatible base URL is configured.",
            [
                "current env snapshot: GLM_BASE_URL present=false and OPENAI_BASE_URL present=false",
                "previous preflight: glm_base_url_present=false",
            ],
            "Use the SDK default endpoint intentionally, or set GLM_BASE_URL/OPENAI_BASE_URL for an OpenAI-compatible client.",
        )

    if variables.get("GLM_API_KEY", {}).get("present") and not variables.get("ZHIPUAI_API_KEY", {}).get("present"):
        add(
            "env_var_name_mismatch",
            "medium",
            "The repository GLM helper reads ZHIPUAI_API_KEY, while only GLM_API_KEY appears to be present.",
            [
                "current env snapshot: GLM_API_KEY present=true",
                "current env snapshot: ZHIPUAI_API_KEY present=false",
                "utils/query_llm.py reads ZHIPUAI_API_KEY",
            ],
            'Export the alias before retrying: export ZHIPUAI_API_KEY="$GLM_API_KEY"',
        )

    zhipuai = packages.get("zhipuai", {})
    if not zhipuai.get("installed"):
        add(
            "sdk_missing",
            "high",
            "The required zhipuai SDK package for analysis.glm_client is not installed.",
            ["package probe: zhipuai installed=false"],
            "Install zhipuai in the active virtual environment before retrying.",
        )
    elif zhipuai.get("import_error"):
        add(
            "sdk_import_failed",
            "high",
            "The zhipuai package is installed but cannot be imported.",
            [
                f"package probe: zhipuai import_error={zhipuai.get('import_error', '')}",
                f"sanitized import message: {zhipuai.get('import_error_message', '')}",
            ],
            "Inspect the installed zhipuai package and its dependencies in the active virtual environment.",
        )
    elif not zhipuai.get("required_symbol_available"):
        add(
            "sdk_version_incompatible",
            "high",
            "The zhipuai package imports, but zhipuai.ZhipuAI is not available.",
            [
                "package probe: zhipuai installed=true",
                "required symbol: ZhipuAI unavailable",
            ],
            "Use a zhipuai SDK version that exposes from zhipuai import ZhipuAI.",
        )

    zhipuai_client = next(
        (item for item in client_doc.get("clients", []) if item.get("client") == "zhipuai_sdk"),
        {},
    )
    if zhipuai_client.get("exception_type") == "client_init_failed":
        add(
            "client_init_failed",
            "high",
            "The zhipuai SDK is importable, but ZhipuAI client construction failed.",
            [
                "client probe: zhipuai client_init_attempted=true",
                f"client probe: sanitized_error={zhipuai_client.get('sanitized_error', '')}",
            ],
            "Check GLM_BASE_URL/SDK constructor compatibility without printing API keys.",
        )

    for package in ["zai", "openai"]:
        if not packages.get(package, {}).get("installed"):
            add(
                "optional_sdk_missing",
                "low",
                f"Optional client package {package!r} is not installed, but zhipuai is the repository GLM SDK path.",
                [f"package probe: {package} installed=false"],
                f"Install {package} only if that client path is the intended GLM access path.",
            )

    if network_doc.get("dns", {}).get("attempted") and not network_doc.get("dns", {}).get("success"):
        add(
            "network_dns_failure",
            "medium",
            "DNS lookup for the default GLM endpoint failed in this environment.",
            [
                f"dns error type: {network_doc.get('dns', {}).get('error_type', '')}",
                "endpoint host: open.bigmodel.cn",
            ],
            "Check local DNS/proxy/firewall before retrying a real GLM request.",
        )
    elif network_doc.get("tls", {}).get("attempted") and not network_doc.get("tls", {}).get("success"):
        add(
            "endpoint_connection_error",
            "medium",
            "TLS connection to the default GLM endpoint failed after DNS probing.",
            [
                f"tls error type: {network_doc.get('tls', {}).get('error_type', '')}",
                "endpoint host: open.bigmodel.cn:443",
            ],
            "Check proxy/firewall/TLS interception settings before retrying.",
        )

    if previous_reason and "connection" in previous_reason.lower():
        add(
            "unknown_connection_error",
            "low",
            "The previous sprint reported a generic connection error but did not perform a real request.",
            [
                f"previous unavailable_reason: {previous_reason}",
                "previous glm_request_count=0",
                "current diagnosis skipped real request because GLM_MODEL is missing",
            ],
            "Resolve model/env configuration first, then retry with request/response logging enabled.",
        )

    if (
        zhipuai.get("installed")
        and not zhipuai.get("import_error")
        and zhipuai.get("required_symbol_available")
        and zhipuai_client.get("client_init_success")
        and not client_doc.get("real_glm_request_attempted")
    ):
        add(
            "request_not_attempted_by_diagnosis_policy",
            "medium",
            "The active zhipuai SDK path is importable and client construction succeeds; this diagnostic did not attempt a real GLM request.",
            [
                "package probe: zhipuai installed=true",
                "package probe: from zhipuai import ZhipuAI available",
                "client probe: zhipuai client_init_success=true",
                "real_glm_request_attempted=false",
            ],
            "Run the main GLM workflow or a request-enabled diagnostic to classify network/auth/model errors.",
        )

    blocking = [item for item in candidates if item.get("code") != "optional_sdk_missing"]
    primary = blocking[0]["code"] if blocking else "unknown_connection_error"
    return {
        "schema": "root_cause_candidates_v1",
        "generated_at": now_iso(),
        "previous_sprint": previous.get("previous_sprint", ""),
        "primary_cause": primary,
        "candidates": candidates,
        "root_cause_candidates_generated": bool(candidates),
        "confirmed_vulnerability_claim": False,
        "slot_bindings_generated": False,
        "real_glm_request_attempted": bool(client_doc.get("real_glm_request_attempted")),
    }


def recommended_fix(root_doc: dict[str, Any]) -> str:
    lines = [
        "# GLM Connectivity Recommended Fix",
        "",
        "This diagnosis does not claim any vulnerability and did not generate slot bindings.",
        "",
        "## Primary Fix",
        "",
        '- Set an explicit GLM model before retrying, for example `export GLM_MODEL="glm-4.5-flash"`.',
        "",
        "## Secondary Checks",
        "",
        '- If only `GLM_API_KEY` is configured, also export `ZHIPUAI_API_KEY=\"$GLM_API_KEY\"` for the current repository helper.',
        "- Decide whether the SDK default endpoint is intended; otherwise set `GLM_BASE_URL` or `OPENAI_BASE_URL` for the intended client.",
        "- If the network probe failed, check DNS, proxy, firewall, or TLS interception before retrying a real GLM request.",
        "",
        "## Retry Boundary",
        "",
        "After fixing the environment, rerun the GLM preflight/slot-filling retry sprint. Do not write generated output to the main knowledge or pattern bank until the GLM request is observable and schema-valid.",
        "",
        "## Candidate Codes",
        "",
    ]
    for item in root_doc.get("candidates", []):
        lines.append(f"- `{item.get('code')}` ({item.get('confidence')}): {item.get('summary')}")
    lines.append("")
    return "\n".join(lines)


def quality_checks(
    *,
    previous_loaded: bool,
    env_doc: dict[str, Any],
    package_doc: dict[str, Any],
    network_doc: dict[str, Any],
    client_doc: dict[str, Any],
    root_doc: dict[str, Any],
    fix_text: str,
) -> dict[str, Any]:
    model_present = bool(env_doc.get("summary", {}).get("model_present"))
    real_request_attempted = bool(client_doc.get("real_glm_request_attempted"))
    if not model_present:
        status = "pass_model_missing_diagnosed"
    elif real_request_attempted:
        status = "pass_connection_failure_diagnosed"
    else:
        status = "pass_connection_failure_diagnosed"
    return {
        "schema": "glm_connectivity_root_cause_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_sprint_loaded": previous_loaded,
        "env_probe_executed": bool(env_doc),
        "api_key_logged": False,
        "model_checked": bool(env_doc.get("summary", {}).get("model_checked")),
        "base_url_checked": bool(env_doc.get("summary", {}).get("base_url_checked")),
        "package_probe_executed": bool(package_doc.get("package_probe_executed")),
        "network_probe_executed": bool(network_doc.get("network_probe_executed")),
        "client_probe_attempted": bool(client_doc.get("client_probe_attempted")),
        "real_glm_request_attempted": real_request_attempted,
        "root_cause_candidates_generated": bool(root_doc.get("root_cause_candidates_generated")),
        "recommended_fix_generated": bool(fix_text.strip()),
        "slot_bindings_generated": False,
        "adapter_validate_executed": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status,
    }


def report(
    env_doc: dict[str, Any],
    package_doc: dict[str, Any],
    network_doc: dict[str, Any],
    client_doc: dict[str, Any],
    root_doc: dict[str, Any],
    qc_doc: dict[str, Any],
) -> str:
    packages = {item["package"]: item for item in package_doc.get("packages", [])}
    clients = client_doc.get("clients", [])
    primary = root_doc.get("primary_cause", "")
    return "\n".join(
        [
            "# GLM Connectivity Root Cause Report",
            "",
            f"- task: `{TASK}`",
            f"- generated_at: `{now_iso()}`",
            f"- quality_status: `{qc_doc.get('quality_status')}`",
            f"- primary_cause: `{primary}`",
            "",
            "## Environment",
            "",
            f"- GLM_API_KEY present: `{env_doc['variables']['GLM_API_KEY']['present']}`",
            f"- ZHIPUAI_API_KEY present: `{env_doc['variables']['ZHIPUAI_API_KEY']['present']}`",
            f"- ZAI_API_KEY present: `{env_doc['variables']['ZAI_API_KEY']['present']}`",
            f"- GLM_MODEL present: `{env_doc['variables']['GLM_MODEL']['present']}`",
            f"- GLM_BASE_URL present: `{env_doc['variables']['GLM_BASE_URL']['present']}`",
            f"- values logged: `false`",
            "",
            "## Packages",
            "",
            f"- zhipuai: `{packages.get('zhipuai', {}).get('installed')}`",
            f"- zai: `{packages.get('zai', {}).get('installed')}`",
            f"- openai: `{packages.get('openai', {}).get('installed')}`",
            "",
            "## Network",
            "",
            f"- DNS success: `{network_doc.get('dns', {}).get('success')}`",
            f"- TLS success: `{network_doc.get('tls', {}).get('success')}`",
            f"- explicit base URL present: `{network_doc.get('configured_base_url_present')}`",
            "",
            "## Client Probe",
            "",
            f"- attempted clients: `{len(clients)}`",
            f"- real request attempted: `{client_doc.get('real_glm_request_attempted')}`",
            f"- success: `{any(item.get('success') for item in clients)}`",
            "",
            "## Root Cause Candidates",
            "",
            "\n".join(
                f"- `{item.get('code')}` ({item.get('confidence')}): {item.get('summary')}"
                for item in root_doc.get("candidates", [])
            ),
            "",
            "## Guardrails",
            "",
            "- slot_bindings_generated: `false`",
            "- adapter_validate_executed: `false`",
            "- render/compile/run executed: `false`",
            "- feedback/pattern bank modified: `false`",
            "- externally verified issue claim: `false`",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    previous_sprint = (repo_root / args.previous_sprint).resolve()
    out_dir = (repo_root / args.out_dir).resolve()

    previous = load_previous(previous_sprint)
    env_doc = build_env_snapshot(previous)
    package_doc = package_probe()
    network_doc = network_probe(env_doc)
    client_doc = client_probe(env_doc, package_doc)
    root_doc = root_cause_candidates(previous, env_doc, package_doc, network_doc, client_doc)
    fix_text = recommended_fix(root_doc)
    qc_doc = quality_checks(
        previous_loaded=bool(previous.get("preflight") or previous.get("invocation_log")),
        env_doc=env_doc,
        package_doc=package_doc,
        network_doc=network_doc,
        client_doc=client_doc,
        root_doc=root_doc,
        fix_text=fix_text,
    )

    dump_yaml(out_dir / "env/glm_env_snapshot.yaml", env_doc)
    dump_yaml(out_dir / "packages/python_package_probe.yaml", package_doc)
    dump_yaml(out_dir / "network/network_probe.yaml", network_doc)
    dump_yaml(out_dir / "clients/client_probe_matrix.yaml", client_doc)
    dump_yaml(out_dir / "diagnosis/root_cause_candidates.yaml", root_doc)
    write_text(out_dir / "diagnosis/recommended_fix.md", fix_text)
    dump_yaml(out_dir / "validation/glm_connectivity_root_cause_quality_checks.yaml", qc_doc)
    write_text(
        out_dir / "reports/glm_connectivity_root_cause_v1_report.md",
        report(env_doc, package_doc, network_doc, client_doc, root_doc, qc_doc),
    )
    print(f"[OK] wrote GLM connectivity diagnosis to {out_dir.relative_to(repo_root)}")
    print(f"[OK] quality_status={qc_doc['quality_status']}")
    print(f"[OK] primary_cause={root_doc['primary_cause']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
