#!/usr/bin/env python3
"""Load card, taxonomy, and mapping-gate contracts for mainline planning."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml


TARGET_ALIASES = {
    "openssl": "openssl",
    "openssl-3.5.5-asan": "openssl",
    "openssl-3.5.6-asan": "openssl",
    "mbedtls": "mbedtls-4.1.0",
    "mbedtls-3.6.4": "mbedtls-3.6.4",
    "mbedtls-3.6.4-asan": "mbedtls-3.6.4",
    "mbedtls-4.1.0": "mbedtls-4.1.0",
    "mbedtls-4.1.0-asan": "mbedtls-4.1.0",
    "botan": "botan-3.10.0",
    "botan-3.10.0": "botan-3.10.0",
    "botan-3.10.0-asan": "botan-3.10.0",
    "wolfssl": "wolfssl",
    "wolfssl-asan": "wolfssl",
}

TARGET_RUNTIME_STATUS = {
    "openssl": "baseline_only",
    "mbedtls-3.6.4": "runtime_ready",
    "mbedtls-4.1.0": "runtime_ready",
    "botan-3.10.0": "runtime_ready",
    "wolfssl": "blocked_runtime",
}

DEFAULT_WOLFSSL_ROOT = "/home/wen/work/install-wolfssl-5.9.1-asan"


def load_yaml_file(path: Path) -> Any:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def split_csv(value: str | list[str]) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def normalize_target_name(target: str) -> str:
    return TARGET_ALIASES.get(target, target)


def wolfssl_preflight() -> dict[str, Any]:
    root = Path(os.environ.get("WOLFSSL_ROOT", DEFAULT_WOLFSSL_ROOT)).expanduser()
    include_dir = Path(os.environ.get("WOLFSSL_INCLUDE_DIR", root / "include")).expanduser()
    lib_dir = Path(os.environ.get("WOLFSSL_LIB_DIR", root / "lib")).expanduser()
    config_tool = root / "bin" / "wolfssl-config"
    pkg_config = shutil.which("pkg-config")
    so_path = lib_dir / "libwolfssl.so"
    static_path = lib_dir / "libwolfssl.a"
    checks = {
        "install_root_exists": root.exists(),
        "options_h": (include_dir / "wolfssl" / "options.h").exists(),
        "ssl_h": (include_dir / "wolfssl" / "ssl.h").exists(),
        "library": so_path.exists() or static_path.exists(),
        "config_tool": config_tool.exists(),
        "pkg_config": False,
    }
    pkg_version = ""
    if pkg_config:
        env = os.environ.copy()
        prior = env.get("PKG_CONFIG_PATH", "")
        pkg_path = str(lib_dir / "pkgconfig")
        env["PKG_CONFIG_PATH"] = f"{pkg_path}:{prior}" if prior else pkg_path
        proc = subprocess.run(
            [pkg_config, "--modversion", "wolfssl"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        )
        checks["pkg_config"] = proc.returncode == 0
        pkg_version = proc.stdout.strip()
    passed = all(checks.values())
    missing = [key for key, ok in checks.items() if not ok]
    return {
        "runtime_status": "runtime_ready" if passed else "blocked_runtime",
        "source_version": "wolfSSL 5.9.1 / v5.9.1-stable",
        "source_path": "/home/wen/work/clean_sources/wolfssl",
        "install_root": str(root),
        "include_dir": str(include_dir),
        "lib_dir": str(lib_dir),
        "config_tool": str(config_tool),
        "pkg_config_version": pkg_version,
        "sanitizer_build": "asan_ubsan",
        "preflight_status": "pass" if passed else "fail",
        "checks": checks,
        "missing": missing,
    }


def target_preflight(target: str) -> dict[str, Any]:
    canonical = normalize_target_name(target)
    if canonical == "wolfssl":
        return wolfssl_preflight()
    status = TARGET_RUNTIME_STATUS.get(canonical, "unknown_target")
    return {
        "runtime_status": status,
        "preflight_status": "pass" if status in {"runtime_ready", "baseline_only"} else "fail",
        "checks": {},
        "missing": [],
    }


def target_runtime_status(target: str) -> str:
    canonical = normalize_target_name(target)
    if canonical == "wolfssl":
        return wolfssl_preflight()["runtime_status"]
    return TARGET_RUNTIME_STATUS.get(canonical, "unknown_target")


def load_yaml_tree(root: Path) -> dict[str, Any]:
    items: dict[str, Any] = {}
    if not root.exists():
        return items
    for path in sorted(root.rglob("*.yaml")):
        key = path.relative_to(root).with_suffix("").as_posix()
        items[key] = load_yaml_file(path)
    return items


def _index_by_id(items: list[dict[str, Any]], id_key: str = "id") -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = item.get(id_key)
        if item_id:
            indexed[str(item_id)] = item
    return indexed


def _missing_fields(cards: dict[str, Any], required: list[str]) -> list[dict[str, str]]:
    missing: list[dict[str, str]] = []
    for card_id, card in cards.items():
        if not isinstance(card, dict):
            missing.append({"card": card_id, "field": "<document>", "reason": "not_a_mapping"})
            continue
        for field in required:
            if field not in card or card.get(field) in (None, "", []):
                missing.append({"card": card_id, "field": field, "reason": "missing_or_empty"})
    return missing


def load_card_bundle(repo_root: Path) -> dict[str, Any]:
    config_root = repo_root / "config"
    knowledge_root = repo_root / "knowledge_raw"
    taxonomy = load_yaml_file(config_root / "family_taxonomy.yaml")
    coverage = load_yaml_file(config_root / "card_coverage_matrix.yaml")
    contract = load_yaml_file(config_root / "orchestrator_card_contract.yaml")
    stage_contract = load_yaml_file(config_root / "mainline_stage_contract.yaml")

    family_cards = load_yaml_tree(knowledge_root / "family_cards")
    pattern_cards = load_yaml_tree(knowledge_root / "pattern_cards")
    api_cards = load_yaml_tree(knowledge_root / "api_cards")
    constraints = load_yaml_tree(knowledge_root / "constraints")
    call_sequences = load_yaml_tree(knowledge_root / "call_sequences")
    negative_feedback = load_yaml_tree(knowledge_root / "negative_feedback")
    mapping_gate = load_yaml_tree(knowledge_root / "mapping_gate")

    framework_families = _index_by_id(taxonomy.get("framework_families", []))
    concrete_patterns = _index_by_id(taxonomy.get("concrete_patterns", []))
    coverage_by_family = {
        row.get("framework_family"): row
        for row in coverage.get("coverage", [])
        if isinstance(row, dict) and row.get("framework_family")
    }

    required = contract.get("required_fields", {}) if isinstance(contract, dict) else {}
    missing_required_fields = []
    missing_required_fields.extend(
        _missing_fields(family_cards, required.get("framework_family_card", []))
    )
    missing_required_fields.extend(_missing_fields(pattern_cards, required.get("concrete_pattern_card", [])))

    summary = {
        "taxonomy_loaded": bool(taxonomy),
        "coverage_loaded": bool(coverage),
        "contract_loaded": bool(contract),
        "stage_contract_loaded": bool(stage_contract),
        "framework_family_count": len(framework_families),
        "concrete_pattern_count": len(concrete_patterns),
        "target_count": len(TARGET_RUNTIME_STATUS),
        "framework_family_cards_loaded": len(family_cards),
        "pattern_cards_loaded": len(pattern_cards),
        "target_api_cards_loaded": len(api_cards),
        "constraints_loaded": len(constraints),
        "call_sequences_loaded": len(call_sequences),
        "negative_feedback_loaded": len(negative_feedback),
        "mapping_gate_loaded": len(mapping_gate),
        "missing_required_field_count": len(missing_required_fields),
        "needs_human_review_count": sum(1 for row in coverage_by_family.values() if row.get("needs_human_review")),
        "blocked_target_count": sum(1 for target in TARGET_RUNTIME_STATUS if target_runtime_status(target) == "blocked_runtime"),
    }

    return {
        "taxonomy": taxonomy,
        "coverage": coverage,
        "contract": contract,
        "stage_contract": stage_contract,
        "framework_families": framework_families,
        "concrete_patterns": concrete_patterns,
        "coverage_by_family": coverage_by_family,
        "family_cards": family_cards,
        "pattern_cards": pattern_cards,
        "api_cards": api_cards,
        "constraints": constraints,
        "call_sequences": call_sequences,
        "negative_feedback": negative_feedback,
        "mapping_gate": mapping_gate,
        "summary": summary,
        "missing_required_fields": missing_required_fields,
    }
