#!/usr/bin/env python3
"""Fix one failed pkcs_container_parsing -> OpenSSL slot binding.

This script only produces YAML slot-binding fixup artifacts. It never renders C,
compiles, runs PoCs, or mutates adapter_recipe/slot_filling_plan inputs.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


EXPECTED_ADAPTER_ID = "pkcs_container_parsing_openssl"
FAMILY = "pkcs_container_parsing"
TARGET_LIBRARY = "openssl"
SOURCE_LIBRARY = "wolfssl"
ALLOWED_TRIGGER_APIS = {"PKCS12_parse", "PKCS7_verify"}
ALLOWED_CLEANUP_APIS = {"PKCS12_free", "PKCS7_free"}
FORBIDDEN_APIS = {"d2i_PKCS7"}
FORBIDDEN_LIBRARY_TERMS = {"mbedtls"}
REQUIRED_FIELDS = [
    "schema",
    "adapter_id",
    "family",
    "source_library",
    "target_library",
    "binding_status",
    "api_mapping",
    "type_mapping",
    "cleanup_mapping",
    "oracle_mapping",
    "input_mapping",
    "mutation_slot_mapping",
    "validation_notes",
    "risk_notes",
]
C_MARKERS = [
    r"#\s*include\b",
    r"\bint\s+main\s*\(",
    r"\bvoid\s+main\s*\(",
    r"\bstatic\s+(?:int|void|char|unsigned|size_t)\b",
    r"\breturn\s+0\s*;",
    r"\bgcc\b",
    r"\bclang\b",
    r"\bcmake\b",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=False), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_md(path: Path, title: str, obj: Any) -> None:
    write_text(path, f"# {title}\n\n```yaml\n{yaml.safe_dump(obj, sort_keys=False)}```\n")


def extract_yaml(raw: str) -> tuple[Any | None, list[str]]:
    notes: list[str] = []
    text = raw.strip()
    fence = re.search(r"```(?:yaml|yml)?\s*(.*?)```", text, re.S | re.I)
    if fence:
        notes.append("markdown_fence_stripped")
        text = fence.group(1).strip()
    try:
        return yaml.safe_load(text), notes
    except yaml.YAMLError as exc:
        notes.append(f"yaml_parse_error: {exc}")
        return None, notes


def contains_c(raw: str, obj: Any | None = None) -> bool:
    text = raw
    if obj is not None:
        text += "\n" + yaml.safe_dump(obj, sort_keys=False)
    return any(re.search(pattern, text, re.I) for pattern in C_MARKERS)


def plan_echo_detected(obj: Any, raw: str) -> bool:
    if isinstance(obj, dict) and obj.get("schema") == "adapter_slot_filling_plan_v1":
        return True
    markers = [
        "selected_mask_units_summary:",
        "validation_before_render:",
        "glm_policy:",
        "template_level: family",
        "slot_groups:",
    ]
    return sum(1 for marker in markers if marker in raw) >= 3


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if "bindings" in value and isinstance(value["bindings"], list):
            return value["bindings"]
        if "input_slots" in value and isinstance(value["input_slots"], list):
            return value["input_slots"]
        if "primary" in value or "target_observables" in value:
            return [value]
        return [{"slot_name": k, **v} if isinstance(v, dict) else {"slot_name": k, "value": v} for k, v in value.items()]
    return [value]


def collect_api_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, str):
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value):
            if token.startswith(("PKCS", "d2i_", "mbedtls")):
                names.add(token)
    elif isinstance(value, list):
        for item in value:
            names.update(collect_api_names(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            names.update(collect_api_names(key))
            names.update(collect_api_names(item))
    return names


def normalize_binding(parsed: Any, raw: str, parse_notes: list[str]) -> dict[str, Any]:
    if not isinstance(parsed, dict):
        return {
            "schema": "adapter_slot_bindings_v1",
            "adapter_id": EXPECTED_ADAPTER_ID,
            "family": FAMILY,
            "source_library": SOURCE_LIBRARY,
            "target_library": TARGET_LIBRARY,
            "binding_status": "validation_failed",
            "api_mapping": [],
            "type_mapping": [],
            "cleanup_mapping": [],
            "oracle_mapping": {"primary": None, "secondary": [], "target_observables": [], "notes": ""},
            "input_mapping": {"input_slots": [], "preservation_requirements": [], "notes": ""},
            "mutation_slot_mapping": [],
            "validation_notes": {
                "no_confirmed_equivalence_claim": True,
                "blocked_targets_respected": True,
                "no_c_generation": not contains_c(raw),
                "cleanup_mapping_present": False,
                "oracle_mapping_present": False,
            },
            "risk_notes": ["GLM output was not a YAML mapping."],
            "_parse_notes": parse_notes,
        }

    if "slot_bindings" in parsed and isinstance(parsed["slot_bindings"], dict):
        parsed = parsed["slot_bindings"]

    obj = dict(parsed)
    obj["schema"] = "adapter_slot_bindings_v1"
    obj["adapter_id"] = EXPECTED_ADAPTER_ID
    obj["family"] = FAMILY
    obj["source_library"] = SOURCE_LIBRARY
    obj["target_library"] = TARGET_LIBRARY
    obj.setdefault("binding_status", "filled_by_glm")
    obj.setdefault("api_mapping", [])
    obj.setdefault("type_mapping", [])
    obj.setdefault("cleanup_mapping", [])
    obj.setdefault("oracle_mapping", {"primary": None, "secondary": [], "target_observables": [], "notes": ""})
    obj.setdefault("input_mapping", {"input_slots": [], "preservation_requirements": [], "notes": ""})
    obj.setdefault("mutation_slot_mapping", [])
    obj.setdefault("validation_notes", {})
    obj.setdefault("risk_notes", [])
    obj["_parse_notes"] = parse_notes
    return obj


def selected_trigger_apis(binding: dict[str, Any]) -> set[str]:
    apis = set()
    api_mapping = binding.get("api_mapping")
    for name in collect_api_names(api_mapping):
        if name in ALLOWED_TRIGGER_APIS or name in FORBIDDEN_APIS or name.lower().startswith("mbedtls"):
            apis.add(name)
    return apis


def cleanup_apis(binding: dict[str, Any]) -> set[str]:
    return {name for name in collect_api_names(binding.get("cleanup_mapping")) if name in ALLOWED_CLEANUP_APIS or name in FORBIDDEN_APIS}


def confirmed_equivalence_claim(binding: dict[str, Any]) -> bool:
    text = yaml.safe_dump(binding, sort_keys=False).lower()
    forbidden_truths = [
        "confirmed_equivalence: true",
        "confirmed equivalence: true",
        "confirmed: true",
        "equivalence_confirmed: true",
    ]
    return any(term in text for term in forbidden_truths)


def nonempty_mapping(value: Any) -> bool:
    if isinstance(value, dict):
        if "bindings" in value:
            return bool(value.get("bindings"))
        if "primary" in value or "target_observables" in value:
            return bool(value.get("primary") or value.get("target_observables") or value.get("secondary"))
        if "input_slots" in value:
            return bool(value.get("input_slots"))
        return bool(value)
    return bool(value)


def validate(binding: dict[str, Any], raw: str) -> dict[str, Any]:
    trigger_apis = selected_trigger_apis(binding)
    cleanup = cleanup_apis(binding)
    forbidden_used = sorted((trigger_apis | cleanup).intersection(FORBIDDEN_APIS))
    mbedtls_used = any(term in yaml.safe_dump(binding, sort_keys=False).lower() for term in FORBIDDEN_LIBRARY_TERMS)
    allowed_only = all(api in ALLOWED_TRIGGER_APIS for api in trigger_apis) and all(api in ALLOWED_CLEANUP_APIS for api in cleanup)
    required_present = all(field in binding for field in REQUIRED_FIELDS)
    api_nonempty = nonempty_mapping(binding.get("api_mapping"))
    cleanup_nonempty = nonempty_mapping(binding.get("cleanup_mapping"))
    oracle_nonempty = nonempty_mapping(binding.get("oracle_mapping"))
    input_present = "input_mapping" in binding and nonempty_mapping(binding.get("input_mapping"))
    mutation_present = "mutation_slot_mapping" in binding and nonempty_mapping(binding.get("mutation_slot_mapping"))
    no_c = not contains_c(raw, binding)
    echo = plan_echo_detected(binding, raw)
    no_confirmed = not confirmed_equivalence_claim(binding)
    blocked_ok = not forbidden_used and not mbedtls_used

    notes: list[str] = []
    if not trigger_apis:
        notes.append("api_mapping has no allowed target trigger API")
    if not cleanup:
        notes.append("cleanup_mapping has no recognized OpenSSL cleanup API")
    if forbidden_used:
        notes.append(f"forbidden API used: {', '.join(forbidden_used)}")
    if mbedtls_used:
        notes.append("mbedTLS term detected in binding")
    if echo:
        notes.append("GLM output appears to echo slot_filling_plan")

    pass_conditions = [
        required_present,
        api_nonempty,
        cleanup_nonempty,
        oracle_nonempty,
        input_present,
        mutation_present,
        blocked_ok,
        no_confirmed,
        no_c,
        allowed_only,
        not echo,
    ]

    status = "pass" if all(pass_conditions) else "fail"
    if binding.get("binding_status") == "glm_unavailable":
        status = "glm_unavailable"
    elif binding.get("binding_status") == "manual_review_needed":
        status = "manual_review_needed"
    elif status == "fail" and not cleanup and trigger_apis and not forbidden_used and not echo:
        status = "manual_review_needed"
        binding["binding_status"] = "manual_review_needed"
        notes.append("manual_review_needed_cleanup_mapping")
    elif status == "fail":
        binding["binding_status"] = "validation_failed"

    validation = {
        "adapter_id": EXPECTED_ADAPTER_ID,
        "slot_bindings_exists": True,
        "binding_status": binding.get("binding_status"),
        "all_required_top_level_fields_present": required_present,
        "api_mapping_present": "api_mapping" in binding,
        "api_mapping_nonempty": api_nonempty,
        "cleanup_mapping_present": "cleanup_mapping" in binding,
        "cleanup_mapping_nonempty": cleanup_nonempty,
        "oracle_mapping_present": "oracle_mapping" in binding,
        "oracle_mapping_nonempty": oracle_nonempty,
        "input_mapping_present": input_present,
        "mutation_slot_mapping_present": mutation_present,
        "blocked_targets_respected": blocked_ok,
        "no_confirmed_equivalence_claim": no_confirmed,
        "no_c_generation_detected": no_c,
        "allowed_target_apis_only": allowed_only,
        "plan_echo_detected": echo,
        "selected_trigger_apis": sorted(trigger_apis),
        "cleanup_apis": sorted(cleanup),
        "forbidden_api_used": forbidden_used,
        "validation_status": status,
        "notes": notes,
    }
    return validation


def make_glm_unavailable(reason: str) -> dict[str, Any]:
    return {
        "schema": "adapter_slot_bindings_v1",
        "adapter_id": EXPECTED_ADAPTER_ID,
        "family": FAMILY,
        "source_library": SOURCE_LIBRARY,
        "target_library": TARGET_LIBRARY,
        "binding_status": "glm_unavailable",
        "api_mapping": [],
        "type_mapping": [],
        "cleanup_mapping": [],
        "oracle_mapping": {"primary": None, "secondary": [], "target_observables": [], "notes": ""},
        "input_mapping": {"input_slots": [], "preservation_requirements": [], "notes": ""},
        "mutation_slot_mapping": [],
        "validation_notes": {
            "no_confirmed_equivalence_claim": True,
            "blocked_targets_respected": True,
            "no_c_generation": True,
            "cleanup_mapping_present": False,
            "oracle_mapping_present": False,
        },
        "risk_notes": [reason],
    }


def build_prompt(slot_plan: dict[str, Any], adapter_recipe: dict[str, Any], family_files: dict[str, Any]) -> str:
    mutation_slots = slot_plan.get("slot_groups", {}).get("mutation_slot_mapping", {}).get("mutation_slots", [])
    input_slots = slot_plan.get("slot_groups", {}).get("input_mapping", {}).get("input_slots", [])
    return f"""Output YAML only. No explanation. No markdown. No ``` fences.
Do not repeat the slot_filling_plan. Do not generate C. Do not generate a harness.

Task: fill ONLY pkcs_container_parsing -> OpenSSL slot_bindings.

Allowed trigger target APIs:
- PKCS12_parse
- PKCS7_verify

Allowed cleanup target APIs:
- PKCS12_free
- PKCS7_free

Forbidden:
- d2i_PKCS7
- any mbedTLS API
- confirmed_equivalence: true
- any C code, #include, int main, function body, compiler command

Required YAML shape:
schema: adapter_slot_bindings_v1
adapter_id: pkcs_container_parsing_openssl
family: pkcs_container_parsing
source_library: wolfssl
target_library: openssl
binding_status: filled_by_glm
api_mapping:
  - source_slot: wc_PKCS12_parse
    source_api: wc_PKCS12_parse
    target_api: PKCS12_parse
    mapping_gate_status: usable_for_adapter
    confirmed_equivalence: false
    notes: candidate mapping only
  - source_slot: wc_PKCS7_VerifySignedData
    source_api: wc_PKCS7_VerifySignedData
    target_api: PKCS7_verify
    mapping_gate_status: usable_for_adapter
    confirmed_equivalence: false
    notes: candidate mapping only
type_mapping: []
cleanup_mapping:
  - target_api: PKCS12_free
    applies_to: PKCS12 object if allocated
    required: true
  - target_api: PKCS7_free
    applies_to: PKCS7 object if allocated
    required: true
oracle_mapping:
  primary: parser_reject_accept
  secondary:
    - return_code_semantics
  target_observables:
    - return_code
    - parser_result
    - output_state
  notes: candidate oracle only; no vulnerability claim
input_mapping:
  input_slots: []
  preservation_requirements:
    - preserve family-level vulnerability path
    - preserve input length/buffer pairing
    - do not introduce blocked target API
  notes: bind only existing family input slots
mutation_slot_mapping: []
validation_notes:
  no_confirmed_equivalence_claim: true
  blocked_targets_respected: true
  no_c_generation: true
  cleanup_mapping_present: true
  oracle_mapping_present: true
risk_notes:
  - candidate mapping only; adapter_validate/render/compile not run

Fill input_mapping.input_slots using exactly these slots:
{yaml.safe_dump(input_slots, sort_keys=False)}

Fill mutation_slot_mapping using exactly these mutation slots:
{yaml.safe_dump(mutation_slots, sort_keys=False)}

Minimal context:
adapter_recipe.target_mapping:
{yaml.safe_dump(adapter_recipe.get("target_mapping", {}), sort_keys=False)}

family mutation slots:
{yaml.safe_dump(family_files.get("mutation_slots", {}).get("mutation_slots", []), sort_keys=False)}

family oracle plan:
{yaml.safe_dump(family_files.get("oracle_plan", {}), sort_keys=False)}
"""


def call_glm(prompt: str) -> tuple[str | None, str | None]:
    try:
        from utils.query_llm import get_glm_response
    except Exception as exc:
        return None, f"import_error: {exc}"
    messages = [
        {
            "role": "system",
            "content": "Return YAML only. Never output markdown, C code, or explanations.",
        },
        {"role": "user", "content": prompt},
    ]
    try:
        return get_glm_response(messages), None
    except Exception as exc:
        return None, f"call_error: {type(exc).__name__}: {exc}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-id", required=True)
    parser.add_argument("--slot-plan", required=True)
    parser.add_argument("--slot-schema", required=True)
    parser.add_argument("--prompt-context", required=True)
    parser.add_argument("--validation-rules", required=True)
    parser.add_argument("--adapter-recipe", required=True)
    parser.add_argument("--family-template", required=True)
    parser.add_argument("--previous-raw", required=True)
    parser.add_argument("--previous-bindings", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-proposed-replacement", choices=["true", "false"], default="false")
    parser.add_argument("--glm-mode", choices=["auto", "off"], default="auto")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.adapter_id != EXPECTED_ADAPTER_ID:
        raise SystemExit(f"this fixup script only handles {EXPECTED_ADAPTER_ID}")

    out_dir = Path(args.out_dir)
    for sub in [
        "input",
        "failure_analysis",
        "prompt_fixup",
        "glm_outputs",
        "slot_bindings/pkcs_container_parsing/openssl",
        "validation",
        "write_summary",
        "reports",
        "logs",
    ]:
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    slot_plan = load_yaml(Path(args.slot_plan)) or {}
    slot_schema = load_yaml(Path(args.slot_schema)) or {}
    validation_rules = load_yaml(Path(args.validation_rules)) or {}
    adapter_recipe = load_yaml(Path(args.adapter_recipe)) or {}
    previous_bindings = load_yaml(Path(args.previous_bindings)) or {}
    previous_raw = Path(args.previous_raw).read_text(encoding="utf-8") if Path(args.previous_raw).exists() else ""
    prompt_context = Path(args.prompt_context).read_text(encoding="utf-8") if Path(args.prompt_context).exists() else ""
    family_template = Path(args.family_template)
    family_files = {
        "family_template_meta": load_yaml(family_template / "family_template_meta.yaml") or {},
        "selected_mask_units": load_yaml(family_template / "selected_mask_units.yaml") or {},
        "mutation_slots": load_yaml(family_template / "mutation_slots.yaml") or {},
        "oracle_plan": load_yaml(family_template / "oracle_plan.yaml") or {},
        "adapter_scope": load_yaml(family_template / "adapter_scope.yaml") or {},
    }
    current_target = Path("adapter_recipes/wolfssl_family/pkcs_container_parsing/openssl/slot_bindings.yaml")
    current_target_exists = current_target.exists()
    current_target_bindings = load_yaml(current_target) if current_target_exists else None

    previous_plan_echo = plan_echo_detected(previous_bindings, previous_raw)
    previous_api_missing = not nonempty_mapping(previous_bindings.get("api_mapping"))
    previous_cleanup_missing = not nonempty_mapping(previous_bindings.get("cleanup_mapping"))
    previous_oracle_missing = not nonempty_mapping(previous_bindings.get("oracle_mapping"))
    previous_input_missing = not nonempty_mapping(previous_bindings.get("input_mapping"))
    previous_mutation_missing = not nonempty_mapping(previous_bindings.get("mutation_slot_mapping"))
    previous_c_generation = contains_c(previous_raw, previous_bindings)
    previous_forbidden_used = bool(collect_api_names(previous_bindings).intersection(FORBIDDEN_APIS))
    previous_confirmed = confirmed_equivalence_claim(previous_bindings)

    input_summary = {
        "schema": "pkcs_fixup_input_summary_v1",
        "generated_at": now_iso(),
        "adapter_id": EXPECTED_ADAPTER_ID,
        "family": FAMILY,
        "target_library": TARGET_LIBRARY,
        "scope": "only pkcs_container_parsing -> OpenSSL",
        "not_touched": [
            "asn1_nested_boundary -> OpenSSL",
            "asn1_nested_boundary -> mbedTLS",
            "blocked targets",
        ],
        "forbidden_actions": [
            "no_render",
            "no_compile_run",
            "no_poc_run",
            "no_c_generation",
            "no_adapter_recipe_yaml_modification",
            "no_slot_filling_plan_yaml_modification",
            "no_family_template_modification",
            "no_knowledge_raw_modification",
            "no_knowledge_base_modification",
            "no_pattern_bank_modification",
            "no_scheduler_seed_modification",
            "no_commit_push_git_add",
        ],
        "inputs": {
            "slot_plan": args.slot_plan,
            "slot_schema": args.slot_schema,
            "prompt_context": args.prompt_context,
            "validation_rules": args.validation_rules,
            "adapter_recipe": args.adapter_recipe,
            "family_template": args.family_template,
            "previous_raw": args.previous_raw,
            "previous_bindings": args.previous_bindings,
            "current_adapter_recipe_slot_bindings": str(current_target) if current_target_exists else None,
        },
        "previous_failure": "GLM echoed the slot filling plan and did not form valid api/cleanup/oracle bindings.",
        "yaml_slot_bindings_only": True,
    }
    dump_yaml(out_dir / "input" / "pkcs_fixup_input_summary.yaml", input_summary)
    write_md(out_dir / "input" / "pkcs_fixup_input_summary.md", "PKCS Fixup Input Summary", input_summary)

    failure = {
        "schema": "pkcs_slot_filling_failure_analysis_v1",
        "adapter_id": EXPECTED_ADAPTER_ID,
        "family": FAMILY,
        "target_library": TARGET_LIBRARY,
        "previous_binding_status": previous_bindings.get("binding_status"),
        "previous_validation_status": "fail",
        "failure_reasons": [
            reason
            for reason, present in [
                ("plan_echo", previous_plan_echo),
                ("missing_api_mapping", previous_api_missing),
                ("missing_cleanup_mapping", previous_cleanup_missing),
                ("missing_oracle_mapping", previous_oracle_missing),
                ("missing_input_mapping", previous_input_missing),
                ("missing_mutation_slot_mapping", previous_mutation_missing),
            ]
            if present
        ],
        "plan_echo": previous_plan_echo,
        "api_mapping_missing": previous_api_missing,
        "cleanup_mapping_missing": previous_cleanup_missing,
        "oracle_mapping_missing": previous_oracle_missing,
        "input_mapping_missing": previous_input_missing,
        "mutation_slot_mapping_missing": previous_mutation_missing,
        "c_generation_detected": previous_c_generation,
        "blocked_api_used": previous_forbidden_used,
        "confirmed_equivalence_claim": previous_confirmed,
        "old_prompt_risks": [
            "prompt bundle was too long and included the full slot_filling_plan",
            "GLM copied context instead of filling the minimal slot_bindings schema",
        ],
        "recommended_fix": "Use a shorter YAML-only prompt with explicit allowed APIs, forbidden APIs, and a minimal output skeleton.",
        "notes": [
            "Do not accept plan echo as valid slot binding.",
            "Do not use d2i_PKCS7 or any mbedTLS API.",
        ],
    }
    dump_yaml(out_dir / "failure_analysis" / "pkcs_slot_filling_failure_analysis.yaml", failure)
    write_md(out_dir / "failure_analysis" / "pkcs_slot_filling_failure_analysis.md", "PKCS Slot Filling Failure Analysis", failure)

    prompt = build_prompt(slot_plan, adapter_recipe, family_files)
    prompt_yaml = {
        "schema": "pkcs_fixup_prompt_v1",
        "adapter_id": EXPECTED_ADAPTER_ID,
        "yaml_only": True,
        "no_markdown": True,
        "no_c_generation": True,
        "do_not_repeat_slot_filling_plan": True,
        "allowed_trigger_apis": sorted(ALLOWED_TRIGGER_APIS),
        "allowed_cleanup_apis": sorted(ALLOWED_CLEANUP_APIS),
        "forbidden_apis": sorted(FORBIDDEN_APIS),
        "forbidden_libraries": sorted(FORBIDDEN_LIBRARY_TERMS),
        "prompt_path": str(out_dir / "prompt_fixup" / "pkcs_container_parsing_openssl_fixup_prompt.md"),
    }
    write_text(out_dir / "prompt_fixup" / "pkcs_container_parsing_openssl_fixup_prompt.md", prompt)
    dump_yaml(out_dir / "prompt_fixup" / "pkcs_container_parsing_openssl_fixup_prompt.yaml", prompt_yaml)

    glm_env = bool(os.environ.get("ZHIPUAI_API_KEY") or os.environ.get("GLM_API_KEY"))
    glm_called = False
    raw = ""
    call_error = None
    parse_notes: list[str] = []
    if args.glm_mode == "off" or not glm_env:
        raw = ""
        binding = make_glm_unavailable("GLM mode off or API key environment missing")
    else:
        glm_called = True
        raw, call_error = call_glm(prompt)
        if call_error:
            binding = make_glm_unavailable(call_error)
            raw = f"[GLM unavailable]\n{call_error}\n"
        else:
            parsed, parse_notes = extract_yaml(raw or "")
            binding = normalize_binding(parsed, raw or "", parse_notes)

    write_text(out_dir / "glm_outputs" / "pkcs_container_parsing_openssl_glm_raw.txt", raw or "")
    parsed_for_output, _ = extract_yaml(raw or "")
    dump_yaml(
        out_dir / "glm_outputs" / "pkcs_container_parsing_openssl_glm_parsed.yaml",
        parsed_for_output if parsed_for_output is not None else {"parse_status": "failed_or_unavailable"},
    )

    validation = validate(binding, raw or "")
    fixed_path = out_dir / "slot_bindings" / "pkcs_container_parsing" / "openssl" / "slot_bindings.fixed.yaml"
    dump_yaml(fixed_path, binding)
    dump_yaml(out_dir / "validation" / "pkcs_fixup_validation.yaml", validation)
    write_md(out_dir / "validation" / "pkcs_fixup_validation.md", "PKCS Fixup Validation", validation)

    proposed_replacement_path = (
        out_dir
        / "write_summary"
        / "proposed_replacement"
        / "adapter_recipes"
        / "wolfssl_family"
        / "pkcs_container_parsing"
        / "openssl"
        / "slot_bindings.yaml"
    )
    apply_script_path = out_dir / "write_summary" / "apply_fixed_slot_bindings.sh"
    replacement_written = False
    apply_script_written = False
    safe_to_apply = validation["validation_status"] == "pass"
    if args.write_proposed_replacement == "true" and safe_to_apply:
        dump_yaml(proposed_replacement_path, binding)
        replacement_written = True
        write_text(
            apply_script_path,
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "cp artifacts/sprints/adapter_slot_filling_fixup_v1/write_summary/proposed_replacement/adapter_recipes/wolfssl_family/pkcs_container_parsing/openssl/slot_bindings.yaml \\\n"
            "   adapter_recipes/wolfssl_family/pkcs_container_parsing/openssl/slot_bindings.yaml\n",
        )
        apply_script_path.chmod(0o755)
        apply_script_written = True

    write_summary = {
        "schema": "pkcs_fixup_write_summary_v1",
        "write_attempted": args.write_proposed_replacement == "true",
        "target_file": str(current_target),
        "target_existing": current_target_exists,
        "target_overwritten": False,
        "proposed_replacement_written": replacement_written,
        "proposed_replacement": str(proposed_replacement_path) if replacement_written else None,
        "apply_script_written": apply_script_written,
        "apply_script": str(apply_script_path) if apply_script_written else None,
        "safe_to_apply": safe_to_apply,
        "reason": "validation pass" if safe_to_apply else "fixed binding did not pass validation; no replacement proposed",
    }
    dump_yaml(out_dir / "write_summary" / "pkcs_fixup_write_summary.yaml", write_summary)
    write_md(out_dir / "write_summary" / "pkcs_fixup_write_summary.md", "PKCS Fixup Write Summary", write_summary)

    if validation["validation_status"] == "pass":
        next_task = "apply_pkcs_slot_bindings_and_adapter_validate_v1"
        why = "Fixed pkcs slot binding passed local structural validation."
    elif validation["validation_status"] == "glm_unavailable":
        next_task = "glm_configuration_or_manual_slot_review_v1"
        why = "GLM was unavailable."
    elif validation["plan_echo_detected"] or not validation["all_required_top_level_fields_present"]:
        next_task = "manual_pkcs_slot_binding_review_v1"
        why = "GLM still echoed plan or missed required fields."
    elif "manual_review_needed_cleanup_mapping" in validation.get("notes", []):
        next_task = "pkcs_adapter_recipe_mapping_gap_fixup_v1"
        why = "Allowed API mapping exists but cleanup binding needs manual review."
    else:
        next_task = "manual_pkcs_slot_binding_review_v1"
        why = "Fixed pkcs slot binding failed validation."

    next_action = {
        "schema": "next_action_after_pkcs_slot_filling_fixup_v1",
        "next_task_name": next_task,
        "why": why,
        "do_not_run_yet": ["render_cases", "compile_run", "PoC execution"],
    }
    dump_yaml(out_dir / "reports" / "next_action_after_pkcs_slot_filling_fixup.yaml", next_action)
    write_md(
        out_dir / "reports" / "next_action_after_pkcs_slot_filling_fixup.md",
        "Next Action After PKCS Slot Filling Fixup",
        next_action,
    )

    report = {
        "schema": "adapter_slot_filling_fixup_v1_report",
        "generated_at": now_iso(),
        "only_fixed_pkcs_container_parsing_openssl": True,
        "previous_failure_reason": failure["failure_reasons"],
        "glm_called": glm_called,
        "glm_available": glm_called and not call_error,
        "glm_call_error": call_error,
        "glm_output_plan_echo": validation["plan_echo_detected"],
        "fixed_slot_bindings_generated": fixed_path.exists(),
        "fixed_slot_bindings_validation_status": validation["validation_status"],
        "c_generation_detected": not validation["no_c_generation_detected"],
        "blocked_api_used": not validation["blocked_targets_respected"],
        "confirmed_equivalence_claim": not validation["no_confirmed_equivalence_claim"],
        "adapter_recipes_old_file_overwritten": False,
        "proposed_replacement": write_summary["proposed_replacement"],
        "next_task_name": next_task,
        "actions_not_performed": {
            "run_poc": False,
            "render": False,
            "compile_run": False,
            "generated_c": False,
            "pattern_bank_modified": False,
            "scheduler_seed_modified": False,
            "knowledge_raw_modified": False,
            "knowledge_base_modified": False,
        },
        "validation": validation,
    }
    dump_yaml(out_dir / "reports" / "adapter_slot_filling_fixup_v1_report.yaml", report)
    write_md(out_dir / "reports" / "adapter_slot_filling_fixup_v1_report.md", "Adapter Slot Filling Fixup V1 Report", report)
    readme = {
        "name": "adapter_slot_filling_fixup_v1",
        "scope": "pkcs_container_parsing -> OpenSSL only",
        "fixed_binding": str(fixed_path),
        "validation": str(out_dir / "validation" / "pkcs_fixup_validation.yaml"),
        "next_action": next_task,
        "no_render_compile_run_or_c_generation": True,
    }
    write_md(out_dir / "README.md", "adapter_slot_filling_fixup_v1", readme)

    print(f"[OK] pkcs fixup artifacts written to {out_dir}")
    print(f"[SUMMARY] validation_status: {validation['validation_status']}")
    print(f"[SUMMARY] next_task_name: {next_task}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
