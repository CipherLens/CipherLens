"""Render profile registry for bounded legacy renderer dispatch.

This module resolves a seed-driven render package to a renderer profile. It does
not generate source, compile, run, or invoke oracle logic.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


BOTAN_DER_POINTER_CONSUMPTION_PROFILE = {
    "profile_id": "botan_der_pointer_consumption_v1",
    "target_library": "botan-3.10.0",
    "family": "der_pointer_consumption",
    "template_id": "RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE",
    "template_reference": "normalized_templates/rsa/rsa_der_trailing_garbage",
    "renderer_entrypoint": "tools/rendering/render_cases_v1.py",
    "renderer_backend": "template_maker.family_case_renderer",
    "render_mode": "legacy_mask_unit_filling",
    "required_slots": [
        "input_buffer",
        "input_length",
        "parse_or_trigger_call",
        "cleanup_call",
        "oracle_check",
        "payload_reference",
    ],
    "required_guardrails": [
        "source_api_context_only",
        "target_api_from_completed_slot_binding",
        "target_api_evidenced_by_api_card",
        "no_runtime_execution",
        "no_compile_execution",
        "no_issue_claim",
    ],
    "expected_outputs_next_round": [
        "case_source",
        "compile_manifest",
        "oracle_hook_manifest",
        "render_provenance",
    ],
    "language": "cpp",
    "source_file": "case.cpp",
    "payload_reference_file": "payload_reference.yaml",
    "compile_manifest": {
        "compiler": "c++",
        "cxx_standard": "c++20",
        "include_paths": [],
        "library_paths": [],
        "libraries": ["botan-3"],
    },
}


OPENSSL_RETURN_CODE_OUTLEN_SEMANTIC_PROFILE = {
    "profile_id": "openssl_return_code_outlen_semantic_v1",
    "target_library": "openssl",
    "family": "return_code_outlen_semantic",
    "target_api": "EVP_DecryptFinal_ex",
    "template_id": "CIPHER_PKCS_PADDING_INVALID_OUTLEN_UNDERFLOW",
    "template_reference": "normalized_templates/cipher/cipher_pkcs_padding_outlen_underflow",
    "renderer_entrypoint": "tools/rendering/render_cases_v1.py",
    "renderer_backend": "template_maker.family_case_renderer",
    "render_mode": "legacy_mask_unit_filling",
    "required_slots": [
        "input_buffer",
        "input_length",
        "output_buffer",
        "output_length",
        "parse_or_trigger_call",
        "return_code",
        "cleanup_call",
        "oracle_check",
    ],
    "required_guardrails": [
        "source_api_context_only",
        "target_api_from_completed_slot_binding",
        "target_api_evidenced_by_api_card",
        "adapter_validate_pass_required",
        "no_runtime_execution",
        "no_compile_execution",
        "no_issue_claim",
    ],
    "expected_outputs_next_round": [
        "case_source",
        "compile_manifest",
        "oracle_hook_manifest",
        "render_provenance",
    ],
    "language": "cpp",
    "source_file": "case.cpp",
    "payload_reference_file": "payload_reference.yaml",
    "compile_manifest": {
        "compiler": "c++",
        "cxx_standard": "c++17",
        "include_paths": [],
        "library_paths": [],
        "libraries": ["crypto"],
    },
    "oracle_hook_manifest": {
        "oracle_kind": "invalid_padding_output_length_oracle",
        "family": "return_code_outlen_semantic",
        "expected_observation_fields": [
            "return_code",
            "output_length_before",
            "output_length_after",
            "input_len",
            "accepted_or_rejected",
            "error_path_state",
        ],
        "runtime_observation_required": True,
        "oracle_dispatcher_execution_allowed": False,
        "campaign_runner_execution_allowed": False,
    },
}


OPENSSL_X509_ASN1_INNER_BOUNDARY_PROFILE = {
    "profile_id": "openssl_x509_asn1_inner_boundary_v1",
    "target_library": "openssl",
    "family": "x509_asn1_inner_boundary",
    "target_api": "d2i_X509",
    "binding_schema": "completed_slot_binding_v2",
    "template_id": "X509_ASN1_INNER_SUBSTRUCTURE_BOUNDARY",
    "template_reference": "normalized_templates/x509/x509_asn1_inner_boundary",
    "renderer_entrypoint": "tools/rendering/render_cases_v1.py",
    "renderer_backend": "template_maker.family_case_renderer",
    "render_mode": "legacy_mask_unit_filling",
    "required_slots": [
        "input_buffer",
        "input_length",
        "parse_or_trigger_call",
        "return_code",
        "cleanup_call",
        "oracle_check",
    ],
    "required_guardrails": [
        "source_api_context_only",
        "target_api_from_completed_slot_binding",
        "target_api_evidenced_by_api_card",
        "adapter_validate_pass_required",
        "no_runtime_execution",
        "no_compile_execution",
        "no_issue_claim",
    ],
    "render_intent": [
        "parse DER-like input through target API",
        "observe parse success_or_failure",
        "expose consumed_or_remaining behavior when available",
        "cleanup target object",
    ],
    "oracle_hook_fields": [
        "return_code",
        "input_len",
        "accepted_or_rejected",
        "consumed_or_remaining_length",
    ],
    "expected_outputs_next_round": [
        "case_source",
        "compile_manifest",
        "oracle_hook_manifest",
        "render_provenance",
    ],
    "language": "cpp",
    "source_file": "case.cpp",
    "payload_reference_file": "payload_reference.yaml",
    "compile_manifest": {
        "compiler": "c++",
        "cxx_standard": "c++17",
        "include_paths": [],
        "library_paths": [],
        "libraries": ["crypto"],
    },
    "oracle_hook_manifest": {
        "oracle_kind": "inner_asn1_boundary_semantic_oracle",
        "family": "x509_asn1_inner_boundary",
        "expected_observation_fields": [
            "return_code",
            "input_len",
            "accepted_or_rejected",
            "consumed_or_remaining_length",
        ],
        "runtime_observation_required": True,
        "oracle_dispatcher_execution_allowed": False,
        "campaign_runner_execution_allowed": False,
    },
}


WOLFSSL_X509_ASN1_INNER_BOUNDARY_PROFILE = {
    "profile_id": "wolfssl_x509_asn1_inner_boundary_v1",
    "target_library": "wolfssl",
    "family": "x509_asn1_inner_boundary",
    "target_api": "wolfSSL_d2i_X509",
    "binding_schema": "completed_slot_binding_v2",
    "source_generation_template_kind": "object_return_pointer_cursor_parser",
    "template_id": "X509_ASN1_INNER_SUBSTRUCTURE_BOUNDARY",
    "template_reference": "normalized_templates/x509/x509_asn1_inner_boundary",
    "renderer_entrypoint": "tools/rendering/render_cases_v1.py",
    "renderer_backend": "template_maker.family_case_renderer",
    "render_mode": "legacy_mask_unit_filling",
    "required_slots": [
        "input_buffer",
        "input_length",
        "parse_or_trigger_call",
        "return_object",
        "return_code",
        "accepted_or_rejected",
        "consumed_length",
        "remaining_length",
        "consumed_or_remaining_length",
        "cleanup_call",
        "oracle_check",
    ],
    "required_guardrails": [
        "source_api_context_only",
        "target_api_from_completed_slot_binding",
        "target_api_evidenced_by_api_card",
        "adapter_validate_pass_required",
        "object_return_not_full_buffer_acceptance",
        "full_consumption_requires_consumed_equals_input_len",
        "no_runtime_execution",
        "no_compile_execution",
        "no_issue_claim",
    ],
    "render_intent": [
        "parse DER-like input through wolfSSL_d2i_X509",
        "observe pointer advancement and consumed length",
        "keep parse success separate from full-buffer consumption",
        "cleanup returned WOLFSSL_X509 object",
    ],
    "include_headers": [
        "wolfssl/options.h",
        "wolfssl/ssl.h",
    ],
    "rendered_parse_call": "WOLFSSL_X509 *x509 = wolfSSL_d2i_X509(NULL, &p, input_len)",
    "return_object_type": "WOLFSSL_X509",
    "pointer_cursor": "p",
    "runtime_observation_fields": [
        "return_code",
        "input_len",
        "accepted_or_rejected",
        "consumed_length",
        "remaining_length",
        "consumed_or_remaining_length",
    ],
    "oracle_hook_fields": [
        "return_code",
        "input_len",
        "accepted_or_rejected",
        "consumed_length",
        "remaining_length",
        "consumed_or_remaining_length",
    ],
    "cleanup_call": "wolfSSL_X509_free(x509)",
    "payload_reference": "input_buffer",
    "expected_outputs_next_round": [
        "case_source",
        "compile_manifest",
        "oracle_hook_manifest",
        "render_provenance",
    ],
    "language": "cpp",
    "source_file": "case.cpp",
    "payload_reference_file": "payload_reference.yaml",
    "compile_manifest": {
        "compiler": "c++",
        "cxx_standard": "c++17",
        "compile_definitions": ["OPENSSL_EXTRA"],
        "include_paths": [],
        "library_paths": [],
        "libraries": ["wolfssl"],
    },
    "oracle_hook_manifest": {
        "oracle_kind": "inner_asn1_boundary_semantic_oracle",
        "family": "x509_asn1_inner_boundary",
        "expected_observation_fields": [
            "return_code",
            "input_len",
            "accepted_or_rejected",
            "consumed_length",
            "remaining_length",
            "consumed_or_remaining_length",
        ],
        "full_consumption_guardrail": "consumed_length == input_len",
        "runtime_observation_required": True,
        "oracle_dispatcher_execution_allowed": False,
        "campaign_runner_execution_allowed": False,
    },
}


RENDER_PROFILE_LIST = [
    BOTAN_DER_POINTER_CONSUMPTION_PROFILE,
    OPENSSL_RETURN_CODE_OUTLEN_SEMANTIC_PROFILE,
    OPENSSL_X509_ASN1_INNER_BOUNDARY_PROFILE,
    WOLFSSL_X509_ASN1_INNER_BOUNDARY_PROFILE,
]


RENDER_PROFILES = {
    profile["profile_id"]: profile for profile in RENDER_PROFILE_LIST
}


def load_yaml(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def dump_yaml(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def slot_names(slot_bindings: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    slots = slot_bindings.get("slots", {}) or {}
    if isinstance(slots, dict):
        names.update(str(name) for name in slots.keys())
    else:
        for slot in slots:
            name = slot.get("slot_name") or slot.get("name")
            if name:
                names.add(str(name))
    return names


def target_api_values(slot_bindings: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    slots = slot_bindings.get("slots", {}) or {}
    if isinstance(slots, dict):
        for slot in slots.values():
            value = (
                slot.get("binding")
                or slot.get("bound_value_or_reference")
                or slot.get("value_or_reference")
            )
            if value:
                values.add(str(value))
    else:
        for slot in slots:
            value = slot.get("bound_value_or_reference") or slot.get("value_or_reference")
            if value:
                values.add(str(value))
    return values


def api_card_candidates(api_card: dict[str, Any]) -> set[str]:
    candidates: set[str] = set()
    for item in api_card.get("candidate_apis", []) or api_card.get("api_candidates", []) or []:
        api = item.get("api") or item.get("api_name") or item.get("function")
        if api:
            candidates.add(str(api))
    return candidates


def resolve_render_profile(
    *,
    seed_id: str,
    target_library: str,
    family: str,
    template_id: str,
    template_reference: str | Path,
    selected_mask_units_path: str | Path,
    slot_bindings_path: str | Path,
    api_card_path: str | Path,
    source_api_boundary_status: str,
) -> dict[str, Any]:
    """Resolve one bounded render profile and return validation metadata."""

    profile = None
    for candidate in RENDER_PROFILES.values():
        if (
            candidate["target_library"] == target_library
            and candidate["family"] == family
            and candidate["template_id"] == template_id
        ):
            profile = candidate
            break

    blocking_reason: list[str] = []
    if profile is None:
        blocking_reason.append("profile_not_registered")
        profile = {}

    template_path = Path(template_reference)
    selected_path = Path(selected_mask_units_path)
    slot_path = Path(slot_bindings_path)
    api_path = Path(api_card_path)

    slot_bindings = load_yaml(slot_path)
    api_card = load_yaml(api_path)
    present_slots = slot_names(slot_bindings)
    missing_slots = [s for s in profile.get("required_slots", []) if s not in present_slots]
    if missing_slots:
        blocking_reason.append("required_slot_missing")
    if not selected_path.exists():
        blocking_reason.append("selected_mask_units_missing")
    if not template_path.exists():
        blocking_reason.append("template_reference_missing")

    bound_api_text = "\n".join(target_api_values(slot_bindings))
    evidenced_apis = api_card_candidates(api_card)
    target_api_evidence_present = any(api in bound_api_text for api in evidenced_apis)
    if not target_api_evidence_present:
        blocking_reason.append("target_api_not_evidenced")
    if source_api_boundary_status != "pass_source_context_only":
        blocking_reason.append("source_api_boundary_not_passed")

    resolved = not blocking_reason
    smoke_status = (
        "profile_resolution_pass_with_guardrails"
        if resolved
        else "blocked_profile_not_registered"
        if "profile_not_registered" in blocking_reason
        else "blocked_required_slot_missing"
        if "required_slot_missing" in blocking_reason
        else "blocked_target_api_not_evidenced"
        if "target_api_not_evidenced" in blocking_reason
        else "blocked_mask_units_missing"
        if "selected_mask_units_missing" in blocking_reason
        else "blocked_source_api_boundary"
        if "source_api_boundary_not_passed" in blocking_reason
        else "needs_manual_review"
    )

    return {
        "seed_id": seed_id,
        "target_library": target_library,
        "family": family,
        "template_reference": str(template_reference),
        "profile_id": profile.get("profile_id", ""),
        "profile_resolved": resolved,
        "selected_renderer_entrypoint": profile.get("renderer_entrypoint", ""),
        "required_slots_present": not missing_slots,
        "missing_required_slots": missing_slots,
        "target_api_evidence_present": target_api_evidence_present,
        "selected_mask_units_present": selected_path.exists(),
        "template_reference_present": template_path.exists(),
        "source_api_boundary_status": source_api_boundary_status,
        "smoke_status": smoke_status,
        "blocking_reason": blocking_reason,
    }


def _slot_value(slot_bindings: dict[str, Any], name: str, default: str = "") -> str:
    slots = slot_bindings.get("slots", {}) or {}
    if isinstance(slots, dict):
        slot = slots.get(name) or {}
        return str(
            slot.get("binding")
            or slot.get("bound_value_or_reference")
            or slot.get("value_or_reference")
            or default
        )
    for slot in slots:
        slot_name = slot.get("slot_name") or slot.get("name")
        if slot_name == name:
            return str(
                slot.get("binding")
                or slot.get("bound_value_or_reference")
                or slot.get("value_or_reference")
                or default
            )
    return default


def _botan_der_pointer_source(case_id: str, payload_reference: str) -> str:
    return f"""/*
 * Generated by profile-aware legacy renderer smoke.
 * profile: botan_der_pointer_consumption_v1
 * case_id: {case_id}
 *
 * This source is an artifact-only render output. It is intended for a later
 * compile smoke and does not assert a security finding.
 */

#include <botan/ber_dec.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

static std::vector<uint8_t> read_file(const std::string& path)
{{
    std::ifstream in(path, std::ios::binary);
    if(!in) {{
        throw std::runtime_error("failed to open input file");
    }}
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}}

int main(int argc, char** argv)
{{
    const std::string input_path =
        argc > 1 ? std::string(argv[1]) : std::string("{payload_reference}");

    std::vector<uint8_t> der;
    try {{
        der = read_file(input_path);
    }} catch(const std::exception& e) {{
        std::cerr << "input_error=" << e.what() << "\\n";
        return 2;
    }}

    int accepted = 0;
    int full_consumption = 0;
    int parser_error = 0;

    try {{
        auto key = Botan::PKCS8::load_key(std::span<const uint8_t>(der.data(), der.size()));
        accepted = key ? 1 : 0;
    }} catch(const std::exception&) {{
        parser_error = 1;
    }}

    try {{
        Botan::BER_Decoder decoder(der.data(), der.size());
        decoder.verify_end();
        full_consumption = 1;
    }} catch(const std::exception&) {{
        full_consumption = 0;
    }}

    std::cout
        << "OBSERVATION"
        << " case_id={case_id}"
        << " family=der_pointer_consumption"
        << " target_library=botan-3.10.0"
        << " api=Botan::PKCS8::load_key"
        << " accepted=" << accepted
        << " parser_error=" << parser_error
        << " input_len=" << der.size()
        << " full_consumption=" << full_consumption
        << "\\n";

    return 0;
}}
"""


def _openssl_return_code_outlen_source(case_id: str) -> str:
    source_case_id = case_id.replace("mbedtls", "source")
    return f"""/*
 * Generated by profile-aware legacy renderer smoke.
 * profile: openssl_return_code_outlen_semantic_v1
 * case_id: {source_case_id}
 *
 * This source is an artifact-only render output. It is intended for a later
 * compile smoke and records only return-code/output-length observations.
 */

#include <openssl/evp.h>

#include <cstdio>
#include <cstring>

int main(void)
{{
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char input[16];
    unsigned char out[32];
    int input_len = (int)sizeof(input);
    int update_len = 0;
    int final_len = 0;
    int final_len_before = 0;
    int ret = 0;
    int accepted_or_rejected = 0;
    EVP_CIPHER_CTX *ctx = nullptr;

    std::memset(key, 0, sizeof(key));
    std::memset(iv, 0, sizeof(iv));
    std::memset(input, 0x41, sizeof(input));
    std::memset(out, 0, sizeof(out));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {{
        std::printf("setup_error=EVP_CIPHER_CTX_new\\n");
        return 2;
    }}

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {{
        std::printf("setup_error=EVP_DecryptInit_ex\\n");
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }}

    EVP_CIPHER_CTX_set_padding(ctx, 1);

    if (EVP_DecryptUpdate(ctx, out, &update_len, input, input_len) != 1) {{
        std::printf("setup_error=EVP_DecryptUpdate\\n");
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }}

    final_len = 0;
    final_len_before = final_len;
    ret = EVP_DecryptFinal_ex(ctx, out + update_len, &final_len);
    accepted_or_rejected = ret > 0 ? 1 : 0;

    std::printf("OBSERVATION case_id={source_case_id} family=return_code_outlen_semantic target_library=openssl api=EVP_DecryptFinal_ex return_code=%d input_len=%d update_len=%d output_length_before=%d output_length_after=%d accepted_or_rejected=%d\\n",
                ret,
                input_len,
                update_len,
                final_len_before,
                final_len,
                accepted_or_rejected);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}}
"""


def _openssl_x509_inner_boundary_source(case_id: str, payload_reference: str) -> str:
    return f"""/*
 * Generated by profile-aware legacy renderer smoke.
 * profile: openssl_x509_asn1_inner_boundary_v1
 * case_id: {case_id}
 *
 * This source is an artifact-only render output. It is intended for a later
 * compile smoke and records only parser boundary observations.
 */

#include <openssl/x509.h>

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static std::vector<unsigned char> read_file(const std::string& path)
{{
    std::ifstream in(path, std::ios::binary);
    if (!in) {{
        return {{}};
    }}
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}}

int main(int argc, char** argv)
{{
    const std::string input_path =
        argc > 1 ? std::string(argv[1]) : std::string("{payload_reference}");
    std::vector<unsigned char> der = read_file(input_path);
    if (der.empty()) {{
        std::printf("OBSERVATION case_id={case_id} family=x509_asn1_inner_boundary target_library=openssl api=d2i_X509 return_code=0 input_len=0 accepted_or_rejected=0 consumed_or_remaining_length=0 setup_error=input_empty_or_missing\\n");
        return 0;
    }}

    const unsigned char* start = der.data();
    const unsigned char* cursor = start;
    X509* cert = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
    int accepted_or_rejected = cert != nullptr ? 1 : 0;
    long consumed = cursor >= start ? static_cast<long>(cursor - start) : 0;
    long remaining = static_cast<long>(der.size()) - consumed;
    int return_code = accepted_or_rejected;

    std::printf("OBSERVATION case_id={case_id} family=x509_asn1_inner_boundary target_library=openssl api=d2i_X509 return_code=%d input_len=%zu accepted_or_rejected=%d consumed_or_remaining_length=%ld\\n",
                return_code,
                der.size(),
                accepted_or_rejected,
                remaining);

    if (cert != nullptr) {{
        X509_free(cert);
    }}
    return 0;
}}
"""


def _object_return_pointer_cursor_parser_source(
    case_id: str,
    payload_reference: str,
    profile: dict[str, Any],
    slot_bindings: dict[str, Any],
) -> str:
    """Render source for object-return parsers that advance an input cursor."""

    include_headers = [
        f"#include <{header}>"
        for header in profile.get("include_headers", [])
        if str(header).strip()
    ]
    target_library = profile.get("target_library", "")
    family = profile.get("family", "")
    target_api = profile.get("target_api", "")
    parse_call = profile.get("rendered_parse_call") or _slot_value(slot_bindings, "parse_or_trigger_call")
    return_object = _slot_value(slot_bindings, "return_object", "obj")
    pointer_cursor = profile.get("pointer_cursor") or _slot_value(slot_bindings, "pointer_cursor", "p")
    cleanup_call = _slot_value(slot_bindings, "cleanup_call", profile.get("cleanup_call", ""))
    oracle_check = _slot_value(slot_bindings, "oracle_check", "consumed == input_len")

    return f"""/*
 * Generated by profile-aware legacy renderer smoke.
 * template_kind: object_return_pointer_cursor_parser
 * profile: {profile.get("profile_id", "")}
 * case_id: {case_id}
 *
 * This source is an artifact-only render output. It is intended for a later
 * compile smoke and records parser cursor observations.
 */

{chr(10).join(include_headers)}

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static std::vector<unsigned char> read_file(const std::string& path)
{{
    std::ifstream in(path, std::ios::binary);
    if (!in) {{
        return {{}};
    }}
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>());
}}

int main(int argc, char** argv)
{{
    const std::string input_path =
        argc > 1 ? std::string(argv[1]) : std::string("{payload_reference}");
    std::vector<unsigned char> der = read_file(input_path);
    if (der.empty()) {{
        std::printf("OBSERVATION case_id={case_id} family={family} target_library={target_library} api={target_api} return_code=0 input_len=0 accepted_or_rejected=0 consumed_length=0 remaining_length=0 consumed_or_remaining_length=0 crash=0 timeout=0 stderr_summary=input_empty_or_missing\\n");
        return 0;
    }}

    const unsigned char* input = der.data();
    const size_t input_len = der.size();
    const unsigned char* {pointer_cursor} = input;
    {parse_call};

    int accepted_or_rejected = {return_object} != nullptr ? 1 : 0;
    int return_code = accepted_or_rejected;
    size_t consumed = {pointer_cursor} >= input ? static_cast<size_t>({pointer_cursor} - input) : 0;
    size_t remaining = input_len >= consumed ? input_len - consumed : 0;
    int full_consumption_guardrail = ({oracle_check}) ? 1 : 0;

    std::printf("OBSERVATION case_id={case_id} family={family} target_library={target_library} api={target_api} return_code=%d input_len=%zu accepted_or_rejected=%d consumed_length=%zu remaining_length=%zu consumed_or_remaining_length=%zu full_consumption_guardrail=%d crash=0 timeout=0 stderr_summary=none\\n",
                return_code,
                input_len,
                accepted_or_rejected,
                consumed,
                remaining,
                remaining,
                full_consumption_guardrail);

    if ({return_object} != nullptr) {{
        {cleanup_call};
    }}
    return 0;
}}
"""


def render_profile_source_package(
    *,
    seed_id: str,
    target_library: str,
    family: str,
    template_id: str,
    template_reference: str | Path,
    selected_mask_units_path: str | Path,
    slot_bindings_path: str | Path,
    api_card_path: str | Path,
    source_api_boundary_status: str,
    out_dir: str | Path,
) -> dict[str, Any]:
    """Render one bounded source package using a registered profile."""

    resolved = resolve_render_profile(
        seed_id=seed_id,
        target_library=target_library,
        family=family,
        template_id=template_id,
        template_reference=template_reference,
        selected_mask_units_path=selected_mask_units_path,
        slot_bindings_path=slot_bindings_path,
        api_card_path=api_card_path,
        source_api_boundary_status=source_api_boundary_status,
    )
    if not resolved["profile_resolved"]:
        return {
            "executed": False,
            "profile_resolution": resolved,
            "generated_files": [],
            "source_generation_status": "blocked_profile_resolution_failed",
        }

    profile = RENDER_PROFILES[resolved["profile_id"]]
    slot_bindings = load_yaml(slot_bindings_path)
    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    payload_reference = _slot_value(slot_bindings, "payload_reference", "payload.der")
    source_path = output_dir / profile["source_file"]
    payload_reference_path = output_dir / profile.get("payload_reference_file", "payload_reference.yaml")
    compile_manifest_path = output_dir / "compile_manifest.yaml"
    oracle_hook_manifest_path = output_dir / "oracle_hook_manifest.yaml"
    render_provenance_path = output_dir / "render_provenance.yaml"

    case_id = seed_id
    if profile["profile_id"] == "botan_der_pointer_consumption_v1":
        source_text = _botan_der_pointer_source(case_id, payload_reference)
    elif profile["profile_id"] == "openssl_return_code_outlen_semantic_v1":
        source_text = _openssl_return_code_outlen_source(case_id)
    elif profile["profile_id"] == "openssl_x509_asn1_inner_boundary_v1":
        source_text = _openssl_x509_inner_boundary_source(case_id, payload_reference)
    elif profile.get("source_generation_template_kind") == "object_return_pointer_cursor_parser":
        source_text = _object_return_pointer_cursor_parser_source(
            case_id,
            payload_reference,
            profile,
            slot_bindings,
        )
    else:
        return {
            "executed": False,
            "profile_resolution": resolved,
            "generated_files": [],
            "source_generation_status": "blocked_profile_resolution_failed",
        }
    source_path.write_text(source_text, encoding="utf-8")
    dump_yaml(
        payload_reference_path,
        {
            "schema": "payload_reference_v1",
            "seed_id": seed_id,
            "payload_reference": payload_reference,
            "payload_embedded": False,
            "notes": ["Payload is referenced, not copied, by this source-generation smoke."],
        },
    )
    dump_yaml(
        compile_manifest_path,
        {
            "schema": "compile_manifest_v1",
            "seed_id": seed_id,
            "source_file": source_path.as_posix(),
            "target_library": target_library,
            "language": profile["language"],
            "compiler": profile["compile_manifest"]["compiler"],
            "cxx_standard": profile["compile_manifest"].get("cxx_standard", ""),
            "c_standard": profile["compile_manifest"].get("c_standard", ""),
            "compile_definitions": profile["compile_manifest"].get("compile_definitions", []),
            "include_paths": profile["compile_manifest"]["include_paths"],
            "library_paths": profile["compile_manifest"]["library_paths"],
            "libraries": profile["compile_manifest"]["libraries"],
            "compile_only": True,
            "runtime_allowed": False,
            "sanitizer_allowed": False,
        },
    )
    dump_yaml(
        oracle_hook_manifest_path,
        {
            "schema": "oracle_hook_manifest_v1",
            "seed_id": seed_id,
            "oracle_kind": profile.get("oracle_hook_manifest", {}).get(
                "oracle_kind", "pointer_consumption_oracle"
            ),
            "family": family,
            "target_library": target_library,
            "expected_observation_fields": profile.get("oracle_hook_manifest", {}).get(
                "expected_observation_fields",
                [
                    "accepted",
                    "parser_error",
                    "input_len",
                    "full_consumption",
                ],
            ),
            "runtime_observation_required": True,
            "oracle_dispatcher_execution_allowed": False,
            "campaign_runner_execution_allowed": False,
        },
    )
    dump_yaml(
        render_provenance_path,
        {
            "schema": "render_provenance_v1",
            "seed_id": seed_id,
            "profile_id": resolved["profile_id"],
            "renderer": "tools.rendering.render_profile_registry.render_profile_source_package",
            "source_generation_template_kind": profile.get("source_generation_template_kind", ""),
            "renderer_entrypoint": resolved["selected_renderer_entrypoint"],
            "template_reference": str(template_reference),
            "selected_mask_units": str(selected_mask_units_path),
            "slot_bindings": str(slot_bindings_path),
            "api_card": str(api_card_path),
            "source_api_boundary_status": source_api_boundary_status,
            "source_generated": True,
            "compile_executed": False,
            "runtime_executed": False,
            "oracle_dispatcher_executed": False,
        },
    )

    generated = [
        (source_path, "source_file"),
        (payload_reference_path, "payload_or_payload_reference"),
        (compile_manifest_path, "compile_manifest"),
        (oracle_hook_manifest_path, "oracle_hook_manifest"),
        (render_provenance_path, "render_provenance"),
    ]
    return {
        "executed": True,
        "profile_resolution": resolved,
        "generated_files": [
            {
                "path": path.as_posix(),
                "output_type": output_type,
                "exists": path.exists(),
                "notes": "artifact-only output",
            }
            for path, output_type in generated
        ],
        "source_generation_status": "legacy_source_generation_pass_with_guardrails",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve and render bounded legacy profiles.")
    parser.add_argument("--seed-id", required=True)
    parser.add_argument("--target-library", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--template-id", required=True)
    parser.add_argument("--template-reference", required=True)
    parser.add_argument("--selected-mask-units", required=True)
    parser.add_argument("--slot-bindings", required=True)
    parser.add_argument("--api-card", required=True)
    parser.add_argument("--source-api-boundary-status", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    result = render_profile_source_package(
        seed_id=args.seed_id,
        target_library=args.target_library,
        family=args.family,
        template_id=args.template_id,
        template_reference=args.template_reference,
        selected_mask_units_path=args.selected_mask_units,
        slot_bindings_path=args.slot_bindings,
        api_card_path=args.api_card,
        source_api_boundary_status=args.source_api_boundary_status,
        out_dir=args.out_dir,
    )
    dump_yaml(Path(args.out_dir) / "render_profile_result.yaml", result)
    print(result["source_generation_status"])
    return 0 if result["executed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
