from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

import yaml

from template_binding_merge.canonical import expected_merge_id
from template_binding_merge.gate import validate_merge_gate
from template_binding_merge.merge import construct_merge
from template_binding_merge.model import TemplateBundle, ValidationContext
from template_binding_merge.render import render_base_source


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "candidate_binding" / "fixtures" / "golden"
FAMILIES = {
    "mbedtls_poc_0020": "normalized_templates/rsa/rsa_der_trailing_garbage/tmpl_mbedtls.c",
    "mbedtls_poc_0004": "normalized_templates/cipher/cipher_pkcs_padding_outlen_underflow/tmpl_mbedtls.c",
    "mbedtls_poc_0005": "normalized_templates/asn1/asn1_store_named_data_zero_len_stale_state/tmpl_mbedtls.c",
}


def load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def inputs(family: str = "mbedtls_poc_0020") -> tuple[TemplateBundle, dict[str, Any], dict[str, Any], dict[str, Any]]:
    directory = FIXTURES / family
    manifest = load_yaml(directory / "template_interface.manifest.yaml")
    binding = load_yaml(directory / "valid.binding.yaml")
    validation = load_yaml(directory / "valid.validation.yaml")
    source_ref = FAMILIES[family]
    source_digest = hashlib.sha256((ROOT / source_ref).read_bytes()).hexdigest()
    bundle = TemplateBundle(
        trigger_template_ref=manifest["trigger_template_ref"],
        trigger_template_digest=manifest["trigger_template_digest"],
        source_artifact_ref=source_ref,
        source_artifact_digest=source_digest,
    )
    return bundle, manifest, binding, validation


def gate(family: str = "mbedtls_poc_0020") -> Any:
    return validate_merge_gate(*inputs(family), ROOT)


def built(family: str = "mbedtls_poc_0020", *, additional_holes: list[dict[str, Any]] | None = None) -> tuple[Any, dict[str, Any], Any]:
    gated = gate(family)
    merge = construct_merge(gated, additional_holes=additional_holes or [])
    rendered = render_base_source(merge, ROOT)
    return gated, merge, rendered


def context(gated: Any, merge: dict[str, Any], rendered: Any) -> ValidationContext:
    return ValidationContext(gated, merge, rendered.source_bytes, rendered.source_map, rendered.bound_source)


def reidentify(merge: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(merge)
    result["merge_id"] = expected_merge_id(result)
    return result


def proposal_hole(replacement: str = "/* exact syntax glue */") -> dict[str, Any]:
    return {
        "hole_id": "hole:proposal-declaration",
        "hole_type": "DECLARATION_SYNTAX",
        "required": True,
        "resolver": "PROPOSAL_ALLOWED",
        "syntax_kind": "C_DECLARATION",
        "allowed_edit_types": ["FILL_HOLE"],
        "allowed_replacement_digests": [hashlib.sha256(replacement.encode("utf-8")).hexdigest()],
        "semantic_guard_refs": ["guard:no-semantic-binding-change"],
        "target_region_ref": "region:proposal-declaration",
        "dependencies": [],
        "type_constraints": ["text=exact-allowlist"],
    }
