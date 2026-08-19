"""Strict target skeletons; they declare holes instead of inventing adapters."""

from __future__ import annotations

from typing import Any, Mapping

from target_knowledge.canonical import identified, semantic_digest
from .model import TARGET_AWARE_BOUND_SOURCE_SCHEMA


_SKELETONS = {
    "symbol:openssl:3.5.5:d2i_RSAPrivateKey": {
        "symbol": "d2i_RSAPrivateKey",
        "holes": ("input_bytes", "input_length", "decoded_object_observation", "pointer_advance_observation", "outcome_observation"),
        "source": """#include <openssl/rsa.h>\n#include <stddef.h>\nint main(void) {\n  const unsigned char *input = /*__CIPHERLENS_HOLE:input_bytes__*/;\n  const unsigned char *cursor = input;\n  long input_length = /*__CIPHERLENS_HOLE:input_length__*/;\n  RSA *decoded = d2i_RSAPrivateKey(NULL, &cursor, input_length);\n  /*__CIPHERLENS_HOLE:decoded_object_observation__*/\n  /*__CIPHERLENS_HOLE:pointer_advance_observation__*/\n  /*__CIPHERLENS_HOLE:outcome_observation__*/\n  return decoded == NULL;\n}\n""",
    },
    "symbol:openssl:3.5.5:EVP_DecryptFinal_ex": {
        "symbol": "EVP_DecryptFinal_ex",
        "holes": ("cipher_context", "output_buffer", "outl_initial", "outcome_observation", "outl_before_observation", "outl_after_observation"),
        "source": """#include <openssl/evp.h>\nint main(void) {\n  EVP_CIPHER_CTX *ctx = /*__CIPHERLENS_HOLE:cipher_context__*/;\n  unsigned char *out = /*__CIPHERLENS_HOLE:output_buffer__*/;\n  int outl = /*__CIPHERLENS_HOLE:outl_initial__*/;\n  int outl_before = outl;\n  int outcome = EVP_DecryptFinal_ex(ctx, out, &outl);\n  /*__CIPHERLENS_HOLE:outcome_observation__*/\n  /*__CIPHERLENS_HOLE:outl_before_observation__*/\n  /*__CIPHERLENS_HOLE:outl_after_observation__*/\n  return outcome == 0;\n}\n""",
    },
}


def _incomplete(reason: str, *, merge: Mapping[str, Any] | None = None, candidate_binding: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": TARGET_AWARE_BOUND_SOURCE_SCHEMA,
        "adaptation_status": "INCOMPLETE",
        "reason": reason,
        "merge_ref": str((merge or {}).get("merge_id", "")),
        "candidate_binding_ref": str((candidate_binding or {}).get("binding_id", "")),
        "unresolved_hole_refs": [],
        "execution_eligible": False,
        "authority": "constrained_target_adaptation_only",
    }


def _rejected(reason: str, *, candidate_binding: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": TARGET_AWARE_BOUND_SOURCE_SCHEMA,
        "adaptation_status": "REJECTED",
        "reason": reason,
        "candidate_binding_ref": str((candidate_binding or {}).get("binding_id", "")),
        "unresolved_hole_refs": [],
        "execution_eligible": False,
        "authority": "constrained_target_adaptation_only",
    }


def adapt_target_source(merge: Mapping[str, Any], candidate_binding: Mapping[str, Any], concrete_expressions: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Emit a target-aware source plan without changing frozen merge records."""
    if candidate_binding is None:
        return _rejected("CANDIDATE_BINDING_ABSENT")
    if not merge:
        return _incomplete("MERGE_ABSENT", candidate_binding=candidate_binding)
    validity = str(candidate_binding.get("validation_status", candidate_binding.get("status", "")))
    if validity != "VALID":
        return _rejected("CANDIDATE_BINDING_NOT_EXPLICITLY_VALID", candidate_binding=candidate_binding)
    required_binding = ("binding_id", "target_symbol_ref", "operation_binding_ref", "input_binding_ref", "observation_binding_refs", "target_scope")
    missing_binding = [key for key in required_binding if not candidate_binding.get(key)]
    if missing_binding:
        return _incomplete(f"CANDIDATE_BINDING_MISSING:{','.join(missing_binding)}", merge=merge, candidate_binding=candidate_binding)
    required_merge = ("merge_id", "operation_mapping_ref", "input_mapping_ref", "observation_mapping_refs")
    missing_merge = [key for key in required_merge if not merge.get(key)]
    if missing_merge:
        return _incomplete(f"MERGE_MISSING:{','.join(missing_merge)}", merge=merge, candidate_binding=candidate_binding)
    target_scope = candidate_binding["target_scope"]
    if not isinstance(target_scope, Mapping) or target_scope.get("library") != "OpenSSL" or target_scope.get("version") != "3.5.5":
        return _incomplete("TARGET_SCOPE_NOT_REGISTERED", merge=merge, candidate_binding=candidate_binding)
    symbol_ref = str(candidate_binding["target_symbol_ref"])
    skeleton = _SKELETONS.get(symbol_ref)
    if not skeleton:
        return _incomplete("TARGET_SYMBOL_NOT_IN_CLOSED_REGISTRY", merge=merge, candidate_binding=candidate_binding)
    symbol = skeleton["symbol"]
    expressions = dict(concrete_expressions or {})
    unknown = set(expressions) - set(skeleton["holes"])
    if unknown:
        return _incomplete(f"UNDECLARED_ADAPTATION_EXPRESSIONS:{','.join(sorted(unknown))}", merge=merge, candidate_binding=candidate_binding)
    source = skeleton["source"]
    unresolved = []
    for hole in skeleton["holes"]:
        marker = f"/*__CIPHERLENS_HOLE:{hole}__*/"
        if hole in expressions:
            source = source.replace(marker, expressions[hole])
        else:
            unresolved.append(f"hole:{symbol}:{hole}")
    source_map = identified({"schema_version": "cipherlens.target_source_map.v0.1", "target_symbol": symbol, "merge_ref": str(merge["merge_id"]), "regions": [{"role": "target_call", "symbol": symbol}], "unresolved_hole_refs": unresolved}, "target-source-map", "source_map_id")
    result = {
        "schema_version": TARGET_AWARE_BOUND_SOURCE_SCHEMA, "adaptation_status": "PREPARED", "merge_ref": str(merge["merge_id"]),
        "candidate_binding_ref": str(candidate_binding["binding_id"]),
        "target_symbol": symbol, "source": source, "source_digest": semantic_digest({"source": source}),
        "source_map": source_map, "unresolved_hole_refs": unresolved, "execution_eligible": not unresolved,
        "authority": "constrained_target_adaptation_only",
    }
    return identified(result, "target-bound-source", "bound_source_id")
