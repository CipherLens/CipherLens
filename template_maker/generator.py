import argparse
import copy
import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List

import yaml

from utils.query_llm import get_glm_response


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def find_template_dirs(root: Path) -> List[Path]:
    return sorted(p.parent for p in root.rglob("template_meta.yaml"))


def build_query_from_meta(meta: Dict[str, Any]) -> str:
    api = meta.get("poc_source", {}).get("api", "")
    abstract = meta.get("operation", {}).get("abstract", "")
    api_family = meta.get("operation", {}).get("api_family", "")
    bug_class = " ".join(meta.get("operation", {}).get("bug_class", []))
    mutation_names = " ".join(mp.get("name", "") for mp in meta.get("mutation_points", []))

    return (
        f"{api} {abstract} {api_family} {bug_class} "
        f"mutation points {mutation_names} boundary constraints oracle"
    )


def retrieve_rag_context(meta: Dict[str, Any], top_k: int = 8) -> List[Dict[str, Any]]:
    """
    Retrieve RAG context. If RAG fails, return an empty list so the pipeline
    can still continue with LLM or fallback logic.
    """
    try:
        from knowledge.rag_query import RAGQuery

        rag = RAGQuery()
        query = build_query_from_meta(meta)
        hits = rag.query(query, top_k=top_k)

        contexts = []
        for h in hits:
            contexts.append({
                "metadata": h.get("metadata", {}),
                "distance": h.get("distance"),
                "text": h.get("text", "")[:1600],
            })
        return contexts

    except Exception as e:
        print(f"[WARN] RAG retrieval failed: {e}")
        return []


def extract_json_object(text: str) -> Dict[str, Any]:
    text = text.strip()

    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    if m:
        text = m.group(1).strip()

    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            text = text[start:end + 1]

    return json.loads(text)


def build_prompt(meta: Dict[str, Any], rag_context: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    sys_prompt = """You are an expert in cryptographic library API harness generation.

Your task is NOT to generate C code.
Your task is to enrich template_meta.yaml for API-level vulnerability-pattern testing.

Given:
1. A template metadata object.
2. Retrieved RAG context from API constraints, unit tests, Wycheproof vectors, and cross-library mappings.

Return ONLY a valid JSON object.

Required JSON schema:
{
  "mutation_updates": {
    "<MUTATION_POINT_NAME>": {
      "values": [...],
      "strategy": "...",
      "constraint": "...",
      "priority": "high|medium|low"
    }
  },
  "oracle_notes": ["..."],
  "generation_notes": ["..."]
}

Rules:
- Do not generate C code.
- Do not invent APIs not present in the input.
- Prefer boundary values and values that reach the trigger path.
- For buffer sizes, include zero, undersized, exact-ish, and larger values.
- For enum-like macros, keep them as strings.
- For string-number mutation points, keep values as strings.
- If uncertain, use conservative values and explain in generation_notes.
- Output JSON only.
"""

    user_payload = {
        "template_meta": meta,
        "rag_context": rag_context,
    }

    usr_prompt = json.dumps(user_payload, ensure_ascii=False, indent=2)

    return [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": usr_prompt},
    ]


def fallback_updates(meta: Dict[str, Any]) -> Dict[str, Any]:
    template_id = meta.get("template_id", "")

    if template_id == "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER":
        updates = {
            "VALUE": {
                "values": [-1, -2, -15, -255, 0, 1, 255],
                "strategy": "negative_and_boundary_values",
                "constraint": "Prioritize negative values because the source PoC targets negative MPI serialization.",
                "priority": "high",
            },
            "RADIX": {
                "values": [2, 10, 16],
                "strategy": "radix_boundary",
                "constraint": "Use supported radices that lead to different serialized output lengths.",
                "priority": "high",
            },
            "BUFLEN": {
                "values": [0, 1, 2, 3, 4, 8, 16, 32],
                "strategy": "small_buffer_first",
                "constraint": "Prioritize buffer sizes smaller than or close to the required serialized length.",
                "priority": "high",
            },
            "CANARY_SIZE": {
                "values": [8, 16, 32],
                "strategy": "fixed_small_set",
                "constraint": "Keep canary size large enough to observe adjacent out-of-bounds writes.",
                "priority": "low",
            },
        }

    elif template_id == "BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY":
        updates = {
            "A_VALUE": {
                "values": ["0", "1", "3", "5", "15", "255"],
                "strategy": "small_left_operand",
                "constraint": "Keep A smaller than B to exercise the negative-result rejection path.",
                "priority": "high",
            },
            "B_VALUE": {
                "values": [
                    "100000000",
                    "123456789abcdef01",
                    "ffffffffffffffff",
                    "ffffffffffffffffffffffff",
                    "deadbeefdeadbeef",
                ],
                "strategy": "large_right_operand",
                "constraint": "Prefer B values whose limb count is greater than A.",
                "priority": "high",
            },
            "A_BASE": {
                "values": [10, 16],
                "strategy": "supported_parse_base",
                "constraint": "Use bases accepted by mbedtls_mpi_read_string.",
                "priority": "medium",
            },
            "B_BASE": {
                "values": [16, 10],
                "strategy": "supported_parse_base",
                "constraint": "Use hexadecimal first for large limb-count values.",
                "priority": "medium",
            },
            "X_LIMB_COUNT": {
                "values": [1, 2, 3, 4],
                "strategy": "output_limb_boundary",
                "constraint": "Prioritize X limb count smaller than the required output limb count.",
                "priority": "high",
            },
            "CANARY_SIZE": {
                "values": [8, 16, 32],
                "strategy": "fixed_small_set",
                "constraint": "Keep canary size large enough to detect adjacent overwrite.",
                "priority": "low",
            },
        }

    elif template_id == "PK_VERIFY_EXT_OPAQUE_RSA_PSS_NULL_DEREF":
        updates = {
            "KEY_BITS": {
                "values": [1024, 2048],
                "strategy": "valid_key_sizes",
                "constraint": "Use valid RSA key sizes to reach the trigger path.",
                "priority": "medium",
            },
            "HASH_LEN": {
                "values": [20, 32, 48, 64],
                "strategy": "digest_length_boundary",
                "constraint": "Match common digest output lengths.",
                "priority": "medium",
            },
            "SIG_LEN": {
                "values": [128, 256],
                "strategy": "key_size_related_signature_length",
                "constraint": "Use signature lengths consistent with RSA key size.",
                "priority": "medium",
            },
            "MD_ALG": {
                "values": ["MBEDTLS_MD_SHA256", "MBEDTLS_MD_SHA384", "MBEDTLS_MD_SHA512"],
                "strategy": "supported_hash_algorithms",
                "constraint": "Use supported digest algorithms.",
                "priority": "high",
            },
            "PK_VERIFY_TYPE": {
                "values": ["MBEDTLS_PK_RSASSA_PSS", "MBEDTLS_PK_RSA"],
                "strategy": "rsa_pss_first",
                "constraint": "Prioritize MBEDTLS_PK_RSASSA_PSS because it is the source trigger path.",
                "priority": "high",
            },
            "EXPECTED_SALT_LEN": {
                "values": ["MBEDTLS_RSA_SALT_LEN_ANY"],
                "strategy": "fixed_initially",
                "constraint": "Keep salt policy fixed until the opaque RSA-PSS path is confirmed buildable.",
                "priority": "low",
            },
        }

    else:
        updates = {}

    return {
        "mutation_updates": updates,
        "oracle_notes": [
            "Fallback enrichment was used or the LLM output was unavailable."
        ],
        "generation_notes": [
            "Values are conservative boundary-focused defaults derived from template_id."
        ],
    }


def apply_updates(meta: Dict[str, Any], updates_obj: Dict[str, Any], source: str) -> Dict[str, Any]:
    enriched = copy.deepcopy(meta)
    mutation_updates = updates_obj.get("mutation_updates", {})

    for mp in enriched.get("mutation_points", []):
        name = mp.get("name")
        if name not in mutation_updates:
            continue

        upd = mutation_updates[name]

        for key in ["values", "strategy", "constraint", "priority"]:
            if key in upd:
                mp[key] = upd[key]

    enriched["llm_enrichment"] = {
        "source": source,
        "oracle_notes": updates_obj.get("oracle_notes", []),
        "generation_notes": updates_obj.get("generation_notes", []),
    }

    enriched["status"] = "enriched"

    return enriched


def copy_template_files(src_dir: Path, dst_dir: Path) -> None:
    dst_dir.mkdir(parents=True, exist_ok=True)

    for p in src_dir.iterdir():
        if p.name == "template_meta.yaml":
            continue
        if p.is_file():
            shutil.copy2(p, dst_dir / p.name)


def enrich_template_dir(
    template_dir: Path,
    root: Path,
    out_root: Path,
    use_llm: bool,
    top_k: int,
) -> Path:
    meta_path = template_dir / "template_meta.yaml"
    meta = load_yaml(meta_path)

    rag_context = retrieve_rag_context(meta, top_k=top_k)

    updates_obj = None
    source = "fallback"

    if use_llm:
        try:
            messages = build_prompt(meta, rag_context)
            response = get_glm_response(messages)
            updates_obj = extract_json_object(response)
            source = "glm"
            print(f"[LLM] enriched by GLM: {template_dir}")
        except Exception as e:
            print(f"[WARN] LLM enrichment failed for {template_dir}: {e}")
            print("[WARN] falling back to deterministic enrichment")

    if updates_obj is None:
        updates_obj = fallback_updates(meta)

    enriched = apply_updates(meta, updates_obj, source=source)

    rel = template_dir.relative_to(root)
    out_dir = out_root / rel

    copy_template_files(template_dir, out_dir)
    dump_yaml(out_dir / "template_meta.yaml", enriched)

    write_text(
        out_dir / "rag_context.json",
        json.dumps(rag_context, ensure_ascii=False, indent=2),
    )

    if use_llm:
        write_text(
            out_dir / "llm_updates.json",
            json.dumps(updates_obj, ensure_ascii=False, indent=2),
        )

    print(f"[OK] enriched {template_dir} -> {out_dir}")
    return out_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Enrich template_meta.yaml using RAG + optional GLM.")
    parser.add_argument("--root", default="generated_templates", help="Input template root.")
    parser.add_argument("--out-root", default="enriched_templates", help="Output enriched template root.")
    parser.add_argument("--top-k", type=int, default=8, help="RAG top-k.")
    parser.add_argument("--use-llm", action="store_true", help="Use GLM. If omitted, fallback mode is used.")

    args = parser.parse_args()

    root = Path(args.root)
    out_root = Path(args.out_root)

    if not root.exists():
        print(f"[ERROR] root not found: {root}")
        return 1

    template_dirs = find_template_dirs(root)
    if not template_dirs:
        print(f"[ERROR] no template_meta.yaml found under {root}")
        return 1

    if out_root.exists():
        shutil.rmtree(out_root)

    for td in template_dirs:
        enrich_template_dir(
            template_dir=td,
            root=root,
            out_root=out_root,
            use_llm=args.use_llm,
            top_k=args.top_k,
        )

    print("=" * 80)
    print(f"[SUMMARY] enriched templates: {len(template_dirs)}")
    print(f"[SUMMARY] output root: {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
