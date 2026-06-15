import argparse
import contextlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
import chromadb

from knowledge.ollama_embedder import OllamaEmbedder


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "rag_config.yaml"

API_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
COMMON_KEYWORDS = {
    "api", "after", "and", "before", "case", "crypto", "final", "for", "from",
    "hash", "invalid", "key", "length", "library", "mutation", "oracle",
    "pattern", "repeated", "return", "safe", "signature", "the", "update",
    "verify", "wrong",
}
KNOWN_FAMILY_TERMS = {
    "mac_lifecycle",
    "pkey_verify",
    "pkey_verify_semantic",
    "signature_verify_semantic",
    "buffer_canary_boundary",
    "der_full_consumption",
    "der_pointer_consumption",
    "asn1_nested_boundary",
    "x509_parsing",
    "x509_asn1_inner_boundary",
    "return_code_outlen_semantic",
    "cipher_aead_lifecycle",
    "bn_mpi_arithmetic",
    "memory_length_boundary",
    "api_state_machine",
}
KNOWN_LIBRARIES = {"openssl", "mbedtls", "psa", "botan"}
PKEY_VERIFY_QUERY_TERMS = {
    "verify",
    "signature",
    "digest",
    "hash",
    "pkey",
    "rsa",
    "pss",
    "saltlen",
}
OPENSSL_PKEY_VERIFY_APIS = {
    "evp_digestverify",
    "evp_pkey_verify",
    "evp_digestverifyinit",
    "evp_pkey_ctx_set_rsa_padding",
    "evp_pkey_ctx_set_rsa_pss_saltlen",
}
PKEY_COUNTERPART_APIS = {"psa_verify_hash", "mbedtls_pk_verify"}


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class RAGQuery:
    def __init__(self):
        self.cfg = load_config()

        emb_cfg = self.cfg["embedding"]

        self.embedder = OllamaEmbedder(
            model_name=emb_cfg["model_name"],
            base_url=emb_cfg.get("base_url", "http://localhost:11434"),
            endpoint=emb_cfg.get("endpoint", "/api/embed"),
        )

        self.db_dir = PROJECT_ROOT / self.cfg["chroma"]["persist_dir"]
        self.collection_name = self.cfg["chroma"]["collection_name"]

        self.client = chromadb.PersistentClient(path=str(self.db_dir))
        self.collection = self.client.get_or_create_collection(name=self.collection_name)

    def query(
        self,
        question: str,
        top_k: int = 8,
        where: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        q_emb = self.embedder.embed([question])[0]
        fetch_k = max(top_k, min(128, top_k * 8))

        result = self.collection.query(
            query_embeddings=[q_emb],
            n_results=fetch_k,
            where=where
        )

        hits = []

        if not result["ids"] or not result["ids"][0]:
            return hits

        ids = result["ids"][0]
        documents = (result.get("documents") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]

        for i in range(len(result["ids"][0])):
            raw_metadata = metadatas[i] if i < len(metadatas) and metadatas[i] else {}
            metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
            distance = distances[i] if i < len(distances) else None
            hit = {
                "rank": i + 1,
                "id": ids[i],
                "text": documents[i] if i < len(documents) else "",
                "metadata": metadata,
                "layer": metadata.get("layer", ""),
                "source_file": metadata.get("source_file", ""),
                "distance": distance,
            }
            if distance is not None:
                hit["score"] = 1 / (1 + distance)
            hits.append(hit)

        reranked = rerank_hits(question, hits)
        return reranked[:top_k]


def query_api_tokens(question: str) -> Set[str]:
    tokens = set()
    for token in API_TOKEN_RE.findall(question or ""):
        if "_" in token or token.startswith(("EVP", "BN", "OSSL", "RSA", "X509", "d2i", "mbedtls", "psa")):
            tokens.add(token)
    return tokens


def normalized_words(text: str) -> Set[str]:
    return {
        token.lower()
        for token in API_TOKEN_RE.findall(text or "")
        if len(token) >= 3 and token.lower() not in COMMON_KEYWORDS
    }


def query_families(question: str) -> Set[str]:
    q_lower = (question or "").lower()
    families = {family for family in KNOWN_FAMILY_TERMS if family in q_lower}
    if "mac" in q_lower and ("final" in q_lower or "lifecycle" in q_lower):
        families.add("mac_lifecycle")
    if ("digestverify" in q_lower or "pkey" in q_lower or "signature" in q_lower) and "verify" in q_lower:
        families.update({"pkey_verify", "pkey_verify_semantic", "signature_verify_semantic"})
    if (
        ("trailing" in q_lower and "garbage" in q_lower)
        or ("full" in q_lower and "consumption" in q_lower)
        or ("accepts prefix" in q_lower or "accepted prefix" in q_lower)
    ) and ("der" in q_lower or "d2i" in q_lower or "asn.1" in q_lower or "asn1" in q_lower):
        families.update({"der_full_consumption", "der_pointer_consumption"})
    if ("x509" in q_lower or "x.509" in q_lower) and ("asn.1" in q_lower or "asn1" in q_lower):
        families.update({"x509_parsing", "asn1_nested_boundary", "x509_asn1_inner_boundary"})
    return families


def rerank_hit(question: str, hit: Dict[str, Any]) -> Tuple[float, List[str]]:
    metadata = hit.get("metadata", {}) if isinstance(hit.get("metadata"), dict) else {}
    text = str(hit.get("text", "") or "")
    source_file = str(hit.get("source_file", "") or metadata.get("source_file", "") or "")
    haystack = "\n".join([text, source_file, " ".join(str(v) for v in metadata.values())])
    haystack_lower = haystack.lower()
    query_lower = (question or "").lower()
    base = float(hit.get("score") or 0.0)
    bonus = 0.0
    reasons: List[str] = []

    api_tokens = query_api_tokens(question)
    for api in sorted(api_tokens):
        api_lower = api.lower()
        if api_lower in haystack_lower:
            add = 0.25 if str(metadata.get("api", "")).lower() == api_lower else 0.15
            bonus += add
            reasons.append(f"api_match:{api}")
            break

    families = query_families(question)
    metadata_family = str(metadata.get("family") or metadata.get("api_family") or "").lower()
    if metadata_family and metadata_family in {family.lower() for family in families}:
        if str(hit.get("layer") or metadata.get("layer") or "") == "poc_patterns":
            bonus += 0.35
            reasons.append("layer:poc_patterns")
        else:
            bonus += 0.10
        reasons.append(f"family_match:{metadata_family}")

    metadata_library = str(metadata.get("library", "") or "").lower()
    for library in KNOWN_LIBRARIES:
        if library in query_lower and (metadata_library == library or library in haystack_lower):
            bonus += 0.10
            reasons.append(f"library_match:{library}")
            break

    if str(hit.get("layer") or metadata.get("layer") or "") == "api_cards":
        bonus += 0.15
        reasons.append("layer:api_cards")

    if source_file and api_tokens:
        source_lower = source_file.lower()
        if any(api.lower() in source_lower for api in api_tokens):
            bonus += 0.10
            reasons.append("source_file_api_match")

    query_words = normalized_words(question)
    hit_words = normalized_words(haystack)
    overlap = sorted(query_words & hit_words)
    if overlap:
        bonus += min(0.10, 0.02 * len(overlap))
        reasons.append("keyword_overlap:" + ",".join(overlap[:6]))

    if "feedback" in haystack_lower or str(metadata.get("layer", "")) == "feedback":
        bonus += 0.05
        reasons.append("recent_feedback_source")

    counterpart_bonus, counterpart_reasons = cross_library_counterpart_bonus(
        question=question,
        metadata=metadata,
        haystack_lower=haystack_lower,
    )
    if counterpart_bonus:
        bonus += counterpart_bonus
        reasons.extend(counterpart_reasons)

    return base + bonus, reasons


def cross_library_counterpart_bonus(
    question: str,
    metadata: Dict[str, Any],
    haystack_lower: str,
) -> Tuple[float, List[str]]:
    query_words = normalized_words(question)
    query_apis = {api.lower() for api in query_api_tokens(question)}
    has_pkey_semantics = bool(query_words & PKEY_VERIFY_QUERY_TERMS)
    has_openssl_pkey_api = bool(query_apis & OPENSSL_PKEY_VERIFY_APIS)
    if not (has_pkey_semantics or has_openssl_pkey_api):
        return 0.0, []

    api = str(metadata.get("api") or "").lower()
    library = str(metadata.get("library") or "").lower()
    layer = str(metadata.get("layer") or "").lower()
    counterpart_match = api in PKEY_COUNTERPART_APIS or any(x in haystack_lower for x in PKEY_COUNTERPART_APIS)
    if not counterpart_match:
        return 0.0, []

    bonus = 0.20
    reasons = ["cross_library_counterpart_match"]
    if layer == "api_cards" and library in {"mbedtls", "psa"} and api in PKEY_COUNTERPART_APIS:
        bonus += 0.10
        reasons.append("api_card_counterpart_bonus")
    return bonus, reasons


def rerank_hits(question: str, hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for hit in hits:
        rerank_score, reasons = rerank_hit(question, hit)
        updated = dict(hit)
        updated["base_score"] = hit.get("score")
        updated["score"] = rerank_score
        updated["rerank_score"] = rerank_score
        updated["rerank_reasons"] = reasons
        out.append(updated)
    out.sort(key=lambda h: (float(h.get("rerank_score") or 0.0), -(h.get("distance") or 0.0)), reverse=True)
    for idx, hit in enumerate(out, start=1):
        hit["rank"] = idx
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Query the crypto-pattern-fuzz RAG knowledge base."
    )
    parser.add_argument(
        "--query",
        help="Query text to search for. If omitted, runs the built-in demo queries.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=8,
        help="Number of nearest RAG chunks to return for --query mode.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the legacy plain-text output.",
    )
    return parser


def print_text_results(query: str, hits: List[Dict[str, Any]]) -> None:
    print("=" * 100)
    print("QUERY:", query)
    print("=" * 100)

    for hit in hits:
        distance = hit.get("distance")
        rank = hit.get("rank", "")
        print(f"\n[{rank}] distance={distance}")
        if hit.get("rerank_score") is not None:
            print(f"rerank_score={hit.get('rerank_score')} reasons={hit.get('rerank_reasons', [])}")
        print("metadata:", hit.get("metadata", {}))
        print(hit.get("text", "")[:1000])


def make_json_output(query: str, top_k: int, hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "query": query,
        "top_k": top_k,
        "results": [
            {
                "rank": hit.get("rank", idx),
                "score": hit.get("score"),
                "distance": hit.get("distance"),
                "base_score": hit.get("base_score"),
                "rerank_score": hit.get("rerank_score"),
                "rerank_reasons": hit.get("rerank_reasons", []),
                "layer": hit.get("layer", ""),
                "source_file": hit.get("source_file", ""),
                "text": hit.get("text", ""),
                "metadata": hit.get("metadata", {}),
            }
            for idx, hit in enumerate(hits, start=1)
        ],
    }


def run_demo() -> None:
    rag = RAGQuery()

    queries = [
        "mbedtls_mpi_write_string negative integer undersized buffer canary",
        "BN_bn2binpad BIGNUM output buffer too small",
        "AES-GCM invalid tag expected reject Wycheproof",
    ]

    for q in queries:
        hits = rag.query(q, top_k=5)
        print_text_results(q, hits)


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.top_k <= 0:
        parser.error("--top-k must be a positive integer")

    if args.json and not args.query:
        parser.error("--json requires --query")

    if not args.query:
        run_demo()
        return 0

    if args.json:
        try:
            with contextlib.redirect_stdout(sys.stderr):
                rag = RAGQuery()
                hits = rag.query(args.query, top_k=args.top_k)
            json.dump(
                make_json_output(args.query, args.top_k, hits),
                sys.stdout,
                ensure_ascii=False,
                indent=2,
            )
            sys.stdout.write("\n")
            return 0
        except Exception as e:
            json.dump(
                {
                    "query": args.query,
                    "top_k": args.top_k,
                    "results": [],
                    "error": str(e),
                },
                sys.stdout,
                ensure_ascii=False,
                indent=2,
            )
            sys.stdout.write("\n")
            return 1

    rag = RAGQuery()
    hits = rag.query(args.query, top_k=args.top_k)
    print_text_results(args.query, hits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
