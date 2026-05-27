import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
import chromadb

from knowledge.ollama_embedder import OllamaEmbedder


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "rag_config.yaml"


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

        result = self.collection.query(
            query_embeddings=[q_emb],
            n_results=top_k,
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

        return hits


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
