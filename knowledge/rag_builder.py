import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List

import yaml
import chromadb
from loguru import logger
from tqdm import tqdm

from knowledge.ollama_embedder import OllamaEmbedder


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "rag_config.yaml"


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class RAGBuilder:
    def __init__(self):
        self.cfg = load_config()

        emb_cfg = self.cfg["embedding"]
        self.batch_size = emb_cfg.get("batch_size", 16)

        self.embedder = OllamaEmbedder(
            model_name=emb_cfg["model_name"],
            base_url=emb_cfg.get("base_url", "http://localhost:11434"),
            endpoint=emb_cfg.get("endpoint", "/api/embed"),
            timeout=emb_cfg.get("timeout", 600),
        )

        self.db_dir = PROJECT_ROOT / self.cfg["chroma"]["persist_dir"]
        self.collection_name = self.cfg["chroma"]["collection_name"]

        self.max_chars = self.cfg["chunking"]["max_chars"]
        self.overlap_chars = self.cfg["chunking"]["overlap_chars"]

        limits = self.cfg.get("limits", {})
        self.max_wycheproof_per_file = limits.get("max_wycheproof_per_file", 50)
        self.wycheproof_include_patterns = limits.get("wycheproof_include_patterns", [])

        logger.info("Opening ChromaDB at {}", self.db_dir)
        self.client = chromadb.PersistentClient(path=str(self.db_dir))

        try:
            self.client.delete_collection(self.collection_name)
            logger.info("Deleted old collection: {}", self.collection_name)
        except Exception:
            pass

        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"description": "Crypto RAG knowledge base"}
        )

    def build(self):
        docs = []
        docs.extend(self.load_text_layer("api_constraints", "api_constraint"))
        docs.extend(self.load_text_layer("unit_tests", "unit_test_call_pattern"))
        docs.extend(self.load_text_layer("poc_patterns", "poc_pattern"))
        docs.extend(self.load_yaml_layer("cross_lib_equivalence", "cross_lib_equivalence"))
        docs.extend(self.load_wycheproof_layer("wycheproof_vectors", "wycheproof_vector"))
        docs.extend(self.load_api_cards_layer())

        logger.info("Total chunks to insert: {}", len(docs))

        if not docs:
            logger.warning("No documents found.")
            return

        self.add_documents(docs)
        logger.success("RAG knowledge base built successfully.")

    def load_text_layer(self, dir_key: str, doc_type: str) -> List[Dict[str, Any]]:
        raw_dir = PROJECT_ROOT / self.cfg["raw_dirs"][dir_key]
        docs = []

        if not raw_dir.exists():
            logger.warning("Directory not found: {}", raw_dir)
            return docs

        exts = {".md", ".txt", ".c", ".h", ".cpp", ".hpp", ".function", ".data"}

        for path in raw_dir.rglob("*"):
            if "_manual_bootstrap" in str(path):
                continue
            if not path.is_file() or path.suffix.lower() not in exts:
                continue

            text = path.read_text(encoding="utf-8", errors="ignore")
            if dir_key == "poc_patterns":
                chunks = self.chunk_poc_pattern_text(text)
            else:
                chunks = [
                    {"text": chunk, "metadata": {}}
                    for chunk in self.chunk_text(text)
                ]
            library = self.guess_library_from_path(path)

            for idx, chunk_obj in enumerate(chunks):
                chunk = chunk_obj["text"]
                chunk_metadata = chunk_obj.get("metadata", {})
                docs.append({
                    "id": self.make_id(doc_type, path.stem, idx),
                    "text": chunk,
                    "metadata": {
                        "layer": dir_key,
                        "doc_type": doc_type,
                        "library": library,
                        "source_file": str(path.relative_to(PROJECT_ROOT)),
                        "pattern_id": chunk_metadata.get("pattern_id", ""),
                        "family": chunk_metadata.get("family", ""),
                        "oracle_type": chunk_metadata.get("oracle_type", ""),
                    }
                })

        logger.info("Loaded {} chunks from {}", len(docs), raw_dir)
        return docs

    def load_yaml_layer(self, dir_key: str, doc_type: str) -> List[Dict[str, Any]]:
        raw_dir = PROJECT_ROOT / self.cfg["raw_dirs"][dir_key]
        docs = []

        if not raw_dir.exists():
            return docs

        for path in raw_dir.rglob("*"):
            if "_manual_bootstrap" in str(path):
                continue
            if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
                continue

            with path.open("r", encoding="utf-8", errors="ignore") as f:
                obj = yaml.safe_load(f)

            if obj is None:
                continue

            text = yaml.safe_dump(obj, allow_unicode=True, sort_keys=False)

            docs.append({
                "id": self.make_id(doc_type, path.stem, 0),
                "text": text,
                "metadata": {
                    "layer": dir_key,
                    "doc_type": doc_type,
                    "source_file": str(path.relative_to(PROJECT_ROOT)),
                    "operation": obj.get("operation", obj.get("abstract_operation", "")),
                    "api_family": obj.get("api_family", ""),
                }
            })

        logger.info("Loaded {} YAML docs from {}", len(docs), raw_dir)
        return docs

    def load_wycheproof_layer(self, dir_key: str, doc_type: str) -> List[Dict[str, Any]]:
        raw_dir = PROJECT_ROOT / self.cfg["raw_dirs"][dir_key]
        docs = []

        if not raw_dir.exists():
            logger.warning("Directory not found: {}", raw_dir)
            return docs

        per_result_limit = self.cfg.get("limits", {}).get("wycheproof_per_result_per_file", 5)

        for path in raw_dir.rglob("*.jsonl"):
            if not self.should_load_wycheproof_file(path.name):
                continue

            result_count = {
                "valid": 0,
                "invalid": 0,
                "acceptable": 0,
                "other": 0,
            }

            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    result = obj.get("result", "")
                    bucket = result if result in result_count else "other"

                    if result_count[bucket] >= per_result_limit:
                        continue

                    text = self.format_wycheproof_entry(obj)

                    docs.append({
                        "id": self.make_id(doc_type, path.stem, line_no),
                        "text": text,
                        "metadata": {
                            "layer": dir_key,
                            "doc_type": doc_type,
                            "source_file": str(path.relative_to(PROJECT_ROOT)),
                            "algorithm": obj.get("algorithm", ""),
                            "api_family": obj.get("api_family", ""),
                            "result": obj.get("result", ""),
                            "expected_behavior": obj.get("expected_behavior", ""),
                        }
                    })

                    result_count[bucket] += 1

                    # valid / invalid / acceptable 都采够后就可以跳过该文件
                    if (
                        result_count["valid"] >= per_result_limit and
                        result_count["invalid"] >= per_result_limit and
                        result_count["acceptable"] >= per_result_limit
                    ):
                        break

            logger.info("Wycheproof {} sampled counts: {}", path.name, result_count)

        logger.info("Loaded {} Wycheproof vector docs from {}", len(docs), raw_dir)
        return docs

    def load_api_cards_layer(self) -> List[Dict[str, Any]]:
        docs = []
        raw_dirs = [PROJECT_ROOT / "knowledge_base" / "api_cards"]
        api_knowledge_dir = self.cfg.get("raw_dirs", {}).get("api_knowledge_cards")
        if api_knowledge_dir:
            raw_dirs.append(PROJECT_ROOT / api_knowledge_dir)

        for raw_dir in raw_dirs:
            if not raw_dir.exists():
                logger.warning("Directory not found: {}", raw_dir)
                continue

            for path in sorted(raw_dir.rglob("*.yaml")):
                if path.name == "schema.yaml":
                    continue
                try:
                    with path.open("r", encoding="utf-8", errors="ignore") as f:
                        obj = yaml.safe_load(f)
                except Exception as e:
                    logger.warning("Skipping malformed API card {}: {}", path, e)
                    continue

                for card_idx, card_obj in enumerate(self.iter_api_card_objects(obj)):
                    if not isinstance(card_obj, dict):
                        continue

                    api = str(card_obj.get("api") or path.stem)
                    library = str(card_obj.get("library") or self.guess_library_from_path(path) or "unknown")
                    family = str(card_obj.get("family") or card_obj.get("api_family") or "")
                    text = self.format_api_card_entry(card_obj, api=api, library=library, family=family)

                    docs.append({
                        "id": self.make_id("api_card", f"{path.stem}_{card_idx}", 0),
                        "text": text,
                        "metadata": {
                            "layer": "api_cards",
                            "doc_type": "api_card",
                            "source_file": str(path.relative_to(PROJECT_ROOT)),
                            "library": library or "unknown",
                            "api": api,
                            "family": family,
                        },
                    })

        logger.info("Loaded {} API card docs", len(docs))
        return docs

    @staticmethod
    def iter_api_card_objects(obj: Any) -> List[Dict[str, Any]]:
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]
        if not isinstance(obj, dict):
            return []
        for key in (
            "api_cards",
            "wolfssl_api_cards_api_card_v0",
            "wolfssl_api_cards",
        ):
            value = obj.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        return [obj]

    def should_load_wycheproof_file(self, filename: str) -> bool:
        if not self.wycheproof_include_patterns:
            return True

        name = filename.lower()
        return any(p.lower() in name for p in self.wycheproof_include_patterns)

    def add_documents(self, docs: List[Dict[str, Any]]):
        for i in tqdm(range(0, len(docs), self.batch_size), desc="Embedding and inserting"):
            batch = docs[i:i + self.batch_size]

            ids = [x["id"] for x in batch]
            texts = [x["text"] for x in batch]
            metadatas = [x["metadata"] for x in batch]

            embeddings = self.embedder.embed(texts)

            self.collection.add(
                ids=ids,
                documents=texts,
                metadatas=metadatas,
                embeddings=embeddings
            )

    def chunk_text(self, text: str) -> List[str]:
        text = text.strip()
        if not text:
            return []

        if len(text) <= self.max_chars:
            return [text]

        chunks = []
        start = 0

        while start < len(text):
            end = min(start + self.max_chars, len(text))
            chunk = text[start:end].strip()

            if chunk:
                chunks.append(chunk)

            if end >= len(text):
                break

            start = max(0, end - self.overlap_chars)

        return chunks

    def chunk_poc_pattern_text(self, text: str) -> List[Dict[str, Any]]:
        sections = self.split_markdown_sections(text)
        chunks: List[Dict[str, Any]] = []
        for section in sections:
            metadata = self.parse_pattern_section_metadata(section)
            for chunk in self.chunk_text(section):
                chunks.append({"text": chunk, "metadata": metadata})
        return chunks

    @staticmethod
    def split_markdown_sections(text: str) -> List[str]:
        text = text.strip()
        if not text:
            return []
        matches = list(re.finditer(r"(?m)^##\s+(.+?)\s*$", text))
        if not matches:
            return [text]
        sections: List[str] = []
        for idx, match in enumerate(matches):
            start = match.start()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
            section = text[start:end].strip()
            if section:
                sections.append(section)
        return sections

    @staticmethod
    def parse_pattern_section_metadata(section: str) -> Dict[str, str]:
        metadata = {
            "pattern_id": "",
            "family": "",
            "oracle_type": "",
        }
        heading = re.search(r"(?m)^##\s+(.+?)\s*$", section)
        if heading:
            metadata["pattern_id"] = heading.group(1).strip()
        family = re.search(r"(?mi)^-\s*Family:\s*(.+?)\s*$", section)
        if family:
            metadata["family"] = family.group(1).strip()
        oracle = re.search(r"(?mi)^-\s*Oracle type:\s*(.+?)\s*$", section)
        if oracle:
            metadata["oracle_type"] = oracle.group(1).strip()
        return metadata

    @staticmethod
    def format_wycheproof_entry(obj: Dict[str, Any]) -> str:
        return (
            f"Source: Wycheproof\n"
            f"File: {obj.get('file', '')}\n"
            f"Algorithm: {obj.get('algorithm', '')}\n"
            f"API family: {obj.get('api_family', '')}\n"
            f"Case ID: {obj.get('case_id', '')}\n"
            f"Comment: {obj.get('comment', '')}\n"
            f"Result: {obj.get('result', '')}\n"
            f"Expected behavior: {obj.get('expected_behavior', '')}\n"
            f"Flags: {obj.get('flags', [])}\n"
            f"Group: {json.dumps(obj.get('group', {}), ensure_ascii=False)}\n"
            f"Params: {json.dumps(obj.get('params', {}), ensure_ascii=False)}\n"
        )

    @staticmethod
    def format_api_card_entry(obj: Dict[str, Any], api: str, library: str, family: str) -> str:
        fields = [
            "api",
            "library",
            "family",
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "valid_invalid_ranges",
            "unsupported_conditions",
            "mutation_hints",
            "oracle_observables",
            "known_pitfalls",
            "notes",
        ]
        card = dict(obj)
        card.setdefault("api", api)
        card.setdefault("library", library)
        card.setdefault("family", family)
        lines = ["Source: API Card"]
        for field in fields:
            value = card.get(field, "")
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (dict, list)):
                rendered = yaml.safe_dump(value, allow_unicode=True, sort_keys=False).strip()
            else:
                rendered = str(value)
            lines.append(f"{field}: {rendered}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def guess_library_from_path(path: Path) -> str:
        s = str(path)
        if "/mbedtls/" in s:
            return "mbedtls"
        if "/openssl/" in s:
            return "openssl"
        if "/botan/" in s:
            return "botan"
        return ""

    @staticmethod
    def make_id(prefix: str, name: str, idx: int) -> str:
        return f"{prefix}_{name}_{idx}_{uuid.uuid4().hex[:8]}"


if __name__ == "__main__":
    builder = RAGBuilder()
    builder.build()
