from typing import List
import time
import httpx


class OllamaEmbedder:
    def __init__(
        self,
        model_name: str = "mxbai-embed-large",
        base_url: str = "http://localhost:11434",
        endpoint: str = "/api/embed",
        timeout: float = 600.0,
        max_retries: int = 3,
    ):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.endpoint = endpoint
        self.timeout = timeout
        self.max_retries = max_retries

    def embed(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []

        url = f"{self.base_url}{self.endpoint}"
        payload = {
            "model": self.model_name,
            "input": texts,
        }

        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, json=payload)
                    resp.raise_for_status()
                    data = resp.json()

                if "embeddings" not in data:
                    raise RuntimeError(f"Ollama response missing embeddings: {data}")

                return data["embeddings"]

            except Exception as e:
                last_error = e
                print(f"[WARN] Ollama embed failed, attempt {attempt}/{self.max_retries}: {e}")
                time.sleep(2 * attempt)

        raise RuntimeError(f"Ollama embedding failed after {self.max_retries} retries: {last_error}")
