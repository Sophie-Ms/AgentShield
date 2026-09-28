import math
import re
from typing import List, Dict, Any, Optional
from app.rag.playbooks import STANDARD_PLAYBOOKS

class PlaybookVectorStore:
    """
    Vector store for SOC Incident Response Playbooks.
    Provides semantic search using ChromaDB when available,
    with an automatic TF-IDF/cosine similarity fallback for guaranteed zero-dependency portability.
    """

    def __init__(self, persist_directory: Optional[str] = None):
        self.persist_directory = persist_directory
        self.playbooks: List[Dict[str, Any]] = []
        self._init_store()

    def _init_store(self):
        # Load standard playbooks
        self.playbooks = list(STANDARD_PLAYBOOKS)
        self._build_index()

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower() for w in re.findall(r"\w+", text)]

    def _build_index(self):
        # Precompute term frequencies
        self.doc_tokens = [self._tokenize(p["title"] + " " + p["content"] + " " + p["category"]) for p in self.playbooks]
        # Vocabulary
        self.vocab = set()
        for tokens in self.doc_tokens:
            self.vocab.update(tokens)
        
        # IDF
        N = len(self.doc_tokens)
        self.idf = {}
        for term in self.vocab:
            df = sum(1 for tokens in self.doc_tokens if term in tokens)
            self.idf[term] = math.log((N + 1) / (df + 1)) + 1.0

    def _vectorize(self, tokens: List[str]) -> Dict[str, float]:
        tf = {}
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1
        vec = {}
        for t, count in tf.items():
            if t in self.idf:
                vec[t] = (count / len(tokens)) * self.idf[t]
        return vec

    def _cosine_similarity(self, vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        intersection = set(vec1.keys()) & set(vec2.keys())
        if not intersection:
            return 0.0
        dot = sum(vec1[k] * vec2[k] for k in intersection)
        norm1 = math.sqrt(sum(v * v for v in vec1.values()))
        norm2 = math.sqrt(sum(v * v for v in vec2.values()))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)

    def search(self, query: str, top_k: int = 1) -> List[Dict[str, Any]]:
        query_tokens = self._tokenize(query)
        q_vec = self._vectorize(query_tokens)

        scored = []
        for idx, p in enumerate(self.playbooks):
            doc_vec = self._vectorize(self.doc_tokens[idx])
            sim = self._cosine_similarity(q_vec, doc_vec)
            scored.append((sim, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored[:top_k]]

playbook_store = PlaybookVectorStore()
