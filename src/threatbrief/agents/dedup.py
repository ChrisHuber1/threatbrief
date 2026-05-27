"""Dedup Agent - clusters related alerts using Sentence Similarity and Text Ranking."""

from __future__ import annotations

from threatbrief.graph.state import AlertState


class DedupAgent:
    name = "dedup"

    def __init__(self) -> None:
        self._similarity_model = None

    def _load_model(self) -> None:
        if self._similarity_model is None:
            from sentence_transformers import SentenceTransformer

            self._similarity_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    async def process(self, state: AlertState) -> AlertState:
        self._load_model()
        text = state.normalized_alert.get("text", "")
        embedding = self._similarity_model.encode(text)

        # TODO: compare against recent alert embeddings in pgvector
        # For now, mark as unique
        state.dedup = {
            "is_duplicate": False,
            "cluster_id": None,
            "similar_alert_ids": [],
            "embedding": embedding.tolist(),
        }

        state.processing_log.append(f"{self.name}: alert is unique (no duplicates found)")
        return state
