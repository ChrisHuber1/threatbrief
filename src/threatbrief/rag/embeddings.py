"""Embedding generation using HuggingFace sentence-transformers."""

from __future__ import annotations

from sentence_transformers import SentenceTransformer

from threatbrief.config import settings


class EmbeddingService:
    def __init__(self, model_name: str | None = None) -> None:
        self._model_name = model_name or settings.embedding_model
        self._model: SentenceTransformer | None = None

    @property
    def model(self) -> SentenceTransformer:
        if self._model is None:
            self._model = SentenceTransformer(self._model_name)
        return self._model

    def embed(self, text: str) -> list[float]:
        return self.model.encode(text).tolist()

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts).tolist()

    @property
    def dimension(self) -> int:
        return self.model.get_sentence_embedding_dimension()
