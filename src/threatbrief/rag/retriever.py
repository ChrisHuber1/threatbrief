"""pgvector-backed retriever for CVE, MITRE ATT&CK, and threat intel."""

from __future__ import annotations

from typing import Any

from threatbrief.config import settings
from threatbrief.rag.embeddings import EmbeddingService


class ThreatIntelRetriever:
    def __init__(self, embedding_service: EmbeddingService | None = None) -> None:
        self._embeddings = embedding_service or EmbeddingService()
        self._db = None

    async def _get_db(self) -> Any:
        if self._db is None:
            import psycopg

            self._db = await psycopg.AsyncConnection.connect(settings.database_url)
        return self._db

    async def retrieve(self, query: str, top_k: int | None = None) -> list[dict]:
        top_k = top_k or settings.top_k_retrieval
        query_embedding = self._embeddings.embed(query)

        db = await self._get_db()
        async with db.cursor() as cur:
            await cur.execute(
                """
                SELECT id, content, source, metadata,
                       1 - (embedding <=> %s::vector) AS similarity
                FROM threat_intel
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (query_embedding, query_embedding, top_k),
            )
            rows = await cur.fetchall()

        return [
            {
                "id": row[0],
                "content": row[1],
                "source": row[2],
                "metadata": row[3],
                "similarity": row[4],
            }
            for row in rows
        ]

    async def ingest(self, documents: list[dict]) -> int:
        texts = [doc["content"] for doc in documents]
        embeddings = self._embeddings.embed_batch(texts)

        db = await self._get_db()
        async with db.cursor() as cur:
            for doc, emb in zip(documents, embeddings):
                await cur.execute(
                    """
                    INSERT INTO threat_intel (content, source, metadata, embedding)
                    VALUES (%s, %s, %s, %s::vector)
                    """,
                    (doc["content"], doc["source"], doc.get("metadata", {}), emb),
                )
        await db.commit()
        return len(documents)
