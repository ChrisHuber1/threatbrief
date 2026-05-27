"""Enrichment Agent - RAG over CVE database and MITRE ATT&CK.

Uses Feature Extraction for embeddings and pgvector for retrieval.
"""

from __future__ import annotations

from threatbrief.graph.state import AlertState
from threatbrief.rag.retriever import ThreatIntelRetriever


class EnrichmentAgent:
    name = "enrichment"

    def __init__(self, retriever: ThreatIntelRetriever | None = None) -> None:
        self._retriever = retriever or ThreatIntelRetriever()

    async def process(self, state: AlertState) -> AlertState:
        text = state.normalized_alert.get("text", "")
        category = state.classification.get("category", "")
        query = f"{category}: {text}"

        results = await self._retriever.retrieve(query)
        state.enrichment = {
            "cve_matches": [r for r in results if r.get("source") == "cve"],
            "mitre_techniques": [r for r in results if r.get("source") == "mitre"],
            "threat_intel": [r for r in results if r.get("source") == "threat_intel"],
            "total_matches": len(results),
        }

        state.processing_log.append(
            f"{self.name}: found {len(results)} relevant intelligence items"
        )
        return state
