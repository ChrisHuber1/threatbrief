"""LangGraph workflow orchestrating the 6-agent triage pipeline."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from threatbrief.agents.briefing import BriefingAgent
from threatbrief.agents.classifier import ClassifierAgent
from threatbrief.agents.dedup import DedupAgent
from threatbrief.agents.enrichment import EnrichmentAgent
from threatbrief.agents.ingestion import IngestionAgent
from threatbrief.agents.triage import TriageAgent
from threatbrief.graph.state import AlertState

ingestion = IngestionAgent()
classifier = ClassifierAgent()
enrichment = EnrichmentAgent()
dedup = DedupAgent()
triage = TriageAgent()
briefing = BriefingAgent()


def should_skip_triage(state: AlertState) -> str:
    if state.dedup.get("is_duplicate"):
        return "skip"
    severity = state.classification.get("severity", "")
    if severity == "informational":
        return "skip"
    return "continue"


def build_workflow() -> StateGraph:
    workflow = StateGraph(AlertState)

    workflow.add_node("ingestion", ingestion.process)
    workflow.add_node("classifier", classifier.process)
    workflow.add_node("enrichment", enrichment.process)
    workflow.add_node("dedup", dedup.process)
    workflow.add_node("triage", triage.process)
    workflow.add_node("briefing", briefing.process)

    workflow.set_entry_point("ingestion")
    workflow.add_edge("ingestion", "classifier")
    workflow.add_edge("classifier", "enrichment")
    workflow.add_edge("enrichment", "dedup")
    workflow.add_conditional_edges(
        "dedup",
        should_skip_triage,
        {"continue": "triage", "skip": END},
    )
    workflow.add_edge("triage", "briefing")
    workflow.add_edge("briefing", END)

    return workflow


graph = build_workflow().compile()
