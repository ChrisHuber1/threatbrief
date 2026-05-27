"""Classifier Agent - severity and category classification.

Uses Text Classification and Zero-Shot Classification from HuggingFace.
"""

from __future__ import annotations

from threatbrief.graph.state import AlertState

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]

ALERT_CATEGORIES = [
    "malware",
    "phishing",
    "brute_force",
    "data_exfiltration",
    "privilege_escalation",
    "lateral_movement",
    "denial_of_service",
    "insider_threat",
    "misconfiguration",
    "reconnaissance",
]


class ClassifierAgent:
    name = "classifier"

    def __init__(self) -> None:
        self._zsc_pipeline = None
        self._text_cls_pipeline = None

    def _load_pipelines(self) -> None:
        if self._zsc_pipeline is None:
            from transformers import pipeline

            self._zsc_pipeline = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli",
            )

    async def process(self, state: AlertState) -> AlertState:
        self._load_pipelines()
        text = state.normalized_alert.get("text", "")

        category_result = self._zsc_pipeline(text, candidate_labels=ALERT_CATEGORIES)
        state.classification = {
            "category": category_result["labels"][0],
            "category_confidence": category_result["scores"][0],
            "all_categories": dict(zip(category_result["labels"], category_result["scores"])),
        }

        severity_result = self._zsc_pipeline(text, candidate_labels=SEVERITY_LEVELS)
        state.classification["severity"] = severity_result["labels"][0]
        state.classification["severity_confidence"] = severity_result["scores"][0]

        state.processing_log.append(
            f"{self.name}: {state.classification['category']} "
            f"({state.classification['category_confidence']:.2f}), "
            f"severity={state.classification['severity']}"
        )
        return state
