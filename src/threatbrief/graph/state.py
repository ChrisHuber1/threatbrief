"""Alert processing state schema shared across all agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AlertState:
    """Mutable state passed through the LangGraph agent pipeline."""

    raw_input: Any = None
    normalized_alert: dict = field(default_factory=dict)
    classification: dict = field(default_factory=dict)
    enrichment: dict = field(default_factory=dict)
    dedup: dict = field(default_factory=dict)
    triage: dict = field(default_factory=dict)
    brief: str = ""
    processing_log: list[str] = field(default_factory=list)
    alert_id: str = ""
    created_at: str = ""
