from __future__ import annotations

from typing import Any, Protocol

from threatbrief.graph.state import AlertState


class BaseAgent(Protocol):
    """Protocol all ThreatBrief agents must implement."""

    name: str

    async def process(self, state: AlertState) -> AlertState:
        """Process the current alert state and return updated state."""
        ...
