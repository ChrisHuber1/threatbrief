"""Tests for individual ThreatBrief agents."""

import pytest

from threatbrief.agents.ingestion import IngestionAgent
from threatbrief.graph.state import AlertState


@pytest.fixture
def siem_alert() -> dict:
    return {
        "event": "login_failure",
        "source": "siem",
        "severity": "high",
        "message": "Multiple failed login attempts from 10.0.0.50 to DC01",
        "timestamp": "2026-01-15T08:30:00Z",
    }


async def test_ingestion_siem_log(siem_alert: dict) -> None:
    agent = IngestionAgent()
    state = AlertState(raw_input=siem_alert)
    result = await agent.process(state)

    assert result.normalized_alert["source"] == "siem"
    assert "failed login" in result.normalized_alert["text"].lower()
    assert len(result.processing_log) == 1


async def test_ingestion_text_input() -> None:
    agent = IngestionAgent()
    state = AlertState(raw_input="Suspicious outbound traffic detected on port 4444")
    result = await agent.process(state)

    assert result.normalized_alert["source"] == "unknown"
    assert "port 4444" in result.normalized_alert["text"]


async def test_state_initialization() -> None:
    state = AlertState(raw_input={"test": True})
    assert state.normalized_alert == {}
    assert state.classification == {}
    assert state.processing_log == []
    assert state.brief == ""
