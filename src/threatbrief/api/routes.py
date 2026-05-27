"""FastAPI routes for the ThreatBrief triage API."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from threatbrief.graph.state import AlertState
from threatbrief.graph.workflow import graph

app = FastAPI(
    title="ThreatBrief",
    description="Autonomous SOC Analyst - AI-powered security alert triage",
    version="0.1.0",
)


class AlertRequest(BaseModel):
    raw_input: Any
    source: str = "api"


class AlertResponse(BaseModel):
    alert_id: str
    priority: str
    category: str
    severity: str
    is_duplicate: bool
    brief: str
    processing_log: list[str]
    processing_time_ms: float


@app.post("/api/v1/triage", response_model=AlertResponse)
async def triage_alert(request: AlertRequest) -> AlertResponse:
    import time

    start = time.perf_counter()
    alert_id = str(uuid.uuid4())

    state = AlertState(
        raw_input=request.raw_input,
        alert_id=alert_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    try:
        result = await graph.ainvoke(state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Triage failed: {e}")

    elapsed_ms = (time.perf_counter() - start) * 1000

    return AlertResponse(
        alert_id=alert_id,
        priority=result.triage.get("priority", "unknown"),
        category=result.classification.get("category", "unknown"),
        severity=result.classification.get("severity", "unknown"),
        is_duplicate=result.dedup.get("is_duplicate", False),
        brief=result.brief,
        processing_log=result.processing_log,
        processing_time_ms=round(elapsed_ms, 1),
    )


@app.get("/api/v1/health")
async def health() -> dict:
    return {"status": "ok", "service": "threatbrief"}
