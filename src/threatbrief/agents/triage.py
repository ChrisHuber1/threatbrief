"""Triage Agent - multi-step priority reasoning with LangGraph.

Combines classification, enrichment, and time-series context to assign
final priority and recommended actions.
"""

from __future__ import annotations

from anthropic import AsyncAnthropic

from threatbrief.config import settings
from threatbrief.graph.state import AlertState

TRIAGE_PROMPT = """You are a Level 1 SOC analyst. Given the following security alert data,
determine the final triage priority (P1-Critical, P2-High, P3-Medium, P4-Low, P5-Info)
and recommend immediate response actions.

Alert Text: {text}
Classification: {classification}
Enrichment Summary: {enrichment_summary}
Similar Past Alerts: {similar_count}

Respond with:
PRIORITY: <P1-P5>
CONFIDENCE: <0.0-1.0>
ACTIONS:
- <action 1>
- <action 2>
- <action 3>
REASONING: <one paragraph>"""


class TriageAgent:
    name = "triage"

    def __init__(self) -> None:
        self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)

    async def process(self, state: AlertState) -> AlertState:
        enrichment_summary = (
            f"{state.enrichment.get('total_matches', 0)} intel matches, "
            f"{len(state.enrichment.get('cve_matches', []))} CVEs, "
            f"{len(state.enrichment.get('mitre_techniques', []))} MITRE techniques"
        )

        prompt = TRIAGE_PROMPT.format(
            text=state.normalized_alert.get("text", ""),
            classification=state.classification,
            enrichment_summary=enrichment_summary,
            similar_count=len(state.dedup.get("similar_alert_ids", [])),
        )

        response = await self._client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        result_text = response.content[0].text
        state.triage = self._parse_triage_response(result_text)
        state.processing_log.append(
            f"{self.name}: priority={state.triage.get('priority', 'unknown')}"
        )
        return state

    def _parse_triage_response(self, text: str) -> dict:
        result: dict = {"raw_response": text}
        for line in text.strip().splitlines():
            line = line.strip()
            if line.startswith("PRIORITY:"):
                result["priority"] = line.split(":", 1)[1].strip()
            elif line.startswith("CONFIDENCE:"):
                try:
                    result["confidence"] = float(line.split(":", 1)[1].strip())
                except ValueError:
                    result["confidence"] = 0.0
            elif line.startswith("REASONING:"):
                result["reasoning"] = line.split(":", 1)[1].strip()
        return result
