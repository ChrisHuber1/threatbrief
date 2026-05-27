"""Briefing Agent - generates executive incident reports using Summarization."""

from __future__ import annotations

from anthropic import AsyncAnthropic

from threatbrief.config import settings
from threatbrief.graph.state import AlertState

BRIEFING_PROMPT = """Generate a concise security incident brief for executive review.

Alert: {text}
Category: {category} (confidence: {category_confidence:.0%})
Severity: {severity}
Priority: {priority}
CVE Matches: {cve_count}
MITRE Techniques: {mitre_count}
Recommended Actions: {actions}

Format as:
## Incident Brief
**Priority:** ...
**Category:** ...
**Summary:** (2-3 sentences)
**Impact:** (1-2 sentences)
**Recommended Actions:** (bulleted list)
**Related Intelligence:** (brief note on CVEs/MITRE techniques if any)"""


class BriefingAgent:
    name = "briefing"

    def __init__(self) -> None:
        self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)

    async def process(self, state: AlertState) -> AlertState:
        prompt = BRIEFING_PROMPT.format(
            text=state.normalized_alert.get("text", ""),
            category=state.classification.get("category", "unknown"),
            category_confidence=state.classification.get("category_confidence", 0),
            severity=state.classification.get("severity", "unknown"),
            priority=state.triage.get("priority", "unknown"),
            cve_count=len(state.enrichment.get("cve_matches", [])),
            mitre_count=len(state.enrichment.get("mitre_techniques", [])),
            actions=state.triage.get("raw_response", "N/A"),
        )

        response = await self._client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )

        state.brief = response.content[0].text
        state.processing_log.append(f"{self.name}: generated incident brief")
        return state
