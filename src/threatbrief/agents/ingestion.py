"""Ingestion Agent - normalizes multimodal inputs into structured alert data.

Handles: SIEM JSON logs, threat intel PDFs (Document QA), dashboard screenshots
(Image-to-Text), voice incident reports (ASR).
"""

from __future__ import annotations

from typing import Any

from threatbrief.graph.state import AlertState


class IngestionAgent:
    name = "ingestion"

    async def process(self, state: AlertState) -> AlertState:
        raw = state.raw_input
        input_type = self._detect_type(raw)

        match input_type:
            case "json_log":
                normalized = self._parse_siem_log(raw)
            case "pdf":
                normalized = await self._extract_from_pdf(raw)
            case "image":
                normalized = await self._extract_from_image(raw)
            case "audio":
                normalized = await self._transcribe_audio(raw)
            case _:
                normalized = {"text": str(raw), "source": "unknown"}

        state.normalized_alert = normalized
        state.processing_log.append(f"{self.name}: ingested as {input_type}")
        return state

    def _detect_type(self, raw: Any) -> str:
        if isinstance(raw, dict) and "event" in raw:
            return "json_log"
        if isinstance(raw, (str, bytes)):
            if hasattr(raw, "endswith") and raw.endswith(".pdf"):
                return "pdf"
            if hasattr(raw, "endswith") and raw.endswith((".png", ".jpg", ".jpeg")):
                return "image"
            if hasattr(raw, "endswith") and raw.endswith((".wav", ".mp3", ".m4a")):
                return "audio"
        return "text"

    def _parse_siem_log(self, raw: dict) -> dict:
        return {
            "text": raw.get("message", ""),
            "source": raw.get("source", "siem"),
            "severity_hint": raw.get("severity", "unknown"),
            "timestamp": raw.get("timestamp"),
            "metadata": {k: v for k, v in raw.items() if k not in ("message", "source", "severity", "timestamp")},
        }

    async def _extract_from_pdf(self, path: str) -> dict:
        # TODO: HuggingFace Document QA pipeline
        return {"text": f"[PDF content from {path}]", "source": "pdf"}

    async def _extract_from_image(self, path: str) -> dict:
        # TODO: HuggingFace Image-to-Text pipeline
        return {"text": f"[Image content from {path}]", "source": "screenshot"}

    async def _transcribe_audio(self, path: str) -> dict:
        # TODO: HuggingFace ASR (Whisper) pipeline
        return {"text": f"[Transcribed audio from {path}]", "source": "voice_report"}
