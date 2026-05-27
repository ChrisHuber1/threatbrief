# ThreatBrief -- Autonomous SOC Analyst Platform

Multi-agent AI system for Level 1 security alert triage. Ingests multimodal security data, classifies/deduplicates/enriches alerts via RAG, and produces prioritized incident briefs.

## Tech Stack
- **Python 3.12+**, FastAPI, LangGraph, pgvector, Streamlit
- **Models:** HuggingFace Transformers + Inference API, Claude for orchestration
- **Database:** PostgreSQL 16 with pgvector extension
- **Deployment:** Docker Compose

## Project Layout
```
src/threatbrief/
  agents/       -- individual agent implementations
  graph/        -- LangGraph workflow definition and state schema
  rag/          -- embedding generation and pgvector retrieval
  eval/         -- eval harness, metrics, and benchmark datasets
  api/          -- FastAPI routes
  dashboard/    -- Streamlit UI
  config.py     -- settings via pydantic-settings
```

## Commands
- `docker compose up -d` -- start PostgreSQL + pgvector
- `uvicorn threatbrief.api.routes:app --reload` -- dev API server
- `streamlit run src/threatbrief/dashboard/app.py` -- dashboard
- `pytest tests/` -- run tests
- `python -m threatbrief.eval.harness` -- run eval suite

## Conventions
- Feature branches: `feat/<short-slug>`
- Commit style: imperative, concise
- All agents implement `BaseAgent` protocol from `agents/__init__.py`
- Type hints everywhere, ruff for linting
