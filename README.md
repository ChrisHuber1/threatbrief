# ThreatBrief

An autonomous SOC analyst that triages security alerts without human intervention. Six AI agents work as a pipeline ;  ingest raw data in any format, classify the threat, pull CVE and MITRE ATT&CK context, deduplicate related alerts, assign priority, and generate an executive incident brief.

I built this because SOC analysts spend most of their time on Level 1 triage that follows the same pattern every time. The interesting work starts at Level 2, but you can't get there if you're buried in 11,000 alerts a day.

## How It Works

```
Raw Alert (JSON / PDF / screenshot / audio)
    |
    v
Ingestion Agent ---- Whisper ASR, Document QA, Image-to-Text
    |
    v
Classifier Agent --- Zero-Shot + Text Classification
    |
    v
Enrichment Agent --- RAG over CVE/MITRE ATT&CK (pgvector)
    |
    v
Dedup Agent -------- Sentence similarity to cluster related alerts
    |
    v
Triage Agent ------- Claude-powered priority reasoning (P1-P5)
    |
    v
Briefing Agent ----- Generates executive incident report
```

Each agent is a node in a LangGraph workflow. The pipeline handles multimodal input ;  it can ingest a Wazuh JSON log, a threat intel PDF, a screenshot of a Defender alert, or a voice memo from an incident responder, and process them all through the same triage flow.

## Tech Stack

| Layer | What | Why |
|---|---|---|
| Orchestration | LangGraph | Needed conditional routing between agents ;  CrewAI's role-based model didn't fit a pipeline architecture |
| Vector store | pgvector on PostgreSQL 16 | Already running PostgreSQL for other projects. Pinecone adds a vendor dependency I don't want |
| NLP models | HuggingFace Transformers | Zero-shot classification, sentence similarity, summarization ;  all run locally on GPU |
| Final triage | Claude API | The priority decision needs reasoning over context that local models can't match yet |
| API | FastAPI | Standard, fast, good OpenAPI docs for free |
| Dashboard | Streamlit | Quick to build, good enough for a monitoring view |
| Eval | Custom harness + pytest | Measures priority accuracy, category accuracy, FP reduction rate, MTTT, P95 latency, cost per alert |
| Deployment | Docker Compose | Single command to bring up the full stack including pgvector |

## Decisions and Tradeoffs

**LangGraph over CrewAI:** CrewAI's "crew of agents with roles" model works well for tasks where agents collaborate. SOC triage is a pipeline ;  each step feeds the next in order. LangGraph's graph-based orchestration maps directly to that flow with conditional edges for routing.

**pgvector over Pinecone:** I'm already running PostgreSQL for TimescaleDB on another project. pgvector keeps everything in one database engine, no external API calls for retrieval, and I can run it locally without a paid tier.

**Claude for final triage, not for everything:** The classification and dedup steps run fine with local HuggingFace models. But the triage decision ;  weighing severity, business context, attack chain position, and whether this alert is actually the same incident as three others ;  needs the kind of reasoning that local models fumble. Claude handles that step; everything else stays local and free.

**Why not just fine-tune one model?** A single model that does ingestion, classification, enrichment, dedup, and triage would be cheaper per-inference but impossible to debug, evaluate per-stage, or improve incrementally. Six specialized agents means I can swap out the classifier without touching the enrichment pipeline.

## HuggingFace Tasks Integrated

| Category | Tasks |
|---|---|
| NLP | Text Classification, Zero-Shot Classification, Summarization, Feature Extraction, Sentence Similarity, Text Ranking, Text Generation |
| Multimodal | Document Question Answering, Visual Question Answering, Image-to-Text |
| Audio | Automatic Speech Recognition |
| Tabular | Time Series Forecasting |

## Running It

```bash
git clone https://github.com/ChrisHuber1/threatbrief.git
cd threatbrief
cp .env.example .env   # Add your API keys

docker compose up -d   # PostgreSQL + pgvector
pip install -e ".[dev,eval]"

uvicorn threatbrief.api.routes:app --reload   # API
streamlit run src/threatbrief/dashboard/app.py # Dashboard
pytest tests/                                  # Tests
python -m threatbrief.eval.harness             # Eval suite
```

## Current State

The scaffold is complete ;  all 6 agents, the LangGraph workflow, RAG pipeline, eval harness, API, dashboard, and tests are in place. HuggingFace pipeline integrations in the ingestion agent are stubbed and need real model wiring. The eval dataset has 5 labeled sample alerts; I need more to get meaningful accuracy numbers.

This is an active build, not a finished product.

## What's Next

1. Wire real HuggingFace pipelines into ingestion agent stubs
2. Seed pgvector with CVE and MITRE ATT&CK data
3. Build out eval dataset to 50+ labeled alerts
4. Add LangSmith tracing for pipeline observability
5. Benchmark end-to-end latency and cost per alert
