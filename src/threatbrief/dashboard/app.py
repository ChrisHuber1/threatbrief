"""Streamlit dashboard for ThreatBrief SOC analyst interface."""

import json

import httpx
import streamlit as st

API_BASE = "http://localhost:8000/api/v1"

st.set_page_config(page_title="ThreatBrief", page_icon="🛡️", layout="wide")
st.title("ThreatBrief -- Autonomous SOC Analyst")

tab_triage, tab_history, tab_metrics = st.tabs(["Triage", "History", "Metrics"])

with tab_triage:
    st.subheader("Submit Alert for Triage")

    input_type = st.selectbox("Input Type", ["JSON Log", "Text", "File Upload"])

    if input_type == "JSON Log":
        raw = st.text_area(
            "Paste SIEM JSON log",
            value='{"event": "login_failure", "source": "siem", "severity": "high", '
            '"message": "Multiple failed login attempts from 10.0.0.50 to DC01", '
            '"timestamp": "2026-01-15T08:30:00Z"}',
            height=150,
        )
    elif input_type == "Text":
        raw = st.text_area("Describe the security incident", height=150)
    else:
        uploaded = st.file_uploader("Upload file (PDF, image, audio)")
        raw = uploaded.name if uploaded else None

    if st.button("Triage Alert", type="primary"):
        if not raw:
            st.error("Please provide alert data")
        else:
            with st.spinner("Running 6-agent triage pipeline..."):
                try:
                    payload = json.loads(raw) if input_type == "JSON Log" else raw
                    response = httpx.post(
                        f"{API_BASE}/triage",
                        json={"raw_input": payload},
                        timeout=120,
                    )
                    response.raise_for_status()
                    result = response.json()

                    col1, col2, col3 = st.columns(3)
                    col1.metric("Priority", result["priority"])
                    col2.metric("Category", result["category"])
                    col3.metric("Processing Time", f"{result['processing_time_ms']:.0f}ms")

                    st.markdown(result["brief"])

                    with st.expander("Processing Log"):
                        for entry in result["processing_log"]:
                            st.text(entry)
                except Exception as e:
                    st.error(f"Triage failed: {e}")

with tab_history:
    st.info("Alert history will be stored in PostgreSQL -- coming soon.")

with tab_metrics:
    st.info("Eval metrics dashboard -- run `python -m threatbrief.eval.harness` first.")
