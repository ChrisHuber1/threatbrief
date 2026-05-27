"""Eval harness - runs the triage pipeline against labeled datasets."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from threatbrief.eval.metrics import Timer, TriageMetrics
from threatbrief.graph.state import AlertState
from threatbrief.graph.workflow import graph

DATASETS_DIR = Path(__file__).parent / "datasets"


async def run_eval(dataset_path: Path | None = None) -> TriageMetrics:
    dataset_path = dataset_path or DATASETS_DIR / "labeled_alerts.json"
    with open(dataset_path) as f:
        dataset = json.load(f)

    metrics = TriageMetrics()

    for sample in dataset:
        state = AlertState(raw_input=sample["input"])
        expected = sample["expected"]

        with Timer() as timer:
            result = await graph.ainvoke(state)

        metrics.total_alerts += 1
        metrics.latencies_ms.append(timer.elapsed_ms)

        if result.triage.get("priority") == expected.get("priority"):
            metrics.correct_priority += 1
        if result.classification.get("category") == expected.get("category"):
            metrics.correct_category += 1
        if expected.get("is_false_positive"):
            metrics.total_false_positives += 1
            predicted_severity = result.classification.get("severity", "")
            if predicted_severity in ("informational", "low"):
                metrics.false_positives_caught += 1

    return metrics


def main() -> None:
    metrics = asyncio.run(run_eval())
    print("\n=== ThreatBrief Eval Results ===")
    for key, value in metrics.summary().items():
        print(f"  {key}: {value}")
    print()


if __name__ == "__main__":
    main()
