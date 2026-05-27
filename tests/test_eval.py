"""Tests for the eval metrics module."""

from threatbrief.eval.metrics import Timer, TriageMetrics


def test_metrics_accuracy() -> None:
    m = TriageMetrics(total_alerts=10, correct_priority=8, correct_category=7)
    assert m.priority_accuracy == 0.8
    assert m.category_accuracy == 0.7


def test_metrics_latency() -> None:
    m = TriageMetrics(latencies_ms=[100.0, 200.0, 300.0, 400.0, 500.0])
    assert m.mean_latency_ms == 300.0
    assert m.p95_latency_ms == 500.0


def test_metrics_empty() -> None:
    m = TriageMetrics()
    assert m.priority_accuracy == 0.0
    assert m.mean_latency_ms == 0.0
    assert m.p95_latency_ms == 0.0


def test_timer() -> None:
    import time

    with Timer() as t:
        time.sleep(0.01)
    assert t.elapsed_ms > 5


def test_metrics_summary() -> None:
    m = TriageMetrics(
        total_alerts=100,
        correct_priority=85,
        correct_category=78,
        false_positives_caught=40,
        total_false_positives=50,
        latencies_ms=[150.0] * 100,
        costs_usd=[0.003] * 100,
    )
    summary = m.summary()
    assert summary["total_alerts"] == 100
    assert "85" in summary["priority_accuracy"]
