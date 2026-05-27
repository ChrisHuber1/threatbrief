"""Evaluation metrics for SOC triage quality."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class TriageMetrics:
    total_alerts: int = 0
    correct_priority: int = 0
    correct_category: int = 0
    false_positives_caught: int = 0
    total_false_positives: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    costs_usd: list[float] = field(default_factory=list)

    @property
    def priority_accuracy(self) -> float:
        if self.total_alerts == 0:
            return 0.0
        return self.correct_priority / self.total_alerts

    @property
    def category_accuracy(self) -> float:
        if self.total_alerts == 0:
            return 0.0
        return self.correct_category / self.total_alerts

    @property
    def false_positive_reduction(self) -> float:
        if self.total_false_positives == 0:
            return 0.0
        return self.false_positives_caught / self.total_false_positives

    @property
    def mean_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return sum(self.latencies_ms) / len(self.latencies_ms)

    @property
    def p95_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_latencies = sorted(self.latencies_ms)
        idx = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]

    @property
    def mean_cost_usd(self) -> float:
        if not self.costs_usd:
            return 0.0
        return sum(self.costs_usd) / len(self.costs_usd)

    def summary(self) -> dict:
        return {
            "total_alerts": self.total_alerts,
            "priority_accuracy": f"{self.priority_accuracy:.1%}",
            "category_accuracy": f"{self.category_accuracy:.1%}",
            "false_positive_reduction": f"{self.false_positive_reduction:.1%}",
            "mean_latency_ms": f"{self.mean_latency_ms:.0f}",
            "p95_latency_ms": f"{self.p95_latency_ms:.0f}",
            "mean_cost_per_alert_usd": f"${self.mean_cost_usd:.4f}",
        }


class Timer:
    def __init__(self) -> None:
        self._start: float = 0
        self.elapsed_ms: float = 0

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args: object) -> None:
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000
