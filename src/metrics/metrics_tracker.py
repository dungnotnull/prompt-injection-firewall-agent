from __future__ import annotations

from src.models import SuccessMetrics


class MetricsTracker:
    def __init__(self, config: dict):
        self.targets = config.get("targets", {
            "recall": 0.95,
            "precision": 0.90,
            "f1": 0.92,
            "latency_ms": 50,
            "false_positive_rate": 0.05,
        })
        self.total = 0
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        self._latencies: list[float] = []

    def update(
        self,
        predicted_malicious: bool,
        is_malicious: bool,
        latency_ms: float,
    ):
        self.total += 1
        self._latencies.append(latency_ms)

        if predicted_malicious and is_malicious:
            self.true_positives += 1
        elif predicted_malicious and not is_malicious:
            self.false_positives += 1
        elif not predicted_malicious and is_malicious:
            self.false_negatives += 1
        else:
            self.true_negatives += 1

    def snapshot(self) -> SuccessMetrics:
        avg_latency = sum(self._latencies) / len(self._latencies) if self._latencies else 0.0
        return SuccessMetrics(
            recall=self._safe_div(self.true_positives, self.true_positives + self.false_negatives),
            precision=self._safe_div(self.true_positives, self.true_positives + self.false_positives),
            f1=self._compute_f1(),
            detection_latency_ms=round(avg_latency, 2),
            false_positive_rate=self._safe_div(self.false_positives, self.false_positives + self.true_negatives),
            total_evaluated=self.total,
            targets=self.targets,
        )

    def _compute_f1(self) -> float:
        p = self._safe_div(self.true_positives, self.true_positives + self.false_positives)
        r = self._safe_div(self.true_positives, self.true_positives + self.false_negatives)
        return self._safe_div(2 * p * r, p + r)

    @staticmethod
    def _safe_div(a: float, b: float) -> float:
        return a / b if b > 0 else 0.0
