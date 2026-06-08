from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest, start_http_server

SCAN_TOTAL = Counter("pifirewall_scan_total", "Total scans processed", ["tenant_id", "verdict"])
SCAN_LATENCY = Histogram("pifirewall_scan_latency_ms", "Scan latency in milliseconds",
                         ["tenant_id"], buckets=[1, 5, 10, 20, 50, 100, 200, 500])
DETECTION_RESULT = Counter("pifirewall_detection_result", "Detection outcomes",
                           ["category", "verdict"])
RISK_SCORE_HISTOGRAM = Histogram("pifirewall_risk_score", "Risk score distribution",
                                 buckets=[0.0, 0.1, 0.3, 0.5, 0.7, 0.85, 0.95, 1.0])
ACTIVE_TENANTS = Gauge("pifirewall_active_tenants", "Number of active tenants")
DECISIONS_PROCESSED = Gauge("pifirewall_decisions_processed", "Total decisions processed")
FALSE_POSITIVE_RATE = Gauge("pifirewall_false_positive_rate", "Current false positive rate")
RECALL_RATE = Gauge("pifirewall_recall_rate", "Current recall rate")
ERROR_COUNTER = Counter("pifirewall_errors_total", "Total errors", ["error_type"])


class ObservabilityServer:
    def __init__(self, config: dict):
        self.port = config.get("metrics_port", 9090)
        self.enabled = config.get("metrics_enabled", True)

    def start(self):
        if self.enabled:
            start_http_server(self.port)

    def record_scan(self, tenant_id: str, verdict: str, category: str,
                    latency_ms: float, risk_score: float):
        SCAN_TOTAL.labels(tenant_id=tenant_id, verdict=verdict).inc()
        SCAN_LATENCY.labels(tenant_id=tenant_id).observe(latency_ms)
        DETECTION_RESULT.labels(category=category, verdict=verdict).inc()
        RISK_SCORE_HISTOGRAM.observe(risk_score)
        DECISIONS_PROCESSED.inc()

    def update_tenant_count(self, count: int):
        ACTIVE_TENANTS.set(count)

    def update_performance(self, false_positive_rate: float, recall: float):
        FALSE_POSITIVE_RATE.set(false_positive_rate)
        RECALL_RATE.set(recall)

    def record_error(self, error_type: str):
        ERROR_COUNTER.labels(error_type=error_type).inc()

    def get_metrics(self) -> bytes:
        return generate_latest()
