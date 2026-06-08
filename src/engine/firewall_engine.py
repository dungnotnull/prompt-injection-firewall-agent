from __future__ import annotations

import time
from pathlib import Path

import yaml

from src.advanced import AgentBehaviorAnalyzer, MultiAgentMonitor, ToolAbuseDetector
from src.layers.continuous_learning import ContinuousLearningEngine
from src.layers.explainability_engine import ExplainabilityEngine
from src.layers.heuristic_engine import HeuristicEngine
from src.layers.ml_classifier import FastSecurityClassifier
from src.layers.threat_intelligence import ThreatIntelligenceLayer
from src.logging import get_audit_logger
from src.models import FirewallDecision, LayerResult, Verdict
from src.metrics.metrics_tracker import MetricsTracker


class FirewallEngine:
    def __init__(self, config_path: str | Path = "./config/default.yaml"):
        with open(config_path, encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        self.layer_1 = FastSecurityClassifier(self.config.get("layer_1_classifier", {}))
        self.layer_2 = HeuristicEngine(self.config.get("layer_2_heuristic", {}))
        self.layer_3 = ThreatIntelligenceLayer(self.config.get("layer_3_threat_intel", {}))
        self.layer_4 = ExplainabilityEngine(self.config.get("layer_4_explainability", {}))
        self.layer_5 = ContinuousLearningEngine(self.config.get("layer_5_continuous_learning", {}))
        self.behavior_analyzer = AgentBehaviorAnalyzer(self.config.get("layer_6_behavior", {}))
        self.tool_abuse_detector = ToolAbuseDetector(self.config.get("layer_6_tool_abuse", {}))
        self.multi_agent_monitor = MultiAgentMonitor(self.config.get("layer_6_multi_agent", {}))

        self._thresholds = self.config.get("firewall", {}).get("decision_threshold", {
            "risk_threshold": 0.5, "quarantine_threshold": 0.7, "block_threshold": 0.85,
        })
        self._decision_history: list[FirewallDecision] = []
        self._audit_logger = get_audit_logger(self.config.get("logging", {}))

    def scan(self, text: str, tenant_id: str = "default", session_id: str = "") -> FirewallDecision:
        start = time.perf_counter()
        layer_results: list[LayerResult] = []

        t0 = time.perf_counter()
        l1 = self.layer_1.predict(text)
        l1.latency_ms = (time.perf_counter() - t0) * 1000
        layer_results.append(l1)

        t0 = time.perf_counter()
        l2 = self.layer_2.scan(text)
        l2.latency_ms = (time.perf_counter() - t0) * 1000
        layer_results.append(l2)

        t0 = time.perf_counter()
        l3 = self.layer_3.scan(text)
        l3.latency_ms = (time.perf_counter() - t0) * 1000
        layer_results.append(l3)

        t0 = time.perf_counter()
        l6a = self.behavior_analyzer.analyze(text)
        l6a.latency_ms = (time.perf_counter() - t0) * 1000
        layer_results.append(l6a)

        t0 = time.perf_counter()
        l6b = self.tool_abuse_detector.analyze(text)
        l6b.latency_ms = (time.perf_counter() - t0) * 1000
        layer_results.append(l6b)

        t0 = time.perf_counter()
        l6c = self.multi_agent_monitor.analyze(text, agent_id=session_id, tenant_id=tenant_id)
        l6c.latency_ms = (time.perf_counter() - t0) * 1000
        layer_results.append(l6c)

        decision = self.layer_4.build_decision(text, layer_results)
        decision.total_latency_ms = (time.perf_counter() - start) * 1000
        decision.tenant_id = tenant_id
        decision.session_id = session_id

        self._decision_history.append(decision)
        self._audit_logger.log_decision(decision)
        return decision

    def evaluate_on_samples(self, samples: list, label_fn=None) -> MetricsTracker:
        tracker = MetricsTracker(self.config.get("metrics", {}))
        for sample in samples:
            decision = self.scan(sample.text)
            predicted_malicious = decision.final_verdict in (Verdict.BLOCK, Verdict.QUARANTINE)
            is_malicious = sample.label in ("malicious", "prompt_injection", "jailbreak", "unsafe", "harmful", "1")
            tracker.update(predicted_malicious=predicted_malicious, is_malicious=is_malicious, latency_ms=decision.total_latency_ms)
        return tracker

    def research_update(self) -> dict:
        return self.layer_5.run_research_cycle()

    def knowledge_summary(self) -> dict:
        return self.layer_5.get_knowledge_summary()

    @property
    def decision_count(self) -> int:
        return len(self._decision_history)

    def get_audit_trail(self, tenant_id: str | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        return self._audit_logger.get_audit_trail(tenant_id=tenant_id, limit=limit, offset=offset)
