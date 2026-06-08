from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from src.models import AttackCategory, FirewallDecision, LayerResult, ThreatIndicator, Verdict


class AgentSession:
    def __init__(self, agent_id: str, tenant_id: str):
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.created_at = datetime.now(timezone.utc)
        self.messages: list[str] = []
        self.decisions: list[FirewallDecision] = []
        self.risk_trend: list[float] = []
        self.anomaly_flags: list[str] = []
        self.blocked_count = 0
        self.total_count = 0

    def record(self, message: str, decision: FirewallDecision):
        self.messages.append(message)
        self.decisions.append(decision)
        self.risk_trend.append(decision.risk_score)
        self.total_count += 1
        if decision.final_verdict in (Verdict.BLOCK, Verdict.QUARANTINE):
            self.blocked_count += 1

    @property
    def risk_escalating(self) -> bool:
        if len(self.risk_trend) < 3:
            return False
        recent = self.risk_trend[-3:]
        return recent[0] < recent[1] < recent[2] and recent[-1] > 0.5

    @property
    def block_ratio(self) -> float:
        return self.blocked_count / self.total_count if self.total_count > 0 else 0.0

    @property
    def is_suspicious(self) -> bool:
        return self.block_ratio > 0.3 or self.risk_escalating


class MultiAgentMonitor:
    def __init__(self, config: dict | None = None):
        self.enabled = True
        if config:
            self.enabled = config.get("enabled", True)
        self._sessions: dict[str, AgentSession] = {}
        self._lock = threading.Lock()
        self._global_stats: dict[str, int] = {"total_agents": 0, "total_messages": 0,
                                                "total_blocks": 0, "suspicious_agents": 0}

    def get_or_create_session(self, agent_id: str, tenant_id: str = "default") -> AgentSession:
        key = f"{tenant_id}:{agent_id}"
        with self._lock:
            if key not in self._sessions:
                self._sessions[key] = AgentSession(agent_id, tenant_id)
                self._global_stats["total_agents"] += 1
            return self._sessions[key]

    def analyze(self, text: str, agent_id: str = "", tenant_id: str = "default",
                decision: Optional[FirewallDecision] = None) -> LayerResult:
        if not self.enabled:
            return LayerResult(layer_name="multi_agent_monitor", risk_score=0.0, verdict=Verdict.ALLOW)

        session = self.get_or_create_session(agent_id, tenant_id)

        if decision:
            session.record(text, decision)

        self._update_global_stats()

        indicators: list[ThreatIndicator] = []

        if session.risk_escalating:
            indicators.append(ThreatIndicator(
                rule_id="MAM-ESCALATE-001",
                category=AttackCategory.AGENT_MANIPULATION,
                severity=Severity.HIGH,
                matched_pattern=f"Risk escalation detected: {session.risk_trend[-3:]}",
                weight=0.80,
                description="Escalating risk across agent messages",
            ))

        if session.block_ratio > 0.5:
            indicators.append(ThreatIndicator(
                rule_id="MAM-BLOCK-001",
                category=AttackCategory.AGENT_MANIPULATION,
                severity=Severity.CRITICAL,
                matched_pattern=f"High block ratio: {session.block_ratio:.2f}",
                weight=0.90,
                description="Agent producing excessive blocked prompts",
            ))

        if session.is_suspicious and not session.anomaly_flags:
            session.anomaly_flags.append(f"Flagged at {datetime.now(timezone.utc).isoformat()}")
            indicators.append(ThreatIndicator(
                rule_id="MAM-SUSPICIOUS-001",
                category=AttackCategory.AGENT_MANIPULATION,
                severity=Severity.HIGH,
                matched_pattern="Agent behavior pattern suspicious",
                weight=0.75,
                description="Agent flagged for suspicious behavior pattern",
            ))

        if not indicators:
            return LayerResult(layer_name="multi_agent_monitor", risk_score=0.0, verdict=Verdict.ALLOW)

        risk_score = max(ind.weight for ind in indicators)
        verdict = Verdict.BLOCK if risk_score >= 0.85 else (Verdict.QUARANTINE if risk_score >= 0.70 else Verdict.ALLOW_WITH_WARNING)

        return LayerResult(
            layer_name="multi_agent_monitor",
            risk_score=risk_score,
            verdict=verdict,
            category=AttackCategory.AGENT_MANIPULATION,
            indicators=indicators,
            raw_output={"agent_id": agent_id, "session_messages": len(session.messages)},
        )

    def get_agent_summary(self, agent_id: str, tenant_id: str = "default") -> dict:
        key = f"{tenant_id}:{agent_id}"
        session = self._sessions.get(key)
        if not session:
            return {"agent_id": agent_id, "status": "unknown"}
        return {
            "agent_id": agent_id,
            "tenant_id": session.tenant_id,
            "messages_processed": session.total_count,
            "blocks": session.blocked_count,
            "block_ratio": session.block_ratio,
            "risk_escalating": session.risk_escalating,
            "suspicious": session.is_suspicious,
            "created_at": session.created_at.isoformat(),
        }

    def get_global_stats(self) -> dict:
        self._update_global_stats()
        return dict(self._global_stats)

    def _update_global_stats(self):
        self._global_stats["total_messages"] = sum(s.total_count for s in self._sessions.values())
        self._global_stats["total_blocks"] = sum(s.blocked_count for s in self._sessions.values())
        self._global_stats["suspicious_agents"] = sum(1 for s in self._sessions.values() if s.is_suspicious)
