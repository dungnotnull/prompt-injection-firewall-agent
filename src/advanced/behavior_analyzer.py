from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from src.models import AttackCategory, LayerResult, Severity, ThreatIndicator, Verdict


class AgentBehaviorAnalyzer:
    COMMAND_PATTERNS = [
        re.compile(r"\b(rm\s+-rf|del\s+/[fsq]|format\s+[a-z]:)", re.I),
        re.compile(r"\b(curl|wget)\s+.*\s*\|\s*(sh|bash|python)", re.I),
        re.compile(r"\b(chmod\s+777|chown\s+root)", re.I),
        re.compile(r"\b(sudo|su\s+-)\b", re.I),
        re.compile(r"\b(kill|pkill|taskkill)\b", re.I),
        re.compile(r"\b(export\s+[A-Z_]+\s*=)", re.I),
    ]

    TOOL_MISUSE_PATTERNS = [
        re.compile(r"\b(tool_code|function_call|tool_calls)\b", re.I),
        re.compile(r"\b(invoke|execute|call)\s+(tool|function)\b", re.I),
        re.compile(r"\b(shell|bash|cmd|powershell)\s*(\(|command|script)", re.I),
        re.compile(r"\b(file_system|read_file|write_file|delete_file)\b", re.I),
        re.compile(r"\b(exec|eval|system|popen|subprocess)\s*\(", re.I),
    ]

    DATA_EXFIL_PATTERNS = [
        re.compile(r"\b(http|https|ftp)://.*\.(exfil|steal|leak)", re.I),
        re.compile(r"\b(base64|encode|decode).*(password|token|key|secret)", re.I),
        re.compile(r"\b(export|dump|extract)\s+(all\s+)?(data|records|users)", re.I),
        re.compile(r"\b(send|post|upload).*(password|token|key|secret)", re.I),
    ]

    def __init__(self, config: dict | None = None):
        self.enabled = True
        if config:
            self.enabled = config.get("enabled", True)

    def analyze(self, text: str, session_history: list[str] | None = None) -> LayerResult:
        if not self.enabled:
            return LayerResult(layer_name="behavior_analyzer", risk_score=0.0, verdict=Verdict.ALLOW)

        indicators: list[ThreatIndicator] = []
        indicators.extend(self._check_command_injection(text))
        indicators.extend(self._check_tool_misuse(text))
        indicators.extend(self._check_data_exfiltration(text))

        if session_history:
            indicators.extend(self._analyze_session_pattern(text, session_history))

        if not indicators:
            return LayerResult(layer_name="behavior_analyzer", risk_score=0.0, verdict=Verdict.ALLOW)

        max_weight = max(ind.weight for ind in indicators)
        severity_bonus = max(
            {"low": 0.0, "medium": 0.1, "high": 0.2, "critical": 0.3}.get(ind.severity, 0.0)
            for ind in indicators
        )
        risk_score = min(1.0, max_weight + severity_bonus)
        verdict = Verdict.BLOCK if risk_score >= 0.85 else (Verdict.QUARANTINE if risk_score >= 0.70 else Verdict.ALLOW_WITH_WARNING)

        return LayerResult(
            layer_name="behavior_analyzer",
            risk_score=risk_score,
            verdict=verdict,
            category=self._dominant_category(indicators),
            indicators=sorted(indicators, key=lambda x: x.weight, reverse=True),
            raw_output={"indicators_found": len(indicators)},
        )

    def _check_command_injection(self, text: str) -> list[ThreatIndicator]:
        indicators: list[ThreatIndicator] = []
        for pattern in self.COMMAND_PATTERNS:
            if m := pattern.search(text):
                indicators.append(ThreatIndicator(
                    rule_id="BEH-CMD-001",
                    category=AttackCategory.AGENT_MANIPULATION,
                    severity=Severity.CRITICAL,
                    matched_pattern=m.group(),
                    weight=0.95,
                    description="Dangerous system command detected",
                ))
        return indicators

    def _check_tool_misuse(self, text: str) -> list[ThreatIndicator]:
        indicators: list[ThreatIndicator] = []
        for pattern in self.TOOL_MISUSE_PATTERNS:
            if m := pattern.search(text):
                indicators.append(ThreatIndicator(
                    rule_id="BEH-TOOL-001",
                    category=AttackCategory.TOOL_ABUSE,
                    severity=Severity.HIGH,
                    matched_pattern=m.group(),
                    weight=0.85,
                    description="Tool invocation attempt detected",
                ))
        return indicators

    def _check_data_exfiltration(self, text: str) -> list[ThreatIndicator]:
        indicators: list[ThreatIndicator] = []
        for pattern in self.DATA_EXFIL_PATTERNS:
            if m := pattern.search(text):
                indicators.append(ThreatIndicator(
                    rule_id="BEH-EXFIL-001",
                    category=AttackCategory.DATA_EXFILTRATION,
                    severity=Severity.CRITICAL,
                    matched_pattern=m.group(),
                    weight=0.90,
                    description="Potential data exfiltration attempt",
                ))
        return indicators

    def _analyze_session_pattern(self, text: str, history: list[str]) -> list[ThreatIndicator]:
        indicators: list[ThreatIndicator] = []
        full_session = " ".join(history[-5:] + [text])

        if len(history) >= 2:
            instruction_words = ["ignore", "forget", "override", "disregard", "new task", "you are now"]
            count = sum(1 for word in instruction_words if word in text.lower())
            history_count = sum(1 for msg in history[-3:] for word in instruction_words if word in msg.lower())
            if count > 0 and history_count > 0:
                indicators.append(ThreatIndicator(
                    rule_id="BEH-SESSION-001",
                    category=AttackCategory.MULTI_TURN_ATTACK,
                    severity=Severity.HIGH,
                    matched_pattern="multi-turn instruction override",
                    weight=0.80,
                    description="Escalating multi-turn attack pattern detected",
                ))

        if "part 1" in full_session.lower() or "part 2" in full_session.lower():
            indicators.append(ThreatIndicator(
                rule_id="BEH-SESSION-002",
                category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                matched_pattern="split-payload across messages",
                weight=0.75,
                description="Prompt splitting detected across session",
            ))

        return indicators

    def _dominant_category(self, indicators: list[ThreatIndicator]) -> AttackCategory:
        counts: dict[AttackCategory, float] = {}
        for ind in indicators:
            counts[ind.category] = counts.get(ind.category, 0.0) + ind.weight
        return max(counts, key=counts.get) if counts else AttackCategory.UNKNOWN
