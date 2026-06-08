from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from src.models import AttackCategory, LayerResult, Severity, ThreatIndicator, Verdict


class ToolAbuseDetector:
    TOOL_SIGNATURES = {
        "file_write": re.compile(r"\b(write|create|save|dump|export)\s+(to\s+)?(file|disk|path)\b", re.I),
        "file_read": re.compile(r"\b(read|open|load|cat|get)\s+(file|path|document|config)\b", re.I),
        "file_delete": re.compile(r"\b(delete|remove|erase|wipe|shred)\s+(file|path|document)\b", re.I),
        "shell_exec": re.compile(r"\b(execute|run|invoke)\s+(shell|command|bash|cmd|script)\b", re.I),
        "network_access": re.compile(r"\b(fetch|curl|wget|request)\s+(http|url|endpoint|api)\b", re.I),
        "code_execution": re.compile(r"\b(execute|run|eval)\s+(code|script|python|js|javascript)\b", re.I),
        "db_access": re.compile(r"\b(query|select|insert|update|delete|drop)\s+(from\s+)?(database|table|db)\b", re.I),
        "email_send": re.compile(r"\b(send|email|forward|transmit)\s+(to\s+)?(email|recipient|address)\b", re.I),
    }

    RISK_THRESHOLDS = {
        "file_delete": 0.95,
        "shell_exec": 0.95,
        "code_execution": 0.90,
        "network_access": 0.80,
        "db_access": 0.85,
        "file_write": 0.75,
        "email_send": 0.70,
        "file_read": 0.50,
    }

    def __init__(self, config: dict | None = None):
        self.enabled = True
        self.allowed_tools: set[str] = set()
        if config:
            self.enabled = config.get("enabled", True)
            self.allowed_tools = set(config.get("allowed_tools", []))

    def analyze(self, text: str, tool_name: str = "", tool_args: str = "") -> LayerResult:
        if not self.enabled:
            return LayerResult(layer_name="tool_abuse_detector", risk_score=0.0, verdict=Verdict.ALLOW)

        indicators: list[ThreatIndicator] = []

        if tool_name and tool_name in self.allowed_tools:
            pass
        else:
            combined = f"{text} {tool_name} {tool_args}"
            for sig_name, pattern in self.TOOL_SIGNATURES.items():
                if m := pattern.search(combined):
                    risk = self.RISK_THRESHOLDS.get(sig_name, 0.60)
                    indicators.append(ThreatIndicator(
                        rule_id=f"TOOL-{sig_name.upper()}",
                        category=AttackCategory.TOOL_ABUSE,
                        severity=Severity.CRITICAL if risk >= 0.90 else Severity.HIGH,
                        matched_pattern=m.group(),
                        weight=risk,
                        description=f"Tool abuse detected: {sig_name}",
                    ))

        if tool_name and not tool_args:
            pass

        if not indicators:
            return LayerResult(layer_name="tool_abuse_detector", risk_score=0.0, verdict=Verdict.ALLOW)

        risk_score = max(ind.weight for ind in indicators)
        verdict = Verdict.BLOCK if risk_score >= 0.85 else Verdict.QUARANTINE

        return LayerResult(
            layer_name="tool_abuse_detector",
            risk_score=risk_score,
            verdict=verdict,
            category=AttackCategory.TOOL_ABUSE,
            indicators=indicators,
            raw_output={"tool_name": tool_name, "matched": len(indicators)},
        )
