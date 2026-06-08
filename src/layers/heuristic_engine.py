from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml

from src.models import (
    AttackCategory,
    LayerResult,
    Severity,
    ThreatIndicator,
    Verdict,
)


class HeuristicRule:
    def __init__(self, rule_data: dict):
        self.id: str = rule_data["id"]
        self.category: AttackCategory = AttackCategory(rule_data["category"])
        self.subcategory: str = rule_data.get("subcategory", "")
        self.description: str = rule_data.get("description", "")
        self.severity: Severity = Severity(rule_data["severity"])
        self.weight: float = rule_data["weight"]
        self._patterns: list[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in rule_data["patterns"]
        ]

    def match(self, text: str) -> list[ThreatIndicator]:
        indicators: list[ThreatIndicator] = []
        for pattern in self._patterns:
            if match := pattern.search(text):
                indicators.append(ThreatIndicator(
                    rule_id=self.id,
                    category=self.category,
                    severity=self.severity,
                    matched_pattern=match.group(),
                    weight=self.weight,
                    description=self.description,
                ))
        return indicators


class HeuristicEngine:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        rules_path = config.get("rules_path", "./config/rules/default_rules.yaml")
        self._rules: list[HeuristicRule] = []
        self._load_rules(rules_path)

    def _load_rules(self, rules_path: str):
        resolved = Path(rules_path)
        if not resolved.exists():
            raise FileNotFoundError(f"Rules file not found: {resolved}")
        with open(resolved, encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)
        for rd in rule_data.get("rules", []):
            self._rules.append(HeuristicRule(rd))

    def scan(self, text: str) -> LayerResult:
        all_indicators: list[ThreatIndicator] = []
        for rule in self._rules:
            all_indicators.extend(rule.match(text))

        if not all_indicators:
            return LayerResult(
                layer_name="heuristic_engine",
                risk_score=0.0,
                verdict=Verdict.ALLOW,
            )

        max_weight = max(ind.weight for ind in all_indicators)
        severity_bonus = max(
            {"low": 0.0, "medium": 0.1, "high": 0.2, "critical": 0.3}[ind.severity]
            for ind in all_indicators
        )
        risk_score = min(1.0, max_weight + severity_bonus)

        verdict = self._verdict_from_risk(risk_score)
        top_category = self._dominant_category(all_indicators)

        indicators = sorted(all_indicators, key=lambda x: x.weight, reverse=True)

        return LayerResult(
            layer_name="heuristic_engine",
            risk_score=risk_score,
            verdict=verdict,
            category=top_category,
            indicators=indicators,
            raw_output={"matched_rules": len(indicators)},
        )

    def _verdict_from_risk(self, risk: float) -> Verdict:
        if risk >= 0.85:
            return Verdict.BLOCK
        if risk >= 0.70:
            return Verdict.QUARANTINE
        if risk >= 0.50:
            return Verdict.ALLOW_WITH_WARNING
        return Verdict.ALLOW

    def _dominant_category(self, indicators: list[ThreatIndicator]) -> AttackCategory:
        counts: dict[AttackCategory, float] = {}
        for ind in indicators:
            counts[ind.category] = counts.get(ind.category, 0.0) + ind.weight
        return max(counts, key=counts.get)
