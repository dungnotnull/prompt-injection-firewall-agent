from __future__ import annotations

import re
from pathlib import Path

import yaml

from src.models import AttackCategory, LayerResult, Severity, ThreatIndicator, Verdict


class ThreatSignature:
    def __init__(self, sig_data: dict):
        self.id: str = sig_data["id"]
        self.name: str = sig_data["name"]
        self.severity: Severity = Severity(sig_data["severity"])
        self.source: str = sig_data.get("source", "unknown")
        self._patterns: list[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in sig_data.get("patterns", [])
        ]

    def match(self, text: str) -> list[ThreatIndicator]:
        indicators: list[ThreatIndicator] = []
        for pattern in self._patterns:
            if m := pattern.search(text):
                indicators.append(ThreatIndicator(
                    rule_id=self.id,
                    category=AttackCategory.UNKNOWN,
                    severity=self.severity,
                    matched_pattern=m.group(),
                    weight=0.85,
                    description=f"Known attack signature: {self.name} (source: {self.source})",
                ))
        return indicators


class ThreatIntelligenceLayer:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.sources: list[str] = config.get("sources", [])
        signatures_path = config.get("signatures_path", "./config/signatures/known_attacks.yaml")
        self._signatures: list[ThreatSignature] = []
        self._load_signatures(signatures_path)

    def _load_signatures(self, signatures_path: str):
        resolved = Path(signatures_path)
        if not resolved.exists():
            return
        with open(resolved, encoding="utf-8") as f:
            sig_data = yaml.safe_load(f)
        for sd in sig_data.get("signatures", []):
            self._signatures.append(ThreatSignature(sd))

    def scan(self, text: str) -> LayerResult:
        if not self.enabled:
            return LayerResult(
                layer_name="threat_intelligence",
                risk_score=0.0,
                verdict=Verdict.ALLOW,
            )

        all_indicators: list[ThreatIndicator] = []
        for sig in self._signatures:
            all_indicators.extend(sig.match(text))

        if not all_indicators:
            return LayerResult(
                layer_name="threat_intelligence",
                risk_score=0.0,
                verdict=Verdict.ALLOW,
            )

        max_weight = max(ind.weight for ind in all_indicators)
        risk_score = min(1.0, max_weight)
        verdict = Verdict.BLOCK if risk_score >= 0.85 else Verdict.QUARANTINE

        return LayerResult(
            layer_name="threat_intelligence",
            risk_score=risk_score,
            verdict=verdict,
            category=AttackCategory.UNKNOWN,
            indicators=all_indicators,
            raw_output={"sources": self.sources, "matched_signatures": len(all_indicators)},
        )
