from __future__ import annotations

from src.models import (AttackCategory, FirewallDecision, LayerResult, Severity,
                        Verdict)


class ExplainabilityEngine:
    def __init__(self, config: dict):
        self.include_indicators = config.get("include_indicators", True)
        self.include_confidence = config.get("include_confidence", True)
        self.include_recommendation = config.get("include_recommendation", True)

    def build_decision(
        self,
        input_text: str,
        layer_results: list[LayerResult],
    ) -> FirewallDecision:
        risk_score, final_verdict = self._aggregate(layer_results)
        category = self._dominant_category(layer_results)
        confidence = self._compute_confidence(layer_results)
        reason = self._build_reason(layer_results)
        recommendations = self._build_recommendations(final_verdict, category)
        audit_id = hex(hash(input_text + str(layer_results)))[:12]

        return FirewallDecision(
            input_text=input_text,
            risk_score=round(risk_score, 4),
            final_verdict=final_verdict,
            attack_category=category,
            confidence=round(confidence, 4),
            reason=reason,
            recommendations=recommendations,
            layer_results=layer_results,
            audit_id=audit_id,
        )

    def _aggregate(self, layer_results: list[LayerResult]) -> tuple[float, Verdict]:
        if not layer_results:
            return 0.0, Verdict.ALLOW

        scores = [lr.risk_score for lr in layer_results]
        max_score = max(scores)

        verdicts = [lr.verdict for lr in layer_results]
        if Verdict.BLOCK in verdicts:
            return max_score, Verdict.BLOCK
        if Verdict.QUARANTINE in verdicts:
            return max_score, Verdict.QUARANTINE
        if Verdict.ALLOW_WITH_WARNING in verdicts:
            return max_score, Verdict.ALLOW_WITH_WARNING
        return max_score, Verdict.ALLOW

    def _dominant_category(self, layer_results: list[LayerResult]) -> AttackCategory:
        for lr in layer_results:
            if lr.category != AttackCategory.UNKNOWN:
                return lr.category
        return AttackCategory.UNKNOWN

    def _compute_confidence(self, layer_results: list[LayerResult]) -> float:
        if not layer_results:
            return 1.0
        scores = [lr.risk_score for lr in layer_results]
        max_score = max(scores)
        if max_score >= 0.85:
            return 0.95
        if max_score >= 0.50:
            return 0.75
        if max_score > 0.0:
            return 0.60
        return 0.98

    def _build_reason(self, layer_results: list[LayerResult]) -> str:
        parts: list[str] = []
        for lr in layer_results:
            if lr.indicators:
                top = lr.indicators[0]
                parts.append(f"[{lr.layer_name}] {top.description} (rule: {top.rule_id})")
        if not parts:
            return "No threats detected across all layers"
        return " | ".join(parts)

    def _build_recommendations(
        self, verdict: Verdict, category: AttackCategory
    ) -> list[str]:
        if verdict == Verdict.ALLOW:
            return []
        recommendations = []
        if verdict == Verdict.BLOCK:
            recommendations.append("Block this prompt and return a generic refusal")
            recommendations.append("Log the incident for audit and retraining review")
        elif verdict == Verdict.QUARANTINE:
            recommendations.append("Quarantine the prompt for human review")
            recommendations.append("Do not forward to the core AI agent")
        elif verdict == Verdict.ALLOW_WITH_WARNING:
            recommendations.append("Allow but attach a security warning to the response")
            recommendations.append("Monitor the conversation for escalation")
        if category == AttackCategory.PROMPT_INJECTION:
            recommendations.append("Consider input sanitization or input-guard patterns")
        if category == AttackCategory.DATA_EXFILTRATION:
            recommendations.append("Audit recent access to sensitive data stores")
        return recommendations
