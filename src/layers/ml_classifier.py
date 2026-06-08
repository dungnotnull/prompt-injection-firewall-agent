from __future__ import annotations

import torch
import torch.nn.functional as F

from src.models import AttackCategory, LayerResult, Verdict


class FastSecurityClassifier:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.model_name = config.get("model_name", "answerdotai/ModernBERT-base")
        self.num_labels = config.get("num_labels", 3)
        self.labels = config.get("labels", ["safe", "suspicious", "malicious"])
        self.max_length = config.get("max_length", 512)
        self.fallback_to_heuristic = config.get("fallback_to_heuristic", True)
        self.device = torch.device(config.get("device", "cuda" if torch.cuda.is_available() else "cpu"))
        self._model = None
        self._tokenizer = None
        self._model_path = config.get("model_path", None)

    def _load_model(self):
        if self._model is not None:
            return
        if not self._model_path:
            return
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            self._model = AutoModelForSequenceClassification.from_pretrained(self._model_path, num_labels=self.num_labels)
            self._tokenizer = AutoTokenizer.from_pretrained(self._model_path)
            self._model.to(self.device)
            self._model.eval()
        except Exception:
            self._model = None

    def predict(self, text: str) -> LayerResult:
        if not self.enabled:
            return LayerResult(layer_name="ml_classifier", risk_score=0.0, verdict=Verdict.ALLOW)
        self._load_model()
        if self._model is None:
            return LayerResult(
                layer_name="ml_classifier", risk_score=0.0, verdict=Verdict.ALLOW,
                raw_output={"status": "fallback_to_heuristic", "model_loaded": False},
            )
        return self._predict_impl(text)

    def _predict_impl(self, text: str) -> LayerResult:
        inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=self.max_length).to(self.device)
        with torch.no_grad():
            outputs = self._model(**inputs)
            probs = F.softmax(outputs.logits, dim=-1).squeeze(0)
        idx = int(probs.argmax().item())
        label = self.labels[idx]
        confidence = float(probs.max().item())
        risk = {"safe": 0.0, "suspicious": 0.55, "malicious": 0.95}.get(label, 0.0)
        verdict = self._verdict_from_label(label, risk)
        return LayerResult(
            layer_name="ml_classifier", risk_score=risk, verdict=verdict,
            category=AttackCategory.UNKNOWN if label == "safe" else AttackCategory.PROMPT_INJECTION,
            confidence=confidence,
            raw_output={"predicted_label": label, "confidence": confidence, "model_name": self.model_name},
        )

    def _verdict_from_label(self, label: str, risk: float) -> Verdict:
        if label == "malicious": return Verdict.BLOCK
        if label == "suspicious": return Verdict.QUARANTINE if risk > 0.7 else Verdict.ALLOW_WITH_WARNING
        return Verdict.ALLOW

    def save(self, path: str):
        if self._model is not None and self._tokenizer is not None:
            self._model.save_pretrained(path)
            self._tokenizer.save_pretrained(path)

    @classmethod
    def from_pretrained(cls, path: str, config: dict | None = None):
        cfg = config or {}
        instance = cls(cfg)
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        instance._model = AutoModelForSequenceClassification.from_pretrained(path)
        instance._tokenizer = AutoTokenizer.from_pretrained(path)
        instance._model.to(instance.device)
        instance._model.eval()
        return instance
