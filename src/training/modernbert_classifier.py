from __future__ import annotations

import torch
import torch.nn.functional as F
from transformers import AutoModelForSequenceClassification, AutoTokenizer


class ModernBERTClassifier:
    def __init__(self, config: dict):
        self.model_name = config.get("model_name", "answerdotai/ModernBERT-base")
        self.num_labels = config.get("num_labels", 3)
        self.labels = config.get("labels", ["safe", "suspicious", "malicious"])
        self.max_length = config.get("max_length", 512)
        self.device = torch.device(config.get("device", "cuda" if torch.cuda.is_available() else "cpu"))
        self.model: AutoModelForSequenceClassification | None = None
        self.tokenizer: AutoTokenizer | None = None
        self._loaded = False

    def load(self):
        if self._loaded:
            return
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name, num_labels=self.num_labels
        )
        self.model.to(self.device)
        self.model.eval()
        self._loaded = True

    def predict(self, text: str) -> tuple[int, str, float, list[float]]:
        if not self._loaded:
            self.load()

        inputs = self.tokenizer(
            text, return_tensors="pt", truncation=True,
            max_length=self.max_length, padding=True
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = F.softmax(logits, dim=-1).squeeze(0)

        pred_idx = int(probs.argmax().item())
        pred_label = self.labels[pred_idx]
        confidence = float(probs.max().item())
        all_probs = probs.tolist()

        return pred_idx, pred_label, confidence, all_probs

    def predict_batch(self, texts: list[str]) -> list[tuple[int, str, float, list[float]]]:
        if not self._loaded:
            self.load()

        inputs = self.tokenizer(
            texts, return_tensors="pt", truncation=True,
            max_length=self.max_length, padding=True
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = F.softmax(logits, dim=-1)

        results = []
        for i in range(len(texts)):
            pred_idx = int(probs[i].argmax().item())
            pred_label = self.labels[pred_idx]
            confidence = float(probs[i].max().item())
            all_probs = probs[i].tolist()
            results.append((pred_idx, pred_label, confidence, all_probs))
        return results

    def save(self, path: str):
        if self.model is not None and self.tokenizer is not None:
            self.model.save_pretrained(path)
            self.tokenizer.save_pretrained(path)

    @classmethod
    def from_pretrained(cls, path: str, config: dict | None = None):
        cfg = config or {}
        instance = cls(cfg)
        instance.model = AutoModelForSequenceClassification.from_pretrained(path)
        instance.tokenizer = AutoTokenizer.from_pretrained(path)
        instance.model.to(instance.device)
        instance.model.eval()
        instance._loaded = True
        return instance
