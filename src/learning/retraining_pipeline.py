from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class RetrainingPipeline:
    def __init__(self, config: dict):
        self.models_dir = Path(config.get("models_dir", "./models"))
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir = Path(config.get("data_dir", "./data"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_threshold = config.get("retrain_trigger", {
            "recall_below": 0.90,
            "fpr_above": 0.10,
            "new_samples_min": 100,
        })
        self.registry_path = self.models_dir / "model_registry.json"
        self._init_registry()

    def _init_registry(self):
        if not self.registry_path.exists():
            self.registry_path.write_text(json.dumps({"versions": []}))

    def should_retrain(self, current_metrics: dict, new_samples_count: int) -> bool:
        recall = current_metrics.get("recall", 1.0)
        fpr = current_metrics.get("false_positive_rate", 0.0)
        if recall < self.metrics_threshold["recall_below"]:
            return True
        if fpr > self.metrics_threshold["fpr_above"]:
            return True
        if new_samples_count >= self.metrics_threshold["new_samples_min"]:
            return True
        return False

    def register_model(self, name: str, path: str, metrics: dict):
        entry = {
            "version": name,
            "path": path,
            "metrics": metrics,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "active",
        }
        registry = json.loads(self.registry_path.read_text())
        for existing in registry["versions"]:
            existing["status"] = "archived"
        registry["versions"].append(entry)
        self.registry_path.write_text(json.dumps(registry, indent=2))

    def get_active_model(self) -> Optional[dict]:
        registry = json.loads(self.registry_path.read_text())
        for version in reversed(registry["versions"]):
            if version["status"] == "active":
                return version
        return None

    def list_versions(self) -> list[dict]:
        registry = json.loads(self.registry_path.read_text())
        return registry["versions"]

    def rollback(self, version: str) -> Optional[dict]:
        registry = json.loads(self.registry_path.read_text())
        target = None
        for v in registry["versions"]:
            if v["version"] == version:
                target = v
                break
        if target is None:
            return None
        for v in registry["versions"]:
            v["status"] = "archived"
        target["status"] = "active"
        self.registry_path.write_text(json.dumps(registry, indent=2))
        return target

    def prepare_retraining_data(self, feedback_file: str,
                                 existing_dataset: str) -> list[dict]:
        combined: list[dict] = []
        if Path(existing_dataset).exists():
            with open(existing_dataset, encoding="utf-8") as f:
                combined = json.load(f)
        if Path(feedback_file).exists():
            with open(feedback_file, encoding="utf-8") as f:
                feedback = json.load(f)
            for fb in feedback:
                if isinstance(fb, dict) and fb.get("correct_verdict"):
                    combined.append({
                        "text": fb.get("notes", ""),
                        "label": fb["correct_verdict"],
                    })
        return combined
