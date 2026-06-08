from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class HumanFeedbackLoop:
    def __init__(self, storage_dir: str = "./data/feedback"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def submit_feedback(self, audit_id: str, decision_correct: bool,
                        correct_verdict: str = "", reviewer: str = "",
                        notes: str = "") -> str:
        feedback = {
            "audit_id": audit_id,
            "decision_correct": decision_correct,
            "correct_verdict": correct_verdict,
            "reviewer": reviewer,
            "notes": notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        feedback_id = f"fb-{audit_id}"
        file_path = self.storage_dir / f"{feedback_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(feedback, f, indent=2, ensure_ascii=False)
        return feedback_id

    def get_pending_reviews(self, limit: int = 50) -> list[dict]:
        pending: list[dict] = []
        for f in sorted(self.storage_dir.glob("*.json"), key=lambda x: x.stat().st_mtime):
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            if not data.get("decision_correct"):
                pending.append(data)
            if len(pending) >= limit:
                break
        return pending

    def get_stats(self) -> dict:
        total = 0
        correct = 0
        for f in self.storage_dir.glob("*.json"):
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            total += 1
            if data.get("decision_correct"):
                correct += 1
        return {
            "total_feedback": total,
            "correct_decisions": correct,
            "incorrect_decisions": total - correct,
            "accuracy": correct / total if total > 0 else 0.0,
        }

    def export_training_data(self) -> list[dict]:
        samples: list[dict] = []
        for f in self.storage_dir.glob("*.json"):
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            if not data.get("decision_correct") and data.get("correct_verdict"):
                samples.append({
                    "audit_id": data["audit_id"],
                    "correct_verdict": data["correct_verdict"],
                    "notes": data.get("notes", ""),
                })
        return samples
