from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from src.data.dataset_loader import DatasetLoader
from src.data.real_dataset_loader import RealDatasetLoader


class ArchitectureValidator:
    def __init__(self, config_path: str = "./config/default.yaml"):
        with open(config_path, encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

    def validate(self) -> dict:
        results = {}
        results["config"] = self._validate_config()
        results["datasets"] = self._validate_datasets()
        results["rules"] = self._validate_rules()
        results["signatures"] = self._validate_signatures()
        results["layers"] = self._validate_layer_connectivity()
        results["metrics_targets"] = self._validate_metrics_targets()

        all_pass = all(
            isinstance(v, bool) or (isinstance(v, dict) and v.get("pass", True))
            for v in results.values()
        )
        results["overall"] = "PASS" if all_pass else "FAIL"
        return results

    def _validate_config(self) -> dict:
        required_keys = ["firewall", "layer_1_classifier", "layer_2_heuristic",
                         "layer_3_threat_intel", "layer_4_explainability",
                         "layer_5_continuous_learning", "datasets", "metrics", "logging"]
        missing = [k for k in required_keys if k not in self.config]
        return {"pass": len(missing) == 0, "missing_keys": missing}

    def _validate_datasets(self) -> dict:
        datasets = self.config.get("datasets", {})
        shortlist = datasets.get("shortlist", [])
        loader = DatasetLoader(config=datasets)
        real_loader = RealDatasetLoader(config=datasets)

        results = {
            "pass": bool(shortlist),
            "shortlist_count": len(shortlist),
            "datasets": [],
        }
        for name in shortlist:
            samples = loader.load_dataset(name)
            results["datasets"].append({
                "name": name,
                "samples_available": len(samples),
            })
        return results

    def _validate_rules(self) -> dict:
        rules_path = self.config.get("layer_2_heuristic", {}).get("rules_path", "")
        path = Path(rules_path)
        if not path.exists():
            return {"pass": False, "error": f"Rules file not found: {path}"}
        with open(path, encoding="utf-8") as f:
            rules = yaml.safe_load(f)
        rule_count = len(rules.get("rules", []))
        categories = set(r.get("category") for r in rules.get("rules", []))
        return {
            "pass": rule_count > 0,
            "rule_count": rule_count,
            "categories": list(categories),
        }

    def _validate_signatures(self) -> dict:
        sig_path = self.config.get("layer_3_threat_intel", {}).get("signatures_path", "")
        path = Path(sig_path)
        if not path.exists():
            return {"pass": False, "error": f"Signatures file not found: {path}"}
        with open(path, encoding="utf-8") as f:
            sigs = yaml.safe_load(f)
        count = len(sigs.get("signatures", []))
        sources = set(s.get("source") for s in sigs.get("signatures", []))
        return {
            "pass": count > 0,
            "signature_count": count,
            "sources": list(sources),
        }

    def _validate_layer_connectivity(self) -> dict:
        layer_configs = [
            self.config.get("layer_1_classifier", {}),
            self.config.get("layer_2_heuristic", {}),
            self.config.get("layer_3_threat_intel", {}),
            self.config.get("layer_4_explainability", {}),
            self.config.get("layer_5_continuous_learning", {}),
        ]
        names = [
            "layer_1_classifier",
            "layer_2_heuristic",
            "layer_3_threat_intel",
            "layer_4_explainability",
            "layer_5_continuous_learning",
        ]
        results = []
        for name, lc in zip(names, layer_configs):
            results.append({
                "name": name,
                "enabled": lc.get("enabled", False),
                "configured": any(lc),
            })
        enabled = [r for r in results if r["enabled"]]
        return {
            "pass": any(r["enabled"] for r in results),
            "enabled_layers": len(enabled),
            "details": results,
        }

    def _validate_metrics_targets(self) -> dict:
        targets = self.config.get("metrics", {}).get("targets", {})
        required = ["recall", "precision", "f1", "latency_ms", "false_positive_rate"]
        missing = [k for k in required if k not in targets]
        return {"pass": len(missing) == 0, "targets": targets, "missing": missing}


def validate_architecture(config_path: str = "./config/default.yaml") -> dict:
    return ArchitectureValidator(config_path).validate()
