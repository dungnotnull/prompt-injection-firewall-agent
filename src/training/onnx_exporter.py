from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import torch

from src.training.modernbert_classifier import ModernBERTClassifier


class ONNXExporter:
    def __init__(self, config: dict):
        self.output_dir = Path(config.get("output_dir", "./models"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.opset_version = config.get("opset_version", 17)
        self.optimize = config.get("optimize", True)

    def export(self, classifier: ModernBERTClassifier, export_name: str = "classifier") -> str:
        model = classifier.model
        tokenizer = classifier.tokenizer

        if model is None or tokenizer is None:
            raise RuntimeError("Classifier not loaded. Call .load() first.")

        model.eval()
        model.to("cpu")

        dummy_input = tokenizer(
            "This is a test input for tracing.",
            return_tensors="pt", truncation=True,
            max_length=classifier.max_length, padding="max_length"
        )

        onnx_path = self.output_dir / f"{export_name}.onnx"
        input_names = ["input_ids", "attention_mask"]
        output_names = ["logits"]
        dynamic_axes = {
            "input_ids": {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "logits": {0: "batch_size"},
        }

        torch.onnx.export(
            model,
            (dummy_input["input_ids"], dummy_input["attention_mask"]),
            str(onnx_path),
            input_names=input_names,
            output_names=output_names,
            dynamic_axes=dynamic_axes,
            opset_version=self.opset_version,
            do_constant_folding=True,
        )

        json_path = self.output_dir / f"{export_name}_config.json"
        config_data = {
            "model_name": classifier.model_name,
            "num_labels": classifier.num_labels,
            "labels": classifier.labels,
            "max_length": classifier.max_length,
        }
        with open(json_path, "w") as f:
            json.dump(config_data, f, indent=2)

        if self.optimize:
            self._optimize_onnx(str(onnx_path))

        classifier.model.to(classifier.device)
        return str(onnx_path)

    def _optimize_onnx(self, onnx_path: str):
        try:
            subprocess.run(
                [sys.executable, "-m", "onnxruntime.tools.optimize_cli",
                 "--model_path", onnx_path, "--output_path", onnx_path],
                capture_output=True, timeout=120,
            )
        except Exception:
            pass


def quantize_int8(classifier: ModernBERTClassifier, output_path: str):
    model = classifier.model
    if model is None:
        raise RuntimeError("Classifier not loaded.")

    model.eval()
    quantized = torch.quantization.quantize_dynamic(
        model, {torch.nn.Linear}, dtype=torch.qint8
    )
    torch.save(quantized.state_dict(), output_path)
    return output_path
