from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.training.modernbert_classifier import ModernBERTClassifier
    from src.training.lora_trainer import LoRATrainer
    from src.training.onnx_exporter import ONNXExporter


def get_modernbert_classifier(*args, **kwargs):
    from src.training.modernbert_classifier import ModernBERTClassifier
    return ModernBERTClassifier(*args, **kwargs)


def get_lora_trainer(*args, **kwargs):
    from src.training.lora_trainer import LoRATrainer
    return LoRATrainer(*args, **kwargs)


def get_onnx_exporter(*args, **kwargs):
    from src.training.onnx_exporter import ONNXExporter
    return ONNXExporter(*args, **kwargs)


def quantize_int8(*args, **kwargs):
    from src.training.onnx_exporter import quantize_int8
    return quantize_int8(*args, **kwargs)
