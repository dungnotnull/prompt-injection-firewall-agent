from __future__ import annotations

import json
from pathlib import Path

import torch
import torch.nn as nn
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model
from torch.optim import AdamW
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from src.training.modernbert_classifier import ModernBERTClassifier


class LoRATrainer:
    def __init__(self, config: dict):
        self.output_dir = Path(config.get("output_dir", "./models"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.learning_rate = config.get("learning_rate", 2e-4)
        self.epochs = config.get("epochs", 3)
        self.batch_size = config.get("batch_size", 16)
        self.max_length = config.get("max_length", 512)
        self.warmup_steps = config.get("warmup_steps", 100)
        self.lora_r = config.get("lora_r", 8)
        self.lora_alpha = config.get("lora_alpha", 16)
        self.lora_dropout = config.get("lora_dropout", 0.1)
        self.device = torch.device(config.get("device", "cuda" if torch.cuda.is_available() else "cpu"))

    def train(self, base_model: ModernBERTClassifier, train_data: Dataset,
              eval_data: Dataset | None = None) -> str:
        tokenizer = base_model.tokenizer
        model = base_model.model

        lora_config = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=self.lora_r,
            lora_alpha=self.lora_alpha,
            lora_dropout=self.lora_dropout,
            target_modules=["query", "key", "value", "dense"],
        )
        peft_model = get_peft_model(model, lora_config)
        peft_model.to(self.device)
        peft_model.train()

        def tokenize(batch):
            return tokenizer(batch["text"], truncation=True, max_length=self.max_length, padding="max_length")

        train_data = train_data.map(tokenize, batched=True)
        train_data.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])

        train_loader = DataLoader(train_data, batch_size=self.batch_size, shuffle=True)

        optimizer = AdamW(peft_model.parameters(), lr=self.learning_rate)
        total_steps = len(train_loader) * self.epochs
        scheduler = get_linear_schedule_with_warmup(
            optimizer, num_warmup_steps=self.warmup_steps, num_training_steps=total_steps
        )

        for epoch in range(self.epochs):
            epoch_loss = 0.0
            for batch in train_loader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["label"].to(self.device)

                optimizer.zero_grad()
                outputs = peft_model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                loss.backward()
                optimizer.step()
                scheduler.step()
                epoch_loss += loss.item()

            avg_loss = epoch_loss / len(train_loader)

        save_path = str(self.output_dir / "lora_adapter")
        peft_model.save_pretrained(save_path)

        stats = {
            "epochs": self.epochs,
            "final_loss": avg_loss,
            "save_path": save_path,
        }
        stats_path = self.output_dir / "training_stats.json"
        with open(stats_path, "w") as f:
            json.dump(stats, f, indent=2)

        return save_path
