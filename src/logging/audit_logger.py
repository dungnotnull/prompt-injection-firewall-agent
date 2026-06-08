from __future__ import annotations

import json
import logging
import logging.handlers
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.models import FirewallDecision, AuditLogEntry


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "audit_id"):
            log_entry["audit_id"] = record.audit_id
        if hasattr(record, "tenant_id"):
            log_entry["tenant_id"] = record.tenant_id
        if hasattr(record, "risk_score"):
            log_entry["risk_score"] = record.risk_score
        if hasattr(record, "verdict"):
            log_entry["verdict"] = record.verdict
        if hasattr(record, "latency_ms"):
            log_entry["latency_ms"] = record.latency_ms
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry, ensure_ascii=False)


class AuditLogger:
    _instance: Optional[AuditLogger] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: Optional[dict] = None):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True
        cfg = config or {}
        self.output_dir = Path(cfg.get("output_dir", "./logs"))
        self.level = cfg.get("level", "INFO")
        self.audit_enabled = cfg.get("audit_log", True)
        self._setup_loggers()

    def _setup_loggers(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.app_logger = logging.getLogger("firewall.app")
        self.app_logger.setLevel(getattr(logging, self.level.upper(), logging.INFO))
        self.app_logger.handlers.clear()

        self.audit_logger = logging.getLogger("firewall.audit")
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.handlers.clear()

        json_formatter = JsonFormatter()

        app_handler = logging.handlers.RotatingFileHandler(
            self.output_dir / "firewall.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=10,
            encoding="utf-8",
        )
        app_handler.setFormatter(json_formatter)
        self.app_logger.addHandler(app_handler)

        audit_handler = logging.handlers.RotatingFileHandler(
            self.output_dir / "audit.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=30,
            encoding="utf-8",
        )
        audit_handler.setFormatter(json_formatter)
        self.audit_logger.addHandler(audit_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        self.app_logger.addHandler(console_handler)

    def log_decision(self, decision: FirewallDecision):
        if not self.audit_enabled:
            return
        entry = AuditLogEntry(
            audit_id=decision.audit_id,
            timestamp=decision.timestamp,
            tenant_id=decision.tenant_id,
            risk_score=decision.risk_score,
            verdict=decision.final_verdict,
            category=decision.attack_category,
            latency_ms=decision.total_latency_ms,
            input_preview=decision.input_text[:200],
        )
        record = logging.LogRecord(
            name="firewall.audit",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=json.dumps(entry.__dict__, default=str),
            args=(),
            exc_info=None,
        )
        record.audit_id = decision.audit_id
        record.tenant_id = decision.tenant_id
        record.risk_score = decision.risk_score
        record.verdict = decision.final_verdict
        record.latency_ms = decision.total_latency_ms
        self.audit_logger.handle(record)

    def log_info(self, message: str, **kwargs):
        self.app_logger.info(message)

    def log_warning(self, message: str, **kwargs):
        self.app_logger.warning(message)

    def log_error(self, message: str, exc_info=None):
        self.app_logger.error(message, exc_info=exc_info)

    def log_debug(self, message: str, **kwargs):
        self.app_logger.debug(message)

    def get_audit_trail(self, tenant_id: Optional[str] = None,
                        limit: int = 100, offset: int = 0) -> list[dict]:
        audit_file = self.output_dir / "audit.log"
        if not audit_file.exists():
            return []
        entries = []
        with open(audit_file, encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if tenant_id and entry.get("tenant_id") != tenant_id:
                        continue
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
        entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return entries[offset:offset + limit]


def get_audit_logger(config: Optional[dict] = None) -> AuditLogger:
    return AuditLogger(config)
