from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from src.engine import FirewallEngine
from src.logging import get_audit_logger

app = FastAPI(title="Prompt Injection Firewall API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.environ.get("JWT_SECRET", "pifirewall-jwt-secret-change-in-production")
JWT_ALGORITHM = "HS256"
engine: Optional[FirewallEngine] = None
audit_logger: Optional[object] = None

USERS_DB = {
    "admin": {"username": "admin", "role": "admin", "tenant": "default"},
    "analyst": {"username": "analyst", "role": "analyst", "tenant": "default"},
    "viewer": {"username": "viewer", "role": "viewer", "tenant": "default"},
}

_users_initialized = False


def _init_users():
    global _users_initialized
    if _users_initialized:
        return
    for username in USERS_DB:
        USERS_DB[username]["hashed_password"] = pwd_context.hash(username)
    _users_initialized = True


class ScanRequest(BaseModel):
    text: str
    tenant_id: str = "default"
    session_id: str = ""


class ScanResponse(BaseModel):
    audit_id: str
    risk_score: float
    verdict: str
    category: str
    confidence: float
    reason: str
    recommendations: list[str]
    timestamp: str
    total_latency_ms: float


class FeedbackRequest(BaseModel):
    audit_id: str
    decision_correct: bool
    correct_verdict: str = ""
    notes: str = ""


class StatsResponse(BaseModel):
    total_decisions: int
    tenant_id: str
    uptime_seconds: float
    model_version: str
    layer_status: dict


def get_engine():
    global engine
    if engine is None:
        engine = FirewallEngine()
    return engine


def get_logger():
    global audit_logger
    if audit_logger is None:
        from src.logging import get_audit_logger
        audit_logger = get_audit_logger({"output_dir": "./logs", "level": "INFO", "audit_log": True})
    return audit_logger


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in USERS_DB:
            raise HTTPException(status_code=401, detail="Invalid token")
        return USERS_DB[username]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(*roles: str):
    async def dependency(request: Request):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing token")
        token = auth_header[7:]
        user = verify_token(token)
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return Depends(dependency)


@app.post("/api/v1/token")
async def login(username: str, password: str):
    _init_users()
    user = USERS_DB.get(username)
    if not user or not pwd_context.verify(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({
        "sub": username,
        "role": user["role"],
        "tenant": user["tenant"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400,
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_prompt(request: ScanRequest, user: dict = require_role("admin", "analyst")):
    eng = get_engine()
    logger = get_logger()
    decision = eng.scan(request.text)
    decision.tenant_id = request.tenant_id or user.get("tenant", "default")
    decision.session_id = request.session_id
    logger.log_decision(decision)
    return ScanResponse(
        audit_id=decision.audit_id,
        risk_score=decision.risk_score,
        verdict=decision.final_verdict,
        category=decision.attack_category,
        confidence=decision.confidence,
        reason=decision.reason,
        recommendations=decision.recommendations,
        timestamp=decision.timestamp,
        total_latency_ms=decision.total_latency_ms,
    )


@app.post("/api/v1/feedback")
async def submit_feedback(request: FeedbackRequest, user: dict = require_role("admin", "analyst")):
    from src.learning import HumanFeedbackLoop
    loop = HumanFeedbackLoop()
    feedback_id = loop.submit_feedback(
        audit_id=request.audit_id,
        decision_correct=request.decision_correct,
        correct_verdict=request.correct_verdict,
        reviewer=user.get("sub", "unknown"),
        notes=request.notes,
    )
    return {"feedback_id": feedback_id, "status": "submitted"}


@app.get("/api/v1/stats", response_model=StatsResponse)
async def get_stats(user: dict = require_role("admin", "analyst", "viewer")):
    eng = get_engine()
    return StatsResponse(
        total_decisions=eng.decision_count,
        tenant_id=user.get("tenant", "default"),
        uptime_seconds=time.time(),
        model_version="1.0.0",
        layer_status={
            "ml_classifier": eng.layer_1.enabled,
            "heuristic_engine": eng.layer_2.enabled,
            "threat_intelligence": eng.layer_3.enabled,
            "explainability": True,
            "continuous_learning": eng.layer_5.enabled,
        },
    )


@app.get("/api/v1/audit-trail")
async def get_audit_trail(limit: int = 100, offset: int = 0,
                          tenant_id: str = "default",
                          user: dict = require_role("admin", "analyst")):
    logger = get_logger()
    entries = logger.get_audit_trail(tenant_id=tenant_id, limit=limit, offset=offset)
    return {"count": len(entries), "entries": entries}


@app.get("/api/v1/health")
async def health_check():
    eng = get_engine()
    return {
        "status": "healthy",
        "version": "1.0.0",
        "decisions_processed": eng.decision_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/research/run")
async def run_research(user: dict = require_role("admin")):
    eng = get_engine()
    result = eng.research_update()
    return result


@app.get("/api/v1/research/summary")
async def research_summary(user: dict = require_role("admin", "analyst", "viewer")):
    eng = get_engine()
    return eng.knowledge_summary()


def create_app(config_path: str = "./config/default.yaml"):
    global engine, audit_logger
    engine = FirewallEngine(config_path)
    from src.logging import get_audit_logger
    audit_logger = get_audit_logger(engine.config.get("logging", {}))
    return app
