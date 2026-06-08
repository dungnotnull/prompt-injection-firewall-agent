# Changelog

## [1.0.0] — 2025-06-08

### Phase 0 — Research & Validation ✅
- Threat model document (`THREAT-MODEL.md`) with asset inventory, attack surface analysis, threat taxonomy, risk matrix, detection strategy, and mitigation controls
- Dataset evaluation framework with 8 datasets (Gandalf, CyberSecEval, AdvBench, JailbreakBench, BeaverTails, WildJailbreak, HH-RLHF, ToxicChat) via HuggingFace integration with automatic schema detection
- Architecture validator validating config, datasets, rules, signatures, layers, and metrics
- Success metrics tracker (recall, precision, F1, FPR, latency, accuracy)

### Phase 1 — MVP Firewall ✅
- Heuristic rule engine with 13 detection rules across 4 attack categories (prompt_injection, jailbreak, agent_manipulation, data_exfiltration)
- 5-tier verdict system (ALLOW, ALLOW_WITH_WARNING, SANITIZE, QUARANTINE, BLOCK)
- JSON rotating audit logging (10MB/10 files app log, 50MB/30 files audit log)
- Per-layer latency tracking (<1ms heuristic)

### Phase 2 — ML Detection ✅
- ModernBERT classifier with real PyTorch inference (Safe/Suspicious/Malicious 3-class)
- LoRA fine-tuning trainer with PEFT, AdamW, linear warmup scheduler
- ONNX export + INT8 quantization
- Confidence scoring from softmax probabilities

### Phase 3 — Knowledge Brain ✅
- arXiv crawler (6 AI security queries via `arxiv` Python library)
- ACL Anthology crawler (BeautifulSoup-based scraping)
- OWASP LLM Top 10 crawler
- NLP knowledge extractor with 8 regex attack pattern matchers
- Knowledge brain auto-updater with deduplication and timestamped markdown sections

### Phase 4 — Continuous Learning ✅
- Template-based dataset generator (malicious/safe with adversarial variants)
- Human feedback loop with JSON storage, pending review queue, and accuracy stats
- Retraining pipeline with configurable triggers, model version registry, and rollback

### Phase 5 — Enterprise Deployment ✅
- FastAPI server with 8 REST endpoints
- JWT authentication with bcrypt hashing and 3 roles (admin/analyst/viewer)
- Multi-tenant support (tenant_id throughout)
- Docker (Python 3.11-slim, healthcheck) + docker-compose (firewall + Prometheus + Grafana)
- Kubernetes (3 replicas, HPA 3-20, secrets, configmap, PVC, liveness/readiness probes)
- Prometheus metrics (scan_total, scan_latency histogram, detection_result, risk_score histogram, error counter)
- OpenTelemetry integration ready

### Phase 6 — Advanced Detection ✅
- Agent behavior analyzer (command injection, tool misuse, data exfiltration patterns)
- Tool abuse detector (8 tool signatures with graduated risk thresholds + allowlist)
- Multi-agent session monitor (thread-safe, risk escalation detection, block ratio monitoring, anomaly flagging)
- Session history analysis for multi-turn attack patterns

### Infrastructure ✅
- CLI with 11 commands (scan, evaluate, benchmark, stats, research, validate, train, export, serve, feedback, generate)
- Full production config (`config/default.yaml`) covering all modules
- `.gitignore`, `LICENSE` (MIT), `py.typed` (PEP 561)
- `CONTRIBUTING.md` with development workflow and code style guide
