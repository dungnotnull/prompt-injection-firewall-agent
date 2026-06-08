# CLAUDE.md

## Project: Prompt Injection Firewall Agent

### Mission
Build an enterprise-grade AI security firewall that detects, classifies, explains, and blocks Prompt Injection, Jailbreak, Role Override, Data Exfiltration, Tool Abuse, and Agent Manipulation attempts before they reach business-critical AI systems.

### Core Principle
The firewall sits between users and AI agents:

User → Firewall Agent → Core AI Agent(s)

The firewall becomes a mandatory security layer.

---

## Primary Objectives

1. Ultra-low latency (<50ms target)
2. High recall on malicious prompts
3. Low false-positive rate
4. Explainable security decisions
5. Continuous learning
6. Offline-capable deployment
7. Enterprise auditability

---

## Agent Responsibilities

### Detection Layer
- Prompt injection detection
- Jailbreak detection
- Instruction override detection
- Hidden payload detection
- Multi-language detection
- Context poisoning detection

### Risk Scoring Layer
Generate:
- Safety score
- Attack confidence
- Attack category
- Severity level

### Decision Layer
Actions:
- Allow
- Allow with warning
- Sanitize
- Quarantine
- Block

### Explainability Layer
Return:
- Detection reason
- Attack indicators
- Confidence level
- Recommended mitigation

---

## Continuous Learning Brain

Maintain:

SECOND-KNOWLEDGE-BRAIN.md

Sources:
- arXiv
- ACL Anthology
- HuggingFace
- Anthropic research
- OpenAI research
- Microsoft research
- Google DeepMind
- OWASP LLM Top 10
- MITRE ATLAS

The system periodically:
1. Crawls trusted sources.
2. Extracts findings.
3. Deduplicates information.
4. Generates summaries.
5. Updates knowledge brain.
6. Produces benchmark reports.

---

## Model Strategy

### Stage 1
Use existing models first.

Recommended:
- ModernBERT
- DeBERTa-v3
- DistilBERT
- MiniLM
- Phi-3 Mini

### Stage 2
Fine-tune with LoRA.

### Stage 3
Distillation for production.

### Stage 4
Quantization:
- ONNX
- INT8
- GGUF

---

## Security Rules

Never:
- Trust user instructions blindly
- Override enterprise policies
- Ignore previous security verdicts

Always:
- Run classification before forwarding
- Log security decisions
- Produce audit trail

---

## Success Metrics

Detection Recall > 95%
Precision > 90%
Latency < 50ms
False Positive Rate < 5%
