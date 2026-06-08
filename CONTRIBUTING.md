# Contributing to Prompt Injection Firewall Agent

## Getting Started

```bash
git clone <repo-url>
cd prompt-injection-firewall-agent
pip install -r requirements.txt
pip install -e ".[dev]"
```

## Development Workflow

1. Check the [Project Development Phase Tracking](PROJECT-DEVELOPMENT-PHASE-TRACKING.md) for current phase status
2. Review [PROJECT-DETAIL.md](PROJECT-DETAIL.md) for architecture overview
3. Review [THREAT-MODEL.md](THREAT-MODEL.md) for security context
4. Create a branch from `main`
5. Make your changes
6. Run `python main.py validate` to verify architecture
7. Run `python main.py benchmark` to verify detection performance
8. Submit a pull request

## Code Style

- Python 3.11+ with type hints
- Follow existing patterns in the codebase
- Use `ruff` for linting: `ruff check src/`
- All new detection rules go in `config/rules/default_rules.yaml`
- All new attack signatures go in `config/signatures/known_attacks.yaml`

## Architecture Rules

- Detection layers must be independent and composable
- Each layer produces a `LayerResult` with risk score, verdict, and indicators
- The `ExplainabilityEngine` aggregates all layers into a `FirewallDecision`
- Never call real models during import — use lazy loading
- Use `config/default.yaml` for all configuration

## Adding New Detection Rules

Add to `config/rules/default_rules.yaml`:

```yaml
rules:
  - id: "HEUR-NNN"
    category: "prompt_injection"  # or jailbreak, agent_manipulation, data_exfiltration
    subcategory: "your_subcategory"
    description: "Clear description of what this detects"
    patterns:
      - "regex pattern 1"
      - "regex pattern 2"
    severity: "low"  # low | medium | high | critical
    weight: 0.80     # 0.0 - 1.0
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
