from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from src.data import DatasetLoader, RealDatasetLoader
from src.engine import FirewallEngine
from src.architecture_validator import validate_architecture

console = Console()


def _load_engine(config_path: str) -> FirewallEngine:
    return FirewallEngine(config_path)


def cmd_scan(args):
    engine = _load_engine(args.config)
    text = args.text
    if not text and args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    if not text:
        console.print("[red]No input provided. Use --text or --file.[/red]")
        sys.exit(1)

    decision = engine.scan(text, tenant_id=args.tenant, session_id=args.session)

    risk_color = "green"
    if decision.risk_score > 0.7: risk_color = "red"
    elif decision.risk_score > 0.4: risk_color = "yellow"

    verdict_style = {"allow": "green", "allow_with_warning": "yellow", "sanitize": "yellow", "quarantine": "red", "block": "bold red"}.get(decision.final_verdict, "white")

    table = Table(title=f"Scan Result — {decision.audit_id}")
    table.add_column("Field", style="cyan"); table.add_column("Value", style="white")
    table.add_row("Risk Score", f"[{risk_color}]{decision.risk_score:.4f}[/{risk_color}]")
    table.add_row("Verdict", f"[{verdict_style}]{decision.final_verdict.upper()}[/{verdict_style}]")
    table.add_row("Category", decision.attack_category)
    table.add_row("Confidence", f"{decision.confidence:.4f}")
    table.add_row("Latency (ms)", f"{decision.total_latency_ms:.2f}")
    table.add_row("Reason", decision.reason)
    table.add_row("Audit ID", decision.audit_id)
    if decision.recommendations:
        table.add_row("Recommendations", "\n".join(f"  [bold]-[/bold] {r}" for r in decision.recommendations))
    console.print(table)

    if args.verbose:
        console.print("\n[bold]Layer Details:[/bold]")
        for lr in decision.layer_results:
            console.print(f"  [{lr.layer_name}] risk={lr.risk_score:.4f} verdict={lr.verdict} latency={lr.latency_ms:.2f}ms indicators={len(lr.indicators)}")

    if args.json:
        console.print_json(json.dumps(decision.to_dict(), indent=2))


def cmd_evaluate(args):
    engine = _load_engine(args.config)
    loader = DatasetLoader(config=engine.config.get("datasets", {}))
    dataset_name = args.dataset or None
    console.print(f"[bold]Evaluating:[/bold] {dataset_name or 'ALL datasets'}")
    results = loader.evaluate(engine, dataset_name)
    for name, tracker in results.items():
        m = tracker.snapshot()
        console.print(f"\n[bold cyan]{name}[/bold cyan] ({m.total_evaluated} samples)")
        console.print(m.status_report)


def cmd_benchmark(args):
    from src.metrics import MetricsTracker
    engine = _load_engine(args.config)
    loader = DatasetLoader(config=engine.config.get("datasets", {}))
    all_samples = []
    for name in loader.get_shortlist():
        all_samples.extend(loader.load_dataset(name))
    console.print(f"[bold]Benchmarking {len(all_samples)} samples...[/bold]")
    tracker = MetricsTracker(engine.config.get("metrics", {}))
    for sample in all_samples:
        d = engine.scan(sample.text)
        pred_mal = d.final_verdict in ("block", "quarantine")
        is_mal = sample.label in ("malicious", "prompt_injection", "jailbreak", "unsafe", "harmful", "1")
        tracker.update(predicted_malicious=pred_mal, is_malicious=is_mal, latency_ms=d.total_latency_ms)
    m = tracker.snapshot()
    console.print("\n[bold]Benchmark Results:[/bold]")
    console.print(m.status_report)
    config_metrics = engine.config.get("metrics", {}).get("targets", {})
    if m.recall >= config_metrics.get("recall", 0.95):
        console.print("\n[green][PASS] Recall meets target[/green]")
    else:
        console.print(f"\n[red][FAIL] Recall {m.recall:.4f} below target ({config_metrics.get('recall', 0.95)})[/red]")


def cmd_stats(args):
    engine = _load_engine(args.config)
    cm = engine.config.get("metrics", {}).get("targets", {})
    knowledge = engine.knowledge_summary()
    table = Table(title="Firewall Status")
    table.add_column("Metric", style="cyan"); table.add_column("Value", style="white")
    table.add_row("Version", engine.config.get("firewall", {}).get("version", "unknown"))
    table.add_row("Decisions processed", str(engine.decision_count))
    table.add_row("Target Recall", str(cm.get("recall", 0.95)))
    table.add_row("Target Precision", str(cm.get("precision", 0.90)))
    table.add_row("Target F1", str(cm.get("f1", 0.92)))
    table.add_row("Target Latency (ms)", str(cm.get("latency_ms", 20)))
    table.add_row("Target FPR", str(cm.get("false_positive_rate", 0.05)))
    table.add_row("Knowledge Brain", knowledge.get("knowledge_brain_path", "N/A"))
    table.add_row("Continuous Learning", "enabled" if knowledge.get("enabled") else "disabled")
    table.add_row("Last Research Run", knowledge.get("last_updated", "never"))
    console.print(table)


def cmd_research(args):
    engine = _load_engine(args.config)
    result = engine.research_update()
    console.print(f"[bold]Research cycle:[/bold] {result.get('status', 'unknown')}")
    console.print(f"  Papers fetched: {result.get('papers_fetched', 0)}")
    console.print(f"  Findings extracted: {result.get('findings_extracted', 0)}")
    console.print(f"  Entries added to brain: {result.get('entries_added', 0)}")
    console.print(f"  Knowledge brain updated: {result.get('knowledge_brain_updated', False)}")


def cmd_validate(args):
    result = validate_architecture(args.config)
    console.print(f"[bold]Architecture Validation:[/bold] [{'green' if result.get('overall') == 'PASS' else 'red'}]{result.get('overall', 'FAIL')}[/]")
    for key, val in result.items():
        if key == "overall": continue
        if isinstance(val, dict):
            status = "[green]PASS[/green]" if val.get("pass") else "[red]FAIL[/red]"
            console.print(f"  {key}: {status}")
            if key == "layers" and "details" in val:
                for d in val["details"]:
                    console.print(f"    {d['name']}: enabled={d['enabled']}")
        elif isinstance(val, list):
            console.print(f"  {key}: {len(val)} items")


def cmd_train(args):
    engine = _load_engine(args.config)
    from src.training import ModernBERTClassifier, LoRATrainer
    from src.data import DatasetLoader
    loader = DatasetLoader(config=engine.config.get("datasets", {}))
    samples = loader.load_dataset(args.dataset or "Gandalf")
    train_config = engine.config.get("training", {})
    classifier = ModernBERTClassifier(train_config)
    try:
        classifier.load()
    except Exception as e:
        console.print(f"[yellow]Model not downloaded yet: {e}. Will fine-tune when available.[/yellow]")
        return
    trainer = LoRATrainer(train_config)
    texts = [s.text for s in samples[:args.limit]]
    labels = [0 if s.label in ("safe",) else 1 for s in samples[:args.limit]]
    import torch
    from torch.utils.data import TensorDataset
    inputs = classifier.tokenizer(texts, truncation=True, max_length=512, padding=True, return_tensors="pt")
    dataset = TensorDataset(inputs["input_ids"], inputs["attention_mask"], torch.tensor(labels))
    output_path = trainer.train(classifier, dataset)
    console.print(f"[green]Training complete. Adapter saved to:[/green] {output_path}")


def cmd_export(args):
    engine = _load_engine(args.config)
    from src.training import ModernBERTClassifier, ONNXExporter
    train_config = engine.config.get("training", {})
    classifier = ModernBERTClassifier(train_config)
    try:
        classifier.load()
    except Exception as e:
        console.print(f"[red]Model not available: {e}[/red]")
        return
    exporter = ONNXExporter(train_config)
    onnx_path = exporter.export(classifier, args.name or "classifier")
    console.print(f"[green]ONNX model exported to:[/green] {onnx_path}")


def cmd_serve(args):
    from src.server import create_app
    create_app(args.config)
    import uvicorn
    sc = args.config
    if isinstance(sc, str):
        import yaml
        with open(sc) as f:
            server_cfg = yaml.safe_load(f).get("server", {})
    else:
        server_cfg = {}
    uvicorn.run("src.server.api:app", host=server_cfg.get("host", "0.0.0.0"),
                port=server_cfg.get("port", 8000), reload=args.reload)


def cmd_feedback(args):
    from src.learning import HumanFeedbackLoop
    loop = HumanFeedbackLoop()
    if args.submit:
        fid = loop.submit_feedback(audit_id=args.audit_id, decision_correct=args.correct.lower() == "true", correct_verdict=args.verdict or "", notes=args.notes or "")
        console.print(f"[green]Feedback submitted: {fid}[/green]")
    else:
        stats = loop.get_stats()
        console.print(f"Total feedback: {stats['total_feedback']}")
        console.print(f"Decision accuracy: {stats['accuracy']:.2%}")
        console.print(f"Correct: {stats['correct_decisions']} | Incorrect: {stats['incorrect_decisions']}")


def cmd_generate(args):
    from src.learning import DatasetGenerator
    gen = DatasetGenerator()
    path = gen.generate_to_file(args.output or "synthetic_dataset.json", count=args.count)
    console.print(f"[green]Generated {args.count} samples to:[/green] {path}")


def main():
    parser = argparse.ArgumentParser(description="Prompt Injection Firewall Agent — Enterprise Security Gateway v1.0.0")
    sub = parser.add_subparsers(dest="command", help="Commands")

    p = sub.add_parser("scan", help="Scan a prompt for threats")
    p.add_argument("--text", help="Text to scan")
    p.add_argument("--file", help="File to scan")
    p.add_argument("--config", default="./config/default.yaml")
    p.add_argument("--tenant", default="default")
    p.add_argument("--session", default="")
    p.add_argument("--json", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("evaluate", help="Evaluate on datasets")
    p.add_argument("--dataset")
    p.add_argument("--config", default="./config/default.yaml")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("benchmark", help="Full benchmark across all datasets")
    p.add_argument("--config", default="./config/default.yaml")
    p.set_defaults(func=cmd_benchmark)

    p = sub.add_parser("stats", help="Show firewall status")
    p.add_argument("--config", default="./config/default.yaml")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("research", help="Run continuous learning research cycle")
    p.add_argument("--config", default="./config/default.yaml")
    p.set_defaults(func=cmd_research)

    p = sub.add_parser("validate", help="Validate architecture and configuration")
    p.add_argument("--config", default="./config/default.yaml")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("train", help="Fine-tune ModernBERT classifier with LoRA")
    p.add_argument("--config", default="./config/default.yaml")
    p.add_argument("--dataset", default="Gandalf")
    p.add_argument("--limit", type=int, default=1000)
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("export", help="Export model to ONNX format")
    p.add_argument("--config", default="./config/default.yaml")
    p.add_argument("--name", default="classifier")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("serve", help="Start FastAPI HTTP server")
    p.add_argument("--config", default="./config/default.yaml")
    p.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("feedback", help="View or submit human feedback")
    p.add_argument("--submit", action="store_true")
    p.add_argument("--audit-id")
    p.add_argument("--correct")
    p.add_argument("--verdict")
    p.add_argument("--notes")
    p.set_defaults(func=cmd_feedback)

    p = sub.add_parser("generate", help="Generate synthetic training data")
    p.add_argument("--count", type=int, default=1000)
    p.add_argument("--output")
    p.set_defaults(func=cmd_generate)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
