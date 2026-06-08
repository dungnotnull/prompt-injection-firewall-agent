from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.knowledge.crawler import (AclCrawler, ArxivCrawler,
                                   KnowledgeBrainUpdater, KnowledgeExtractor,
                                   OwaspCrawler)


class ContinuousLearningEngine:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", False)
        self.update_interval_hours = config.get("update_interval_hours", 168)
        self.knowledge_brain_path = Path(config.get("knowledge_brain_path", "./SECOND-KNOWLEDGE-BRAIN.md"))
        self.research_sources: list[str] = config.get("research_sources", [])
        crawler_cfg = config.get("crawler_config", {})
        self._arxiv_crawler = ArxivCrawler(crawler_cfg)
        self._acl_crawler = AclCrawler(crawler_cfg)
        self._owasp_crawler = OwaspCrawler()
        self._extractor = KnowledgeExtractor()
        self._brain_updater = KnowledgeBrainUpdater(str(self.knowledge_brain_path))
        self._last_run: datetime | None = None
        self._total_findings = 0
        self._last_result: dict = {}

    def run_research_cycle(self) -> dict:
        if not self.enabled:
            return {"status": "disabled", "message": "Continuous learning is not enabled"}
        papers = []
        papers.extend(self._arxiv_crawler.fetch())
        papers.extend(self._acl_crawler.fetch())
        papers.extend(self._owasp_crawler.fetch())
        findings = self._extractor.extract(papers)
        update_result = self._brain_updater.update(findings)
        self._last_run = datetime.now(timezone.utc)
        self._total_findings += update_result.get("entries_added", 0)
        self._last_result = {
            "status": "completed",
            "sources_processed": len(self.research_sources) if self.research_sources else 3,
            "papers_fetched": len(papers),
            "findings_extracted": len(findings),
            "entries_added": update_result.get("entries_added", 0),
            "knowledge_brain_updated": update_result.get("updated", False),
            "last_run": self._last_run.isoformat(),
        }
        return self._last_result

    def get_knowledge_summary(self) -> dict:
        return {
            "knowledge_brain_path": str(self.knowledge_brain_path),
            "last_updated": self._last_run.isoformat() if self._last_run else "never",
            "total_entries": self._total_findings,
            "enabled": self.enabled,
            "last_run_summary": self._last_result,
        }
