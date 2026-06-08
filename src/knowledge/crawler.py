from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import arxiv
import feedparser
import requests
from bs4 import BeautifulSoup


class ArxivCrawler:
    QUERIES = [
        "prompt injection LLM security",
        "jailbreak large language model",
        "AI agent security attack",
        "adversarial prompt machine learning",
        "LLM safety alignment",
        "tool use security agent",
    ]
    MAX_RESULTS_PER_QUERY = 20

    def __init__(self, config: dict):
        self.sources = config.get("research_sources", [])
        self.queries = config.get("crawler_queries", self.QUERIES)
        self.max_results = config.get("max_results", self.MAX_RESULTS_PER_QUERY)

    def fetch(self) -> list[dict]:
        papers: list[dict] = []
        seen_ids: set[str] = set()

        for query in self.queries:
            search = arxiv.Search(
                query=query,
                max_results=self.max_results,
                sort_by=arxiv.SortCriterion.SubmittedDate,
            )
            for result in search.results():
                if result.entry_id in seen_ids:
                    continue
                seen_ids.add(result.entry_id)
                papers.append({
                    "id": result.entry_id,
                    "title": result.title,
                    "summary": result.summary,
                    "authors": [a.name for a in result.authors],
                    "published": result.published.isoformat(),
                    "url": result.entry_id,
                    "categories": result.categories,
                })
            time.sleep(3)
        return papers


class AclCrawler:
    BASE_URL = "https://aclanthology.org"

    def __init__(self, config: dict):
        self.keywords = config.get("acl_keywords", [
            "prompt injection", "jailbreak", "adversarial prompt", "LLM safety"
        ])

    def fetch(self) -> list[dict]:
        papers: list[dict] = []
        for keyword in self.keywords[:2]:
            try:
                url = f"{self.BASE_URL}/search/?q={keyword}"
                resp = requests.get(url, timeout=30)
                soup = BeautifulSoup(resp.text, "html.parser")
                for item in soup.select(".search-result")[:5]:
                    title_el = item.select_one("strong")
                    link_el = item.select_one("a")
                    if title_el:
                        papers.append({
                            "title": title_el.get_text(strip=True),
                            "url": urljoin(self.BASE_URL, link_el["href"]) if link_el and link_el.get("href") else "",
                            "source": "ACL Anthology",
                            "keyword": keyword,
                        })
                time.sleep(2)
            except Exception:
                continue
        return papers


class OwaspCrawler:
    URLS = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]

    def fetch(self) -> list[dict]:
        results: list[dict] = []
        for url in self.URLS:
            try:
                resp = requests.get(url, timeout=30)
                soup = BeautifulSoup(resp.text, "html.parser")
                for item in soup.select("h2, h3, li")[:20]:
                    text = item.get_text(strip=True)
                    if text and len(text) > 30:
                        results.append({
                            "title": text[:120],
                            "url": url,
                            "source": "OWASP",
                            "content": text,
                        })
            except Exception:
                continue
        return results


class KnowledgeExtractor:
    ATTACK_PATTERNS = [
        re.compile(r"(prompt\s*injection)", re.I),
        re.compile(r"(jailbreak)", re.I),
        re.compile(r"(data\s*exfiltration)", re.I),
        re.compile(r"(tool\s*abuse|tool\s*misuse)", re.I),
        re.compile(r"(memory\s*poisoning)", re.I),
        re.compile(r"(adversarial\s*(prompt|suffix|attack|example))", re.I),
        re.compile(r"(role\s*override|system\s*prompt\s*(leak|extract|steal))", re.I),
        re.compile(r"(unicode\s*obfuscation|base64\s*payload)", re.I),
    ]

    def extract(self, papers: list[dict]) -> list[dict]:
        findings: list[dict] = []
        for paper in papers:
            text = paper.get("summary", "") + " " + paper.get("title", "")
            matched_techniques: list[str] = []
            for pattern in self.ATTACK_PATTERNS:
                if pattern.search(text):
                    matched_techniques.append(pattern.pattern)

            if matched_techniques:
                findings.append({
                    "title": paper.get("title", ""),
                    "url": paper.get("url", ""),
                    "techniques": matched_techniques,
                    "summary": paper.get("summary", "")[:500],
                    "credibility_score": min(1.0, 0.5 + len(matched_techniques) * 0.15),
                    "extracted_at": datetime.now(timezone.utc).isoformat(),
                })
        return findings


class KnowledgeBrainUpdater:
    def __init__(self, brain_path: str):
        self.brain_path = Path(brain_path)

    def update(self, findings: list[dict]) -> dict:
        if not findings:
            return {"updated": False, "entries_added": 0}

        existing_entries: set[str] = set()
        if self.brain_path.exists():
            content = self.brain_path.read_text(encoding="utf-8")
            existing_entries = {self._hash_entry(line) for line in content.split("\n") if line.strip().startswith("-")}

        new_entries: list[str] = []
        for finding in findings[:20]:
            entry_hash = self._hash_entry(finding["title"])
            if entry_hash in existing_entries:
                continue
            existing_entries.add(entry_hash)
            tech = ", ".join(finding.get("techniques", []))
            new_entries.append(
                f"- [{finding['title']}]({finding['url']}) — {tech} "
                f"(credibility: {finding['credibility_score']:.2f})"
            )

        if not new_entries:
            return {"updated": False, "entries_added": 0}

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        block = f"\n\n## Research Update — {timestamp}\n\n" + "\n".join(new_entries)

        with open(self.brain_path, "a", encoding="utf-8") as f:
            f.write(block)

        return {"updated": True, "entries_added": len(new_entries), "timestamp": timestamp}

    @staticmethod
    def _hash_entry(text: str) -> str:
        return hashlib.md5(text.strip().lower().encode()).hexdigest()
