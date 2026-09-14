"""
harness/label_mapper.py — Bidirectional rule/article mapper and benchmark dataset loader.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# Known GDPR articles covered by our system's rule pack
DEFAULT_SUPPORTED_ARTICLES: Set[int] = {5, 6, 17, 25, 32}
DEFAULT_SUPPORTED_RULES: Set[str] = {
    f"GDPR-Art.{art}" for art in DEFAULT_SUPPORTED_ARTICLES
}


class LabelMapper:
    """Bidirectional mapper between compliance rule_id strings and integer GDPR articles.

    Tracks unmapped rules and unsupported article numbers encountered during evaluation.
    """

    def __init__(
        self,
        supported_articles: Optional[Iterable[int]] = None,
    ) -> None:
        self.supported_articles: Set[int] = (
            set(supported_articles)
            if supported_articles is not None
            else set(DEFAULT_SUPPORTED_ARTICLES)
        )
        self.supported_rules: Set[str] = {
            f"GDPR-Art.{art}" for art in self.supported_articles
        }
        self.unmapped_rules: Set[str] = set()
        self.unmapped_articles: Set[int] = set()

    def rule_to_article(self, rule_id: str) -> Optional[int]:
        """Convert a rule_id string (e.g. 'GDPR-Art.32') to its integer article (e.g. 32).

        Extracts GDPR article numbers from composite strings (e.g. 'PCI-REQ-4 / GDPR-Art.32')
        or various formatting conventions ('Article 32', 'Art.32', 'GDPR-Art.32').

        Returns:
            The integer article number, or None if no GDPR article is present.
        """
        if not rule_id:
            return None

        # Regex extracts article number following 'Art.' or 'Article' (case-insensitive)
        match = re.search(r"(?:GDPR-)?(?:Art\.|Article)\s*(\d+)", rule_id, re.IGNORECASE)
        if not match:
            self.unmapped_rules.add(rule_id)
            logger.debug("Unmapped rule_id (no GDPR article found): %s", rule_id)
            return None

        article = int(match.group(1))
        if article not in self.supported_articles:
            self.unmapped_articles.add(article)
            logger.debug(
                "Article %d mapped from rule '%s' is not in supported articles %s",
                article,
                rule_id,
                self.supported_articles,
            )
        return article

    def article_to_rule(self, article: int) -> str:
        """Convert an integer article (e.g. 32) to canonical rule_id ('GDPR-Art.32').

        Flags the article if it is not in the supported rule pack.
        """
        if article not in self.supported_articles:
            self.unmapped_articles.add(article)
            logger.debug(
                "Article %d is not in supported rule pack %s",
                article,
                self.supported_articles,
            )
        return f"GDPR-Art.{article}"

    def is_supported_rule(self, rule_id: str) -> bool:
        """Check whether a rule_id corresponds to a supported GDPR rule."""
        article = self.rule_to_article(rule_id)
        return article is not None and article in self.supported_articles

    def is_supported_article(self, article: int) -> bool:
        """Check whether an integer article is supported by the rule pack."""
        return article in self.supported_articles

    def reset_flags(self) -> None:
        """Clear recorded unmapped rules and articles."""
        self.unmapped_rules.clear()
        self.unmapped_articles.clear()

    def get_unmapped_summary(self) -> dict[str, list[Any]]:
        """Return a dictionary summarizing any unmapped rules and unsupported articles."""
        return {
            "unmapped_rules": sorted(self.unmapped_rules),
            "unmapped_articles": sorted(self.unmapped_articles),
        }


# ---------------------------------------------------------------------------
# Dataset Record Schema & Loader
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkRecord:
    """Represents a single record in the GDPR-Bench-Android dataset."""

    app_name: str
    repo_url: str
    commit_id: str
    violated_article: Union[int, List[int]]
    code_snippet_path: str
    code_snippet: str
    annotation_note: str = ""
    file_path: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None


def parse_code_snippet_path(path_str: str) -> Tuple[str, Optional[int], Optional[int]]:
    """Parse code_snippet_path string into (file_path, start_line, end_line).

    Handles patterns like:
      - 'app/src/Foo.java:120-135'
      - 'app/src/Foo.java:120'
      - 'app/src/Foo.java lines 120-135'
      - 'app/src/Foo.java line 120'
      - 'app/src/Foo.java#L120-L135'
      - 'app/src/Foo.java'
    """
    path_str = path_str.strip()
    if not path_str:
        return "", None, None

    # Try matching lines X-Y or line X at the end
    m = re.search(
        r"(?:[:#]|(?:\s+lines?\s+))(?:\s*L)?(\d+)(?:\s*[-–—to:]\s*(?:L)?(\d+))?\s*$",
        path_str,
        re.IGNORECASE,
    )
    if m:
        start_line = int(m.group(1))
        end_line = int(m.group(2)) if m.group(2) is not None else start_line
        file_path = path_str[: m.start()].rstrip(":# ")
        return file_path, start_line, end_line

    return path_str, None, None


def _parse_record_dict(raw: dict[str, Any]) -> BenchmarkRecord:
    """Construct a BenchmarkRecord from a raw dictionary."""
    app_name = raw.get("app_name", "")
    repo_url = raw.get("repo_url", "")
    commit_id = raw.get("commit_id") or raw.get("Commit_ID") or ""
    snippet_path = raw.get("code_snippet_path", "")
    code_snippet = raw.get("code_snippet") or raw.get("file_content") or ""
    annotation_note = raw.get("annotation_note", "")

    # Article field might be 'violated_article' (int) or 'violated_articles' (list)
    if "violated_articles" in raw:
        violated_article: Union[int, List[int]] = [
            int(a) for a in raw["violated_articles"]
        ]
    elif "violated_article" in raw:
        v = raw["violated_article"]
        if isinstance(v, list):
            violated_article = [int(a) for a in v]
        elif v is not None:
            violated_article = int(v)
        else:
            violated_article = []
    else:
        violated_article = []

    file_path, start_line, end_line = parse_code_snippet_path(snippet_path)
    if not file_path and "file_path" in raw:
        file_path = raw["file_path"]

    return BenchmarkRecord(
        app_name=app_name,
        repo_url=repo_url,
        commit_id=commit_id,
        violated_article=violated_article,
        code_snippet_path=snippet_path,
        code_snippet=code_snippet,
        annotation_note=annotation_note,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
    )


def load_dataset(source: Union[str, Path]) -> List[BenchmarkRecord]:
    """Load benchmark records from a file (JSON/JSONL) or directory."""
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Dataset path does not exist: {path}")

    # If directory, find relevant JSON or JSONL file
    if path.is_dir():
        candidates = [
            path / "task1.json",
            path / "task1_dataset.json",
            path / "task2.json",
            path / "task2_dataset.json",
            path / "gdpr_violations.json",
            path / "dataset.json",
        ]
        found = next((c for c in candidates if c.exists()), None)
        if not found:
            json_files = list(path.glob("*.json")) + list(path.glob("*.jsonl"))
            if not json_files:
                raise FileNotFoundError(f"No JSON/JSONL dataset files found in {path}")
            found = json_files[0]
        path = found

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    # Detect JSON array vs JSONL
    if text.startswith("["):
        raw_items = json.loads(text)
    elif text.startswith("{"):
        try:
            raw_items = json.loads(text)
            if isinstance(raw_items, dict):
                # Wrapped list under common keys
                for k in ("records", "instances", "data", "violations"):
                    if k in raw_items and isinstance(raw_items[k], list):
                        raw_items = raw_items[k]
                        break
                else:
                    raw_items = [raw_items]
        except json.JSONDecodeError:
            raw_items = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        raw_items = [json.loads(line) for line in text.splitlines() if line.strip()]

    return [_parse_record_dict(item) for item in raw_items]


def load_task1_dataset(source: Union[str, Path]) -> List[BenchmarkRecord]:
    """Load Task 1 dataset (multi-granularity localization)."""
    path = Path(source)
    if path.is_dir():
        for name in ("task1.json", "task1_dataset.json"):
            target = path / name
            if target.exists():
                return load_dataset(target)
    return load_dataset(source)


def load_task2_dataset(source: Union[str, Path]) -> List[BenchmarkRecord]:
    """Load Task 2 dataset (snippet-level multi-label classification).

    If the source contains individual violation records, automatically groups them
    by code_snippet_path to produce multi-label entries.
    """
    path = Path(source)
    if path.is_dir():
        for name in ("task2.json", "task2_dataset.json"):
            target = path / name
            if target.exists():
                return load_dataset(target)

    records = load_dataset(source)
    # Check if records are already multi-label
    if all(isinstance(r.violated_article, list) for r in records):
        return records

    # Group by snippet identifier (code_snippet_path, app_name, repo_url)
    grouped: dict[str, BenchmarkRecord] = {}
    grouped_articles: dict[str, Set[int]] = {}

    for r in records:
        key = r.code_snippet_path or f"{r.file_path}:{r.start_line}-{r.end_line}"
        art = r.violated_article
        articles_to_add = art if isinstance(art, list) else ([art] if art else [])

        if key not in grouped:
            grouped[key] = r
            grouped_articles[key] = set(articles_to_add)
        else:
            grouped_articles[key].update(articles_to_add)

    result: List[BenchmarkRecord] = []
    for key, r in grouped.items():
        sorted_articles = sorted(grouped_articles[key])
        result.append(
            BenchmarkRecord(
                app_name=r.app_name,
                repo_url=r.repo_url,
                commit_id=r.commit_id,
                violated_article=sorted_articles,
                code_snippet_path=r.code_snippet_path,
                code_snippet=r.code_snippet,
                annotation_note=r.annotation_note,
                file_path=r.file_path,
                start_line=r.start_line,
                end_line=r.end_line,
            )
        )
    return result
