from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import feedparser
import requests


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
PUBLIC_DIR = ROOT / "docs" / "intel"

DATA_DIR.mkdir(exist_ok=True)
PUBLIC_DIR.mkdir(parents=True, exist_ok=True)


SOURCES = [
    {
        "name": "github-advisory-pip",
        "type": "json-feed",
        "url": "https://azu.github.io/github-advisory-database-rss/pip.json",
        "category": "software-advisory",
    },
    {
        "name": "github-advisory-npm",
        "type": "json-feed",
        "url": "https://azu.github.io/github-advisory-database-rss/npm.json",
        "category": "software-advisory",
    },
    {
        "name": "owasp-news",
        "type": "rss",
        "url": "https://owasp.org/news/feed.xml",
        "category": "owasp-update",
    },
    {
        "name": "arxiv-ai-security",
        "type": "atom",
        "url": "http://export.arxiv.org/api/query?search_query=all:LLM%20security%20OR%20all:prompt%20injection%20OR%20all:AI%20security&start=0&max_results=10&sortBy=submittedDate&sortOrder=descending",
        "category": "research",
    },
]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_text(value: Any, limit: int = 500) -> str:
    if value is None:
        return ""
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    return text[:limit]


def normalize_item(
    *,
    source_name: str,
    source_category: str,
    title: str,
    summary: str,
    url: str,
    published: str,
    tags: List[str],
) -> Dict[str, Any]:
    raw_id = f"{source_name}|{title}|{url}|{published}"

    return {
        "id": sha256_text(raw_id)[:16],
        "source": source_name,
        "category": source_category,
        "title": safe_text(title, 180),
        "summary": safe_text(summary, 500),
        "published": safe_text(published, 80),
        "impact_scope": "metadata-only",
        "tags": [safe_text(t, 40) for t in tags[:8]],
        "url": safe_text(url, 500),
        "safety_policy": {
            "metadata_only": True,
            "no_exploit_code": True,
            "no_attack_prompt": True,
            "no_payload_collection": True,
        },
    }


def fetch_json_feed(source: Dict[str, str]) -> List[Dict[str, Any]]:
    response = requests.get(source["url"], timeout=20)
    response.raise_for_status()
    payload = response.json()

    items = []
    for item in payload.get("items", [])[:20]:
        items.append(
            normalize_item(
                source_name=source["name"],
                source_category=source["category"],
                title=item.get("title", ""),
                summary=item.get("summary") or item.get("content_text", ""),
                url=item.get("url", ""),
                published=item.get("date_published", ""),
                tags=item.get("tags", []),
            )
        )
    return items


def fetch_feedparser(source: Dict[str, str]) -> List[Dict[str, Any]]:
    feed = feedparser.parse(source["url"])

    items = []
    for entry in feed.entries[:20]:
        tags = []
        for tag in entry.get("tags", []):
            if isinstance(tag, dict) and tag.get("term"):
                tags.append(tag["term"])

        items.append(
            normalize_item(
                source_name=source["name"],
                source_category=source["category"],
                title=entry.get("title", ""),
                summary=entry.get("summary", ""),
                url=entry.get("link", ""),
                published=entry.get("published", entry.get("updated", "")),
                tags=tags,
            )
        )
    return items


def dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []

    for item in items:
        key = item["id"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    return unique


def write_public_index(items: List[Dict[str, Any]]) -> None:
    generated_at = datetime.now(timezone.utc).isoformat()

    output = {
        "stage": 336,
        "system": "Safe Live Intelligence Fetcher",
        "generated_at": generated_at,
        "mode": "safe-metadata-only",
        "item_count": len(items),
        "items": items,
    }

    json_path = PUBLIC_DIR / "index.json"
    json_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")

    rows = "\n".join(
        f"""
        <tr>
          <td>{item['category']}</td>
          <td>{item['title']}</td>
          <td>{item['published']}</td>
          <td><a href="{item['url']}">source</a></td>
        </tr>
        """
        for item in items[:50]
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Stage336 Safe Live Intelligence Fetcher</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 40px; line-height: 1.6; }}
    .badge {{ display:inline-block; padding:6px 10px; border:1px solid #ddd; border-radius:999px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 24px; }}
    th, td {{ border-bottom: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f7f7f7; }}
    code {{ background:#f3f3f3; padding:2px 5px; border-radius:4px; }}
  </style>
</head>
<body>
  <h1>Stage336 Safe Live Intelligence Fetcher</h1>
  <p class="badge">safe metadata only</p>

  <h2>What this page proves</h2>
  <p>
    Stage336 collects public AI/security intelligence metadata without collecting exploit code,
    attack prompts, payloads, or reproduction instructions.
  </p>

  <h2>Safety Policy</h2>
  <ul>
    <li>Metadata only</li>
    <li>No exploit code</li>
    <li>No attack prompt collection</li>
    <li>No payload collection</li>
  </ul>

  <h2>Latest Intelligence Metadata</h2>
  <p>Generated at: <code>{generated_at}</code></p>
  <p>JSON: <a href="./index.json">index.json</a></p>

  <table>
    <thead>
      <tr>
        <th>Category</th>
        <th>Title</th>
        <th>Published</th>
        <th>URL</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""
    (PUBLIC_DIR / "index.html").write_text(html, encoding="utf-8")


def main() -> None:
    all_items: List[Dict[str, Any]] = []

    for source in SOURCES:
        try:
            if source["type"] == "json-feed":
                all_items.extend(fetch_json_feed(source))
            else:
                all_items.extend(fetch_feedparser(source))
        except Exception as exc:
            all_items.append(
                normalize_item(
                    source_name=source["name"],
                    source_category="fetch-error",
                    title=f"Fetch failed: {source['name']}",
                    summary=str(exc),
                    url=source["url"],
                    published=datetime.now(timezone.utc).isoformat(),
                    tags=["fetch-error"],
                )
            )

    safe_items = dedupe(all_items)
    write_public_index(safe_items)

    local_log = DATA_DIR / "last_fetch.json"
    local_log.write_text(
        json.dumps(
            {
                "stage": 336,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "item_count": len(safe_items),
                "items": safe_items,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"Stage336 complete: {len(safe_items)} metadata items written.")
    print("Public JSON: docs/intel/index.json")
    print("Public HTML: docs/intel/index.html")
    print("Private log: data/last_fetch.json")


if __name__ == "__main__":
    main()
