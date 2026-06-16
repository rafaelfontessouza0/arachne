"""Data structures shared across the crawler."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


@dataclass
class Task:
    """A unit of work in the frontier."""
    url: str
    method: str = "GET"
    depth: int = 0
    referrer: Optional[str] = None
    # seed|html|js|json|sitemap|robots|render|form|imported|openapi|graphql
    # |ffuf|feroxbuster|arjun|katana|hakrawler|gospider|gau|waybackurls|urlfinder
    source: str = "seed"

    def key(self) -> str:
        return f"{self.method} {self.url}"


@dataclass
class Result:
    """A discovered/fetched resource."""
    url: str
    method: str = "GET"
    status: Optional[int] = None
    content_type: Optional[str] = None
    length: Optional[int] = None
    title: Optional[str] = None
    source: str = "html"
    depth: int = 0
    referrer: Optional[str] = None
    is_api: bool = False
    params: List[str] = field(default_factory=list)
    redirected_to: Optional[str] = None
    note: Optional[str] = None

    def to_json(self) -> str:
        d: Dict[str, Any] = asdict(self)
        return json.dumps({k: v for k, v in d.items() if v not in (None, [], "")},
                          ensure_ascii=False, sort_keys=True)
