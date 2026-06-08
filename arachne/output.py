"""Streaming output writer."""
from __future__ import annotations

import json
import os
import sys
from typing import Dict, Set, TextIO

from .models import Result


class Output:
    def __init__(self, output_dir: str):
        self.dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._jsonl: TextIO = open(os.path.join(output_dir, "endpoints.jsonl"), "w", encoding="utf-8")
        self.urls: Set[str] = set()
        self.api: Set[str] = set()
        self.js: Set[str] = set()
        self.params: Set[str] = set()
        self.status_counts: Dict[int, int] = {}
        self.source_counts: Dict[str, int] = {}
        self.n_results = 0

    def write(self, r: Result) -> None:
        self.n_results += 1
        self._jsonl.write(r.to_json() + "\n")
        self.urls.add(r.url)
        if r.is_api:
            self.api.add(r.url)
        for p in r.params:
            self.params.add(p)
        if r.status is not None:
            self.status_counts[r.status] = self.status_counts.get(r.status, 0) + 1
        self.source_counts[r.source] = self.source_counts.get(r.source, 0) + 1

    def add_js(self, url: str) -> None:
        self.js.add(url)

    def _dump(self, name: str, items: Set[str]) -> None:
        with open(os.path.join(self.dir, name), "w", encoding="utf-8") as fh:
            for v in sorted(items):
                fh.write(v + "\n")

    def close(self) -> None:
        self._jsonl.close()
        self._dump("urls.txt", self.urls)
        self._dump("api.txt", self.api)
        self._dump("js.txt", self.js)
        self._dump("params.txt", self.params)
        summary = {
            "results": self.n_results,
            "unique_urls": len(self.urls),
            "api_endpoints": len(self.api),
            "js_files": len(self.js),
            "params": len(self.params),
            "status_counts": self.status_counts,
            "source_counts": self.source_counts,
        }
        with open(os.path.join(self.dir, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, sort_keys=True)
        return summary
