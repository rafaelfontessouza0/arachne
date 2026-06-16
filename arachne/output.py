"""Streaming output writer."""
from __future__ import annotations

import json
import os
from typing import Dict, List, Set, TextIO, Optional

from .models import Result


class Output:
    def __init__(self, output_dir: str):
        self.dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._jsonl: TextIO = open(os.path.join(output_dir, "endpoints.jsonl"), "w", encoding="utf-8")
        self._secrets_fh: Optional[TextIO] = None
        self.urls: Set[str] = set()
        self.api: Set[str] = set()
        self.js: Set[str] = set()
        self.params: Set[str] = set()
        self.candidates: Set[str] = set()
        self.graphql: List[dict] = []
        self.status_counts: Dict[int, int] = {}
        self.source_counts: Dict[str, int] = {}
        self.secret_types: Dict[str, int] = {}
        self.secrets_count = 0
        self.openapi_endpoints = 0
        self.auth_failures = 0
        self.reauths = 0
        self.fuzz_hits = 0          # paths confirmed by an active content fuzzer (ffuf)
        self.active_params = 0      # params confirmed by an active param fuzzer (arjun)
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
        if r.source == "openapi":
            self.openapi_endpoints += 1

    def add_js(self, url: str) -> None:
        self.js.add(url)

    def add_param(self, name: str) -> None:
        self.params.add(name)

    def add_candidate(self, url: str) -> None:
        self.candidates.add(url)

    def write_secret(self, finding: dict) -> None:
        if self._secrets_fh is None:
            self._secrets_fh = open(os.path.join(self.dir, "secrets.jsonl"), "w", encoding="utf-8")
        self._secrets_fh.write(json.dumps(finding, ensure_ascii=False, sort_keys=True) + "\n")
        self.secrets_count += 1
        t = finding.get("type", "unknown")
        self.secret_types[t] = self.secret_types.get(t, 0) + 1

    def write_graphql(self, entry: dict) -> None:
        self.graphql.append(entry)

    def _dump(self, name: str, items: Set[str]) -> None:
        with open(os.path.join(self.dir, name), "w", encoding="utf-8") as fh:
            for v in sorted(items):
                fh.write(v + "\n")

    def close(self) -> dict:
        self._jsonl.close()
        if self._secrets_fh is not None:
            self._secrets_fh.close()
        self._dump("urls.txt", self.urls)
        self._dump("api.txt", self.api)
        self._dump("js.txt", self.js)
        self._dump("params.txt", self.params)
        self._dump("candidates.txt", self.candidates)
        if self.graphql:
            with open(os.path.join(self.dir, "graphql.json"), "w", encoding="utf-8") as fh:
                json.dump(self.graphql, fh, indent=2, ensure_ascii=False)
        summary = {
            "results": self.n_results,
            "unique_urls": len(self.urls),
            "api_endpoints": len(self.api),
            "openapi_endpoints": self.openapi_endpoints,
            "graphql_endpoints": len(self.graphql),
            "auth_failures": self.auth_failures,
            "reauths": self.reauths,
            "fuzz_hits": self.fuzz_hits,
            "active_params": self.active_params,
            "js_files": len(self.js),
            "params": len(self.params),
            "candidates": len(self.candidates),
            "secrets": self.secrets_count,
            "secret_types": self.secret_types,
            "status_counts": self.status_counts,
            "source_counts": self.source_counts,
        }
        with open(os.path.join(self.dir, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, sort_keys=True)
        return summary
