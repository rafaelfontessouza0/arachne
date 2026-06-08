"""Authentication material loading: headers, cookies, bearer, storage-state.

Both authenticated and unauthenticated crawls use the same engine; an
unauthenticated run is simply one with no auth material supplied.
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Tuple, Optional

from .config import Config


def parse_header_args(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in items or []:
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def parse_cookie_arg(raw: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def load_cookies_file(path: str) -> Dict[str, str]:
    """Accept JSON (list of {name,value} or {k:v} map) or Netscape cookies.txt."""
    out: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    content_stripped = content.lstrip()
    if content_stripped.startswith(("{", "[")):
        data = json.loads(content)
        if isinstance(data, dict):
            for k, v in data.items():
                out[str(k)] = str(v)
        elif isinstance(data, list):
            for c in data:
                if isinstance(c, dict) and "name" in c and "value" in c:
                    out[str(c["name"])] = str(c["value"])
        return out
    # Netscape format
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) >= 7:
            out[fields[5]] = fields[6]
    return out


def load_auth_json(path: str) -> Tuple[Dict[str, str], Dict[str, str], Optional[str], Optional[str]]:
    """Load a bundle: {headers:{}, cookies:{} or [], bearer:"", storage_state:""}."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    headers = {str(k): str(v) for k, v in (data.get("headers") or {}).items()}
    cookies: Dict[str, str] = {}
    raw_cookies = data.get("cookies")
    if isinstance(raw_cookies, dict):
        cookies = {str(k): str(v) for k, v in raw_cookies.items()}
    elif isinstance(raw_cookies, list):
        for c in raw_cookies:
            if isinstance(c, dict) and "name" in c and "value" in c:
                cookies[str(c["name"])] = str(c["value"])
    bearer = data.get("bearer")
    storage_state = data.get("storage_state")
    return headers, cookies, bearer, storage_state


def apply_auth(cfg: Config) -> None:
    """Mutate cfg in place, merging all auth sources into cfg.headers/cookies."""
    if cfg.cookies_file:
        cfg.cookies.update(load_cookies_file(cfg.cookies_file))
    if cfg.storage_state and os.path.exists(cfg.storage_state):
        # Pull cookies out of a Playwright storage_state so they also apply to httpx.
        try:
            with open(cfg.storage_state, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            for c in state.get("cookies", []):
                if c.get("name") and c.get("value") is not None:
                    cfg.cookies.setdefault(str(c["name"]), str(c["value"]))
        except Exception:
            pass


def is_authenticated(cfg: Config) -> bool:
    return bool(cfg.headers or cfg.cookies or cfg.bearer or cfg.storage_state)
