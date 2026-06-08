"""Authentication material loading: headers, cookies, bearer, storage-state.

Both authenticated and unauthenticated crawls use the same engine; an
unauthenticated run is simply one with no auth material supplied.
"""
from __future__ import annotations

import json
import os
import re
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


_TOKEN_KEY_RE = re.compile(
    r"(access[_-]?token|^token$|jwt|auth[_-]?token|id[_-]?token|bearer|"
    r"accesstoken|authtoken|idtoken)", re.I)
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}$")


def _search_token_in_obj(obj) -> Optional[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v and _TOKEN_KEY_RE.search(str(k)):
                return v
        for v in obj.values():
            r = _search_token_in_obj(v)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _search_token_in_obj(v)
            if r:
                return r
    elif isinstance(obj, str) and _JWT_RE.match(obj.strip()):
        return obj.strip()
    return None


def _token_from_value(value: str) -> Optional[str]:
    value = str(value).strip()
    if _JWT_RE.match(value):
        return value
    if value.startswith("{"):
        try:
            return _search_token_in_obj(json.loads(value))
        except Exception:
            pass
    if 8 <= len(value) <= 4096 and " " not in value and "\n" not in value:
        return value
    return None


def extract_token_from_storage(state: dict, key: Optional[str] = None) -> Optional[str]:
    """Find a bearer token in a Playwright storage_state's localStorage."""
    for origin in state.get("origins", []) or []:
        ls = origin.get("localStorage", [])
        items: List[Tuple] = []
        if isinstance(ls, list):
            items = [(i.get("name"), i.get("value")) for i in ls if isinstance(i, dict)]
        elif isinstance(ls, dict):
            items = list(ls.items())
        for name, value in items:
            if not value:
                continue
            if key:
                if name == key:
                    t = _token_from_value(value)
                    if t:
                        return t
                continue
            if name and _TOKEN_KEY_RE.search(str(name)):
                t = _token_from_value(value)
                if t:
                    return t
            sval = str(value).strip()
            if _JWT_RE.match(sval):
                return sval
            if sval.startswith("{"):
                try:
                    t = _search_token_in_obj(json.loads(sval))
                    if t:
                        return t
                except Exception:
                    pass
    return None


def apply_auth(cfg: Config) -> None:
    """Merge all auth sources into cfg.headers/cookies and, when possible, bridge a
    localStorage token from storage_state into the static (httpx) engine."""
    if cfg.cookies_file:
        cfg.cookies.update(load_cookies_file(cfg.cookies_file))
    if cfg.storage_state and os.path.exists(cfg.storage_state):
        try:
            with open(cfg.storage_state, "r", encoding="utf-8") as fh:
                state = json.load(fh)
        except Exception:
            state = None
        if isinstance(state, dict):
            for c in state.get("cookies", []):
                if c.get("name") and c.get("value") is not None:
                    cfg.cookies.setdefault(str(c["name"]), str(c["value"]))
            if cfg.auto_token and not cfg.bearer and cfg.auth_header not in cfg.headers:
                tok = extract_token_from_storage(state, cfg.auth_token_key)
                if tok:
                    cfg.bearer = tok
                    cfg.token_bridged = True


def is_authenticated(cfg: Config) -> bool:
    return bool(cfg.headers or cfg.cookies or cfg.bearer or cfg.storage_state)
