"""Passive session import: seed a crawl from a captured HAR, Postman collection,
or Burp Suite XML export — optionally adopting the captured auth (cookies +
Authorization header). This is the highest-yield way to map an authenticated
API: drive the app through a proxy, export, and let arachne expand from the
real authenticated requests.
"""
from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional


@dataclass
class Imported:
    entries: List[Tuple[str, str]] = field(default_factory=list)  # (method, url)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    def merge(self, other: "Imported") -> None:
        self.entries.extend(other.entries)
        for k, v in other.cookies.items():
            self.cookies.setdefault(k, v)
        for k, v in other.headers.items():
            self.headers.setdefault(k, v)


def _add_cookie_header(out: Imported, value: str) -> None:
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out.cookies[k.strip()] = v.strip()


def load_har(path: str) -> Imported:
    out = Imported()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    for e in data.get("log", {}).get("entries", []):
        req = e.get("request", {})
        url = req.get("url")
        if url:
            out.entries.append((str(req.get("method", "GET")).upper(), url))
        for c in req.get("cookies", []) or []:
            if c.get("name"):
                out.cookies[str(c["name"])] = str(c.get("value", ""))
        for h in req.get("headers", []) or []:
            n = (h.get("name") or "").lower()
            if n == "authorization":
                out.headers["Authorization"] = h.get("value", "")
            elif n == "cookie":
                _add_cookie_header(out, h.get("value", ""))
    return out


def load_postman(path: str) -> Imported:
    out = Imported()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    def url_of(req) -> Optional[str]:
        u = req.get("url")
        if isinstance(u, str):
            return u
        if isinstance(u, dict):
            if u.get("raw"):
                return u["raw"]
            host = u.get("host")
            path_parts = u.get("path")
            host_s = ".".join(host) if isinstance(host, list) else (host or "")
            path_s = "/".join(path_parts) if isinstance(path_parts, list) else (path_parts or "")
            proto = u.get("protocol", "https")
            if host_s:
                return f"{proto}://{host_s}/{path_s}"
        return None

    def walk(items):
        for it in items or []:
            if isinstance(it, dict) and it.get("item"):
                walk(it["item"])
            req = it.get("request") if isinstance(it, dict) else None
            if isinstance(req, dict):
                u = url_of(req)
                if u and "{{" not in u:   # skip unresolved {{variables}}
                    out.entries.append((str(req.get("method", "GET")).upper(), u))
                for h in req.get("header", []) or []:
                    if (h.get("key") or "").lower() == "authorization":
                        out.headers["Authorization"] = h.get("value", "")

    walk(data.get("item"))
    auth = data.get("auth") or {}
    if auth.get("type") == "bearer":
        for b in auth.get("bearer", []) or []:
            if b.get("key") == "token" and b.get("value"):
                out.headers.setdefault("Authorization", "Bearer " + str(b["value"]))
    return out


def load_burp(path: str) -> Imported:
    out = Imported()
    tree = ET.parse(path)
    for item in tree.getroot().findall(".//item"):
        url = item.findtext("url")
        method = item.findtext("method") or "GET"
        if url:
            out.entries.append((method.strip().upper(), url.strip()))
        req_el = item.find("request")
        if req_el is not None and req_el.text:
            raw = req_el.text
            if (req_el.get("base64") or "").lower() == "true":
                try:
                    raw = base64.b64decode(raw).decode("utf-8", "replace")
                except Exception:
                    raw = ""
            for line in raw.replace("\r\n", "\n").split("\n"):
                low = line.lower()
                if low.startswith("cookie:"):
                    _add_cookie_header(out, line.split(":", 1)[1])
                elif low.startswith("authorization:"):
                    out.headers["Authorization"] = line.split(":", 1)[1].strip()
    return out


def load_any(har: Optional[str] = None, postman: Optional[str] = None,
             burp: Optional[str] = None) -> Optional[Imported]:
    result = Imported()
    used = False
    for loader, p in ((load_har, har), (load_postman, postman), (load_burp, burp)):
        if p:
            result.merge(loader(p))
            used = True
    return result if used else None
