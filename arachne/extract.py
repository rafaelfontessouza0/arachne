"""Extractors: HTML links/forms, JS endpoints, JSON URL mining."""
from __future__ import annotations

import json
import re
from typing import List, Set, Tuple, Optional, Any
from urllib.parse import urlsplit, parse_qsl

# Optional fast HTML parser; fall back to bs4 if unavailable.
try:
    from selectolax.parser import HTMLParser as _SelectoParser  # type: ignore
    _HAVE_SELECTO = True
except Exception:  # pragma: no cover
    _HAVE_SELECTO = False
try:
    from bs4 import BeautifulSoup  # type: ignore
    _HAVE_BS4 = True
except Exception:  # pragma: no cover
    _HAVE_BS4 = False


# Attributes that carry navigable URLs, by tag.
_URL_ATTRS = [
    ("a", "href"), ("area", "href"), ("link", "href"),
    ("script", "src"), ("iframe", "src"), ("frame", "src"),
    ("form", "action"), ("img", "src"), ("img", "data-src"),
    ("source", "src"), ("embed", "src"), ("object", "data"),
    ("audio", "src"), ("video", "src"), ("track", "src"),
    ("button", "formaction"),
]

# LinkFinder-style regex (Gerben Javado), extended with backtick delimiters.
_JS_ENDPOINT_RE = re.compile(r"""
  (?:"|'|`)
  (
    ((?:[a-zA-Z]{1,10}://|//)[^"'`/]{1,}\.[a-zA-Z]{2,}[^"'`]{0,})
    |
    ((?:/|\.\./|\./)[^"'`><,;|*()(%$^/\\\[\]][^"'`><,;|()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|))
  )
  (?:"|'|`)
""", re.VERBOSE)

_FULL_URL_RE = re.compile(r"https?://[^\s\"'`<>()\[\]{}]+")

_API_HINT_RE = re.compile(
    r"(/api/|/rest/|/graphql|/v\d+/|/gateway/|/service/|/svc/|/rpc/|\.json(\?|$)|/oauth|/token)",
    re.IGNORECASE,
)


def looks_like_api(url: str, content_type: Optional[str] = None) -> bool:
    if content_type and ("json" in content_type or "graphql" in content_type):
        return True
    return bool(_API_HINT_RE.search(url))


def param_names(url: str) -> List[str]:
    q = urlsplit(url).query
    if not q:
        return []
    return sorted({k for k, _ in parse_qsl(q, keep_blank_values=True)})


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _decode(body: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return body.decode(enc)
        except Exception:
            continue
    return body.decode("utf-8", "replace")


def extract_html(html: bytes) -> Tuple[Set[str], Set[str], Set[str], List[str], Optional[str]]:
    """Return (links, js_urls, inline_script_blobs, form_params, title)."""
    text = _decode(html) if isinstance(html, (bytes, bytearray)) else html
    links: Set[str] = set()
    js_urls: Set[str] = set()
    scripts: Set[str] = set()
    params: Set[str] = set()
    title: Optional[str] = None

    if _HAVE_SELECTO:
        tree = _SelectoParser(text)
        node = tree.css_first("title")
        if node:
            title = (node.text() or "").strip() or None
        for tag, attr in _URL_ATTRS:
            for el in tree.css(tag):
                val = el.attributes.get(attr)
                if not val:
                    continue
                if tag == "script" and attr == "src":
                    js_urls.add(val)
                else:
                    links.add(val)
        for el in tree.css("script"):
            if not el.attributes.get("src"):
                blob = el.text() or ""
                if blob.strip():
                    scripts.add(blob)
        for el in tree.css("input,select,textarea,button"):
            name = el.attributes.get("name")
            if name:
                params.add(name)
        for el in tree.css("meta"):
            if (el.attributes.get("http-equiv") or "").lower() == "refresh":
                content = el.attributes.get("content") or ""
                m = re.search(r"url=([^;]+)", content, re.IGNORECASE)
                if m:
                    links.add(m.group(1).strip())
    elif _HAVE_BS4:
        soup = BeautifulSoup(text, "lxml" if _lxml_ok() else "html.parser")
        if soup.title and soup.title.string:
            title = soup.title.string.strip() or None
        for tag, attr in _URL_ATTRS:
            for el in soup.find_all(tag):
                val = el.get(attr)
                if not val:
                    continue
                if tag == "script" and attr == "src":
                    js_urls.add(val)
                else:
                    links.add(val)
        for el in soup.find_all("script"):
            if not el.get("src") and el.string:
                scripts.add(str(el.string))
        for el in soup.find_all(["input", "select", "textarea", "button"]):
            name = el.get("name")
            if name:
                params.add(name)
    else:  # last resort: regex over raw HTML
        for m in re.finditer(r'(?:href|src|action|data)\s*=\s*["\']([^"\']+)["\']', text, re.I):
            links.add(m.group(1))

    return links, js_urls, scripts, sorted(params), title


def _lxml_ok() -> bool:
    try:
        import lxml  # noqa: F401
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

def extract_js(text: str) -> Set[str]:
    """Return raw endpoint/URL candidates mined from JS/source text."""
    out: Set[str] = set()
    for m in _JS_ENDPOINT_RE.finditer(text):
        val = (m.group(1) or "").strip()
        if val and 1 < len(val) < 400:
            out.add(val)
    for m in _FULL_URL_RE.finditer(text):
        out.add(m.group(0))
    return out


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

_URLISH_RE = re.compile(r"^(https?://|//|/)[^\s]+")
_URL_KEY_RE = re.compile(r"(url|href|link|endpoint|api|path|uri|src|action|location)", re.I)


def extract_json(body: bytes) -> Set[str]:
    out: Set[str] = set()
    try:
        data = json.loads(body)
    except Exception:
        return out

    def walk(obj: Any, key_hint: bool) -> None:
        if isinstance(obj, str):
            s = obj.strip()
            if _URLISH_RE.match(s) or (key_hint and "/" in s and " " not in s and len(s) < 300):
                out.add(s)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, bool(_URL_KEY_RE.search(str(k))))
        elif isinstance(obj, list):
            for v in obj:
                walk(v, key_hint)

    walk(data, False)
    return out
