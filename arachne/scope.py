"""Scope rules and URL normalization."""
from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit, urljoin, parse_qsl, urlencode

import tldextract

from .config import Config

# tldextract without live PSL fetch (offline, deterministic).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def registered_domain(host: str) -> str:
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host.lower()


class Scope:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.allow = [re.compile(p) for p in cfg.allow_regex]
        self.deny = [re.compile(p) for p in cfg.effective_deny()]

        self.hosts: set = set()
        self.reg_domains: set = set()
        for s in list(cfg.seeds) + list(cfg.extra_scope):
            host = self._host(s)
            if host:
                self.hosts.add(host)
                self.reg_domains.add(registered_domain(host))
        # primary origin used to resolve root-relative endpoints mined from JS
        self.primary_origin: Optional[str] = None
        if cfg.seeds:
            sp = urlsplit(cfg.seeds[0])
            if sp.scheme and sp.netloc:
                self.primary_origin = f"{sp.scheme}://{sp.netloc}"

    @staticmethod
    def _host(value: str) -> str:
        if "://" not in value:
            value = "http://" + value
        return urlsplit(value).netloc.split("@")[-1].split(":")[0].lower()

    def host_in_scope(self, host: str) -> bool:
        host = host.lower()
        if self.cfg.include_subdomains:
            return registered_domain(host) in self.reg_domains
        return host in self.hosts

    def in_scope(self, url: str) -> bool:
        try:
            sp = urlsplit(url)
        except ValueError:
            return False
        if sp.scheme not in ("http", "https"):
            return False
        if not sp.netloc:
            return False
        if not self.host_in_scope(sp.netloc.split("@")[-1].split(":")[0]):
            return False
        if self.deny and any(p.search(url) for p in self.deny):
            return False
        if self.allow and not any(p.search(url) for p in self.allow):
            return False
        return True

    def is_asset(self, url: str) -> bool:
        path = urlsplit(url).path
        if "." not in path.rsplit("/", 1)[-1]:
            return False
        ext = path.rsplit(".", 1)[-1].lower()
        return ext in self.cfg.skip_ext

    def is_js(self, url: str) -> bool:
        path = urlsplit(url).path.lower()
        return path.endswith(".js") or path.endswith(".mjs") or path.endswith(".jsx")

    def normalize(self, url: str, base: Optional[str] = None) -> Optional[str]:
        """Resolve against base, drop fragment, sort query, return canonical URL."""
        if base:
            url = urljoin(base, url)
        url = url.strip()
        if not url or url.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "#")):
            return None
        try:
            sp = urlsplit(url)
        except ValueError:
            return None
        if sp.scheme not in ("http", "https"):
            return None
        netloc = sp.netloc.lower()
        # strip default ports
        netloc = re.sub(r":80$", "", netloc) if sp.scheme == "http" else netloc
        netloc = re.sub(r":443$", "", netloc) if sp.scheme == "https" else netloc
        path = sp.path or "/"
        query = sp.query
        if query:
            pairs = parse_qsl(query, keep_blank_values=True)
            pairs.sort()
            query = urlencode(pairs)
        return urlunsplit((sp.scheme, netloc, path, query, ""))

    def dedup_key(self, url: str, method: str = "GET") -> str:
        """Key used to decide whether we've already queued/seen this resource."""
        sp = urlsplit(url)
        path = sp.path or "/"
        if self.cfg.dedup_params and sp.query:
            names = sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)})
            q = "&".join(names)
        else:
            q = sp.query
        return f"{method} {sp.scheme}://{sp.netloc.lower()}{path}?{q}"
