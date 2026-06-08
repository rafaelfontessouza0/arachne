"""Async HTTP client wrapper: proxy, TLS, retries, per-host rate limiting, and
optional curl_cffi TLS-fingerprint impersonation (JA3/HTTP2) for WAF'd targets."""
from __future__ import annotations

import asyncio
import time
from typing import Optional, Dict
from urllib.parse import urlsplit

import httpx

from .config import Config


class RateLimiter:
    """Simple async token-bucket. rate<=0 disables limiting."""

    def __init__(self, rate: float):
        self.rate = rate
        self._tokens = rate
        self._last = time.monotonic()
        self._lock: Optional[asyncio.Lock] = None

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0
                self._last = time.monotonic()
            else:
                self._tokens -= 1


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except Exception:
        return ""


class HttpClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._global_sem = asyncio.Semaphore(cfg.concurrency)
        self._limiters: Dict[str, RateLimiter] = {}   # per-host token buckets
        self._host_sems: Dict[str, asyncio.Semaphore] = {}

        headers = {"User-Agent": cfg.user_agent}
        headers.update(cfg.headers)
        if cfg.bearer:
            scheme = (cfg.auth_scheme + " ") if cfg.auth_scheme else ""
            headers[cfg.auth_header or "Authorization"] = f"{scheme}{cfg.bearer}"

        self.backend = "curl" if cfg.impersonate else "httpx"
        self._client = None
        self._session = None

        if self.backend == "curl":
            try:
                from curl_cffi.requests import AsyncSession
            except Exception as exc:  # pragma: no cover
                raise RuntimeError("curl_cffi is required for --impersonate "
                                   "(install: pip install curl_cffi)") from exc
            self._curl_errors = self._resolve_curl_errors()
            proxies = {"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else None
            self._session = AsyncSession(
                impersonate=cfg.impersonate, verify=not cfg.insecure, proxies=proxies,
                headers=headers, cookies=(cfg.cookies or None), timeout=cfg.timeout)
        else:
            limits = httpx.Limits(max_connections=cfg.concurrency,
                                  max_keepalive_connections=cfg.concurrency)
            kwargs = dict(headers=headers, cookies=cfg.cookies or None,
                          timeout=httpx.Timeout(cfg.timeout),
                          follow_redirects=cfg.follow_redirects,
                          verify=not cfg.insecure, limits=limits, http2=True)
            if cfg.proxy:
                try:
                    self._client = httpx.AsyncClient(proxy=cfg.proxy, **kwargs)
                except TypeError:
                    self._client = httpx.AsyncClient(proxies=cfg.proxy, **kwargs)
            else:
                self._client = httpx.AsyncClient(**kwargs)

    @staticmethod
    def _resolve_curl_errors():
        for mod, name in (("curl_cffi.requests.errors", "RequestsError"),
                          ("curl_cffi.requests.exceptions", "RequestException"),
                          ("curl_cffi", "CurlError")):
            try:
                m = __import__(mod, fromlist=[name])
                return (getattr(m, name),)
            except Exception:
                continue
        return (Exception,)

    @property
    def _net_errors(self):
        if self.backend == "curl":
            return self._curl_errors
        return (httpx.TransportError, httpx.HTTPError)

    def _limiter(self, host: str) -> RateLimiter:
        lim = self._limiters.get(host)
        if lim is None:
            lim = RateLimiter(self.cfg.rate)
            self._limiters[host] = lim
        return lim

    def _host_sem(self, host: str) -> Optional[asyncio.Semaphore]:
        if self.cfg.per_host_concurrency <= 0:
            return None
        sem = self._host_sems.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self.cfg.per_host_concurrency)
            self._host_sems[host] = sem
        return sem

    async def _do(self, method: str, url: str):
        if self.backend == "curl":
            return await self._session.request(
                method, url, allow_redirects=self.cfg.follow_redirects)
        return await self._client.request(method, url)

    async def request(self, method: str, url: str):
        host = _host_of(url)
        attempts = self.cfg.retries + 1
        backoff = 0.5
        for i in range(attempts):
            await self._limiter(host).acquire()
            if self.cfg.delay:
                await asyncio.sleep(self.cfg.delay)
            try:
                hsem = self._host_sem(host)
                async with self._global_sem:
                    if hsem is not None:
                        async with hsem:
                            resp = await self._do(method, url)
                    else:
                        resp = await self._do(method, url)
                if getattr(resp, "status_code", None) == 429 and i < attempts - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            except self._net_errors:
                if i < attempts - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                return None
        return None

    async def post_json(self, url: str, payload):
        host = _host_of(url)
        await self._limiter(host).acquire()
        if self.cfg.delay:
            await asyncio.sleep(self.cfg.delay)
        try:
            async with self._global_sem:
                if self.backend == "curl":
                    return await self._session.post(
                        url, json=payload, allow_redirects=self.cfg.follow_redirects)
                return await self._client.post(url, json=payload)
        except self._net_errors:
            return None

    def update_auth(self, cookies=None, headers=None) -> None:
        """Hot-swap credentials on the live client (used by mid-crawl re-auth)."""
        target = self._session if self.backend == "curl" else self._client
        if cookies:
            for k, v in cookies.items():
                try:
                    target.cookies.set(k, v)
                except Exception:
                    try:
                        target.cookies[k] = v
                    except Exception:
                        pass
        if headers:
            for k, v in headers.items():
                target.headers[k] = v

    async def aclose(self) -> None:
        try:
            if self._session is not None:
                await self._session.close()
            if self._client is not None:
                await self._client.aclose()
        except Exception:
            pass
