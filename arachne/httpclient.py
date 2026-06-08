"""Async HTTP client wrapper: proxy, TLS, retries, rate limiting."""
from __future__ import annotations

import asyncio
import time
from typing import Optional

import httpx

from .config import Config


class RateLimiter:
    """Simple async token-bucket. rate<=0 disables limiting."""

    def __init__(self, rate: float):
        self.rate = rate
        self._tokens = rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
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


class HttpClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.limiter = RateLimiter(cfg.rate)
        self._sem = asyncio.Semaphore(cfg.concurrency)

        headers = {"User-Agent": cfg.user_agent}
        headers.update(cfg.headers)
        if cfg.bearer:
            headers["Authorization"] = f"Bearer {cfg.bearer}"

        limits = httpx.Limits(max_connections=cfg.concurrency,
                              max_keepalive_connections=cfg.concurrency)
        kwargs = dict(
            headers=headers,
            cookies=cfg.cookies or None,
            timeout=httpx.Timeout(cfg.timeout),
            follow_redirects=cfg.follow_redirects,
            verify=not cfg.insecure,
            limits=limits,
            http2=True,
        )
        # httpx renamed `proxies` -> `proxy`; support both.
        if cfg.proxy:
            try:
                self._client = httpx.AsyncClient(proxy=cfg.proxy, **kwargs)
            except TypeError:
                self._client = httpx.AsyncClient(proxies=cfg.proxy, **kwargs)
        else:
            self._client = httpx.AsyncClient(**kwargs)

    async def request(self, method: str, url: str) -> Optional[httpx.Response]:
        attempts = self.cfg.retries + 1
        backoff = 0.5
        for i in range(attempts):
            await self.limiter.acquire()
            if self.cfg.delay:
                await asyncio.sleep(self.cfg.delay)
            try:
                async with self._sem:
                    resp = await self._client.request(method, url)
                if resp.status_code == 429 and i < attempts - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            except (httpx.TransportError, httpx.HTTPError):
                if i < attempts - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                return None
        return None

    async def post_json(self, url: str, payload) -> Optional[httpx.Response]:
        """Single read-only JSON POST (used for GraphQL introspection)."""
        await self.limiter.acquire()
        if self.cfg.delay:
            await asyncio.sleep(self.cfg.delay)
        try:
            async with self._sem:
                return await self._client.post(url, json=payload)
        except (httpx.TransportError, httpx.HTTPError):
            return None

    async def aclose(self) -> None:
        await self._client.aclose()
