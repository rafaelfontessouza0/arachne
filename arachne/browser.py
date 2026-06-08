"""Optional Playwright render pass: execute JS, capture XHR/fetch, harvest DOM links.

This is what surfaces the API surface of SPA targets (e.g. heavy JS betting/
banking apps) that never appears in static HTML.
"""
from __future__ import annotations

from typing import List, Dict, Set, Tuple, Optional

from .config import Config


class PlaywrightUnavailable(RuntimeError):
    pass


class BrowserRenderer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._pw = None
        self._browser = None
        self._context = None

    async def __aenter__(self) -> "BrowserRenderer":
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise PlaywrightUnavailable(
                "Playwright is not installed. Run: pip install playwright && playwright install chromium"
            ) from exc

        self._pw = await async_playwright().start()
        launch_kwargs: Dict = {"headless": not self.cfg.headful}
        if self.cfg.proxy:
            launch_kwargs["proxy"] = {"server": self.cfg.proxy}
        self._browser = await self._pw.chromium.launch(**launch_kwargs)

        ctx_kwargs: Dict = {
            "ignore_https_errors": self.cfg.insecure,
            "user_agent": self.cfg.user_agent,
        }
        if self.cfg.storage_state:
            ctx_kwargs["storage_state"] = self.cfg.storage_state
        self._context = await self._browser.new_context(**ctx_kwargs)

        extra_headers = dict(self.cfg.headers)
        if self.cfg.bearer:
            extra_headers["Authorization"] = f"Bearer {self.cfg.bearer}"
        if extra_headers:
            await self._context.set_extra_http_headers(extra_headers)
        if self.cfg.cookies:
            await self._add_cookies()
        return self

    async def _add_cookies(self) -> None:
        from urllib.parse import urlsplit
        cookies = []
        domains = set()
        for s in self.cfg.seeds:
            host = urlsplit(s).netloc.split("@")[-1].split(":")[0]
            if host:
                domains.add(host)
        for name, value in self.cfg.cookies.items():
            for host in domains:
                cookies.append({"name": name, "value": value, "domain": host, "path": "/"})
        if cookies:
            try:
                await self._context.add_cookies(cookies)
            except Exception:
                pass

    async def __aexit__(self, *exc) -> None:
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass

    async def render(self, url: str) -> Tuple[List[Dict], Set[str]]:
        """Navigate to url; return (captured network requests, DOM link set)."""
        captured: List[Dict] = []
        page = await self._context.new_page()

        def on_request(req) -> None:
            captured.append({"url": req.url, "method": req.method,
                             "resource_type": req.resource_type})

        page.on("request", on_request)
        links: Set[str] = set()
        try:
            await page.goto(url, wait_until="domcontentloaded",
                            timeout=int(self.cfg.timeout * 1000))
            if self.cfg.render_scroll:
                await self._auto_scroll(page)
            await page.wait_for_timeout(self.cfg.render_wait)
            try:
                await page.wait_for_load_state("networkidle",
                                               timeout=int(self.cfg.timeout * 1000))
            except Exception:
                pass
            hrefs = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)")
            links.update(h for h in hrefs if h)
        except Exception:
            pass
        finally:
            await page.close()
        return captured, links

    @staticmethod
    async def _auto_scroll(page) -> None:
        try:
            await page.evaluate(
                """async () => {
                    await new Promise(resolve => {
                        let total = 0; const step = 400;
                        const t = setInterval(() => {
                            window.scrollBy(0, step); total += step;
                            if (total >= document.body.scrollHeight || total > 12000) {
                                clearInterval(t); resolve();
                            }
                        }, 100);
                    });
                }"""
            )
        except Exception:
            pass
