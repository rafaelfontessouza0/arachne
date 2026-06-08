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


DEFAULT_USER_SELECTOR = ('input[type="email"], input[name="username"], '
                         'input[name="email"], input[name="user"], input[type="text"]')
DEFAULT_PASS_SELECTOR = 'input[type="password"]'
DEFAULT_SUBMIT_SELECTOR = 'button[type="submit"], input[type="submit"], button'


async def login_to_storage_state(cfg) -> Optional[dict]:
    """Perform a form login with Playwright and return a fresh storage_state dict
    (cookies + localStorage). Returns None if Playwright is missing or login fails."""
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None
    user_sel = cfg.login_user_selector or DEFAULT_USER_SELECTOR
    pass_sel = cfg.login_pass_selector or DEFAULT_PASS_SELECTOR
    submit_sel = cfg.login_submit_selector or DEFAULT_SUBMIT_SELECTOR

    pw = await async_playwright().start()
    launch: Dict = {"headless": not cfg.headful}
    if cfg.proxy:
        launch["proxy"] = {"server": cfg.proxy}
    browser = await pw.chromium.launch(**launch)
    ctx = await browser.new_context(ignore_https_errors=cfg.insecure, user_agent=cfg.user_agent)
    try:
        page = await ctx.new_page()
        await page.goto(cfg.login_url, wait_until="domcontentloaded",
                        timeout=int(cfg.timeout * 1000))
        if cfg.login_username:
            await page.locator(user_sel).first.fill(cfg.login_username)
        if cfg.login_password:
            await page.locator(pass_sel).first.fill(cfg.login_password)
        await page.locator(submit_sel).first.click()
        try:
            await page.wait_for_load_state("networkidle", timeout=int(cfg.timeout * 1000))
        except Exception:
            pass
        success = cfg.login_success
        if success:
            try:
                if success.startswith("http") or success.startswith("/"):
                    await page.wait_for_url("**" + success + "**", timeout=int(cfg.timeout * 1000))
                else:
                    await page.wait_for_selector(success, timeout=int(cfg.timeout * 1000))
            except Exception:
                pass
        await page.wait_for_timeout(cfg.login_wait)
        return await ctx.storage_state()
    except Exception:
        return None
    finally:
        try:
            await ctx.close()
            await browser.close()
            await pw.stop()
        except Exception:
            pass
