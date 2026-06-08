"""Crawl orchestration: static async phase, API-doc/GraphQL discovery, render."""
from __future__ import annotations

import asyncio
import json
import re
import sys
from typing import List, Set, Optional, Tuple
from urllib.parse import urlsplit

from .config import Config
from .scope import Scope
from .frontier import Frontier
from .httpclient import HttpClient
from .output import Output
from .models import Task, Result
from . import extract, secrets, apidocs

MAX_TEXT_BYTES = 10 * 1024 * 1024  # cap body size we parse

# signals that an authenticated request fell back to a login flow
_LOGIN_RE = re.compile(
    r"(login|sign[-_]?in|signin|/auth(/|$)|/sso|account/login|session/new|/oauth)", re.I)


class Crawler:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.scope = Scope(cfg)
        self.out = Output(cfg.output_dir)
        # asyncio-bound objects (Queue/Lock/Semaphore/AsyncClient) must be created
        # inside the running loop — built in run(), not here.
        self.frontier: Frontier = None  # type: ignore[assignment]
        self.http: HttpClient = None    # type: ignore[assignment]
        self.html_pages: List[str] = []
        self._html_seen: Set[str] = set()
        self._discovery_seen: Set[Tuple[str, str]] = set()
        self._secret_seen: Set[Tuple[str, str]] = set()
        self._sitemap_seen: Set[str] = set()
        self._rendered: Set[str] = set()
        self._fetched = 0
        self._authed = False
        self._auth_failures = 0
        self._auth_warned = False
        self.reauth = None  # built in run()

    # -- logging -----------------------------------------------------------
    def _log(self, msg: str) -> None:
        if not self.cfg.quiet:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()

    def _vlog(self, msg: str) -> None:
        if self.cfg.verbose and not self.cfg.quiet:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()

    # -- enqueue helpers ---------------------------------------------------
    def _record_discovery(self, url: str, source: str, depth: int, referrer: str,
                          note: str, is_api: Optional[bool] = None) -> None:
        key = (url, note)
        if key in self._discovery_seen:
            return
        self._discovery_seen.add(key)
        self.out.write(Result(
            url=url, source=source, depth=depth, referrer=referrer,
            is_api=extract.looks_like_api(url) if is_api is None else is_api,
            params=extract.param_names(url), note=note))

    async def _enqueue_link(self, raw: str, base: Optional[str], depth: int, referrer: str,
                            source: str = "html") -> None:
        url = self.scope.normalize(raw, base)
        if not url:
            return
        if self.scope.is_asset(url) and not self.cfg.include_assets:
            return
        if self.scope.in_scope(url):
            await self.frontier.add(Task(url=url, method="GET", depth=depth,
                                         referrer=referrer, source=source))

    async def _enqueue_js(self, raw: str, base: Optional[str], depth: int, referrer: str) -> None:
        url = self.scope.normalize(raw, base)
        if not url:
            return
        self.out.add_js(url)
        # Fetch JS regardless of host (first-party bundles often live on a CDN),
        # but only to mine it — discovered endpoints are re-scoped to the target.
        await self.frontier.add(Task(url=url, method="GET", depth=depth,
                                     referrer=referrer, source="js"))

    async def _enqueue_endpoint(self, raw: str, base: Optional[str], depth: int,
                                referrer: str, source: str) -> None:
        cls = extract.classify_endpoint(raw)
        if cls == "reject":
            return
        cands = set()
        n = self.scope.normalize(raw, base)
        if n:
            cands.add(n)
        if raw.startswith("/") and not raw.startswith("//") and self.scope.primary_origin:
            n2 = self.scope.normalize(raw, self.scope.primary_origin)
            if n2:
                cands.add(n2)
        for url in cands:
            if self.scope.is_asset(url) and not self.cfg.include_assets:
                continue
            if not self.scope.in_scope(url):
                self._record_discovery(url, source, depth, referrer, "out-of-scope")
                continue
            if cls == "strong" or (cls == "weak" and
                                   (self.cfg.fetch_candidates or self.scope.is_js(url))):
                await self.frontier.add(Task(url=url, method="GET", depth=depth,
                                             referrer=referrer, source=source))
            else:
                # weak, in-scope, not auto-fetched -> record as a candidate
                self.out.add_candidate(url)
                self._record_discovery(url, source, depth, referrer, "candidate")

    # -- response processing ----------------------------------------------
    async def _process(self, task: Task, resp) -> None:
        ct = (resp.headers.get("content-type") or "").lower()
        final_url = str(resp.url)
        body = resp.content if hasattr(resp, "content") else b""
        is_api = extract.looks_like_api(final_url, ct)

        result = Result(
            url=final_url, method=task.method, status=resp.status_code,
            content_type=ct.split(";")[0] or None, length=len(body),
            source=task.source, depth=task.depth, referrer=task.referrer,
            is_api=is_api, params=extract.param_names(final_url),
            redirected_to=(final_url if str(task.url) != final_url else None),
        )

        if len(body) > MAX_TEXT_BYTES:
            self.out.write(result)
            return

        is_html = "html" in ct or task.source == "html"
        is_js = ("javascript" in ct or "ecmascript" in ct or self.scope.is_js(final_url)
                 or task.source == "js")
        is_json = "json" in ct or (body[:1] in (b"{", b"[") and "javascript" not in ct)
        is_text = is_html or is_js or is_json or "text" in ct or "xml" in ct

        text = body.decode("utf-8", "replace") if is_text else ""

        if is_html and "html" in ct:
            links, js_urls, scripts, params, title = extract.extract_html(body)
            result.title = title
            if params:
                result.params = sorted(set(result.params) | set(params))
            if final_url not in self._html_seen and self.scope.in_scope(final_url):
                self._html_seen.add(final_url)
                self.html_pages.append(final_url)
            for raw in links:
                await self._enqueue_link(raw, final_url, task.depth + 1, final_url)
            for raw in js_urls:
                await self._enqueue_js(raw, final_url, task.depth + 1, final_url)
            for blob in scripts:
                for raw in extract.extract_js(blob):
                    await self._enqueue_endpoint(raw, final_url, task.depth + 1, final_url, "js")
        elif is_js:
            for raw in extract.extract_js(text):
                await self._enqueue_endpoint(raw, final_url, task.depth + 1, final_url, "js")
        elif is_json:
            result.is_api = True
            for raw in extract.extract_json(body):
                await self._enqueue_endpoint(raw, final_url, task.depth + 1, final_url, "json")

        if self.cfg.scan_secrets and is_text and text:
            self._scan_secrets(text, final_url)

        self.out.write(result)

    async def _fetch(self, task: Task):
        """Fetch with mid-crawl re-auth: on a dead session, re-authenticate once
        (deduped across workers) and retry the request with fresh credentials."""
        gen = self.reauth.generation if self.reauth else 0
        resp = await self.http.request(task.method, task.url)
        if resp is None:
            return None
        failure, dead = self._auth_signal(task, resp)
        if failure:
            self._record_auth_failure()
        if dead and self.reauth and self.reauth.enabled:
            if await self.reauth.refresh(gen):
                retry = await self.http.request(task.method, task.url)
                if retry is not None:
                    resp = retry
        return resp

    def _auth_signal(self, task: Task, resp) -> Tuple[bool, bool]:
        """Return (counts_as_failure, session_dead) for an authenticated response."""
        if not self._authed:
            return (False, False)
        final_url = str(resp.url)
        login_redirect = (str(task.url) != final_url) and bool(_LOGIN_RE.search(final_url))
        failure = resp.status_code in (401, 403) or login_redirect
        dead = resp.status_code == 401 or login_redirect
        return (failure, dead)

    def _record_auth_failure(self) -> None:
        self._auth_failures += 1
        if self._auth_warned:
            return
        if self.reauth and self.reauth.enabled:
            return  # re-auth handles recovery and logs separately
        if self._auth_failures >= self.cfg.auth_fail_threshold:
            self._auth_warned = True
            self._log(f"[!] WARNING: {self._auth_failures} authenticated requests returned "
                      "401/403 or redirected to login — your session may be expired or the "
                      "token isn't being applied (check --storage-state / --bearer / cookies, "
                      "or set --login-url / --reauth-command to auto-recover).")

    def _scan_secrets(self, text: str, url: str) -> None:
        for f in secrets.scan(text, redact=self.cfg.redact_secrets):
            key = (f["type"], f["match"])
            if key in self._secret_seen:
                continue
            self._secret_seen.add(key)
            f["url"] = url
            self.out.write_secret(f)
            self._vlog(f"  [secret:{f['confidence']}] {f['type']} @ {url}")

    # -- workers -----------------------------------------------------------
    async def _worker(self, wid: int) -> None:
        while True:
            task = await self.frontier.get()
            try:
                resp = await self._fetch(task)
                if resp is not None:
                    self._fetched += 1
                    await self._process(task, resp)
                    self._vlog(f"  [{resp.status_code}] {task.method} {task.url}")
                    if not self.cfg.quiet and self._fetched % 25 == 0:
                        self._log(f"[*] fetched {self._fetched} | queued {self.frontier.queued} "
                                  f"| urls {len(self.out.urls)} | api {len(self.out.api)} "
                                  f"| secrets {self.out.secrets_count}")
                else:
                    self._vlog(f"  [ERR] {task.method} {task.url}")
            except Exception as exc:  # never let one task kill a worker
                self._vlog(f"  [EXC] {task.url}: {exc}")
            finally:
                self.frontier.task_done()

    async def _drain(self) -> None:
        workers = [asyncio.ensure_future(self._worker(i)) for i in range(self.cfg.concurrency)]
        try:
            await self.frontier.join()
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    # -- seeding -----------------------------------------------------------
    def _origins(self) -> Set[str]:
        origins = set()
        for s in self.cfg.seeds:
            sp = urlsplit(s)
            if sp.scheme and sp.netloc:
                origins.add(f"{sp.scheme}://{sp.netloc}")
        for _, url in self.cfg.import_entries:
            sp = urlsplit(url)
            host = sp.netloc.split("@")[-1].split(":")[0]
            if sp.scheme and sp.netloc and self.scope.host_in_scope(host):
                origins.add(f"{sp.scheme}://{sp.netloc}")
        return origins

    async def _seed(self) -> None:
        for s in self.cfg.seeds:
            url = self.scope.normalize(s)
            if url:
                await self.frontier.add(Task(url=url, method="GET", depth=0, source="seed"))
        await self._seed_imports()
        if self.cfg.urlfinder:
            await self._seed_urlfinder()
        if self.cfg.crawl_sitemap or self.cfg.respect_robots:
            await self._seed_robots_sitemap()

    async def _seed_imports(self) -> None:
        if not self.cfg.import_entries:
            return
        n_in = 0
        for method, url in self.cfg.import_entries:
            n = self.scope.normalize(url)
            if not n:
                continue
            if self.scope.in_scope(n):
                if method != "GET":
                    self._record_discovery(n, "imported", 0, "import",
                                           f"imported-{method.lower()}",
                                           is_api=extract.looks_like_api(n))
                if await self.frontier.add(Task(url=n, method="GET", depth=0,
                                                referrer="import", source="imported")):
                    n_in += 1
            else:
                self._record_discovery(n, "imported", 0, "import", "out-of-scope")
        self._log(f"[*] imported {len(self.cfg.import_entries)} captured request(s), "
                  f"{n_in} in-scope queued")

    async def _seed_urlfinder(self) -> None:
        from . import passive
        domains = sorted(self.scope.reg_domains)
        if not domains:
            return
        self._log(f"[*] urlfinder: passive URL discovery over {len(domains)} domain(s)")
        loop = asyncio.get_event_loop()
        urls = await loop.run_in_executor(
            None, passive.run_urlfinder, domains, self.cfg.urlfinder_path)
        if urls is None:
            self._log("[!] urlfinder binary not found — skipping "
                      "(install: go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest)")
            return
        added = 0
        for u in urls:
            n = self.scope.normalize(u)
            if n and self.scope.in_scope(n):
                if self.scope.is_asset(n) and not self.cfg.include_assets:
                    continue
                if await self.frontier.add(Task(url=n, method="GET", depth=1,
                                                referrer="urlfinder", source="passive")):
                    added += 1
        self._log(f"[+] urlfinder: {len(urls)} URLs found, {added} in-scope queued")

    async def _seed_robots_sitemap(self) -> None:
        for origin in self._origins():
            resp = await self.http.request("GET", origin + "/robots.txt")
            if not resp or resp.status_code >= 400:
                continue
            for line in resp.text.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("sitemap:") and self.cfg.crawl_sitemap:
                    await self._seed_sitemap(line.split(":", 1)[1].strip())
                elif low.startswith("disallow:") or low.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        await self._enqueue_link(path, origin, 1, origin + "/robots.txt", "robots")

    async def _seed_sitemap(self, url: str, depth: int = 0) -> None:
        if url in self._sitemap_seen or depth > 5 or len(self._sitemap_seen) > 50:
            return
        self._sitemap_seen.add(url)
        resp = await self.http.request("GET", url)
        if not resp or resp.status_code >= 400:
            return
        for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text, re.IGNORECASE):
            loc = m.group(1).strip()
            if loc.endswith(".xml"):
                await self._seed_sitemap(loc, depth + 1)
            else:
                await self._enqueue_link(loc, url, 1, url, "sitemap")

    # -- API-doc / GraphQL discovery --------------------------------------
    async def _discover_api_docs(self) -> None:
        found = 0
        for origin in self._origins():
            for path in apidocs.SPEC_PATHS:
                url = origin + path
                resp = await self.http.request("GET", url)
                if not resp or resp.status_code != 200:
                    continue
                ct = (resp.headers.get("content-type") or "").lower()
                if "json" not in ct and resp.content[:1] not in (b"{", b"["):
                    continue
                try:
                    spec = json.loads(resp.content)
                except Exception:
                    continue
                if not apidocs.is_openapi(spec):
                    continue
                eps = apidocs.parse_openapi(spec, origin)
                self._record_discovery(url, "openapi", 1, origin, "openapi-spec", is_api=True)
                for ep in eps:
                    self.out.write(Result(url=ep["url"], method=ep["method"], source="openapi",
                                          depth=1, referrer=url, is_api=True, params=ep["params"],
                                          note="from-openapi"))
                    if (ep["method"] == "GET" and "{" not in ep["url"]
                            and self.scope.in_scope(ep["url"])):
                        await self.frontier.add(Task(url=ep["url"], method="GET", depth=1,
                                                     referrer=url, source="openapi"))
                found += 1
                self._log(f"[+] OpenAPI/Swagger spec found: {url} -> {len(eps)} endpoints")
        if not found:
            self._vlog("  [api-docs] no OpenAPI/Swagger spec found")

    async def _discover_graphql(self) -> None:
        candidates: Set[str] = set()
        for origin in self._origins():
            for p in apidocs.GRAPHQL_PATHS:
                candidates.add(origin + p)
        for u in list(self.out.urls):
            if "graphql" in u.lower() or u.lower().rstrip("/").endswith("/gql"):
                candidates.add(u)
        for url in candidates:
            if not self.scope.in_scope(url):
                continue
            resp = await self.http.post_json(url, apidocs.INTROSPECTION_QUERY)
            if not resp or resp.status_code >= 400:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            if not apidocs.has_introspection(data):
                continue
            summary = apidocs.summarize_schema(data)
            summary["endpoint"] = url
            self.out.write_graphql(summary)
            self.out.write(Result(url=url, method="POST", source="graphql", depth=1,
                                  is_api=True, note="graphql-introspection-enabled"))
            self._log(f"[+] GraphQL introspection ENABLED: {url} "
                      f"({len(summary.get('queries', []))} queries, "
                      f"{len(summary.get('mutations', []))} mutations)")

    # -- render phase ------------------------------------------------------
    async def _render_phase(self, pages=None, drain: bool = True) -> None:
        from .browser import BrowserRenderer, PlaywrightUnavailable
        source_pages = (self.cfg.seeds + self.html_pages) if pages is None else pages
        norm: List[str] = []
        seen = set()
        for u in source_pages:
            n = self.scope.normalize(u)
            if n and n not in seen and n not in self._rendered:
                seen.add(n)
                norm.append(n)
            if len(norm) >= self.cfg.render_pages:
                break
        if not norm:
            return
        self._log(f"[*] render phase: {len(norm)} page(s) via headless Chromium"
                  + (" (stealth)" if self.cfg.stealth else ""))
        try:
            async with BrowserRenderer(self.cfg) as br:
                for i, url in enumerate(norm, 1):
                    self._rendered.add(url)
                    captured, dom_links = await br.render(url)
                    self._vlog(f"  [render {i}/{len(norm)}] {url} "
                               f"({len(captured)} requests, {len(dom_links)} links)")
                    for raw in dom_links:
                        await self._enqueue_link(raw, url, 1, url, "render")
                    for req in captured:
                        rtype = req.get("resource_type")
                        u = req.get("url", "")
                        if rtype in ("xhr", "fetch", "document", "script") or extract.looks_like_api(u):
                            await self._enqueue_endpoint(u, url, 1, url, "render")
        except PlaywrightUnavailable as exc:
            self._log(f"[!] {exc}")
            return
        if drain:
            await self._drain()

    # -- public ------------------------------------------------------------
    async def run(self) -> dict:
        self._authed = bool(self.cfg.headers or self.cfg.cookies or
                            self.cfg.bearer or self.cfg.storage_state)
        mode = "authenticated" if self._authed else "unauthenticated"
        self._log(f"[*] arachne starting | {mode} | seeds={len(self.cfg.seeds)} "
                  f"| concurrency={self.cfg.concurrency} | depth={self.cfg.max_depth} "
                  f"| render={'on' if self.cfg.render else 'off'}"
                  + (f" | proxy={self.cfg.proxy}" if self.cfg.proxy else ""))
        if self.cfg.token_bridged:
            self._log("[*] bridged Authorization token from storage_state localStorage "
                      "into the static engine")
        # build loop-bound objects now that the event loop is running
        self.frontier = Frontier(self.cfg, self.scope)
        self.http = HttpClient(self.cfg)
        if self.cfg.impersonate:
            self._log(f"[*] TLS impersonation: {self.cfg.impersonate} (curl_cffi backend)")
        if self.cfg.per_host_concurrency:
            self._log(f"[*] per-host concurrency cap: {self.cfg.per_host_concurrency}")
        from .reauth import ReAuth
        self.reauth = ReAuth(self.cfg, self.http, self._log)
        if self.reauth.enabled:
            self._log("[*] re-auth armed — will recover the session on 401/login-redirect "
                      f"(max {self.cfg.reauth_max} attempts)")
        try:
            await self._seed()
            if self.cfg.browser_first:
                self._log("[*] browser-first: rendering seeds before the static crawl")
                await self._render_phase(pages=list(self.cfg.seeds), drain=False)
            await self._drain()
            if self.cfg.api_docs:
                await self._discover_api_docs()
            if self.cfg.graphql:
                await self._discover_graphql()
            await self._drain()
            if self.cfg.render:
                await self._render_phase()
        finally:
            self.out.auth_failures = self._auth_failures
            self.out.reauths = self.reauth.reauths if self.reauth else 0
            await self.http.aclose()
            summary = self.out.close()
        self._log(f"[+] done | fetched {self._fetched} | urls {summary['unique_urls']} "
                  f"| api {summary['api_endpoints']} | openapi {summary['openapi_endpoints']} "
                  f"| graphql {summary['graphql_endpoints']} | js {summary['js_files']} "
                  f"| params {summary['params']} | candidates {summary['candidates']} "
                  f"| secrets {summary['secrets']}"
                  + (f" | auth-failures {self._auth_failures}" if self._auth_failures else "")
                  + (f" | reauths {summary['reauths']}" if summary.get('reauths') else ""))
        self._log(f"[+] output written to: {self.cfg.output_dir}/")
        return summary
