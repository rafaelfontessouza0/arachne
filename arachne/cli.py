"""Command-line interface."""
from __future__ import annotations

import argparse
import asyncio
import sys
from typing import List

from . import __version__
from .config import Config, DEFAULT_SKIP_EXT, DEFAULT_USER_AGENT
from .auth import (parse_header_args, parse_cookie_arg, load_auth_json, apply_auth)
from .crawler import Crawler

BANNER = r"""
  __ _ _ __ __ _  ___| |__  _ __   ___
 / _` | '__/ _` |/ __| '_ \| '_ \ / _ \   web + API crawler / spider
| (_| | | | (_| | (__| | | | | | |  __/   authenticated + unauthenticated
 \__,_|_|  \__,_|\___|_| |_|_| |_|\___|   v%s
""" % __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="arachne",
        description="Async web and API crawler/spider for authenticated and unauthenticated recon.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # unauthenticated crawl
  arachne -u https://target.tld -d 3 -o out

  # authenticated crawl with a cookie, through Burp, JS render on
  arachne -u https://target.tld --burp --cookie "session=abc; token=xyz" --render

  # API-focused crawl using a bearer token and a seed list
  arachne -l seeds.txt --bearer "eyJ..." --allow "/api/" -c 40

  # reuse a Playwright login session and render SPA routes
  arachne -u https://target.tld --storage-state state.json --render

output files (in -o dir):
  endpoints.jsonl   every discovered/fetched resource (full detail)
  urls.txt          unique URLs        api.txt    API-looking endpoints
  js.txt            JavaScript bundles params.txt parameter names
  summary.json      run statistics
""")

    # targets
    g = p.add_argument_group("targets")
    g.add_argument("-u", "--url", action="append", default=[], metavar="URL",
                   help="seed URL (repeatable)")
    g.add_argument("-l", "--list", metavar="FILE", help="file with seed URLs (one per line)")
    g.add_argument("--scope", action="append", default=[], metavar="DOMAIN",
                   help="extra in-scope domain (repeatable)")

    # scope
    g = p.add_argument_group("scope")
    g.add_argument("--no-subdomains", action="store_true",
                   help="restrict to exact seed hosts (default: whole registered domain)")
    g.add_argument("--allow", action="append", default=[], metavar="REGEX",
                   help="only crawl URLs matching REGEX (repeatable)")
    g.add_argument("--deny", action="append", default=[], metavar="REGEX",
                   help="never crawl URLs matching REGEX (repeatable)")
    g.add_argument("--include-assets", action="store_true",
                   help="also fetch static assets (css/img/fonts/...)")
    g.add_argument("--no-dedup-params", action="store_true",
                   help="treat differing query values as distinct URLs")

    # budget
    g = p.add_argument_group("budget / traversal")
    g.add_argument("-d", "--depth", type=int, default=3, help="max crawl depth (default 3)")
    g.add_argument("-m", "--max-pages", type=int, default=1000,
                   help="max resources to queue (default 1000)")
    g.add_argument("-c", "--concurrency", type=int, default=20,
                   help="concurrent requests (default 20)")
    g.add_argument("--rate", type=float, default=0.0,
                   help="max requests/second (0 = unlimited)")
    g.add_argument("--delay", type=float, default=0.0, help="fixed delay per request (sec)")
    g.add_argument("-t", "--timeout", type=float, default=20.0, help="request timeout (sec)")
    g.add_argument("--retries", type=int, default=2, help="retries on error/429 (default 2)")

    # safety / methods
    g = p.add_argument_group("safety")
    g.add_argument("--allow-active", action="store_true",
                   help="permit state-changing paths (logout/delete/withdraw/...) — off by default")
    g.add_argument("--respect-robots", action="store_true", help="obey robots.txt Disallow")
    g.add_argument("--no-sitemap", action="store_true", help="do not seed from sitemap.xml")

    # transport
    g = p.add_argument_group("transport")
    g.add_argument("--proxy", metavar="URL", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    g.add_argument("--burp", action="store_true",
                   help="shortcut for --proxy http://127.0.0.1:8080 --insecure")
    g.add_argument("-k", "--insecure", action="store_true", help="ignore TLS certificate errors")
    g.add_argument("-A", "--user-agent", default=DEFAULT_USER_AGENT, help="custom User-Agent")
    g.add_argument("--no-redirects", action="store_true", help="do not follow redirects")

    # auth
    g = p.add_argument_group("authentication")
    g.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                   help="extra request header (repeatable)")
    g.add_argument("-b", "--cookie", metavar="'k=v; k2=v2'", help="cookie header value")
    g.add_argument("--cookies-file", metavar="FILE", help="cookies (JSON map/list or cookies.txt)")
    g.add_argument("--bearer", metavar="TOKEN", help="shortcut for Authorization: Bearer TOKEN")
    g.add_argument("--auth-json", metavar="FILE",
                   help="bundle: {headers,cookies,bearer,storage_state}")
    g.add_argument("--storage-state", metavar="FILE",
                   help="Playwright storage_state json (used by --render and for cookies)")

    # render
    g = p.add_argument_group("browser render (SPA / XHR capture)")
    g.add_argument("--render", action="store_true",
                   help="render pages with headless Chromium and capture XHR/fetch (needs playwright)")
    g.add_argument("--render-pages", type=int, default=50, help="max pages to render (default 50)")
    g.add_argument("--render-wait", type=int, default=2500,
                   help="ms to wait after load for XHRs to fire (default 2500)")
    g.add_argument("--no-scroll", action="store_true", help="disable auto-scroll during render")
    g.add_argument("--headful", action="store_true", help="show the browser window")

    # output
    g = p.add_argument_group("output")
    g.add_argument("-o", "--output", default="arachne-out", help="output directory")
    g.add_argument("-q", "--quiet", action="store_true", help="suppress progress")
    g.add_argument("-v", "--verbose", action="store_true", help="log every request")
    g.add_argument("-V", "--version", action="version", version=f"arachne {__version__}")
    return p


def _read_seed_list(path: str) -> List[str]:
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def config_from_args(ns: argparse.Namespace) -> Config:
    seeds = list(ns.url)
    if ns.list:
        seeds.extend(_read_seed_list(ns.list))
    seeds = [s if "://" in s else "https://" + s for s in seeds]

    proxy = ns.proxy
    insecure = ns.insecure
    if ns.burp:
        proxy = proxy or "http://127.0.0.1:8080"
        insecure = True

    cfg = Config(
        seeds=seeds,
        extra_scope=list(ns.scope),
        include_subdomains=not ns.no_subdomains,
        allow_regex=list(ns.allow),
        deny_regex=list(ns.deny),
        include_assets=ns.include_assets,
        dedup_params=not ns.no_dedup_params,
        concurrency=max(1, ns.concurrency),
        rate=ns.rate,
        delay=ns.delay,
        timeout=ns.timeout,
        retries=ns.retries,
        max_depth=ns.depth,
        max_pages=ns.max_pages,
        allow_active=ns.allow_active,
        respect_robots=ns.respect_robots,
        crawl_sitemap=not ns.no_sitemap,
        proxy=proxy,
        insecure=insecure,
        user_agent=ns.user_agent,
        follow_redirects=not ns.no_redirects,
        headers=parse_header_args(ns.header),
        cookies=parse_cookie_arg(ns.cookie),
        cookies_file=ns.cookies_file,
        bearer=ns.bearer,
        storage_state=ns.storage_state,
        render=ns.render,
        render_pages=ns.render_pages,
        render_wait=ns.render_wait,
        render_scroll=not ns.no_scroll,
        headful=ns.headful,
        output_dir=ns.output,
        quiet=ns.quiet,
        verbose=ns.verbose,
    )

    if ns.auth_json:
        h, c, bearer, storage = load_auth_json(ns.auth_json)
        cfg.headers.update(h)
        cfg.cookies.update(c)
        cfg.bearer = cfg.bearer or bearer
        cfg.storage_state = cfg.storage_state or storage
    apply_auth(cfg)
    return cfg


def main(argv: List[str] = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    if not ns.url and not ns.list:
        parser.error("at least one seed is required (-u URL or -l FILE)")
    cfg = config_from_args(ns)
    if not cfg.seeds:
        parser.error("no valid seeds")
    if not cfg.quiet:
        sys.stderr.write(BANNER + "\n")
    crawler = Crawler(cfg)
    try:
        asyncio.run(crawler.run())
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] interrupted — partial output saved\n")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
