"""Command-line interface."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import List

from . import __version__
from .config import Config, DEFAULT_SKIP_EXT, DEFAULT_USER_AGENT
from .auth import (parse_header_args, parse_cookie_arg, load_auth_json, apply_auth)
from . import importers
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
                   help="max requests/second per host (0 = unlimited)")
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
    g.add_argument("--impersonate", metavar="BROWSER",
                   help="impersonate a browser TLS/JA3 fingerprint via curl_cffi "
                        "(e.g. chrome124, safari17_0) — for WAF'd targets; needs curl_cffi")
    g.add_argument("--host-concurrency", type=int, default=0, metavar="N",
                   help="max concurrent requests per host (0 = global cap only)")

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
    g.add_argument("--auth-header", default="Authorization", metavar="NAME",
                   help="header name for --bearer / bridged token (default Authorization)")
    g.add_argument("--auth-scheme", default="Bearer", metavar="SCHEME",
                   help="auth scheme prefix (default 'Bearer'; pass '' for a raw token)")
    g.add_argument("--auth-token-key", metavar="KEY",
                   help="localStorage key holding the token (default: auto-detect)")
    g.add_argument("--no-auto-token", action="store_true",
                   help="don't bridge a localStorage token from --storage-state to the static engine")

    # passive import / seeding
    g = p.add_argument_group("passive import / seeding")
    g.add_argument("--har", metavar="FILE", help="seed from a HAR capture")
    g.add_argument("--postman", metavar="FILE", help="seed from a Postman collection")
    g.add_argument("--burp-xml", metavar="FILE", help="seed from a Burp Suite XML export")
    g.add_argument("--import-auth", action="store_true",
                   help="also adopt cookies + Authorization captured in the import")
    g.add_argument("--urlfinder", action="store_true",
                   help="run projectdiscovery/urlfinder for passive URL discovery (needs the binary)")
    g.add_argument("--urlfinder-path", default="urlfinder", metavar="PATH",
                   help="path to the urlfinder binary (default: urlfinder on PATH)")

    # re-authentication
    g = p.add_argument_group("re-authentication (recover an expired session mid-crawl)")
    g.add_argument("--login-url", metavar="URL",
                   help="login page URL — enables browser-based re-auth on session death")
    g.add_argument("--login-user", metavar="USER", help="username/email to fill on the login form")
    g.add_argument("--login-pass", metavar="PASS", help="password to fill on the login form")
    g.add_argument("--login-user-selector", metavar="CSS", help="CSS selector for the username field")
    g.add_argument("--login-pass-selector", metavar="CSS", help="CSS selector for the password field")
    g.add_argument("--login-submit-selector", metavar="CSS", help="CSS selector for the submit button")
    g.add_argument("--login-success", metavar="SEL|URL",
                   help="selector or URL substring that signals a successful login")
    g.add_argument("--login-recipe", metavar="FILE",
                   help="JSON login recipe (see examples/login.example.json)")
    g.add_argument("--reauth-command", metavar="CMD",
                   help="shell command that prints fresh auth JSON {cookies,headers,bearer}")
    g.add_argument("--reauth-max", type=int, default=3, metavar="N",
                   help="max re-auth attempts before giving up (default 3)")

    # discovery
    g = p.add_argument_group("discovery / extraction")
    g.add_argument("--no-api-docs", action="store_true",
                   help="skip OpenAPI/Swagger spec probing + parsing")
    g.add_argument("--no-graphql", action="store_true",
                   help="skip GraphQL introspection probing")
    g.add_argument("--no-secrets", action="store_true",
                   help="skip secret scanning of response bodies")
    g.add_argument("--show-secrets", action="store_true",
                   help="write secrets unredacted (default: redacted)")
    g.add_argument("--fetch-candidates", action="store_true",
                   help="also fetch low-confidence mined endpoints (candidates.txt)")

    # render
    g = p.add_argument_group("browser render (SPA / XHR capture)")
    g.add_argument("--render", action="store_true",
                   help="render pages with headless Chromium and capture XHR/fetch (needs playwright)")
    g.add_argument("--render-pages", type=int, default=50, help="max pages to render (default 50)")
    g.add_argument("--render-wait", type=int, default=2500,
                   help="ms to wait after load for XHRs to fire (default 2500)")
    g.add_argument("--no-scroll", action="store_true", help="disable auto-scroll during render")
    g.add_argument("--headful", action="store_true", help="show the browser window")
    g.add_argument("--browser-first", action="store_true",
                   help="render seed pages with the browser BEFORE the static crawl (SPA-first)")
    g.add_argument("--stealth", action="store_true",
                   help="apply playwright-stealth during render/login (needs playwright-stealth)")

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

    recipe = {}
    if ns.login_recipe:
        with open(ns.login_recipe, "r", encoding="utf-8") as fh:
            recipe = json.load(fh)

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
        impersonate=ns.impersonate,
        per_host_concurrency=ns.host_concurrency,
        headers=parse_header_args(ns.header),
        cookies=parse_cookie_arg(ns.cookie),
        cookies_file=ns.cookies_file,
        bearer=ns.bearer,
        storage_state=ns.storage_state,
        auth_header=ns.auth_header,
        auth_scheme=ns.auth_scheme,
        auto_token=not ns.no_auto_token,
        auth_token_key=ns.auth_token_key,
        login_url=ns.login_url or recipe.get("url"),
        login_username=ns.login_user or recipe.get("username"),
        login_password=ns.login_pass or recipe.get("password"),
        login_user_selector=ns.login_user_selector or recipe.get("user_selector"),
        login_pass_selector=ns.login_pass_selector or recipe.get("pass_selector"),
        login_submit_selector=ns.login_submit_selector or recipe.get("submit_selector"),
        login_success=ns.login_success or recipe.get("success"),
        login_wait=recipe.get("wait", 3000),
        reauth_command=ns.reauth_command or recipe.get("command"),
        reauth_max=ns.reauth_max,
        urlfinder=ns.urlfinder,
        urlfinder_path=ns.urlfinder_path,
        fetch_candidates=ns.fetch_candidates,
        scan_secrets=not ns.no_secrets,
        redact_secrets=not ns.show_secrets,
        api_docs=not ns.no_api_docs,
        graphql=not ns.no_graphql,
        render=ns.render,
        render_pages=ns.render_pages,
        render_wait=ns.render_wait,
        render_scroll=not ns.no_scroll,
        headful=ns.headful,
        browser_first=ns.browser_first,
        stealth=ns.stealth,
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

    imp = importers.load_any(har=ns.har, postman=ns.postman, burp=ns.burp_xml)
    if imp:
        cfg.import_entries = imp.entries
        if ns.import_auth:
            for k, v in imp.cookies.items():
                cfg.cookies.setdefault(k, v)
            for k, v in imp.headers.items():
                cfg.headers.setdefault(k, v)

    apply_auth(cfg)
    return cfg


def main(argv: List[str] = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    has_import = bool(ns.har or ns.postman or ns.burp_xml)
    if not ns.url and not ns.list and not (has_import and ns.scope):
        parser.error("provide -u/-l, or an import (--har/--postman/--burp-xml) together with --scope")
    cfg = config_from_args(ns)
    if not cfg.seeds and not cfg.import_entries:
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
