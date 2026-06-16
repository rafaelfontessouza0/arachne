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
from . import importers, external
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
    g.add_argument("--no-auth-preflight", action="store_true",
                   help="skip the pre-crawl check that verifies the session is actually authenticated")

    # passive import / seeding
    g = p.add_argument_group("passive import / seeding")
    g.add_argument("--har", metavar="FILE", help="seed from a HAR capture")
    g.add_argument("--postman", metavar="FILE", help="seed from a Postman collection")
    g.add_argument("--burp-xml", metavar="FILE", help="seed from a Burp Suite XML export")
    g.add_argument("--burp-import", metavar="FILE",
                   help="seed from any exported Burp result (XML site-map, or JSON issues/REST result)")
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

    # external-tool orchestration
    g = p.add_argument_group("external-tool orchestration")
    g.add_argument("--check-tools", action="store_true",
                   help="list orchestrated tools, what's installed, and how to install the rest, then exit")
    g.add_argument("--fetch-wordlists", nargs="?", const="", metavar="DIR",
                   help="shallow-clone SecLists for richer fuzzing (default ~/.arachne/wordlists/SecLists), then exit")
    g.add_argument("--enum-tool", action="append", default=[], metavar="NAME",
                   choices=external.known_tools(),
                   help="orchestrate a specific tool (repeatable): "
                        + ", ".join(external.known_tools()))
    g.add_argument("--all-tools", action="store_true",
                   help="orchestrate every installed tool (discovery crawlers + passive + active fuzzers)")
    g.add_argument("--tool-path", action="append", default=[], metavar="NAME=PATH",
                   help="override a tool's binary path, e.g. --tool-path katana=/opt/katana (repeatable)")
    # discovery crawlers / passive archives (no --fuzz needed)
    g.add_argument("--katana", action="store_true", help="JS-aware crawl via katana")
    g.add_argument("--gau", action="store_true", help="passive URLs via gau (Wayback/CC/OTX/URLScan)")
    # active enumeration (gated behind --fuzz)
    g.add_argument("--fuzz", action="store_true",
                   help="run the active enumeration phase (directory + parameter discovery via ffuf + arjun)")
    g.add_argument("--fuzz-dirs", action="store_true",
                   help="directory/content discovery via ffuf (implies --fuzz)")
    g.add_argument("--fuzz-params", action="store_true",
                   help="parameter discovery via arjun (implies --fuzz)")
    g.add_argument("--fuzz-wordlist", metavar="FILE",
                   help="content wordlist for ffuf/feroxbuster (default: SecLists if found, else a vendored starter)")
    g.add_argument("--param-wordlist", metavar="FILE",
                   help="parameter wordlist for arjun (default: arjun's built-in)")
    g.add_argument("--seclists-root", metavar="DIR",
                   help="path to a SecLists checkout for wordlist resolution")
    g.add_argument("--ffuf-path", default="ffuf", metavar="PATH", help="path to the ffuf binary")
    g.add_argument("--arjun-path", default="arjun", metavar="PATH", help="path to the arjun binary")
    g.add_argument("--tool-timeout", type=int, default=180, metavar="SEC",
                   help="per-tool subprocess timeout (default 180)")
    g.add_argument("--fuzz-max-endpoints", type=int, default=50, metavar="N",
                   help="max in-scope endpoints to probe for parameters (default 50)")
    g.add_argument("--tool-max-results", type=int, default=0, metavar="N",
                   help="cap results folded back per tool (0 = unlimited)")

    # stateful scanners (Burp Pro / OWASP ZAP)
    g = p.add_argument_group("scanners (Burp Pro REST API / OWASP ZAP daemon)")
    g.add_argument("--zap", action="store_true",
                   help="drive a ZAP daemon: spider the target and fold its URLs into the crawl")
    g.add_argument("--zap-url", default="http://127.0.0.1:8080", metavar="URL",
                   help="ZAP daemon API base (default http://127.0.0.1:8080)")
    g.add_argument("--zap-api-key", metavar="KEY", help="ZAP API key (if the daemon requires one)")
    g.add_argument("--zap-launch", action="store_true",
                   help="launch a ZAP daemon (via --zap-path) if none is reachable")
    g.add_argument("--zap-path", default="zap.sh", metavar="PATH",
                   help="ZAP launcher used by --zap-launch (default zap.sh)")
    g.add_argument("--zap-ajax", action="store_true",
                   help="also run ZAP's AJAX spider (better SPA coverage)")
    g.add_argument("--burp-scan", action="store_true",
                   help="drive a Burp Pro authenticated scan via the REST API; fold issue URLs in")
    g.add_argument("--burp-api-url", default="http://127.0.0.1:1337", metavar="URL",
                   help="Burp Pro REST API base (default http://127.0.0.1:1337)")
    g.add_argument("--burp-api-key", metavar="KEY", help="Burp Pro REST API key")
    g.add_argument("--burp-config", metavar="NAME",
                   help="Burp named scan configuration (e.g. 'Crawl and Audit - Lightweight')")
    g.add_argument("--burp-headless", action="store_true",
                   help="launch Burp Pro headless (no REST API) and route the whole crawl through "
                        "its proxy; Burp records/scans into a saved .burp project")
    g.add_argument("--burp-jar", metavar="PATH",
                   help="path to burpsuite_pro.jar for --burp-headless (else auto-detected)")
    g.add_argument("--burp-headless-port", type=int, default=8080, metavar="PORT",
                   help="port arachne expects Burp's proxy on (default 8080 is Burp's built-in "
                        "listener; other ports need a --burp-config-file defining that listener)")
    g.add_argument("--burp-project", metavar="FILE",
                   help="Burp .burp project file for --burp-headless (else <out>/burp-headless.burp)")
    g.add_argument("--burp-config-file", action="append", default=[], metavar="FILE",
                   help="Burp project config(s) for --burp-headless (scope/auth/live-audit; repeatable)")

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


def print_tool_catalog() -> None:
    """Render the orchestrated-tool inventory: what's installed and how to get the rest."""
    rows = external.tool_catalog()
    name_w = max(len(r["name"]) for r in rows)
    cat_w = max(len(r["category"]) for r in rows)
    print("arachne — orchestrated external tools\n")
    print(f"  {'tool'.ljust(name_w)}  {'kind'.ljust(cat_w)}  status      purpose")
    print(f"  {'-' * name_w}  {'-' * cat_w}  ----------  -------")
    missing = []
    for r in rows:
        mark = "[ok]     " if r["available"] else "[MISSING]"
        print(f"  {r['name'].ljust(name_w)}  {r['category'].ljust(cat_w)}  {mark}  {r['purpose']}")
        if not r["available"]:
            missing.append(r)
    if missing:
        print("\ninstall the missing tools:")
        for r in missing:
            print(f"  {r['name']}:  {r['install']}")
    else:
        print("\nall orchestrated tools are installed.")

    # wordlist status — what ffuf/feroxbuster will use out of the box
    cfg = Config(seeds=["https://example.com"])
    content = external.resolve_content_wordlist(cfg)
    seclists = external.seclists_content(cfg)
    print("\nwordlists:")
    print(f"  default content list:  {content or '(none)'}")
    print(f"  SecLists:              {'found: ' + seclists if seclists else 'not found — run: arachne --fetch-wordlists'}")
    print(f"  vendored shortcuts:    " + ", ".join("@" + k for k in external.VENDORED_WORDLISTS))

    print("\nselect tools with --enum-tool NAME (repeatable), --all-tools, or the\n"
          "convenience flags --katana/--gau (discovery) and --fuzz/--fuzz-dirs/--fuzz-params (active).")


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

    # Resolve which external tools to drive. --enum-tool selects explicitly;
    # --all-tools selects everything; --katana/--gau/--fuzz-dirs/--fuzz-params and
    # --urlfinder are conveniences; bare --fuzz drives the default active pair.
    # fuzz (the active phase) is on iff any *active* tool ends up selected.
    enum_tools = list(dict.fromkeys(ns.enum_tool))
    if ns.all_tools:
        enum_tools = list(external.known_tools())
    for flag, tool in ((ns.katana, "katana"), (ns.gau, "gau"),
                       (ns.fuzz_dirs, "ffuf"), (ns.fuzz_params, "arjun"),
                       (ns.urlfinder, "urlfinder")):
        if flag and tool not in enum_tools:
            enum_tools.append(tool)
    if ns.fuzz and not any(external.is_active(t) for t in enum_tools):
        for t in ("ffuf", "arjun"):
            if t not in enum_tools:
                enum_tools.append(t)
    fuzz = bool(ns.fuzz or any(external.is_active(t) for t in enum_tools))

    tool_paths = {}
    for item in ns.tool_path:
        if "=" in item:
            k, v = item.split("=", 1)
            if k.strip() and v.strip():
                tool_paths[k.strip()] = v.strip()

    scanners = []
    if ns.zap:
        scanners.append("zap")
    if ns.burp_scan:
        scanners.append("burp")

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
        auth_preflight=not ns.no_auth_preflight,
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
        fuzz=fuzz,
        external_tools=enum_tools,
        tool_paths=tool_paths,
        scanners=scanners,
        zap_url=ns.zap_url,
        zap_api_key=ns.zap_api_key,
        zap_path=ns.zap_path,
        zap_launch=ns.zap_launch,
        zap_ajax=ns.zap_ajax,
        burp_api_url=ns.burp_api_url,
        burp_api_key=ns.burp_api_key,
        burp_config_name=ns.burp_config,
        burp_headless=ns.burp_headless,
        burp_jar=ns.burp_jar,
        burp_headless_port=ns.burp_headless_port,
        burp_project=ns.burp_project,
        burp_config_files=list(ns.burp_config_file),
        fuzz_wordlist=ns.fuzz_wordlist,
        param_wordlist=ns.param_wordlist,
        seclists_root=ns.seclists_root,
        ffuf_path=ns.ffuf_path,
        arjun_path=ns.arjun_path,
        tool_timeout=ns.tool_timeout,
        tool_max_results=ns.tool_max_results,
        fuzz_max_endpoints=ns.fuzz_max_endpoints,
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

    imp = importers.load_any(har=ns.har, postman=ns.postman,
                             burp=ns.burp_xml or ns.burp_import)
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
    if ns.check_tools:
        print_tool_catalog()
        return 0
    if ns.fetch_wordlists is not None:
        dest = ns.fetch_wordlists or None
        print(f"[*] fetching SecLists into {dest or external.DEFAULT_SECLISTS_DEST} (this can take a while)...")
        ok, msg = external.fetch_seclists(dest)
        print(("[+] " if ok else "[!] ") + msg)
        if ok:
            print("[*] arachne auto-detects this checkout; fuzz with: arachne -u <URL> --fuzz")
        return 0 if ok else 1
    has_import = bool(ns.har or ns.postman or ns.burp_xml or ns.burp_import)
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
