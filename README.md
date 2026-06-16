# arachne

**Authenticated web & API recon crawler — it doesn't replace your toolbox, it _drives_ it.**

`arachne` maps the full reachable surface of a web target — pages **and** APIs —
and is built for the case most crawlers fumble: **authenticated** testing. A fast
`asyncio` + `httpx` engine is the spine. On top of it, arachne carries your
session (cookies **and** `localStorage` JWT), **verifies it's live before
crawling**, **re-authenticates mid-crawl** when it expires, and then
**orchestrates** as many best-of-breed external tools as you have installed —
`katana`, `gau`, `ffuf`, `arjun`, `hakrawler`, `gospider`, **Burp Pro**, **ZAP**
and more — folding every finding into **one** deduplicated, provenance-tagged
result set. Run it with no credentials and it's an unauthenticated crawl, so you
can diff the two surfaces.

### Why arachne

- **Built for authenticated targets** — carries the session as a cookie **and**
  a localStorage JWT, runs a pre-crawl **auth preflight** so a dead token fails
  *loudly* (not silently), **self-heals** the session mid-crawl, and can seed from
  a captured session (HAR / Burp / Postman).
- **Spine + orchestration** — keeps a native crawler **and** drives `katana`,
  `gau`, `waybackurls`, `hakrawler`, `gospider`, `ffuf`, `feroxbuster`, `arjun`,
  `urlfinder` — one unified output with per-tool provenance. `--check-tools` shows
  what's installed; missing tools are skipped, never fatal.
- **Burp & ZAP from the command line** — launch **Burp Pro headless with no REST
  API** and route the whole crawl through it, or drive its REST-API scan; drive a
  **ZAP** daemon's spider; proxy-feed through either; import their exports.
- **API-first** — OpenAPI/Swagger parsing, GraphQL introspection, JS/XHR
  endpoint mining, and headless-Chromium SPA rendering surface the API behind
  modern single-page apps.
- **Safe & polite by default** — `GET`/`HEAD` only, destructive paths denied,
  per-host rate limiting, and browser **TLS/JA3 impersonation** for WAF'd targets.
- **Zero-config** — curated wordlists ship in the box, tools auto-detect on
  `PATH`, and `--fetch-wordlists` pulls SecLists when you want depth.

### Proven in a controlled A/B

Same target (PortSwigger's deliberately-vulnerable `ginandjuice.shop`), same
scope, unauthenticated — **orchestration on vs. the crawl-only baseline**:

| | crawl-only (baseline) | **+ orchestration** |
|---|---|---|
| URLs discovered | 128 | **175**  (+37%) |
| API endpoints | 7 | **18**  (2.6×) |

It surfaced an **`/admin` login panel** (via `ffuf`) plus 10 other endpoints the
passive crawl never linked to. The native crawl spine is byte-for-byte unchanged
between versions — the gain is pure orchestration.

**Pipeline:** seed (URLs · sitemap · HAR/Burp/Postman) → **auth preflight** →
**discovery orchestration** (katana · gau · waybackurls · hakrawler · gospider ·
urlfinder) → optional browser render → async crawl + JS/JSON endpoint mining →
OpenAPI + GraphQL discovery → **active enumeration** (`--fuzz`: ffuf/feroxbuster +
arjun) → secret scan → structured output (`endpoints.jsonl`, `api.txt`, …).

---

## Features

- **Static async crawl** — `httpx` with HTTP/2, configurable concurrency, rate
  limiting, retries/backoff.
- **JS-aware** — mines endpoints from JavaScript bundles and inline scripts
  (LinkFinder-style regex) and walks JSON responses for more URLs.
- **Confidence-filtered** — mined candidates are graded *strong* / *weak* /
  *reject*, so MIME types, module specifiers and version strings don't become
  bogus requests; weak ones land in `candidates.txt` for review.
- **OpenAPI / Swagger discovery** — probes well-known spec paths and, when found,
  parses the spec into every declared path + method + parameter.
- **GraphQL introspection** — probes common GraphQL endpoints with a read-only
  introspection query; dumps the schema to `graphql.json` when it's enabled.
- **Secret detection** — scans HTML/JS/JSON bodies for AWS/GCP keys, JWTs,
  GitHub/Slack/Stripe tokens, private keys, basic-auth URLs → `secrets.jsonl`
  (redacted by default).
- **Render mode** — headless Chromium (Playwright) renders SPA routes,
  auto-scrolls, and records all network requests → real API discovery.
- **API-aware** — flags `/api/`, `/v1/`, `graphql`, `.json`, etc. and writes a
  dedicated `api.txt`.
- **Tool orchestration** — drives best-of-breed external CLIs and folds their
  findings into one unified crawl/output with per-tool provenance: **katana**
  (JS-aware crawl), **gau** / **waybackurls** / **urlfinder** (passive archives),
  **hakrawler** / **gospider** (breadth crawl) for discovery; **ffuf** /
  **feroxbuster** (content) and **arjun** (parameters) for active enumeration
  under `--fuzz`. `--all-tools` runs everything installed; `--check-tools` lists
  what's present and how to install the rest. Missing binaries are skipped, never
  fatal.
- **Active enumeration** — `--fuzz` adds directory/content (ffuf, feroxbuster)
  and hidden-parameter (arjun) discovery; every in-scope hit re-enters the
  frontier so it's re-crawled and re-mined (the compounding loop).
- **Auth preflight** — before crawling, verifies the session is *actually*
  authenticated (a dead cookie/token silently degrades to the public surface);
  raises a loud warning instead of letting findings come up quietly thin.
- **Wordlists included** — curated, lean content/API/param lists ship in the box
  (`@common`, `@api`, `@params`); `arachne --fetch-wordlists` pulls SecLists for
  deep coverage and arachne auto-detects it.
- **Burp Pro & ZAP, driven from the CLI** — `--burp-headless` launches your
  licensed Burp Pro **headless (no REST API)** and routes the whole crawl through
  its proxy into a saved `.burp` project; `--burp-scan` runs an authenticated scan
  over the REST API; `--zap` drives a ZAP daemon's spider (+ AJAX) with the session
  injected. All fold into the unified output. Proxy-feed (`--burp`/`--proxy`) and
  result import (`--burp-import`, XML or JSON) are supported too.
- **Auth, any form** — header / cookie string / cookie file / bearer token /
  `--auth-json` bundle / Playwright `storage_state`.
- **Unified auth** — bridges a `localStorage` JWT from `storage_state` into the
  static engine (so token-in-localStorage SPAs are *actually* authenticated, not
  just the render pass), and **warns when the session expires** mid-crawl.
- **Passive seeding** — import a captured session from **HAR / Postman / Burp**
  (optionally adopting its auth), or run **projectdiscovery/urlfinder** for
  passive URL discovery.
- **Self-healing sessions** — on a `401`/login-redirect mid-crawl,
  re-authenticate automatically (Playwright login recipe or a `--reauth-command`
  hook) and retry the failed request with fresh credentials.
- **Evasion-ready** — impersonate a real browser's **TLS/JA3 fingerprint**
  (`--impersonate chrome124`, via `curl_cffi`) and apply `--stealth` to the
  headless browser, for targets behind Cloudflare/Akamai.
- **Browser-primary mode** — `--browser-first` renders the seeds *before* the
  static crawl, so SPA routes and XHR/API calls are captured up front.
- **Polite** — per-host token-bucket rate limiting (`--rate`) and per-host
  concurrency caps (`--host-concurrency`), not just a global limit.
- **Burp-friendly** — `--burp` routes everything through `127.0.0.1:8080` with
  TLS verification off, in one flag.
- **Scope control** — registered-domain or exact-host scoping, allow/deny
  regex, asset skipping, parameter-aware de-duplication.
- **Safe by default** — `GET`/`HEAD` only, never auto-submits forms, and denies
  destructive paths (`logout`, `delete`, `withdraw`, …) unless `--allow-active`.
- **Clean output** — streamed `endpoints.jsonl` plus `urls.txt`, `api.txt`,
  `js.txt`, `params.txt`, and a `summary.json`.

---

## The crawl spine: 15 tools, reimplemented natively

> **`arachne`'s core crawl/spider engine reimplements these capabilities
> natively in a single Python codebase — it does not shell out for them.** The
> only two from this stack it *uses as libraries* are **httpx** (its HTTP
> engine) and **Playwright** (for the optional `--render` mode). Everything else
> in the table below is rebuilt, not invoked.
>
> For **discovery and active enumeration**, arachne does the opposite — it
> *orchestrates* best-of-breed external tools (katana, gau, waybackurls,
> hakrawler, gospider, ffuf, feroxbuster, arjun, urlfinder) and folds their
> findings back into the same crawl and unified output. Several rows below
> (katana, GoSpider, hakrawler, gau, waybackurls) are therefore both
> reimplemented natively **and** orchestrated — use whichever you have. See
> [External-tool orchestration](#external-tool-orchestration) below. The native
> engine is the spine; orchestration is the reach.

These are the 15 dedicated web + API crawler/spider tools whose capabilities
`arachne` reimplements natively in its crawl spine:

| # | Tool | Category | Covered by | Relationship |
|---|------|----------|------------|--------------|
| 1 | Playwright | dynamic browser crawler | `--render` | **uses** (library) |
| 2 | Puppeteer | dynamic browser crawler | `--render` | reimplemented |
| 3 | Crawlee (PlaywrightCrawler) | dynamic browser crawler | `--render` + async frontier | reimplemented |
| 4 | Katana | dynamic browser crawler | `--render` + `--katana` | reimplemented + **orchestrated** |
| 5 | GoSpider | static spider | core async crawl + `--enum-tool gospider` | reimplemented + **orchestrated** |
| 6 | hakrawler | static spider | core async crawl + `--enum-tool hakrawler` | reimplemented + **orchestrated** |
| 7 | Scrapy | static spider | async crawl + HTML extractor | reimplemented |
| 8 | gau | passive URL collection | `--gau` + sitemap/robots | reimplemented + **orchestrated** |
| 9 | waybackurls | passive URL collection | `--enum-tool waybackurls` | reimplemented + **orchestrated** |
| 10 | subjs | JS URL extraction | JS endpoint miner | reimplemented |
| 11 | getJS | JS URL extraction | JS endpoint miner | reimplemented |
| 12 | LinkFinder | JS endpoint extraction | JS miner (LinkFinder-style regex) | reimplemented |
| 13 | SecretFinder | JS secret extraction | JS / JSON mining | reimplemented |
| 14 | xnLinkFinder | JS endpoint + param extraction | JS miner + param extraction | reimplemented |
| 15 | mantra | JS secret scanning | JS / JSON mining | reimplemented |

### Supporting discovery tools also folded in

- **httpx** → async fetch/validation engine (**used** as a library)
- **katana** → **orchestrated** JS-aware crawl (`--katana` / `--enum-tool katana`)
- **gau / waybackurls** → **orchestrated** passive archive URLs (`--gau` / `--enum-tool waybackurls`)
- **hakrawler / gospider** → **orchestrated** breadth crawl (`--enum-tool …`)
- **ffuf / feroxbuster** → **orchestrated** active directory/content discovery (`--fuzz`)
- **Arjun** → **orchestrated** active parameter discovery (`--fuzz`)
- **projectdiscovery/urlfinder** → **orchestrated** passive URL discovery (`--urlfinder`)
- **chrome-devtools MCP** → `--render` network capture
- **HAR / Postman / Burp** → passive session import (`--har` / `--postman` / `--burp-xml`)
- **Burp Pro / ZAP** → **driven from the CLI** (`--burp-scan` REST API scan /
  `--zap` daemon spider), routed through as a proxy (`--burp` / `--proxy`), or
  result-imported (`--burp-import`). See [Burp Suite & OWASP ZAP](#burp-suite--owasp-zap).

> See [External-tool orchestration](#external-tool-orchestration) for the full
> list, install commands, and `--check-tools`.

> Out of scope by design: vulnerability scanners such as **nuclei**. `arachne`
> is a crawler/spider, not a scanner — feed its `api.txt` / `urls.txt` into the
> scanner of your choice.

## Built with

- **Python 3.9+**, `asyncio`
- **httpx** — async HTTP/2 client
- **selectolax** — fast HTML parsing (falls back to **beautifulsoup4** + **lxml**)
- **tldextract** — scope / registered-domain logic
- **Playwright** — optional, only for `--render`

---

## Install

Requires Python 3.9+.

```bash
git clone https://github.com/rafaelfontessouza0/arachne.git
cd arachne
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt           # core crawler

# optional — only for --render (SPA / XHR capture):
pip install playwright && playwright install chromium

# optional — TLS impersonation (--impersonate) and browser stealth (--stealth):
pip install curl_cffi playwright-stealth

# optional — orchestrated external tools (auto-detected on PATH; install any subset)
go install github.com/projectdiscovery/katana/cmd/katana@latest        # JS-aware crawl
go install github.com/lc/gau/v2/cmd/gau@latest                         # passive archive URLs
go install github.com/tomnomnom/waybackurls@latest                     # passive archive URLs
go install github.com/hakluke/hakrawler@latest                        # breadth crawl
go install github.com/jaeles-project/gospider@latest                  # breadth crawl
go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest  # passive URL discovery
go install github.com/ffuf/ffuf/v2@latest                            # directory / content discovery
brew install feroxbuster                                              # recursive content discovery
pipx install arjun                                                   # hidden parameter discovery
```

Check what's installed (and get the exact install command for anything missing):

```bash
arachne --check-tools          # tool inventory + default wordlist status
arachne --fetch-wordlists      # pull SecLists for deep fuzzing (auto-detected after)
```

Or install as a command:

```bash
pip install -e .        # gives you the `arachne` command
```

---

## Usage

```bash
# unauthenticated crawl, depth 3
python -m arachne -u https://target.tld -d 3 -o out

# authenticated crawl through Burp, with cookies, render JS
python -m arachne -u https://target.tld --burp \
    --cookie "session=abc; accessToken=xyz" --render

# API-focused crawl with a bearer token and a seed list
python -m arachne -l seeds.txt --bearer "eyJ..." --allow "/api/" -c 40

# reuse a Playwright login session and crawl SPA routes
python -m arachne -u https://target.tld --storage-state state.json --render

# WAF-resistant SPA crawl: impersonate Chrome's TLS fingerprint, render seeds first
python -m arachne -u https://app.target.tld --impersonate chrome124 --browser-first --stealth

# maximal authenticated enumeration: every installed tool, carrying the session
python -m arachne -u https://app.target.tld --cookie "session=abc" --all-tools --render

# discovery only (no brute force): katana JS-crawl + gau archive URLs, folded in
python -m arachne -u https://app.target.tld --bearer "eyJ..." --katana --gau
```

If installed with `pip install -e .`, replace `python -m arachne` with `arachne`.

### Authenticated vs unauthenticated diff

Run the same target twice into different output dirs, then compare `api.txt`:

```bash
python -m arachne -u https://target.tld -o out-anon
python -m arachne -u https://target.tld -o out-auth --cookie "session=abc"
comm -13 <(sort out-anon/api.txt) <(sort out-auth/api.txt)   # auth-only endpoints
```

---

## Authentication options

| Flag | Use |
|------|-----|
| `-H "Name: value"` | any request header (repeatable) |
| `-b "k=v; k2=v2"` | cookie header string |
| `--cookies-file FILE` | cookies as JSON (`{k:v}` or `[{name,value}]`) or Netscape `cookies.txt` |
| `--bearer TOKEN` | shortcut for `Authorization: Bearer TOKEN` |
| `--auth-json FILE` | bundle of `headers` + `cookies` + `bearer` + `storage_state` (see `examples/auth.example.json`) |
| `--storage-state FILE` | Playwright `storage_state` — cookies **and** a `localStorage` token are applied to the static crawl, and the session is reused by `--render` |
| `--auth-token-key KEY` | localStorage key holding the token (default: auto-detect) |
| `--auth-header NAME` / `--auth-scheme SCHEME` | customise the auth header/scheme (e.g. `--auth-header X-Auth-Token --auth-scheme ""` for a raw token) |
| `--no-auto-token` | disable bridging a localStorage token to the static engine |

**Unified auth (cookies *and* localStorage).** Many SPAs keep the JWT in
`localStorage` and send it as `Authorization: Bearer`, not as a cookie. arachne
extracts that token from a Playwright `storage_state.json` and applies it to the
**static** `httpx` engine too — so a `--storage-state` crawl is genuinely
authenticated for token-in-localStorage APIs, not just the render pass. It also
**warns when your session expires** mid-crawl (a burst of 401/403s or
login-redirects on authenticated requests is surfaced, and counted in
`summary.json` as `auth_failures`).

Easiest path for a logged-in session: log in once in a browser, export the
cookies (e.g. from Burp or a browser extension) into a JSON file, and pass
`--cookies-file`. For SPA flows, save a Playwright `storage_state.json` and pass
`--storage-state`.

---

## Passive import / seeding

Map an authenticated API the high-yield way: drive the app through a proxy (or
record it), then let arachne expand from the **real** authenticated requests.

| Flag | Use |
|------|-----|
| `--har FILE` | seed from a HAR capture (browser DevTools, mitmproxy, …) |
| `--postman FILE` | seed from a Postman collection (v2.1) |
| `--burp-xml FILE` | seed from a Burp Suite XML export |
| `--import-auth` | also adopt the cookies + `Authorization` header found in the import |
| `--urlfinder` | run [`projectdiscovery/urlfinder`](https://github.com/projectdiscovery/urlfinder) for passive URL discovery and fold the results into the crawl |

```bash
# crawl + expand from a Burp-captured authenticated session
python -m arachne -u https://app.target.tld --burp-xml capture.xml --import-auth

# passive URL discovery (needs the urlfinder binary on PATH) + active crawl
python -m arachne -u https://target.tld --urlfinder -d 2
```

Imported requests are crawled **read-only** (GET-probed) — original non-GET
methods are recorded in `endpoints.jsonl` but never replayed. Imports require a
scope: pass `-u`/`-l`, or `--scope DOMAIN` when seeding purely from a capture.
`urlfinder` is an optional external binary — install with
`go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest`; if it's
absent the crawl continues without it.

---

## Automatic re-authentication

Long authenticated crawls outlive their tokens. When a request returns `401` or
is redirected to a login page, arachne **re-authenticates and retries the failed
request** — so the crawl keeps its session instead of drowning in 401s. A burst
of concurrent failures triggers exactly one login (deduped via a lock +
generation counter), capped at `--reauth-max` attempts (default 3).

**1. Browser login (Playwright)** — drive a real login form:

```bash
python -m arachne -u https://app.target.tld --storage-state state.json --render \
    --login-url https://app.target.tld/login \
    --login-user "$USER" --login-pass "$PASS" --login-success /dashboard
```

Common username/password/submit fields auto-detect; override with
`--login-user-selector` / `--login-pass-selector` / `--login-submit-selector`,
or put it all in a JSON recipe and pass `--login-recipe` (see
`examples/login.example.json`). A successful login captures a fresh
`storage_state` (cookies **and** localStorage token), bridged into the static
engine and reused by the render phase.

**2. Command hook** — for OAuth refresh, SSO or anything custom, point
`--reauth-command` at a script that prints fresh auth JSON:

```bash
# refresh.sh prints e.g.  {"cookies":{...},"headers":{...},"bearer":"eyJ...new"}
python -m arachne -u https://api.target.tld --bearer "$TOKEN" \
    --reauth-command './refresh.sh'
```

`summary.json` reports `auth_failures` (failures seen) and `reauths` (successful
recoveries).

---

## External-tool orchestration

arachne keeps a native crawl spine and *drives* best-of-breed external CLIs,
folding every in-scope finding back into **one** deduplicated, provenance-tagged
result set (re-crawled and re-mined like any other URL). Two families:

**Discovery** (no `--fuzz` needed — they expand the URL surface):

| Tool | Role | Install |
|------|------|---------|
| [`katana`](https://github.com/projectdiscovery/katana) | JS-aware crawl (links, JS endpoints, known files), carries the session | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [`gau`](https://github.com/lc/gau) | passive URLs (Wayback/CommonCrawl/OTX/URLScan) | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [`waybackurls`](https://github.com/tomnomnom/waybackurls) | passive URLs (Wayback Machine) | `go install github.com/tomnomnom/waybackurls@latest` |
| [`hakrawler`](https://github.com/hakluke/hakrawler) | fast breadth crawl + JS links | `go install github.com/hakluke/hakrawler@latest` |
| [`gospider`](https://github.com/jaeles-project/gospider) | fast crawl + passive sources | `go install github.com/jaeles-project/gospider@latest` |
| [`urlfinder`](https://github.com/projectdiscovery/urlfinder) | passive URL discovery | `go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest` |

**Active** (gated behind `--fuzz`, GET-only):

| Tool | Role | Install |
|------|------|---------|
| [`ffuf`](https://github.com/ffuf/ffuf) | directory / content discovery (unlinked paths) | `go install github.com/ffuf/ffuf/v2@latest` |
| [`feroxbuster`](https://github.com/epi052/feroxbuster) | recursive directory / content discovery | `brew install feroxbuster` |
| [`arjun`](https://github.com/s0md3v/Arjun) | hidden parameter discovery (anomaly diffing) | `pipx install arjun` |

```bash
arachne --check-tools                               # what's installed + how to get the rest

# maximal: run every installed tool, carrying the authenticated session
python -m arachne -u https://app.target.tld --cookie "session=abc" --all-tools

# discovery only (safe, no brute force)
python -m arachne -u https://target.tld --katana --gau
python -m arachne -u https://target.tld --enum-tool katana --enum-tool waybackurls

# active enumeration (directory + parameter discovery)
python -m arachne -u https://target.tld --fuzz                 # ffuf + arjun
python -m arachne -u https://target.tld --enum-tool feroxbuster --enum-tool arjun
python -m arachne -u https://target.tld --fuzz-params          # arjun only

# wordlists: vendored shortcut, your own file, or a fetched SecLists checkout
python -m arachne -u https://target.tld --fuzz --fuzz-wordlist @api
python -m arachne --fetch-wordlists                            # then just --fuzz
```

**How it compounds.** Discovered/brute-forced paths (e.g. a katana-found
`/internal/` or an ffuf-confirmed `/admin/`) are added to the frontier and
re-crawled — their HTML/JS is mined by the normal extractor, yielding *more*
URLs and params. arjun-discovered params land in `params.txt`, and arachne
synthesises a `?param=…` URL per endpoint and crawls it so the parameterised
response is captured. Provenance for every result is in `summary.json`
`source_counts`.

**Safety.** Active tools are **opt-in** (`--fuzz`) and stay GET-only. Every hit
is filtered through scope rules, so destructive paths
(`logout`/`delete`/`withdraw`/…) remain denied unless you pass `--allow-active`.
External binaries don't share arachne's HTTP rate limiter, so `--rate` /
`--delay` are passed through to each tool's own throttle flags. Missing binary or
wordlist → logged and skipped, never fatal.

| Flag | Use |
|------|-----|
| `--check-tools` | list tools, availability, install commands + wordlist status, then exit |
| `--enum-tool NAME` | orchestrate a specific tool (repeatable; any of the tables above) |
| `--all-tools` | orchestrate every installed tool (discovery + active) |
| `--katana` / `--gau` | discovery convenience flags |
| `--fuzz` | run the active phase (drives ffuf + arjun) |
| `--fuzz-dirs` / `--fuzz-params` | ffuf only / arjun only |
| `--fuzz-wordlist FILE\|@name` | content wordlist (`@common`/`@api`/`@starter`; default: SecLists if found, else vendored) |
| `--param-wordlist FILE\|@name` | arjun wordlist (`@params`; default: arjun's built-in) |
| `--seclists-root DIR` | SecLists checkout to resolve wordlists from |
| `--fetch-wordlists [DIR]` | shallow-clone SecLists (default `~/.arachne/wordlists/SecLists`) |
| `--tool-path NAME=PATH` | override a tool's binary path (repeatable) |
| `--tool-timeout SEC` | per-tool subprocess timeout (default 180) |
| `--fuzz-max-endpoints N` | cap endpoints probed for params (default 50) |
| `--tool-max-results N` | cap results folded back per tool (0 = unlimited) |

Wordlists ship in the box (curated content/API/param lists) and resolve
automatically; see [`arachne/data/wordlists/WORDLISTS.md`](arachne/data/wordlists/WORDLISTS.md).

---

## Burp Suite & OWASP ZAP

Burp and ZAP aren't subprocess tools — they're long-running services. arachne
drives both from the command line and folds what they find into the same unified
output. Four ways to combine them:

**1. Headless Burp Pro — no REST API, no GUI (`--burp-headless`).** arachne
launches your licensed `burpsuite_pro.jar` headless, routes the *entire*
authenticated crawl (native engine **and** every orchestrated tool) through Burp's
proxy, and shuts it down when done — Burp records and (with a live-audit config)
scans everything into a saved `.burp` project you can open in the GUI afterwards.

```bash
python -m arachne -u https://app.target.tld --cookie "session=abc" --burp-headless
# Burp jar auto-detected from /Applications; override with --burp-jar
# project saved to <out>/burp-headless.burp ; live log at <out>/burp-headless.log
```

arachne carries the session itself (it's the proxy client), so Burp sees
authenticated traffic with no extra setup. Burp opens its built-in proxy on
`:8080`; if your GUI Burp is already there, close it or pass `--burp-headless-port`
**with** a `--burp-config-file` that defines that listener. To make Burp actively
audit (not just record), pass a `--burp-config-file` that enables live audit of
in-scope items. Verified end-to-end on Burp Suite Professional.

**2. Drive an authenticated scan from arachne (REST API).**

```bash
# Burp Pro: enable Settings > Suite > REST API, create a key, then:
python -m arachne -u https://app.target.tld --cookie "session=abc" \
    --burp-scan --burp-api-key "$BURP_KEY" \
    --login-user "$USER" --login-pass "$PASS" \
    --burp-config "Crawl and Audit - Lightweight"

# OWASP ZAP: connect to a running daemon (or let arachne launch one):
python -m arachne -u https://app.target.tld --bearer "eyJ..." \
    --zap --zap-ajax --zap-api-key "$ZAP_KEY"          # connect
python -m arachne -u https://app.target.tld --zap --zap-launch  # auto-launch zap.sh
```

arachne POSTs an authenticated scan to Burp's REST API (your `--login-user` /
`--login-pass` become `application_logins`), polls to completion, folds the issue
URLs into the crawl, and writes the full result to `burp-result.json`. For ZAP it
injects the session as Replacer header rules, runs the spider (+ AJAX spider with
`--zap-ajax`), and folds the discovered URLs. Both **degrade gracefully** if the
service isn't reachable — you get a clear "start the service" message, not a
crash. (Recorded-login / SSO sequences still have to be authored in the Burp GUI
and referenced via `--burp-config`; the official REST API can't express them.)

**3. Proxy-feed (existing Burp/ZAP, no launch).** Route the *entire* arachne crawl — native engine
**and** every orchestrated tool — through Burp/ZAP, so they build their site map
from arachne's superior coverage, then do the manual testing in the GUI:

```bash
python -m arachne -u https://app.target.tld --burp --all-tools   # via Burp at :8080
python -m arachne -u https://app.target.tld --proxy http://127.0.0.1:8090 --katana
```

**4. Import an exported result.** Already done a Burp run? Feed its export back in
(seeds the crawl from Burp's findings, optionally adopting their auth):

```bash
python -m arachne -u https://app.target.tld --burp-import sitemap.xml --import-auth
python -m arachne --scope app.target.tld --burp-import issues.json   # XML or JSON
```

| Flag | Use |
|------|-----|
| `--burp-headless` | launch Burp Pro headless (no REST API) and route the crawl through its proxy |
| `--burp-jar` / `--burp-headless-port` | jar path (else auto-detected) / proxy port (default 8080) |
| `--burp-project` / `--burp-config-file` | `.burp` project file / project config(s) for scope, auth, live audit |
| `--burp-scan` | run an authenticated Burp Pro scan via the REST API and fold issue URLs |
| `--burp-api-url` / `--burp-api-key` | Burp REST API base (default `:1337`) and key |
| `--burp-config NAME` | Burp named scan configuration (also where a recorded login lives) |
| `--zap` | drive a ZAP daemon's spider and fold discovered URLs |
| `--zap-url` / `--zap-api-key` | ZAP daemon API base (default `:8080`) and key |
| `--zap-launch` / `--zap-path` | launch a ZAP daemon if none is reachable |
| `--zap-ajax` | also run ZAP's AJAX spider (SPA coverage) |
| `--burp` / `--proxy URL` | proxy-feed: route the whole crawl through Burp/ZAP |
| `--burp-import` / `--burp-xml` | ingest an exported Burp result (XML site-map or JSON) |

> Burp's official REST API exposes **issues**, not the full site map — for the
> complete crawl tree, export it from the GUI and use `--burp-import`. `--all-tools`
> covers the subprocess tools (katana/ffuf/…); enable Burp/ZAP explicitly with the
> flags above since they need a running service and credentials.

---

## Output

All files land in the `-o` directory (default `arachne-out/`):

| File | Contents |
|------|----------|
| `endpoints.jsonl` | one JSON record per discovered/fetched resource (url, method, status, content-type, length, source, depth, params, api flag, …) |
| `urls.txt` | unique URLs |
| `api.txt` | API-looking endpoints (incl. every path parsed from OpenAPI/Swagger) |
| `js.txt` | JavaScript bundle URLs |
| `params.txt` | discovered parameter names (passively extracted + actively found by `arjun` under `--fuzz`) |
| `candidates.txt` | low-confidence mined endpoints (not auto-fetched; review manually or rerun with `--fetch-candidates`) |
| `secrets.jsonl` | detected secrets — `{type, confidence, match, url}`, redacted unless `--show-secrets` |
| `graphql.json` | introspected GraphQL schemas (queries, mutations, types) per endpoint |
| `burp-result.json` | full Burp Pro scan result (issues + metrics) when `--burp-scan` is used |
| `burp-headless.burp` / `.log` | the Burp project (open it in the GUI) + launch log when `--burp-headless` is used |
| `summary.json` | counts by status / source / secret type, plus `auth_failures` + `reauths` (session-health) and `fuzz_hits` + `active_params` (active enumeration) |

The `source` field on each record tells you where it came from: `seed`, `html`,
`js`, `json`, `render`, `openapi`, `graphql`, `imported` (HAR/Postman/Burp), or
the name of the external tool that surfaced it — `katana`, `gau`, `waybackurls`,
`hakrawler`, `gospider`, `urlfinder` (discovery), `ffuf`, `feroxbuster` (content),
`arjun` (parameters). `summary.json` `source_counts` tallies them all.

---

## Key options

```
targets      -u URL (repeatable) | -l FILE | --scope DOMAIN
scope        --no-subdomains  --allow REGEX  --deny REGEX  --include-assets
budget       -d DEPTH  -m MAX_PAGES  -c CONCURRENCY  --rate RPS/host  --host-concurrency N  --delay S
safety       --allow-active  --respect-robots  --no-sitemap
transport    --proxy URL  --burp  -k/--insecure  -A UA  --no-redirects  --impersonate BROWSER
auth         -H  -b  --cookies-file  --bearer  --auth-json  --storage-state
             --auth-token-key  --auth-header  --auth-scheme  --no-auto-token  --no-auth-preflight
passive      --har FILE  --postman FILE  --burp-xml FILE  --burp-import FILE  --import-auth  --urlfinder
orchestrate  --check-tools  --enum-tool NAME  --all-tools  --katana  --gau  --tool-path NAME=PATH
fuzz         --fuzz  --fuzz-dirs  --fuzz-params  --fuzz-wordlist FILE|@name  --param-wordlist FILE|@name
wordlists    --seclists-root DIR  --fetch-wordlists [DIR]  (vendored: @common @api @params @starter)
scanners     --burp-headless  --burp-jar PATH  --burp-scan  --burp-api-key KEY  --zap  --zap-ajax  --zap-launch
reauth       --login-url  --login-user  --login-pass  --login-recipe  --reauth-command  --reauth-max
discovery    --no-api-docs  --no-graphql  --no-secrets  --show-secrets  --fetch-candidates
render       --render  --browser-first  --stealth  --render-pages N  --render-wait MS  --headful
output       -o DIR  -q  -v
```

Run `python -m arachne -h` for the complete list.

---

## Notes on safety & scope

`arachne` is a reconnaissance tool for **authorized** security testing only. By
default it issues `GET`/`HEAD` requests, never submits forms, and refuses to
follow logout/delete/withdraw-style links so an authenticated crawl does not
mutate state or destroy your session. Use `--allow-active` only when you
understand the consequences, and keep `--rate`/`--delay` reasonable against
production systems. Only test targets you have explicit permission to assess.

## License

MIT — see [LICENSE](LICENSE).
