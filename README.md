# arachne

**Async web + API crawler / spider for authenticated and unauthenticated recon.**

`arachne` maps the full reachable surface of a web target — pages **and** APIs —
in a single tool. It combines a fast `asyncio` + `httpx` static crawler with an
optional headless-Chromium render pass (Playwright) that executes JavaScript and
captures every `XHR`/`fetch`, so the API surface of modern SPAs (betting,
banking, dashboards) actually shows up instead of hiding behind client-side
routing.

It works the same whether you give it credentials or not — an *unauthenticated*
run is just an *authenticated* run with no auth material supplied — so you can
diff the two surfaces.

---

## Features

- **Static async crawl** — `httpx` with HTTP/2, configurable concurrency, rate
  limiting, retries/backoff.
- **JS-aware** — mines endpoints from JavaScript bundles and inline scripts
  (LinkFinder-style regex) and walks JSON responses for more URLs.
- **Render mode** — headless Chromium (Playwright) renders SPA routes,
  auto-scrolls, and records all network requests → real API discovery.
- **API-aware** — flags `/api/`, `/v1/`, `graphql`, `.json`, etc. and writes a
  dedicated `api.txt`.
- **Auth, any form** — header / cookie string / cookie file / bearer token /
  `--auth-json` bundle / Playwright `storage_state`.
- **Burp-friendly** — `--burp` routes everything through `127.0.0.1:8080` with
  TLS verification off, in one flag.
- **Scope control** — registered-domain or exact-host scoping, allow/deny
  regex, asset skipping, parameter-aware de-duplication.
- **Safe by default** — `GET`/`HEAD` only, never auto-submits forms, and denies
  destructive paths (`logout`, `delete`, `withdraw`, …) unless `--allow-active`.
- **Clean output** — streamed `endpoints.jsonl` plus `urls.txt`, `api.txt`,
  `js.txt`, `params.txt`, and a `summary.json`.

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
| `--storage-state FILE` | Playwright `storage_state` — used by `--render` and its cookies are also applied to the static crawl |

Easiest path for a logged-in session: log in once in a browser, export the
cookies (e.g. from Burp or a browser extension) into a JSON file, and pass
`--cookies-file`. For SPA flows, save a Playwright `storage_state.json` and pass
`--storage-state` so both the static and render phases share the session.

---

## Output

All files land in the `-o` directory (default `arachne-out/`):

| File | Contents |
|------|----------|
| `endpoints.jsonl` | one JSON record per discovered/fetched resource (url, method, status, content-type, length, source, depth, params, api flag, …) |
| `urls.txt` | unique URLs |
| `api.txt` | API-looking endpoints |
| `js.txt` | JavaScript bundle URLs |
| `params.txt` | discovered parameter names |
| `summary.json` | counts by status / source |

---

## Key options

```
targets      -u URL (repeatable) | -l FILE | --scope DOMAIN
scope        --no-subdomains  --allow REGEX  --deny REGEX  --include-assets
budget       -d DEPTH  -m MAX_PAGES  -c CONCURRENCY  --rate RPS  --delay S
safety       --allow-active  --respect-robots  --no-sitemap
transport    --proxy URL  --burp  -k/--insecure  -A UA  --no-redirects
auth         -H  -b  --cookies-file  --bearer  --auth-json  --storage-state
render       --render  --render-pages N  --render-wait MS  --no-scroll  --headful
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
