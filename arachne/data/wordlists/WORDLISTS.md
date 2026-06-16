# Wordlists

arachne ships a few **lean, curated** wordlists so directory/parameter discovery
works out of the box with no setup. They're deliberately small and high-signal —
for deep coverage, fetch the big community lists (below); arachne picks them up
automatically.

## Vendored lists (always available)

| File | Shortcut | Entries¹ | Use |
|------|----------|---------|-----|
| `content-common.txt` | `@common` | ~450 | default for `ffuf`/`feroxbuster` content discovery |
| `content-starter.txt` | `@starter` | ~185 | tiny fast smoke list |
| `api-routes.txt` | `@api` | ~175 | API path segments (API-focused fuzzing) |
| `params-common.txt` | `@params` | ~230 | common query/body parameter names |

¹ approximate; see `wc -l`.

Reference a vendored list by shortcut on the CLI:

```bash
arachne -u https://target.tld --fuzz --fuzz-wordlist @api
arachne -u https://target.tld --fuzz-params --param-wordlist @params
```

These are hand-curated in the spirit of SecLists `raft`/`common` and Assetnote —
admin/auth/api routes, config & backup files, VCS/CI metadata, framework paths,
and the most-seen parameter names. No comment lines: every line is a literal
fuzz value, so nothing turns into a junk request.

## Bigger lists (recommended for real engagements)

arachne resolves a content wordlist in this order:

1. `--fuzz-wordlist PATH` (or `@shortcut`)
2. **SecLists**, auto-discovered under `--seclists-root`, `$SECLISTS_ROOT`,
   `~/.arachne/wordlists/SecLists`, `/usr/share/seclists`, `/opt/SecLists`, …
   (looks for `Discovery/Web-Content/raft-medium-directories.txt`, then
   `common.txt`, then `directory-list-2.3-medium.txt`)
3. the vendored `content-common.txt`

Get SecLists with one command (shallow clone into `~/.arachne/wordlists/SecLists`,
auto-detected afterwards):

```bash
arachne --fetch-wordlists
# or a custom location:
arachne --fetch-wordlists /opt/SecLists
```

Other excellent sources to point `--fuzz-wordlist` / `--param-wordlist` at:

- **SecLists** — https://github.com/danielmiessler/SecLists
  (`Discovery/Web-Content/*`, `Discovery/Web-Content/api/*`, `Fuzzing/*`)
- **Assetnote wordlists** — https://wordlists.assetnote.io
  (best-in-class, generated from real internet data)
- **fuzzdb** — https://github.com/fuzzdb-project/fuzzdb
- **OneListForAll** — https://github.com/six2dez/OneListForAll

## Tips

- `--rate` / `--delay` are passed through to ffuf/feroxbuster — keep them sane
  against production.
- Bigger list ⇒ more requests ⇒ more load and more chance of tripping a WAF or
  rate limiter. Start small (`@common`), escalate to SecLists raft, then
  directory-list-2.3 only when warranted.
- `arachne --check-tools` shows which content list will be used by default.
