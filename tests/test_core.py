"""Lightweight unit tests. Run: python -m pytest -q   (or: python tests/test_core.py)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import tempfile

from arachne.extract import classify_endpoint, extract_js, extract_json, looks_like_api
from arachne import secrets, apidocs, importers
from arachne.auth import extract_token_from_storage


def test_classify_rejects_junk():
    # MIME types, module specifiers and versions must not become fetchable URLs
    assert classify_endpoint("application/json") == "reject"
    assert classify_endpoint("text/html") == "reject"
    assert classify_endpoint("multipart/form-data") == "reject"
    assert classify_endpoint("react-dom/client") == "reject"
    assert classify_endpoint("1.2.3/build") == "reject"


def test_classify_keeps_real_endpoints():
    assert classify_endpoint("/api/ug/user/devices") == "strong"
    assert classify_endpoint("https://t.tld/v1/x") == "strong"
    assert classify_endpoint("//cdn.t.tld/a.js") == "strong"
    assert classify_endpoint("vendor/chunk-abc.js") == "weak"
    assert classify_endpoint("api/v1/users") == "weak"


def test_secret_detection():
    text = (
        'aws="AKIAIOSFODNN7EXAMPLE"; gh="ghp_' + "a" * 36 + '";'
        'k="AIza' + "B" * 35 + '"; jwt="eyJhbGciOi.' + "e" * 12 + '.' + "s" * 12 + '"'
    )
    types = {f["type"] for f in secrets.scan(text)}
    assert "aws_access_key_id" in types
    assert "github_token" in types
    assert "google_api_key" in types
    # redaction hides the middle
    aws = [f for f in secrets.scan(text) if f["type"] == "aws_access_key_id"][0]
    assert "*" in aws["match"] and aws["match"].startswith("AKIA")


def test_openapi_parse():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.t.tld/v1"}],
        "paths": {
            "/users/{id}": {
                "get": {"parameters": [{"name": "id", "in": "path"},
                                       {"name": "expand", "in": "query"}]},
                "delete": {},
            },
            "/orders": {"get": {}},
        },
    }
    eps = apidocs.parse_openapi(spec, "https://api.t.tld")
    urls = {(e["method"], e["url"]) for e in eps}
    assert ("GET", "https://api.t.tld/v1/users/{id}") in urls
    assert ("DELETE", "https://api.t.tld/v1/users/{id}") in urls
    assert ("GET", "https://api.t.tld/v1/orders") in urls
    get_users = [e for e in eps if e["url"].endswith("/users/{id}") and e["method"] == "GET"][0]
    assert set(get_users["params"]) == {"id", "expand"}


def test_graphql_summary():
    data = {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"name": "Query", "fields": [{"name": "me"}, {"name": "orders"}]},
            {"name": "Mutation", "fields": [{"name": "login"}]},
            {"name": "User", "fields": [{"name": "id"}]},
            {"name": "__Type", "fields": []},
        ],
    }}}
    assert apidocs.has_introspection(data)
    s = apidocs.summarize_schema(data)
    assert s["queries"] == ["me", "orders"]
    assert s["mutations"] == ["login"]
    assert "User" in s["types"] and "__Type" not in s["types"]


def test_localstorage_token_bridge():
    jwt = "eyJhbGciOi." + "p" * 12 + "." + "s" * 12
    # token under a recognised key
    state = {"origins": [{"origin": "https://app.t.tld",
                          "localStorage": [{"name": "accessToken", "value": jwt}]}]}
    assert extract_token_from_storage(state) == jwt
    # token nested inside a JSON-encoded value
    state2 = {"origins": [{"localStorage": [
        {"name": "auth", "value": json.dumps({"user": "x", "id_token": jwt})}]}]}
    assert extract_token_from_storage(state2) == jwt
    # explicit key selection
    state3 = {"origins": [{"localStorage": [
        {"name": "weird_key", "value": jwt}]}]}
    assert extract_token_from_storage(state3, key="weird_key") == jwt


def test_har_import():
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://api.t.tld/v1/me",
                     "headers": [{"name": "Authorization", "value": "Bearer abc"}],
                     "cookies": [{"name": "sid", "value": "xyz"}]}},
        {"request": {"method": "POST", "url": "https://api.t.tld/v1/orders",
                     "headers": [], "cookies": []}},
    ]}}
    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as fh:
        json.dump(har, fh)
        path = fh.name
    imp = importers.load_har(path)
    urls = {u for _, u in imp.entries}
    assert "https://api.t.tld/v1/me" in urls
    assert ("POST", "https://api.t.tld/v1/orders") in imp.entries
    assert imp.headers.get("Authorization") == "Bearer abc"
    assert imp.cookies.get("sid") == "xyz"


def test_postman_import():
    coll = {"item": [
        {"name": "folder", "item": [
            {"request": {"method": "GET", "url": {"raw": "https://api.t.tld/v1/users"}}},
        ]},
        {"request": {"method": "DELETE", "url": "https://api.t.tld/v1/users/1",
                     "header": [{"key": "Authorization", "value": "Bearer tkn"}]}},
        {"request": {"method": "GET", "url": {"raw": "{{baseUrl}}/skip"}}},  # unresolved -> skipped
    ]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(coll, fh)
        path = fh.name
    imp = importers.load_postman(path)
    urls = {u for _, u in imp.entries}
    assert "https://api.t.tld/v1/users" in urls
    assert ("DELETE", "https://api.t.tld/v1/users/1") in imp.entries
    assert not any("{{" in u for u in urls)
    assert imp.headers.get("Authorization") == "Bearer tkn"


def test_reauth_command_single_run_under_concurrency():
    import asyncio
    from arachne.config import Config
    from arachne.reauth import ReAuth

    class FakeHttp:
        def __init__(self):
            self.applied = []

        def update_auth(self, cookies=None, headers=None):
            self.applied.append((cookies, headers))

    cfg = Config(seeds=["https://t.tld/"],
                 reauth_command='echo \'{"bearer":"NEWTOK","cookies":{"s":"1"}}\'',
                 reauth_max=3)
    http = FakeHttp()
    ra = ReAuth(cfg, http, lambda m: None)
    assert ra.enabled

    # five workers all observe generation 0 and request a refresh at once
    results = asyncio.run(_gather(ra, [0, 0, 0, 0, 0]))
    assert all(results)            # every worker ends up with fresh creds
    assert ra.attempts == 1        # but exactly ONE real re-auth ran (no thundering herd)
    assert ra.reauths == 1
    assert ra.generation == 1
    assert cfg.bearer == "NEWTOK"
    assert http.applied[0][1].get("Authorization") == "Bearer NEWTOK"


def test_reauth_command_failure_is_capped():
    import asyncio
    from arachne.config import Config
    from arachne.reauth import ReAuth

    class FakeHttp:
        def update_auth(self, cookies=None, headers=None):
            pass

    cfg = Config(seeds=["https://t.tld/"], reauth_command="echo not-json", reauth_max=2)
    ra = ReAuth(cfg, FakeHttp(), lambda m: None)
    assert asyncio.run(ra.refresh(0)) is False     # bad output -> no fresh creds
    assert ra.generation == 0 and ra.attempts == 1


async def _gather(ra, gens):
    import asyncio
    return await asyncio.gather(*[ra.refresh(g) for g in gens])


def test_external_ffuf_command_and_parse():
    from arachne.config import Config
    from arachne.external import FfufTool

    cfg = Config(seeds=["https://t.tld/"], concurrency=10, rate=5.0, delay=0.1,
                 bearer="TOK", cookies={"sid": "1"})
    t = FfufTool(cfg)
    cmd = t.build_command("https://t.tld", "/wl.txt", "/out.json")
    assert cmd[0] == "ffuf"
    assert "-u" in cmd and "https://t.tld/FUZZ" in cmd
    assert "-of" in cmd and "json" in cmd
    assert "-ac" in cmd                       # soft-404 calibration
    assert "-rate" in cmd and "5" in cmd      # inherits arachne rate budget
    assert "-p" in cmd and "0.1" in cmd       # inherits delay
    assert "Authorization: Bearer TOK" in cmd
    assert "-b" in cmd and "sid=1" in cmd

    # ffuf -of json file shape: {"results": [{"url": ..., "status": ...}, ...]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"results": [
            {"url": "https://t.tld/admin", "status": 200},
            {"url": "https://t.tld/api", "status": 401},
            {"nope": True},
        ]}, fh)
        path = fh.name
    found = t.parse_output(path)
    urls = {f.url for f in found}
    assert urls == {"https://t.tld/admin", "https://t.tld/api"}
    assert all(f.kind == "url" and f.source == "ffuf" for f in found)


def test_external_arjun_command_and_parse():
    from arachne.config import Config
    from arachne.external import ArjunTool

    cfg = Config(seeds=["https://t.tld/"], delay=0.2, rate=4.0, headers={"X-Api": "z"})
    t = ArjunTool(cfg)
    cmd = t.build_command("/in.txt", "/out.json")
    assert cmd[0] == "arjun"
    assert "-i" in cmd and "-oJ" in cmd and "--stable" in cmd
    assert "-d" in cmd and "0.2" in cmd
    assert "--rate-limit" in cmd and "4" in cmd
    assert "--headers" in cmd
    hdr = cmd[cmd.index("--headers") + 1]
    assert "X-Api: z" in hdr

    # arjun -oJ file shape: {url: {"params": [...], "method": ..., "headers": ...}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({
            "https://t.tld/search": {"params": ["q", "page"], "method": "GET", "headers": {}},
            "https://t.tld/empty": {"params": [], "method": "GET", "headers": {}},
        }, fh)
        path = fh.name
    found = t.parse_output(path)
    by_url = {f.url: f.params for f in found}
    assert by_url == {"https://t.tld/search": ["q", "page"]}
    assert all(f.kind == "param" and f.source == "arjun" for f in found)


def test_external_missing_binary_skips_gracefully():
    from arachne.config import Config
    from arachne.external import ExternalTool, build_tools

    cfg = Config(seeds=["https://t.tld/"], external_tools=["ffuf", "arjun"],
                 ffuf_path="definitely-not-a-real-binary-xyz")
    tools = build_tools(cfg)
    assert [t.name for t in tools] == ["ffuf", "arjun"]
    # path override is honoured, and an absent binary reports unavailable (no crash)
    ffuf = tools[0]
    assert ffuf.binary == "definitely-not-a-real-binary-xyz"
    assert ffuf.available() is False


def test_external_wordlist_resolution_falls_back_to_vendored():
    import os
    from arachne.config import Config
    from arachne import external

    # no override, SecLists absent on this host -> richest vendored content list
    cfg = Config(seeds=["https://t.tld/"])
    wl = external.resolve_content_wordlist(cfg)
    assert wl is not None and os.path.exists(wl)
    assert wl.endswith("content-common.txt")

    # an explicit but missing override resolves to None (caller skips ffuf)
    cfg2 = Config(seeds=["https://t.tld/"], fuzz_wordlist="/no/such/wordlist.txt")
    assert external.resolve_content_wordlist(cfg2) is None


def test_external_vendored_wordlist_shortcuts():
    import os
    from arachne.config import Config
    from arachne import external

    # every vendored shortcut resolves to an existing file
    for short in external.VENDORED_WORDLISTS:
        p = external.vendored_path(short)
        assert p is not None and os.path.exists(p)

    # @shortcut on the CLI value resolves to the vendored list
    cfg = Config(seeds=["https://t.tld/"], fuzz_wordlist="@api")
    wl = external.resolve_content_wordlist(cfg)
    assert wl is not None and wl.endswith("api-routes.txt")
    # unknown shortcut -> None (caller skips, never a bogus path)
    assert external.resolve_content_wordlist(
        Config(seeds=["https://t.tld/"], fuzz_wordlist="@nope")) is None

    # param resolver: explicit/@shortcut only, else None (arjun keeps its builtin)
    assert external.resolve_param_wordlist(Config(seeds=["https://t.tld/"])) is None
    pw = external.resolve_param_wordlist(
        Config(seeds=["https://t.tld/"], param_wordlist="@params"))
    assert pw is not None and pw.endswith("params-common.txt")
    # arjun command picks up the resolved list
    from arachne.external import ArjunTool
    cmd = ArjunTool(Config(seeds=["https://t.tld/"], param_wordlist="@params")).build_command("/i", "/o")
    assert "-w" in cmd and cmd[cmd.index("-w") + 1].endswith("params-common.txt")


def test_external_synthesize_param_url():
    from arachne.external import synthesize_param_url
    u = synthesize_param_url("https://t.tld/search", ["q", "page"])
    assert u == "https://t.tld/search?page=1&q=1"   # sorted, probe value 1
    # existing params are preserved, not duplicated
    u2 = synthesize_param_url("https://t.tld/x?a=7", ["a", "b"])
    assert u2 == "https://t.tld/x?a=7&b=1"
    assert synthesize_param_url("not a url", ["q"]) is None


def test_cli_fuzz_flag_wiring():
    from arachne.cli import build_parser, config_from_args

    # bare --fuzz drives both tools
    cfg = config_from_args(build_parser().parse_args(["-u", "https://t.tld", "--fuzz"]))
    assert cfg.fuzz and set(cfg.external_tools) == {"ffuf", "arjun"}

    # --fuzz-dirs implies fuzz and selects only ffuf
    cfg2 = config_from_args(build_parser().parse_args(["-u", "https://t.tld", "--fuzz-dirs"]))
    assert cfg2.fuzz and cfg2.external_tools == ["ffuf"]

    # --enum-tool alone enables fuzzing with just that tool
    cfg3 = config_from_args(build_parser().parse_args(
        ["-u", "https://t.tld", "--enum-tool", "arjun"]))
    assert cfg3.fuzz and cfg3.external_tools == ["arjun"]

    # no fuzz flags -> phase off
    cfg4 = config_from_args(build_parser().parse_args(["-u", "https://t.tld"]))
    assert cfg4.fuzz is False and cfg4.external_tools == []


def test_fold_findings_integration():
    import asyncio
    import os
    import tempfile
    from arachne.config import Config
    from arachne.crawler import Crawler
    from arachne.frontier import Frontier
    from arachne.external import Finding

    async def run():
        outdir = tempfile.mkdtemp()
        cfg = Config(seeds=["https://t.tld/"], output_dir=outdir)
        cr = Crawler(cfg)
        cr.frontier = Frontier(cfg, cr.scope)   # loop-bound object built in run() normally
        findings = [
            Finding(kind="url", url="https://t.tld/admin", status=200, source="ffuf"),
            Finding(kind="url", url="https://evil.tld/x", source="ffuf"),          # out of scope
            Finding(kind="param", url="https://t.tld/search", params=["q", "page"], source="arjun"),
        ]
        added = await cr._fold_findings(findings, "ffuf")
        assert added == 2                       # admin url + one synthesized param url
        assert cr.out.fuzz_hits == 1            # evil.tld dropped, not counted
        assert cr.out.active_params == 2
        assert {"q", "page"} <= cr.out.params
        summary = cr.out.close()
        assert summary["fuzz_hits"] == 1 and summary["active_params"] == 2
        with open(os.path.join(outdir, "params.txt")) as fh:
            names = set(fh.read().split())
        assert {"q", "page"} <= names

    asyncio.run(run())


def test_external_url_extractor_is_tolerant():
    from arachne.config import Config
    from arachne.external import KatanaTool

    t = KatanaTool(Config(seeds=["https://t.tld/"]))
    text = ("https://t.tld/a\n"
            "[inf] noise https://t.tld/b?x=1 trailing\n"
            "https://t.tld/a\n"                         # dup
            "[href] - https://t.tld/c,\n"               # tagged + trailing comma
            "# comment\n")
    finds = t._url_findings(text)
    urls = [f.url for f in finds]
    assert urls == ["https://t.tld/a", "https://t.tld/b?x=1", "https://t.tld/c"]
    assert all(f.kind == "url" and f.source == "katana" for f in finds)
    # tool_max_results caps the fold
    capped = KatanaTool(Config(seeds=["https://t.tld/"], tool_max_results=2))
    assert len(capped._url_findings(text)) == 2


def test_external_katana_command():
    from arachne.config import Config
    from arachne.external import KatanaTool

    cfg = Config(seeds=["https://t.tld/"], max_depth=2, concurrency=8, rate=3.0,
                 cookies={"sid": "1"}, bearer="TOK")
    cmd = KatanaTool(cfg).build_command(["https://t.tld/"])
    assert cmd[0] == "katana"
    assert "-jc" in cmd and "-kf" in cmd and "all" in cmd     # JS crawl + known files
    assert "-d" in cmd and "2" in cmd                          # depth
    assert "-fs" in cmd and "rdn" in cmd                       # root-domain field scope
    assert "-rl" in cmd and "3" in cmd                         # rate budget
    assert "-u" in cmd and "https://t.tld/" in cmd
    assert "Authorization: Bearer TOK" in cmd
    assert "Cookie: sid=1" in cmd


def test_external_gau_and_waybackurls_commands():
    from arachne.config import Config
    from arachne.external import GauTool, WaybackurlsTool

    cfg = Config(seeds=["https://t.tld/"], concurrency=8)   # include_subdomains default True
    gau = GauTool(cfg).build_command("t.tld")
    assert gau[0] == "gau" and gau[-1] == "t.tld"
    assert "--subs" in gau and "--threads" in gau
    wb = WaybackurlsTool(cfg).build_command("t.tld")
    assert wb == ["waybackurls", "t.tld"]


def test_external_feroxbuster_command_and_skip():
    from arachne.config import Config
    from arachne.external import FeroxbusterTool

    cfg = Config(seeds=["https://t.tld/"], insecure=True, rate=5.0, concurrency=10,
                 max_depth=3, cookies={"sid": "1"}, bearer="TOK")
    t = FeroxbusterTool(cfg)
    cmd = t.build_command("https://t.tld", "/wl.txt")
    assert cmd[0] == "feroxbuster"
    assert "--silent" in cmd and "--no-state" in cmd
    assert "-w" in cmd and "/wl.txt" in cmd
    assert "-u" in cmd and "https://t.tld/" in cmd
    assert "-k" in cmd                                         # insecure
    assert "--rate-limit" in cmd and "5" in cmd
    assert "Authorization: Bearer TOK" in cmd
    assert "-b" in cmd and "sid=1" in cmd
    # vendored wordlist exists on this host -> no skip; a missing override -> skip
    assert t.skip_reason() is None
    cfg2 = Config(seeds=["https://t.tld/"], fuzz_wordlist="/no/such/list.txt")
    assert FeroxbusterTool(cfg2).skip_reason() is not None


def test_external_hakrawler_and_gospider_commands():
    from arachne.config import Config
    from arachne.external import HakrawlerTool, GospiderTool

    cfg = Config(seeds=["https://t.tld/"], max_depth=2, concurrency=6,
                 cookies={"sid": "1"}, bearer="TOK")
    cmd, stdin = HakrawlerTool(cfg).build_command(["https://t.tld/"])
    assert cmd[0] == "hakrawler" and "-u" in cmd and "-subs" in cmd
    assert stdin == "https://t.tld/\n"
    h = cmd[cmd.index("-h") + 1]
    assert "Authorization: Bearer TOK" in h and "Cookie: sid=1" in h and ";;" in h

    g = GospiderTool(cfg).build_command(["https://t.tld/"])
    assert g[0] == "gospider" and "-q" in g
    assert "-s" in g and "https://t.tld/" in g
    assert "--cookie" in g and "sid=1" in g
    assert "Authorization: Bearer TOK" in g


def test_external_registry_catalog_and_is_active():
    from arachne import external

    names = set(external.known_tools())
    assert {"ffuf", "feroxbuster", "arjun", "katana", "hakrawler",
            "gospider", "gau", "waybackurls", "urlfinder"} <= names
    # active gating: brute-forcers active, discovery/passive not
    assert external.is_active("ffuf") and external.is_active("feroxbuster") and external.is_active("arjun")
    assert not external.is_active("katana") and not external.is_active("gau")
    assert not external.is_active("urlfinder") and not external.is_active("waybackurls")

    cat = {r["name"]: r for r in external.tool_catalog()}
    assert cat["katana"]["install"].startswith("go install")
    assert cat["arjun"]["category"] == "param"
    assert cat["gau"]["category"] == "passive"
    assert "available" in cat["ffuf"] and isinstance(cat["ffuf"]["available"], bool)


def test_external_build_tools_path_override_and_urlfinder_safe():
    from arachne.config import Config
    from arachne import external

    cfg = Config(seeds=["https://t.tld/"], external_tools=["katana", "gau"],
                 tool_paths={"katana": "/opt/katana"})
    tools = {t.name: t for t in external.build_tools(cfg)}
    assert tools["katana"].binary == "/opt/katana"     # --tool-path override honoured
    assert tools["gau"].binary == "gau"                # default when not overridden
    # urlfinder wraps passive.py; with the binary absent it folds to nothing, no crash
    uf = external.build_tools(Config(seeds=["https://t.tld/"], external_tools=["urlfinder"]))[0]
    assert uf.run(["t.tld"]) == []


def test_cli_orchestration_wiring():
    from arachne.cli import build_parser, config_from_args
    from arachne import external

    def cfg(*args):
        return config_from_args(build_parser().parse_args(["-u", "https://t.tld", *args]))

    # discovery tools don't enable the active phase
    c = cfg("--enum-tool", "katana")
    assert c.external_tools == ["katana"] and c.fuzz is False
    c = cfg("--katana")
    assert c.external_tools == ["katana"] and c.fuzz is False
    c = cfg("--gau")
    assert c.external_tools == ["gau"] and c.fuzz is False

    # an active tool selected explicitly turns the fuzz phase on
    c = cfg("--enum-tool", "feroxbuster")
    assert c.external_tools == ["feroxbuster"] and c.fuzz is True

    # --all-tools selects the whole registry and enables active
    c = cfg("--all-tools")
    assert set(c.external_tools) == set(external.known_tools()) and c.fuzz is True

    # --urlfinder routes through the registry as a discovery tool
    c = cfg("--urlfinder")
    assert c.external_tools == ["urlfinder"] and c.fuzz is False

    # --tool-path parsing + --no-auth-preflight
    c = cfg("--enum-tool", "katana", "--tool-path", "katana=/opt/katana", "--no-auth-preflight")
    assert c.tool_paths == {"katana": "/opt/katana"} and c.auth_preflight is False


def test_cli_check_tools_exits_zero():
    from arachne.cli import main
    assert main(["--check-tools"]) == 0     # runs without seeds, prints catalog, exits clean


def test_fold_discovery_does_not_inflate_fuzz_hits():
    import asyncio
    import tempfile
    from arachne.config import Config
    from arachne.crawler import Crawler
    from arachne.frontier import Frontier
    from arachne.external import Finding

    async def run():
        cfg = Config(seeds=["https://t.tld/"], output_dir=tempfile.mkdtemp())
        cr = Crawler(cfg)
        cr.frontier = Frontier(cfg, cr.scope)
        findings = [
            Finding(kind="url", url="https://t.tld/blog/2019", source="gau"),
            Finding(kind="url", url="https://t.tld/old", source="katana"),
        ]
        added = await cr._fold_findings(findings, "katana", bump_fuzz=False)
        assert added == 2
        assert cr.out.fuzz_hits == 0      # passive/crawl URLs are not "fuzz hits"
        cr.out.close()

    asyncio.run(run())


def test_burp_scanner_request_and_issue_parse():
    from arachne.config import Config
    from arachne.scanners import BurpScanner

    cfg = Config(seeds=["https://app.t.tld/"], burp_api_key="KEY",
                 burp_config_name="Crawl and Audit - Lightweight",
                 login_username="pentester", login_password="hunter2")
    sc = BurpScanner(cfg)
    assert sc._endpoint() == "http://127.0.0.1:1337/KEY/v0.1/scan"
    assert sc._endpoint("/42") == "http://127.0.0.1:1337/KEY/v0.1/scan/42"

    body = sc.build_scan_request(["https://app.t.tld/dashboard"])
    assert body["urls"] == ["https://app.t.tld/dashboard"]
    assert {"rule": "https://app.t.tld/"} in body["scope"]["include"]
    assert body["application_logins"] == [{"username": "pentester", "password": "hunter2"}]
    assert body["scan_configurations"][0]["name"] == "Crawl and Audit - Lightweight"
    # destructive paths excluded from scope unless --allow-active
    assert any("logout" in r["rule"] for r in body["scope"]["exclude"])

    data = {"scan_status": "succeeded", "issue_events": [
        {"issue": {"origin": "https://app.t.tld", "path": "/admin"}},
        {"issue": {"url": "https://app.t.tld/api/users"}},
        {"issue": {"origin": "https://app.t.tld", "path": "/admin"}},   # dup
    ]}
    assert sc.scan_status(data) == "succeeded"
    assert sc.issue_urls(data) == ["https://app.t.tld/admin", "https://app.t.tld/api/users"]


def test_zap_scanner_api_url_and_parse():
    from arachne.config import Config
    from arachne.scanners import ZapScanner

    cfg = Config(seeds=["https://t.tld/"], zap_api_key="K", bearer="TOK", cookies={"sid": "1"})
    sc = ZapScanner(cfg)
    url = sc.api_url("spider", "action", "scan", {"url": "https://t.tld/"})
    assert url.startswith("http://127.0.0.1:8080/JSON/spider/action/scan/?")
    assert "apikey=K" in url and "url=https%3A%2F%2Ft.tld%2F" in url

    # auth is injected as Replacer header rules
    rules = sc.replacer_rules()
    by = {r["matchString"]: r["replacement"] for r in rules}
    assert by["Authorization"] == "Bearer TOK"
    assert by["Cookie"] == "sid=1"
    assert all(r["matchType"] == "REQ_HEADER" for r in rules)

    assert sc.parse_urls('{"urls": ["https://t.tld/a", "https://t.tld/b", "x"]}') == \
        ["https://t.tld/a", "https://t.tld/b"]
    assert sc.parse_urls('{"results": ["https://t.tld/c"]}') == ["https://t.tld/c"]
    assert sc.parse_urls("not json") == []


def test_cli_scanner_wiring():
    from arachne.cli import build_parser, config_from_args

    ns = build_parser().parse_args(
        ["-u", "https://t.tld", "--zap", "--zap-ajax", "--zap-api-key", "K",
         "--burp-scan", "--burp-api-key", "BK", "--burp-config", "Lightweight"])
    cfg = config_from_args(ns)
    assert cfg.scanners == ["zap", "burp"]
    assert cfg.zap_ajax is True and cfg.zap_api_key == "K"
    assert cfg.burp_api_key == "BK" and cfg.burp_config_name == "Lightweight"


def test_burp_import_json_export():
    import json
    import tempfile
    from arachne import importers

    # a Burp REST/issues JSON export -> URL entries
    export = {"issue_events": [
        {"issue": {"origin": "https://api.t.tld", "path": "/v1/users"}},
        {"issue": {"url": "https://api.t.tld/v1/orders"}},
    ], "urls": ["https://api.t.tld/health"]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(export, fh)
        path = fh.name
    imp = importers.load_burp(path)        # auto-detects JSON vs XML
    urls = {u for _, u in imp.entries}
    assert "https://api.t.tld/v1/users" in urls
    assert "https://api.t.tld/v1/orders" in urls
    assert "https://api.t.tld/health" in urls


def test_burp_headless_command_and_guards():
    import socket
    from arachne.config import Config
    from arachne.scanners import BurpHeadless

    cfg = Config(seeds=["https://t.tld/"], burp_jar="/x/burpsuite_pro.jar",
                 burp_headless_port=8085, output_dir="/tmp/arachne-x",
                 burp_config_files=["/cfg/scope.json"])
    bh = BurpHeadless(cfg)
    assert bh.proxy_url() == "http://127.0.0.1:8085"
    cmd = bh.build_command("/tmp/p.burp")
    assert cmd[:4] == ["java", "-Djava.awt.headless=true", "-jar", "/x/burpsuite_pro.jar"]
    assert "--project-file=/tmp/p.burp" in cmd
    assert "--unpause-spider-and-scanner" in cmd
    assert "--config-file=/cfg/scope.json" in cmd
    # bogus jar -> unavailable; start() refuses gracefully (no launch)
    assert bh.available() is False
    logs = []
    assert bh.start(logs.append) is False
    assert any("not found" in m for m in logs)

    # port-busy guard: bind a port, point a (real-jar-or-not) BurpHeadless at it
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
    busy = s.getsockname()[1]
    cfg2 = Config(seeds=["https://t.tld/"], burp_jar=__file__,  # exists -> available() jar check passes
                  burp_headless_port=busy)
    logs2 = []
    # available() also needs java; if java is absent this still returns False before the port check
    BurpHeadless(cfg2).start(logs2.append)
    s.close()
    assert logs2  # logged a skip reason either way (port busy or missing java)


def test_per_host_rate_limiters_isolated():
    import asyncio
    from arachne.config import Config
    from arachne.httpclient import HttpClient

    async def run():
        cfg = Config(seeds=["https://t.tld/"], rate=5.0, concurrency=4, per_host_concurrency=2)
        h = HttpClient(cfg)
        try:
            la = h._limiter("a.tld")
            lb = h._limiter("b.tld")
            assert la is not lb                 # each host gets its own bucket
            assert h._limiter("a.tld") is la    # and it's cached
            assert la.rate == 5.0
            assert h.backend == "httpx"         # no --impersonate -> httpx backend
            sa = h._host_sem("a.tld")
            assert sa is not None and h._host_sem("a.tld") is sa
        finally:
            await h.aclose()

    asyncio.run(run())


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed")
