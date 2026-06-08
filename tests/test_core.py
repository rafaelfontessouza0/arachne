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
