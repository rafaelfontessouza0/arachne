"""Lightweight unit tests. Run: python -m pytest -q   (or: python tests/test_core.py)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arachne.extract import classify_endpoint, extract_js, extract_json, looks_like_api
from arachne import secrets, apidocs


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


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed")
