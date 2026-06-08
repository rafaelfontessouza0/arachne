"""OpenAPI/Swagger discovery + GraphQL introspection.

- OpenAPI/Swagger: probe well-known spec paths; when a JSON spec is found,
  enumerate every declared path/method/parameter for free.
- GraphQL: probe well-known endpoints with a read-only introspection query;
  if `data.__schema` comes back, introspection is enabled (a finding) and the
  schema is summarised.
"""
from __future__ import annotations

from typing import List, Dict, Any

# Common locations for OpenAPI / Swagger documents.
SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/v2/swagger.json", "/v3/api-docs",
    "/v2/api-docs", "/api-docs", "/swagger/v1/swagger.json",
    "/api/openapi.json", "/api/swagger.json", "/api/v1/openapi.json",
    "/api/v1/swagger.json", "/.well-known/openapi.json",
    "/swagger-ui/swagger.json", "/docs/openapi.json", "/redoc/openapi.json",
    "/openapi", "/swagger.yaml", "/openapi.yaml",
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v1/graphql/console",
    "/query", "/gql", "/graphql/v1", "/api/v1/graphql",
]

INTROSPECTION_QUERY = {
    "query": (
        "query IntrospectionQuery { __schema { "
        "queryType { name } mutationType { name } subscriptionType { name } "
        "types { kind name fields { name } } } }"
    )
}


def parse_openapi(spec: dict, origin: str) -> List[Dict]:
    """Enumerate {url, method, params, source} from an OpenAPI/Swagger spec."""
    out: List[Dict] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return out

    prefixes: List[str] = []
    servers = spec.get("servers")
    if isinstance(servers, list):
        for s in servers:
            if isinstance(s, dict) and s.get("url"):
                prefixes.append(str(s["url"]))
    if spec.get("basePath"):
        prefixes.append(str(spec["basePath"]))
    if not prefixes:
        prefixes = [""]

    for path, item in paths.items():
        if not isinstance(item, dict) or not isinstance(path, str):
            continue
        common = _params(item.get("parameters"))
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "delete",
                                      "patch", "head", "options"):
                continue
            params = list(common)
            if isinstance(op, dict):
                params += _params(op.get("parameters"))
            seen_urls = set()
            for pref in prefixes:
                full = _join(origin, pref, path)
                if full in seen_urls:
                    continue
                seen_urls.add(full)
                out.append({
                    "url": full, "method": method.upper(),
                    "params": sorted(set(params)), "source": "openapi",
                })
    return out


def _params(plist: Any) -> List[str]:
    out = []
    if isinstance(plist, list):
        for p in plist:
            if isinstance(p, dict) and p.get("name"):
                out.append(str(p["name"]))
    return out


def _join(origin: str, prefix: str, path: str) -> str:
    if prefix.startswith("http"):
        return prefix.rstrip("/") + "/" + path.lstrip("/")
    p = (prefix.rstrip("/") + "/" + path.lstrip("/")) if prefix else path
    if not p.startswith("/"):
        p = "/" + p
    return origin.rstrip("/") + p


def is_openapi(spec: Any) -> bool:
    return isinstance(spec, dict) and (
        "openapi" in spec or "swagger" in spec or isinstance(spec.get("paths"), dict)
    )


def has_introspection(data: dict) -> bool:
    return isinstance(data, dict) and isinstance(
        (data.get("data") or {}).get("__schema"), dict)


def summarize_schema(data: dict) -> dict:
    schema = (data.get("data") or {}).get("__schema") or data.get("__schema")
    if not isinstance(schema, dict):
        return {}

    types = schema.get("types") or []

    def fields_of(typename):
        if not typename:
            return []
        for t in types:
            if isinstance(t, dict) and t.get("name") == typename:
                return [f.get("name") for f in (t.get("fields") or [])
                        if isinstance(f, dict) and f.get("name")]
        return []

    q = (schema.get("queryType") or {}).get("name")
    m = (schema.get("mutationType") or {}).get("name")
    s = (schema.get("subscriptionType") or {}).get("name")
    return {
        "query_type": q, "mutation_type": m, "subscription_type": s,
        "queries": fields_of(q),
        "mutations": fields_of(m),
        "subscriptions": fields_of(s),
        "types": [t.get("name") for t in types
                  if isinstance(t, dict) and t.get("name")
                  and not str(t.get("name")).startswith("__")],
    }
