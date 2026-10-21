"""Elasticsearch / OpenSearch seeding over the REST API (httpx; no client library).

  elasticsearch://[user:pass@]host:9200[/index1,index2]     (https: elasticsearch+https://...)
  opensearch://...                                           (same API)
  API key: VEIL_ES_API_KEY (sent as `Authorization: ApiKey ...`)

Fields come from `_mapping` (text/keyword/... leaves, nested objects as dotted paths);
field `meta` (`"meta": {"pii": "email"}`) is a native tag. Documents are sampled with a
random score for classification, then read with scroll. Index documents are often
denormalised events (an order carrying customer_full_name and customer_email), so a
record's person is its `customer_id` / `user_id` field when there is one, not `_id`.
System and hidden indices (`.kibana`, `.ds-...`) are skipped.
"""

from __future__ import annotations

import os
from urllib.parse import unquote, urlparse

import httpx

from ..detect import KnownValues
from .core import Container, Report
from .sql import run

TEXTISH = {"text", "keyword", "match_only_text", "search_as_you_type", "wildcard", "constant_keyword", "ip"}
PERSON_KEYS = ("customer_id", "user_id", "account_id", "person_id", "member_id", "client_id")


def _client(uri: str) -> tuple[httpx.Client, list[str]]:
    u = urlparse(uri)
    scheme = "https" if u.scheme.endswith("+https") else "http"
    base = f"{scheme}://{u.hostname or '127.0.0.1'}:{u.port or 9200}"
    headers = {"content-type": "application/json"}
    if os.environ.get("VEIL_ES_API_KEY"):
        headers["authorization"] = f"ApiKey {os.environ['VEIL_ES_API_KEY']}"
    auth = (unquote(u.username), unquote(u.password or "")) if u.username else None
    indices = [i for i in u.path.strip("/").split(",") if i]
    return httpx.Client(base_url=base, headers=headers, auth=auth, timeout=30, trust_env=False), indices


def _fields(props: dict, prefix: str = "") -> dict[str, dict]:
    out = {}
    for name, spec in (props or {}).items():
        path = f"{prefix}{name}"
        if "properties" in spec:
            out.update(_fields(spec["properties"], path + "."))
        elif spec.get("type", "object") in TEXTISH:
            meta = spec.get("meta") or {}
            pii = meta.get("pii") or meta.get("PII")
            out[path] = {"json": False, "comment": f"pii:{pii}" if pii and pii != "true" else ("pii" if pii else None)}
    return out


def _flat(doc: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in (doc or {}).items():
        if isinstance(v, dict):
            out.update(_flat(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def seed_elasticsearch(known: KnownValues, uri: str, client: httpx.Client | None = None,
                       max_docs: int = 500_000) -> Report:
    own, indices = _client(uri)
    es = client or own
    if not indices:
        cat = es.get("/_cat/indices", params={"format": "json", "h": "index"}).json()
        indices = sorted(i["index"] for i in cat if not i["index"].startswith("."))
    mappings = es.get("/" + ",".join(indices) + "/_mapping").json()

    def sample(index: str, n: int) -> list[dict]:
        body = {"size": n, "query": {"function_score": {"query": {"match_all": {}}, "random_score": {}}}}
        hits = es.post(f"/{index}/_search", json=body).json().get("hits", {}).get("hits", [])
        return [{"_id": h["_id"], **_flat(h.get("_source"))} for h in hits]

    def scroll(index: str):
        r = es.post(f"/{index}/_search", params={"scroll": "2m"}, json={"size": 1000, "sort": ["_doc"]}).json()
        seen = 0
        try:
            while True:
                hits = r.get("hits", {}).get("hits", [])
                if not hits:
                    return
                for h in hits:
                    yield {"_id": h["_id"], **_flat(h.get("_source"))}
                    seen += 1
                    if seen >= max_docs:
                        return
                r = es.post("/_search/scroll", json={"scroll": "2m", "scroll_id": r["_scroll_id"]}).json()
        finally:
            if r.get("_scroll_id"):
                es.request("DELETE", "/_search/scroll", json={"scroll_id": r["_scroll_id"]})

    containers, keys = [], {}
    for index, m in mappings.items():
        if index.startswith("."):
            continue
        cols = _fields((m.get("mappings") or {}).get("properties"))
        if not cols:
            continue
        key = next((k for k in PERSON_KEYS if k in cols), "_id")
        cols.pop(key, None)
        keys[index] = key
        containers.append(Container(index, key, cols, sample(index, 300), {}))
    try:
        return run(known, containers, lambda c, _cols: scroll(c.name))
    finally:
        if client is None:
            own.close()
