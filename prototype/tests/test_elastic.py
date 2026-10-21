"""Elasticsearch / OpenSearch seeding over REST, against a fake server shaped like the
Kibana ecommerce sample (denormalised order events)."""

import json
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

from veil.proxy import LocalHTTPServer
import pytest

from veil.detect import KnownValues
from veil.reseed import fingerprint
from veil.sources import seed

ORDERS = [
    {"customer_id": "38", "customer_full_name": "Eddie Underwood", "customer_first_name": "Eddie",
     "customer_last_name": "Underwood", "email": "eddie@underwood-family.zzz", "user": "eddie",
     "geoip": {"city_name": "Cairo", "country_iso_code": "EG"}, "notes": "leave at the back door",
     "order_id": 584677, "taxful_total_price": 36.98},
    {"customer_id": "38", "customer_full_name": "Eddie Underwood", "customer_first_name": "Eddie",
     "customer_last_name": "Underwood", "email": "eddie@underwood-family.zzz", "user": "eddie",
     "geoip": {"city_name": "Cairo", "country_iso_code": "EG"}, "notes": "",
     "order_id": 584678, "taxful_total_price": 12.5},
    {"customer_id": "17", "customer_full_name": "Mary Bailey", "customer_first_name": "Mary",
     "customer_last_name": "Bailey", "email": "mary@bailey-family.zzz", "user": "mary",
     "geoip": {"city_name": "Dubai", "country_iso_code": "AE"}, "notes": "",
     "order_id": 584679, "taxful_total_price": 9.0},
]
MAPPING = {"properties": {
    "customer_id": {"type": "keyword"}, "customer_full_name": {"type": "text"},
    "customer_first_name": {"type": "keyword"}, "customer_last_name": {"type": "keyword"},
    "email": {"type": "keyword"}, "user": {"type": "keyword"}, "order_id": {"type": "long"},
    "taxful_total_price": {"type": "half_float"},
    "notes": {"type": "text", "meta": {"pii": "true"}},
    "geoip": {"properties": {"city_name": {"type": "keyword"}, "country_iso_code": {"type": "keyword"}}}}}


@pytest.fixture
def es():
    docs = {"shop_orders": [dict(o) for o in ORDERS], ".kibana": [{"secret": "x"}]}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("content-length") or 0)
            return json.loads(self.rfile.read(n)) if n else {}

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/_cat/indices":
                return self._json([{"index": i} for i in docs])
            if path.endswith("/_mapping"):
                names = path.strip("/").split("/")[0].split(",")
                return self._json({n: {"mappings": MAPPING if n == "shop_orders" else {}} for n in names})
            if "/_stats/" in path:
                n = sum(len(v) for k, v in docs.items() if not k.startswith("."))
                return self._json({"_all": {"primaries": {"docs": {"count": n}, "indexing": {"index_total": n}}}})
            self.send_response(404); self.end_headers()

        def do_POST(self):
            path, body = urlparse(self.path).path, self._body()
            if path == "/_search/scroll":
                return self._json({"_scroll_id": "s1", "hits": {"hits": []}})
            index = path.strip("/").split("/")[0]
            hits = [{"_id": str(i), "_source": d} for i, d in enumerate(docs[index])][: body.get("size", 10)]
            return self._json({"_scroll_id": "s1", "hits": {"hits": hits}})

        def do_DELETE(self):
            self._body()
            self._json({"succeeded": True})

    srv = LocalHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"elasticsearch://127.0.0.1:{srv.server_port}", docs
    srv.shutdown()


def test_index_fields_meta_and_customer_grouping(es):
    uri, _ = es
    known = KnownValues()
    report = seed(known, uri)
    kinds = {f.path: f.kind for f in report.fields}
    assert kinds["email"] == "email" and kinds["user"] == "username" and kinds["customer_full_name"] == "name"
    assert kinds["customer_first_name"] == "first_name" and kinds["notes"] == "pii"    # field meta tag
    assert kinds.get("geoip.city_name") == "qi:city"
    assert "taxful_total_price" not in kinds and not any(f.container == ".kibana" for f in report.fields)
    # one customer across two order events = one person (grouped by customer_id, not _id)
    assert known.group_of("Eddie Underwood") == known.group_of("eddie@underwood-family.zzz") == "shop_orders:38"
    assert known.group_of("Mary Bailey") != known.group_of("Eddie Underwood")


def test_fingerprint_changes_when_documents_arrive(es):
    uri, docs = es
    before = fingerprint(uri)
    assert fingerprint(uri) == before
    docs["shop_orders"].append(dict(ORDERS[0], customer_id="99", email="new@customer.zzz"))
    assert fingerprint(uri) != before
