"""DynamoDB seeding: personal data inside single-table keys (PK = USER#email), against
a fake endpoint speaking DynamoDB's JSON protocol to a real botocore client (and
DynamoDB Local when it runs on :58000)."""

import json
import threading
from http.server import BaseHTTPRequestHandler

import pytest

pytest.importorskip("botocore")

from veil.detect import KnownValues
from veil.proxy import LocalHTTPServer
from veil.sources import seed

ITEMS = [  # single-table design: a user, their profile and orders, and an unrelated config row
    {"PK": {"S": "USER#leonekohler@surfeu.de"}, "SK": {"S": "PROFILE"}, "fullName": {"S": "Leonie Köhler"},
     "phone": {"S": "+49 0711 2842222"}, "GSI1PK": {"S": "CITY#Stuttgart"}},
    {"PK": {"S": "USER#leonekohler@surfeu.de"}, "SK": {"S": "ORDER#2026-10-01#293"}, "total": {"N": "0.99"}},
    {"PK": {"S": "USER#bjorn.hansen@yahoo.no"}, "SK": {"S": "PROFILE"}, "fullName": {"S": "Bjørn Hansen"},
     "phone": {"S": "+47 22 44 22 22"}},
    {"PK": {"S": "USER#priya.raman@gmail.com"}, "SK": {"S": "PROFILE"}, "fullName": {"S": "Priya Raman"},
     "tags": {"SS": ["vip", "beta"]}},
    {"PK": {"S": "USER#astrid.gruber@apple.at"}, "SK": {"S": "PROFILE"}, "fullName": {"S": "Astrid Gruber"}},
    {"PK": {"S": "USER#terhi.hamalainen@apple.fi"}, "SK": {"S": "PROFILE"}, "fullName": {"S": "Terhi Hämäläinen"}},
    {"PK": {"S": "CONFIG#feature-flags"}, "SK": {"S": "v1"}, "value": {"S": "dark-mode"}},
]
DESC = {"Table": {"TableName": "App", "KeySchema": [{"AttributeName": "PK", "KeyType": "HASH"},
                                                   {"AttributeName": "SK", "KeyType": "RANGE"}],
                  "GlobalSecondaryIndexes": [{"IndexName": "GSI1", "KeySchema": [
                      {"AttributeName": "GSI1PK", "KeyType": "HASH"}]}],
                  "ItemCount": len(ITEMS), "TableSizeBytes": 1000}}


@pytest.fixture
def fake_ddb(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake"); monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            op = self.headers["X-Amz-Target"].split(".")[1]
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            if op == "ListTables":
                out = {"TableNames": ["App"]}
            elif op == "DescribeTable":
                out = DESC
            elif op == "Scan":  # two pages, to exercise pagination
                start = int((body.get("ExclusiveStartKey") or {}).get("i", {}).get("N", "0"))
                n = min(body.get("Limit", 1000), 4)
                out = {"Items": ITEMS[start:start + n], "Count": len(ITEMS[start:start + n])}
                if start + n < len(ITEMS):
                    out["LastEvaluatedKey"] = {"i": {"N": str(start + n)}}
            else:
                self.send_response(400); self.end_headers(); return
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("content-type", "application/x-amz-json-1.0")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = LocalHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"dynamodb://local?endpoint=http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_key_segments_and_single_table_grouping(fake_ddb):
    k = KnownValues()
    report = seed(k, fake_ddb)
    kinds = {f.path: f.kind for f in report.fields}
    assert kinds["PK:USER"] == "email" and kinds["fullName"] == "name" and kinds["phone"] == "phone"
    assert kinds.get("GSI1PK:CITY") == "qi:city"                  # a GSI key segment, by its prefix name
    g = k.group_of("leonekohler@surfeu.de")
    assert g == "App:USER#leonekohler@surfeu.de" == k.group_of("Leonie Köhler") == k.group_of("+49 0711 2842222")
    assert k.group_of("Bjørn Hansen") != g
    assert not k.canonical("dark-mode") and not k.canonical("feature-flags")


def test_live_dynamodb_local(monkeypatch):
    import botocore.session
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake"); monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake")
    from botocore.config import Config
    ddb = botocore.session.get_session().create_client(
        "dynamodb", region_name="us-east-1", endpoint_url="http://127.0.0.1:58000",
        config=Config(connect_timeout=1, read_timeout=5, retries={"max_attempts": 1}))
    try:
        existing = ddb.list_tables()["TableNames"]
    except Exception as e:
        pytest.skip(f"DynamoDB Local not running on :58000: {type(e).__name__}")
    if "VeilTest" in existing:
        ddb.delete_table(TableName="VeilTest")
    ddb.create_table(TableName="VeilTest", BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                           {"AttributeName": "SK", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}])
    for it in ITEMS:
        ddb.put_item(TableName="VeilTest", Item={k: v for k, v in it.items() if k != "GSI1PK"})
    k = KnownValues()
    seed(k, "dynamodb://local/VeilTest?endpoint=http://127.0.0.1:58000")
    assert k.group_of("leonekohler@surfeu.de") == k.group_of("Leonie Köhler") == "VeilTest:USER#leonekohler@surfeu.de"
    ddb.delete_table(TableName="VeilTest")
