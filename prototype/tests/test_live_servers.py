"""Seeders against real servers (CI service containers; skipped when not running):
SQL Server with native sensitivity classification and masking, Elasticsearch."""

import json

import httpx
import pytest

from veil.detect import KnownValues
from veil.engine import Veil
from veil.mcpdb import Server, open_source
from veil.reseed import fingerprint
from veil.sources import seed
from veil.vault import Vault

MSSQL = "mssql://sa:Veil_Test_Pw1!@127.0.0.1:51433/{db}"
ES = "http://127.0.0.1:59200"


def _mssql(db="master"):
    pymssql = pytest.importorskip("pymssql")
    try:
        return pymssql.connect(server="127.0.0.1", port=51433, user="sa", password="Veil_Test_Pw1!", database=db,
                               login_timeout=3, autocommit=True)
    except Exception as e:
        pytest.skip(f"SQL Server not running on :51433: {type(e).__name__}")


def test_sql_server_native_classification_live():
    c = _mssql()
    cur = c.cursor()
    cur.execute("IF DB_ID('veiltest') IS NULL CREATE DATABASE veiltest")
    c.close()
    c = _mssql("veiltest")
    cur = c.cursor()
    for stmt in [
        "DROP TABLE IF EXISTS dbo.Orders", "DROP TABLE IF EXISTS dbo.Customers",
        "CREATE TABLE dbo.Customers (CustomerId int PRIMARY KEY, ContactName nvarchar(100), "
        "Reach nvarchar(200) MASKED WITH (FUNCTION = 'email()'), Notes nvarchar(400), NationalCode varchar(40), "
        "BirthDate date, Region nvarchar(20), Gateway varchar(40))",
        "CREATE TABLE dbo.Orders (OrderId int PRIMARY KEY, CustomerId int REFERENCES dbo.Customers(CustomerId), "
        "ShipAddress nvarchar(200))",
        "INSERT INTO dbo.Customers VALUES (1, N'Leonie Köhler', N'leonekohler@surfeu.de', N'prefers calls after 5', "
        "'DE-77812345', '1978-03-02', N'EMEA', '84.191.20.7'), (2, N'Bjørn Hansen', N'bjorn.hansen@yahoo.no', "
        "N'VIP since 2019', 'NO-11223344', '1981-11-30', N'EMEA', '81.2.69.160')",
        "INSERT INTO dbo.Orders VALUES (10, 1, N'Theodor-Heuss-Straße 34'), (11, 2, N'Ullevålsveien 14')",
        "ADD SENSITIVITY CLASSIFICATION TO dbo.Customers.Notes WITH (LABEL = 'Confidential', INFORMATION_TYPE = 'Other')",
        "ADD SENSITIVITY CLASSIFICATION TO dbo.Customers.BirthDate WITH (LABEL = 'Confidential - GDPR', INFORMATION_TYPE = 'Date Of Birth')",
        "ADD SENSITIVITY CLASSIFICATION TO dbo.Customers.NationalCode WITH (LABEL = 'Highly Confidential', INFORMATION_TYPE = 'National ID')",
        "ADD SENSITIVITY CLASSIFICATION TO dbo.Customers.Region WITH (LABEL = 'Public')",
        "EXEC sp_addextendedproperty 'MS_Description', 'pii:ipv4 (support only)', 'SCHEMA', 'dbo', 'TABLE', "
        "'Customers', 'COLUMN', 'Gateway'",
    ]:
        cur.execute(stmt)
    c.close()
    k = KnownValues()
    report = seed(k, MSSQL.format(db="veiltest"))
    kinds = {(f.container, f.path): f.kind for f in report.fields}
    assert kinds[("Customers", "Reach")] == "email" and kinds[("Customers", "NationalCode")] == "id_number"
    assert kinds[("Customers", "Notes")] == "pii" and kinds[("Customers", "BirthDate")] == "qi:dob"
    assert kinds[("Customers", "Gateway")] == "ipv4" and ("Customers", "Region") not in kinds
    assert k.group_of("Theodor-Heuss-Straße 34") == k.group_of("leonekohler@surfeu.de")   # FK grouping
    # and the agent's database tool, by pseudonym, on the real server
    veil = Veil(Vault(":memory:", b"s"), k)
    out = Server(veil, open_source(MSSQL.format(db="veiltest"))).call("query", {
        "sql": f"SELECT ContactName, Reach FROM dbo.Customers WHERE Reach = '{veil.redact('leonekohler@surfeu.de')}'"})
    assert "(1 row)" in out and "leonekohler" not in out and "Köhler" not in out


def test_elasticsearch_live():
    try:
        httpx.get(ES, timeout=2, trust_env=False).raise_for_status()
    except Exception as e:
        pytest.skip(f"Elasticsearch not running on :59200: {type(e).__name__}")
    with httpx.Client(base_url=ES, timeout=30, trust_env=False) as es:
        es.delete("/veil_orders")
        es.put("/veil_orders", json={"mappings": {"properties": {
            "customer_id": {"type": "keyword"}, "customer_full_name": {"type": "text"},
            "email": {"type": "keyword"}, "user": {"type": "keyword"}, "notes": {"type": "text", "meta": {"pii": "true"}},
            "taxful_total_price": {"type": "half_float"}}}}).raise_for_status()
        docs = [{"customer_id": "38", "customer_full_name": "Eddie Underwood", "email": "eddie@underwood-family.zzz",
                 "user": "eddie", "notes": "leave at the back door", "taxful_total_price": 36.98},
                {"customer_id": "38", "customer_full_name": "Eddie Underwood", "email": "eddie@underwood-family.zzz",
                 "user": "eddie", "notes": "", "taxful_total_price": 12.5},
                {"customer_id": "17", "customer_full_name": "Mary Bailey", "email": "mary@bailey-family.zzz",
                 "user": "mary", "notes": "", "taxful_total_price": 9.0}]
        body = "".join(json.dumps({"index": {}}) + "\n" + json.dumps(d) + "\n" for d in docs)
        es.post("/veil_orders/_bulk?refresh=true", content=body, headers={"content-type": "application/x-ndjson"}).raise_for_status()
        k = KnownValues()
        report = seed(k, "elasticsearch://127.0.0.1:59200/veil_orders")
        kinds = {f.path: f.kind for f in report.fields}
        assert kinds["email"] == "email" and kinds["customer_full_name"] == "name" and kinds["notes"] == "pii"
        assert k.group_of("Eddie Underwood") == k.group_of("eddie@underwood-family.zzz") == "veil_orders:38"
        before = fingerprint("elasticsearch://127.0.0.1:59200/veil_orders")
        es.post("/veil_orders/_doc?refresh=true", json={**docs[2], "customer_id": "99", "email": "new@x.zzz"})
        assert fingerprint("elasticsearch://127.0.0.1:59200/veil_orders") != before
        es.delete("/veil_orders")
