"""SQL Server seeding with native classification (sys.sensitivity_classifications,
dynamic data masking, MS_Description), against a fake DB-API connection that answers
the catalog queries the seeder sends."""

import re

from veil.detect import KnownValues
from veil.sources import mssql

CUSTOMERS = [
    {"CustomerId": i, "ContactName": n, "Reach": e, "Notes": note, "BirthDate": dob, "NationalCode": nid,
     "Region": "EMEA", "Gateway": ip}
    for i, (n, e, note, dob, nid, ip) in enumerate([
        ("Leonie Köhler", "leonekohler@surfeu.de", "prefers calls after 5", "1978-03-02 00:00:00", "DE-77812345", "84.191.20.7"),
        ("Bjørn Hansen", "bjorn.hansen@yahoo.no", "VIP since 2019", "1981-11-30 00:00:00", "NO-11223344", "81.2.69.160"),
    ], start=1)
]
ORDERS = [{"OrderId": 10, "CustomerId": 1, "ShipAddress": "Theodor-Heuss-Straße 34"},
          {"OrderId": 11, "CustomerId": 2, "ShipAddress": "Ullevålsveien 14"}]
TABLES = {("dbo", "Customers"): CUSTOMERS, ("sales", "Orders"): ORDERS}

CATALOG = {
    mssql.COLUMNS: [
        ("dbo", "Customers", "CustomerId", "int", None),
        ("dbo", "Customers", "ContactName", "nvarchar", None),
        ("dbo", "Customers", "Reach", "nvarchar", None),                       # masked with email()
        ("dbo", "Customers", "Notes", "nvarchar", None),                       # classified "Other"
        ("dbo", "Customers", "BirthDate", "datetime2", None),                  # classified "Date Of Birth"
        ("dbo", "Customers", "NationalCode", "varchar", None),                 # classified "National ID"
        ("dbo", "Customers", "Region", "nvarchar", None),                      # labelled Public
        ("dbo", "Customers", "Gateway", "varchar", "pii:ipv4 (support only)"),  # MS_Description tag
        ("sales", "Orders", "OrderId", "int", None),
        ("sales", "Orders", "CustomerId", "int", None),
        ("sales", "Orders", "ShipAddress", "nvarchar", None),
    ],
    mssql.CLASSIFICATIONS: [
        ("dbo", "Customers", "Notes", "Other", "Confidential"),
        ("dbo", "Customers", "BirthDate", "Date Of Birth", "Confidential - GDPR"),
        ("dbo", "Customers", "NationalCode", "National ID", "Highly Confidential"),
        ("dbo", "Customers", "Region", None, "Public"),
    ],
    mssql.MASKS: [("dbo", "Customers", "Reach", "email()")],
    mssql.KEYS: [("dbo", "Customers", "CustomerId", True), ("sales", "Orders", "OrderId", True)],
    mssql.FKS: [("sales", "Orders", "CustomerId", "dbo", "Customers")],
}


class FakeCursor:
    def __init__(self):
        self.result, self.description = [], None
        self.queries = []

    def execute(self, sql):
        self.queries.append(sql)
        if sql in CATALOG:
            self.result = CATALOG[sql]
            return
        m = re.match(r"SELECT TOP \((\d+)\) (.*) FROM \[(\w+)\]\.\[(\w+)\]$", sql)
        assert m, sql
        limit, sel, schema, table = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        exprs = [e.strip() for e in sel.split(",")]
        names, cols = [], []
        for e in exprs:
            col, _, alias = e.partition(" AS ")
            names.append(alias or col.strip("[]"))
            cols.append(col.strip("[]"))
        self.description = [(n,) for n in names]
        self.result = [tuple(r[c] for c in cols) for r in TABLES[(schema, table)][:limit]]

    def fetchall(self):
        return self.result


class FakeConn:
    def __init__(self):
        self.cur = FakeCursor()
        self.closed = False

    def cursor(self):
        return self.cur

    def close(self):
        self.closed = True


def test_native_classification_drives_seeding():
    conn = FakeConn()
    known = KnownValues()
    report = mssql.seed_mssql(known, "mssql://u:p@db/app", connect=lambda: conn)
    kinds = {(f.container, f.path): (f.kind, f.signal) for f in report.fields}
    assert kinds[("Customers", "Reach")] == ("email", "comment")             # email() mask
    assert kinds[("Customers", "NationalCode")] == ("id_number", "comment")  # National ID
    assert kinds[("Customers", "Notes")][0] == "pii"                         # Other / Confidential
    assert kinds[("Customers", "BirthDate")][0] == "qi:dob"                  # a quasi-identifier
    assert kinds[("Customers", "Gateway")] == ("ipv4", "comment")            # MS_Description pii:ipv4
    assert kinds[("Customers", "ContactName")][0] == "name"                  # name rules still apply
    assert ("Customers", "Region") not in kinds                              # labelled Public
    assert known.group_of("Theodor-Heuss-Straße 34") == known.group_of("leonekohler@surfeu.de")  # FK grouping
    assert known.canonical("DE-77812345") and "1978-03-02" in known._quasi
    assert conn.closed
    assert all(q.startswith("SELECT") or q.lstrip().startswith("SELECT") for q in conn.cur.queries)  # read-only


def test_classify_native_contact_info_uses_the_column_name():
    assert mssql.classify_native("Contact Info", "Confidential", "WorkEmail") == "pii:email"
    assert mssql.classify_native("Contact Info", "Confidential", "MobilePhone") == "pii:phone"
    assert mssql.classify_native("Contact Info", "Confidential", "Stuff") == "pii"
    assert mssql.classify_native(None, "Public", "x") is None
