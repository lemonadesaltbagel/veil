"""Snowflake (fake DB-API connection) and BigQuery (fake REST API): native privacy
classification drives seeding."""

import json
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

import httpx

from veil.detect import KnownValues
from veil.proxy import LocalHTTPServer
from veil.sources import warehouse

# -- Snowflake -------------------------------------------------------------------
SF_ROWS = [("Leonie Köhler", "leonekohler@surfeu.de", "078-05-1120", "1978-03-02", '{"tier": "gold"}', "EU"),
           ("Bjørn Hansen", "bjorn.hansen@yahoo.no", "219-09-9999", "1981-11-30", '{"tier": "free"}', "EU")]
SF_COLS = ["CONTACT", "REACH", "GOV_ID", "BIRTH", "PROFILE", "REGION"]


class SFCursor:
    def __init__(self):
        self.description, self.result = None, []

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        if "information_schema.columns" in s:
            self.result = [("CRM", "PEOPLE", c, t, None) for c, t in zip(SF_COLS, ["VARCHAR", "VARCHAR", "VARCHAR", "DATE", "VARIANT", "VARCHAR"])]
        elif "account_usage.tag_references" in s:
            raise RuntimeError("Insufficient privileges")          # fall back to the per-table function
        elif "tag_references_all_columns" in s:
            assert params == ("CRM.PEOPLE",)
            self.result = [("CONTACT", "SNOWFLAKE.CORE.SEMANTIC_CATEGORY", "NAME"),
                           ("REACH", "SNOWFLAKE.CORE.SEMANTIC_CATEGORY", "EMAIL"),
                           ("GOV_ID", "SNOWFLAKE.CORE.SEMANTIC_CATEGORY", "US_SSN"),
                           ("BIRTH", "SNOWFLAKE.CORE.SEMANTIC_CATEGORY", "DATE_OF_BIRTH"),
                           ("REGION", "SNOWFLAKE.CORE.PRIVACY_CATEGORY", "QUASI_IDENTIFIER")]
        elif s.startswith("SELECT"):
            cols = [c.strip('"') for c in s[len("SELECT "):s.index(" FROM ")].split(", ")]
            self.description = [(c,) for c in cols]
            self.result = [tuple(dict(zip(SF_COLS, r))[c] for c in cols) for r in SF_ROWS]
        else:
            raise AssertionError(s)

    def fetchall(self):
        return self.result


class SFConn:
    def cursor(self):
        return SFCursor()

    def close(self):
        pass


def test_snowflake_semantic_categories():
    k = KnownValues()
    report = warehouse.seed_snowflake(k, "snowflake://u:p@acct/APP/CRM", connect=SFConn)
    kinds = {f.path: (f.kind, f.signal) for f in report.fields}
    assert kinds["CONTACT"] == ("name", "comment") and kinds["REACH"] == ("email", "comment")
    assert kinds["GOV_ID"] == ("id_number", "comment") and kinds["BIRTH"][0] == "qi:dob"
    assert "REGION" not in kinds                                   # a quasi tag without category: names decide
    assert k.group_of("Leonie Köhler") == k.group_of("leonekohler@surfeu.de") and k.canonical("078-05-1120")


# -- BigQuery --------------------------------------------------------------------
BQ_SCHEMA = {"fields": [
    {"name": "user_id", "type": "INTEGER"},
    {"name": "display", "type": "STRING", "description": "pii:name"},
    {"name": "contact", "type": "STRING", "policyTags": {"names": ["projects/p/locations/eu/taxonomies/1/policyTags/2"]}},
    {"name": "plan", "type": "STRING"},
    {"name": "profile", "type": "RECORD", "fields": [
        {"name": "emails", "type": "STRING", "mode": "REPEATED"},
        {"name": "address", "type": "RECORD", "fields": [{"name": "city", "type": "STRING"}]}]}]}
BQ_ROWS = [{"f": [{"v": "1"}, {"v": "Leonie Köhler"}, {"v": "+49 0711 2842222"}, {"v": "pro"},
                  {"v": {"f": [{"v": [{"v": "leonekohler@surfeu.de"}, {"v": "leonie.k@work.example.de"}]},
                               {"v": {"f": [{"v": "Stuttgart"}]}}]}}]},
           {"f": [{"v": "2"}, {"v": "Bjørn Hansen"}, {"v": "+47 22 44 22 22"}, {"v": "free"},
                  {"v": {"f": [{"v": [{"v": "bjorn.hansen@yahoo.no"}]}, {"v": {"f": [{"v": "Oslo"}]}}]}}]}]


def _bq_server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            p = urlparse(self.path).path
            if p.endswith("/datasets"):
                out = {"datasets": [{"datasetReference": {"datasetId": "app"}}]}
            elif p.endswith("/tables"):
                out = {"tables": [{"tableReference": {"tableId": "users"}, "type": "TABLE"},
                                  {"tableReference": {"tableId": "users_view"}, "type": "VIEW"}]}
            elif p.endswith("/tables/users"):
                out = {"schema": BQ_SCHEMA, "numRows": "2"}
            elif p.endswith("/tables/users/data"):
                out = {"rows": BQ_ROWS, "totalRows": "2"}
            else:
                self.send_response(404); self.end_headers(); return
            data = json.dumps(out).encode()
            self.send_response(200); self.send_header("content-length", str(len(data))); self.end_headers()
            self.wfile.write(data)
    srv = LocalHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_bigquery_policy_tags_descriptions_and_nested_fields():
    srv = _bq_server()
    try:
        client = httpx.Client(base_url=f"http://127.0.0.1:{srv.server_port}/bigquery/v2", trust_env=False)
        k = KnownValues()
        report = warehouse.seed_bigquery(k, "bigquery://proj", client=client)
    finally:
        srv.shutdown()
    kinds = {f.path: f.kind for f in report.fields}
    assert kinds["display"] == "name" and kinds["contact"] == "pii"     # policy tag; 2 rows are too few to sample
    assert kinds["profile.emails[]"] == "email" and kinds.get("profile.address.city") == "qi:city"
    assert "plan" not in kinds
    assert k.group_of("Leonie Köhler") == k.group_of("leonie.k@work.example.de") == k.group_of("+49 0711 2842222")
