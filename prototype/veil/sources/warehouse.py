"""Warehouses: Snowflake and BigQuery, native privacy classification first.

Snowflake  (pip install snowflake-connector-python)
    snowflake://user:pass@account/DATABASE[/SCHEMA]?warehouse=WH&role=ROLE
    Tags from Snowflake's classification -- SNOWFLAKE.CORE.SEMANTIC_CATEGORY (EMAIL, NAME,
    PHONE_NUMBER, US_SSN, DATE_OF_BIRTH, ...) and PRIVACY_CATEGORY (IDENTIFIER /
    QUASI_IDENTIFIER / SENSITIVE) -- via ACCOUNT_USAGE.TAG_REFERENCES (needs a grant),
    else INFORMATION_SCHEMA.TAG_REFERENCES_ALL_COLUMNS per table; column comments
    (`pii:email`); then names and sampled values. VARIANT/OBJECT columns are JSON.

BigQuery   (REST; token from VEIL_BIGQUERY_TOKEN or `gcloud auth print-access-token`)
    bigquery://PROJECT[/DATASET[,DATASET]]
    Schema fields with policy tags (column-level security) are sensitive; field
    descriptions carry `pii:<kind>`; RECORD/REPEATED fields are nested paths.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from ..detect import KnownValues
from .core import Container, Report
from .sql import _norm, run

# Snowflake semantic categories -> veil kinds (qi:* are quasi-identifiers)
SEMANTIC = {"EMAIL": "email", "NAME": "name", "PHONE_NUMBER": "phone", "IP_ADDRESS": "ipv4",
            "STREET_ADDRESS": "address", "US_SSN": "id_number", "NATIONAL_IDENTIFIER": "id_number",
            "PASSPORT": "id_number", "DRIVERS_LICENSE": "id_number", "IBAN": "id_number", "TAX_IDENTIFIER": "id_number",
            "PAYMENT_CARD": "secret", "BANK_ACCOUNT": "id_number", "DATE_OF_BIRTH": "qi:dob", "CITY": "qi:city",
            "POSTAL_CODE": "qi:postal_code", "ORGANIZATION_IDENTIFIER": "qi:company", "OCCUPATION": "qi:job_title"}
TEXTY = ("VARCHAR", "TEXT", "STRING", "CHAR", "VARIANT", "OBJECT", "ARRAY")


def _tag_comment(semantic: str | None, privacy: str | None) -> str | None:
    kind = SEMANTIC.get((semantic or "").upper())
    if kind:
        return "pii:" + kind[3:] if kind.startswith("qi:") else f"pii:{kind}"
    if (privacy or "").upper() in ("IDENTIFIER", "SENSITIVE"):
        return "pii"
    return None  # QUASI_IDENTIFIER without a category: name rules decide


def _snowflake_connect(uri: str):
    import snowflake.connector  # pip install snowflake-connector-python
    u = urlparse(uri)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    db, _, schema = u.path.strip("/").partition("/")
    return snowflake.connector.connect(account=u.hostname, user=unquote(u.username or ""),
                                       password=unquote(u.password or ""), database=db, schema=schema or None, **q)


def seed_snowflake(known: KnownValues, uri: str, connect: Callable[[], Any] | None = None,
                   max_rows: int = 500_000) -> Report:
    conn = connect() if connect else _snowflake_connect(uri)
    cur = conn.cursor()
    schema_filter = urlparse(uri).path.strip("/").partition("/")[2].upper()

    def rows(sql: str, params=None) -> list[tuple]:
        try:
            cur.execute(sql, params) if params else cur.execute(sql)
            return list(cur.fetchall())
        except Exception:
            return []

    q = lambda s: '"' + s.replace('"', '""') + '"'
    tables: dict[tuple[str, str], dict] = {}
    for schema, table, col, typ, comment in rows(
            "SELECT table_schema, table_name, column_name, data_type, comment FROM information_schema.columns "
            "WHERE table_schema <> 'INFORMATION_SCHEMA' ORDER BY table_schema, table_name, ordinal_position"):
        if schema_filter and schema.upper() != schema_filter:
            continue
        tables.setdefault((schema, table), {})
        if typ.upper().startswith(TEXTY) or typ.upper() in ("DATE", "TIMESTAMP_NTZ") and "BIRTH" in col.upper():
            tables[(schema, table)][col] = {"json": typ.upper() in ("VARIANT", "OBJECT", "ARRAY"), "comment": comment}
    tags: dict[tuple[str, str, str], dict[str, str]] = {}
    ref = rows("SELECT object_schema, object_name, column_name, tag_name, tag_value "
               "FROM snowflake.account_usage.tag_references WHERE domain = 'COLUMN' "
               "AND object_database = CURRENT_DATABASE() AND object_deleted IS NULL")
    if not ref:  # no ACCOUNT_USAGE grant: ask table by table
        for schema, table in tables:
            ref += [(schema, table, c, n, v) for c, n, v in rows(
                "SELECT column_name, tag_name, tag_value FROM TABLE(information_schema.tag_references_all_columns("
                "%s, 'table'))", (f"{schema}.{table}",))]
    for schema, table, col, name, value in ref:
        tags.setdefault((schema, table, col), {})[name.upper().split(".")[-1]] = value  # SNOWFLAKE.CORE.X -> X
    for (schema, table, col), t in tags.items():
        meta = tables.get((schema, table), {}).get(col)
        tag = _tag_comment(t.get("SEMANTIC_CATEGORY"), t.get("PRIVACY_CATEGORY"))
        if meta is not None and tag:
            meta["comment"] = tag

    def select(st, cols: list[str], limit: int, sample: bool = False):
        cur.execute(f"SELECT {', '.join(q(c) for c in cols)} FROM {q(st[0])}.{q(st[1])}"
                    + (" SAMPLE (300 ROWS)" if sample else f" LIMIT {int(limit)}"))
        names = [d[0] for d in cur.description]
        for i, r in enumerate(cur.fetchall()):
            yield {"__key": i, **{k: _norm(v) for k, v in zip(names, r)}}

    containers, by_name = [], {}
    for st, cols in tables.items():
        if cols:
            c = Container(f"{st[0]}.{st[1]}".lower(), "__key", cols, list(select(st, sorted(cols), 300, True)), {})
            containers.append(c)
            by_name[c.name] = st
    try:
        return run(known, containers, lambda c, cols: select(by_name[c.name], cols, max_rows))
    finally:
        conn.close()


# -- BigQuery -----------------------------------------------------------------------

API = "https://bigquery.googleapis.com/bigquery/v2"


def _bq_token() -> str | None:
    tok = os.environ.get("VEIL_BIGQUERY_TOKEN")
    if tok:
        return tok
    try:
        return subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True,
                              timeout=30).stdout.strip() or None
    except OSError:
        return None


def _bq_fields(fields: list[dict], prefix: str = "") -> dict[str, dict]:
    out = {}
    for f in fields or []:
        path = prefix + f["name"] + ("[]" if f.get("mode") == "REPEATED" else "")
        if f.get("type") in ("RECORD", "STRUCT"):
            out.update(_bq_fields(f.get("fields"), path + "."))
        elif f.get("type") in ("STRING", "JSON") or (f.get("type") in ("DATE", "DATETIME") and "birth" in f["name"].lower()):
            desc = f.get("description") or ""
            tagged = "pii" if (f.get("policyTags") or {}).get("names") else None
            out[path] = {"json": f.get("type") == "JSON", "comment": desc if "pii" in desc.lower() else tagged}
    return out


def _bq_value(field: dict, cell: Any) -> Any:
    v = cell.get("v") if isinstance(cell, dict) else cell
    if v is None:
        return None
    if field.get("mode") == "REPEATED":
        return [_bq_value({**field, "mode": "NULLABLE"}, x) for x in v]
    if field.get("type") in ("RECORD", "STRUCT"):
        return {sf["name"]: _bq_value(sf, c) for sf, c in zip(field["fields"], v["f"])}
    return v


def seed_bigquery(known: KnownValues, uri: str, client: httpx.Client | None = None,
                  max_rows: int = 500_000) -> Report:
    u = urlparse(uri)
    project, datasets = u.hostname, [d for d in u.path.strip("/").split(",") if d]
    own = client is None
    if own:
        tok = _bq_token()
        client = httpx.Client(base_url=API, headers={"authorization": f"Bearer {tok}"} if tok else {}, timeout=60)
    get = lambda path, **params: client.get(path, params=params).raise_for_status().json()
    if not datasets:
        datasets = [d["datasetReference"]["datasetId"] for d in get(f"/projects/{project}/datasets").get("datasets", [])]
    schemas = {}
    for ds in datasets:
        for t in get(f"/projects/{project}/datasets/{ds}/tables").get("tables", []):
            if t.get("type", "TABLE") != "TABLE":
                continue
            tid = t["tableReference"]["tableId"]
            schemas[(ds, tid)] = get(f"/projects/{project}/datasets/{ds}/tables/{tid}")["schema"]["fields"]

    def rows(ds_t, limit: int):
        fields, token, n = schemas[ds_t], None, 0
        while n < limit:
            params = {"maxResults": min(10_000, limit - n)}
            if token:
                params["pageToken"] = token
            page = get(f"/projects/{project}/datasets/{ds_t[0]}/tables/{ds_t[1]}/data", **params)
            for r in page.get("rows", []):
                yield {"__key": n, **{f["name"]: _bq_value(f, c) for f, c in zip(fields, r["f"])}}
                n += 1
            token = page.get("pageToken")
            if not token:
                return

    containers, by_name = [], {}
    for ds_t, fields in schemas.items():
        cols = {p.split(".")[0].removesuffix("[]"): {"json": True, "comment": None} for p in _bq_fields(fields)}
        flat = _bq_fields(fields)
        for p, meta in flat.items():  # tags on top-level columns (nested paths: names and values decide)
            if "." not in p:
                cols[p.removesuffix("[]")] = meta
        if cols:
            c = Container(f"{ds_t[0]}.{ds_t[1]}", "__key", cols, list(rows(ds_t, 300)), {})
            containers.append(c)
            by_name[c.name] = ds_t
    try:
        return run(known, containers, lambda c, _cols: rows(by_name[c.name], max_rows))
    finally:
        if own:
            client.close()
