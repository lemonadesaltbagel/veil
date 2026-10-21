"""Relational sources: SQLite, PostgreSQL, MySQL/MariaDB.

Each adapter only describes containers (columns + comments, primary key,
single-column foreign keys and whether they are unique) and streams records.
All connections are read-only; only text-like columns are ever selected.
"""

from __future__ import annotations

import ipaddress
import os
import pathlib
import sqlite3
import uuid
from typing import Any, Callable, Iterable

from ..detect import KnownValues
from .core import Container, Report, Seeder, classify_label, classify_quasi, plan

SAMPLE = 200


def _norm(v: Any) -> Any:
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Interface,
                      ipaddress.IPv6Interface, uuid.UUID)):
        return str(v)
    if isinstance(v, (list, tuple)):
        return [_norm(x) for x in v]
    if isinstance(v, (bytes, bytearray, memoryview)):
        return None
    return v


def run(known: KnownValues, containers: list[Container],
        fetch: Callable[[Container, list[str]], Iterable[dict]]) -> Report:
    seeder = Seeder(known)
    plans = {c.name: plan(c) for c in containers}
    for c in seeder.order(containers, plans):
        fields = plans[c.name]
        if not fields:
            continue
        cols = sorted({f.path.split(".")[0].removesuffix("[]") for f in fields})
        seeder.ingest(c, fields, fetch(c, cols))
    return seeder.report


# -- SQLite -------------------------------------------------------------------

def seed_sqlite(known: KnownValues, path: str, max_rows: int = 500_000) -> Report:
    db = sqlite3.connect(pathlib.Path(os.path.abspath(path)).as_uri() + "?mode=ro", uri=True)  # Windows-safe URI
    db.row_factory = sqlite3.Row
    q = lambda s: '"' + s.replace('"', '""') + '"'
    keys: dict[str, str] = {}

    def select(table: str, cols: list[str], limit: int):
        sel = ", ".join([f"{q(keys[table])} AS __key"] + [q(c) for c in cols])
        for r in db.execute(f"SELECT {sel} FROM {q(table)} LIMIT {int(limit)}"):
            yield dict(r)

    containers = []
    for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        info = db.execute(f"PRAGMA table_info({q(table)})").fetchall()
        pks = [r["name"] for r in info if r["pk"]]
        keys[table] = pks[0] if len(pks) == 1 else "rowid"
        types = {r["name"]: (r["type"] or "").upper() for r in info}
        text_cols = {c: {"json": "JSON" in t} for c, t in types.items()
                     if not t or any(x in t for x in ("CHAR", "TEXT", "CLOB", "JSON"))
                     or ("DATE" in t or "TIME" in t) and classify_quasi(c) == "dob"}
        unique = set()
        for ix in db.execute(f"PRAGMA index_list({q(table)})").fetchall():
            cols = db.execute(f"PRAGMA index_info({q(ix['name'])})").fetchall()
            if ix["unique"] and len(cols) == 1:
                unique.add(cols[0]["name"])
        fk_rows = db.execute(f"PRAGMA foreign_key_list({q(table)})").fetchall()
        multi = {r["id"] for r in fk_rows if r["seq"] > 0}
        fks = {r["from"]: (r["table"], r["from"] in unique) for r in fk_rows if r["id"] not in multi}
        if text_cols:
            sample = list(select(table, sorted(set(text_cols) | set(fks)), 200))
            containers.append(Container(table, "__key", text_cols, sample, fks))
    return run(known, containers, lambda c, cols: select(c.name, sorted(set(cols) | set(c.fks)), max_rows))


# -- PostgreSQL -------------------------------------------------------------

PG_COLUMNS = """
SELECT n.nspname, c.relname, a.attname, t.typname, t.typcategory, coalesce(et.typcategory, ''),
       col_description(c.oid, a.attnum)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
JOIN pg_type t ON t.oid = a.atttypid
LEFT JOIN pg_type et ON et.oid = t.typelem AND t.typcategory = 'A'
WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
ORDER BY 1, 2, a.attnum
"""
PG_INDEXES = """
SELECT n.nspname, c.relname, a.attname, i.indisprimary
FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
WHERE (i.indisprimary OR i.indisunique) AND i.indnatts = 1
"""
PG_LABELS = """
SELECT n.nspname AS s, c.relname AS t, a.attname AS c, l.label
FROM pg_seclabels l
JOIN pg_class c ON c.oid = l.objoid JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = l.objsubid
WHERE l.provider = 'anon' AND l.objtype = 'column'
"""
PG_FKS = """
SELECT cn.nspname AS s, cl.relname AS t, a.attname AS c, fn.nspname AS fs, fl.relname AS ft
FROM pg_constraint k
JOIN pg_class cl ON cl.oid = k.conrelid JOIN pg_namespace cn ON cn.oid = cl.relnamespace
JOIN pg_class fl ON fl.oid = k.confrelid JOIN pg_namespace fn ON fn.oid = fl.relnamespace
JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
WHERE k.contype = 'f' AND array_length(k.conkey, 1) = 1
"""


def _pg_name(schema: str, table: str) -> str:
    return table if schema == "public" else f"{schema}.{table}"


def seed_postgres(known: KnownValues, dsn: str, max_rows: int = 500_000) -> Report:
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    conn = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
    conn.execute("SET default_transaction_read_only = on")
    conn.execute("SET statement_timeout = '60s'")
    tables: dict[tuple[str, str], dict[str, dict]] = {}
    for r in conn.execute(PG_COLUMNS).fetchall():
        schema, table, col, typ, cat, elem_cat, comment = r.values()
        textish = cat in ("S", "I") or typ in ("json", "jsonb") or (cat == "A" and elem_cat in ("S", "I")) \
            or cat == "D" and classify_quasi(col) == "dob"  # dates only for a birth date
        tables.setdefault((schema, table), {})
        if textish:
            tables[(schema, table)][col] = {"json": typ in ("json", "jsonb"), "comment": comment}
    # Native classification: pg_anonymizer masking rules (SECURITY LABEL FOR anon ...)
    for r in conn.execute(PG_LABELS).fetchall():
        st, col, label = (r["s"], r["t"]), r["c"], r["label"]
        kind = classify_label(label)
        if kind and col in tables.get(st, {}):
            tables[st][col]["comment"] = f"pii:{kind}" if kind != "pii" else "pii"
    keys, unique = {}, set()
    for r in conn.execute(PG_INDEXES).fetchall():
        schema, table, col, primary = r.values()
        if primary:
            keys[(schema, table)] = col
        unique.add((schema, table, col))
    fks: dict[tuple[str, str], dict] = {}
    for r in conn.execute(PG_FKS).fetchall():
        schema, table, col, fschema, ftable = r.values()
        fks.setdefault((schema, table), {})[col] = (_pg_name(fschema, ftable), (schema, table, col) in unique)

    def select(st: tuple[str, str], cols: list[str], limit: int):
        key = keys.get(st)
        key_expr = sql.Identifier(key) if key else sql.SQL("ctid::text")
        q = sql.SQL("SELECT {} AS __key{} FROM {}.{} LIMIT {}").format(
            key_expr, sql.SQL("").join(sql.SQL(", ") + sql.Identifier(c) for c in cols),
            sql.Identifier(st[0]), sql.Identifier(st[1]), sql.Literal(limit))
        for row in conn.execute(q):
            yield {k: _norm(v) for k, v in row.items()}

    containers, by_name = [], {}
    for st, cols in tables.items():
        fk = fks.get(st, {})
        if not cols:
            continue
        sel = sorted(set(cols) | set(fk))
        c = Container(_pg_name(*st), "__key", cols, list(select(st, sel, 200)), fk)
        containers.append(c)
        by_name[c.name] = st

    def fetch(c: Container, cols: list[str]):
        return select(by_name[c.name], sorted(set(cols) | set(c.fks)), max_rows)
    return run(known, containers, fetch)


# -- MySQL / MariaDB ----------------------------------------------------------

def seed_mysql(known: KnownValues, host: str, user: str, password: str, database: str,
               port: int = 3306, max_rows: int = 500_000) -> Report:
    import pymysql

    conn = pymysql.connect(host=host, port=port, user=user, password=password, database=database,
                           cursorclass=pymysql.cursors.DictCursor, charset="utf8mb4")
    with conn.cursor() as cur:
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        cur.execute("""SELECT TABLE_NAME t, COLUMN_NAME c, DATA_TYPE d, COLUMN_KEY k, COLUMN_COMMENT m
                       FROM information_schema.COLUMNS c JOIN information_schema.TABLES USING (TABLE_SCHEMA, TABLE_NAME)
                       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
                       ORDER BY TABLE_NAME, ORDINAL_POSITION""")
        cols_rows = cur.fetchall()
        cur.execute("""SELECT TABLE_NAME t, COLUMN_NAME c, REFERENCED_TABLE_NAME r, CONSTRAINT_NAME n
                       FROM information_schema.KEY_COLUMN_USAGE
                       WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL""")
        fk_rows = cur.fetchall()
    text_types = {"char", "varchar", "tinytext", "text", "mediumtext", "longtext", "json", "enum", "set"}
    tables: dict[str, dict] = {}
    keys, unique = {}, set()
    for r in cols_rows:
        tables.setdefault(r["t"], {})
        if r["k"] == "PRI":
            keys.setdefault(r["t"], []).append(r["c"])
        if r["k"] in ("PRI", "UNI"):
            unique.add((r["t"], r["c"]))
        if r["d"].lower() in text_types or \
                r["d"].lower() in ("date", "datetime", "timestamp") and classify_quasi(r["c"]) == "dob":
            tables[r["t"]][r["c"]] = {"json": r["d"].lower() == "json", "comment": r["m"] or None}
    per_constraint: dict[str, list] = {}
    for r in fk_rows:
        per_constraint.setdefault((r["t"], r["n"]), []).append(r)
    fks: dict[str, dict] = {}
    for rows in per_constraint.values():
        if len(rows) == 1:
            r = rows[0]
            fks.setdefault(r["t"], {})[r["c"]] = (r["r"], (r["t"], r["c"]) in unique)

    q = lambda s: "`" + s.replace("`", "``") + "`"

    def select(table: str, cols: list[str], limit: int):
        key = keys.get(table, [])
        key_expr = q(key[0]) if len(key) == 1 else "NULL"
        with conn.cursor(pymysql.cursors.SSDictCursor) as cur:
            cur.execute(f"SELECT {key_expr} AS __key{''.join(', ' + q(c) for c in cols)} FROM {q(table)} LIMIT {int(limit)}")
            for i, row in enumerate(cur):
                if row["__key"] is None:
                    row["__key"] = i
                yield row

    containers = []
    for table, cols in tables.items():
        if cols:
            fk = fks.get(table, {})
            containers.append(Container(table, "__key", cols, list(select(table, sorted(set(cols) | set(fk)), 200)), fk))
    return run(known, containers, lambda c, cols: select(c.name, sorted(set(cols) | set(c.fks)), max_rows))
