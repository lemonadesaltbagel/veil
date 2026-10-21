"""SQL Server seeding, using its native classification first.

  sys.sensitivity_classifications  (SQL Server 2019+ / Azure SQL: ADD SENSITIVITY CLASSIFICATION)
  sys.masked_columns                (dynamic data masking: email() => email, partial()/default() => pii)
  MS_Description extended property  (column comments: `pii:email`)
then the usual name rules and value sampling. Read-only; text-like columns only (plus
date columns named for a birth date).

    veil seed "mssql://user:pass@host:1433/app"        (pip install pymssql)
"""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import unquote, urlparse

from ..detect import KnownValues
from .core import Container, Report, classify_quasi
from .sql import _norm, run

TEXT = {"char", "varchar", "nchar", "nvarchar", "text", "ntext", "sysname"}
DATES = {"date", "datetime", "datetime2", "smalldatetime", "datetimeoffset"}

COLUMNS = """
SELECT s.name, t.name, c.name, ty.name, CAST(ep.value AS nvarchar(4000))
FROM sys.columns c
JOIN sys.tables t ON t.object_id = c.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.types ty ON ty.user_type_id = c.user_type_id
LEFT JOIN sys.extended_properties ep
  ON ep.major_id = c.object_id AND ep.minor_id = c.column_id AND ep.class = 1 AND ep.name = 'MS_Description'
WHERE t.is_ms_shipped = 0
"""
CLASSIFICATIONS = """
SELECT SCHEMA_NAME(o.schema_id), o.name, c.name, CAST(sc.information_type AS nvarchar(256)), CAST(sc.label AS nvarchar(256))
FROM sys.sensitivity_classifications sc
JOIN sys.objects o ON o.object_id = sc.major_id
JOIN sys.columns c ON c.object_id = sc.major_id AND c.column_id = sc.minor_id
"""
MASKS = """
SELECT OBJECT_SCHEMA_NAME(mc.object_id), OBJECT_NAME(mc.object_id), mc.name, mc.masking_function
FROM sys.masked_columns mc
"""
KEYS = """
SELECT s.name, t.name, c.name, i.is_primary_key
FROM sys.indexes i
JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
JOIN sys.tables t ON t.object_id = i.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE (i.is_primary_key = 1 OR i.is_unique = 1)
  AND (SELECT COUNT(*) FROM sys.index_columns x WHERE x.object_id = i.object_id AND x.index_id = i.index_id) = 1
"""
FKS = """
SELECT SCHEMA_NAME(pt.schema_id), pt.name, pc.name, SCHEMA_NAME(rt.schema_id), rt.name
FROM sys.foreign_key_columns fkc
JOIN sys.tables pt ON pt.object_id = fkc.parent_object_id
JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
JOIN sys.tables rt ON rt.object_id = fkc.referenced_object_id
WHERE (SELECT COUNT(*) FROM sys.foreign_key_columns x WHERE x.constraint_object_id = fkc.constraint_object_id) = 1
"""

# Information types of SQL Server's built-in taxonomy (and Purview) -> veil kinds.
# None: decided by the column name (Contact Info is an email, a phone or an address).
INFO_TYPES = {"name": "name", "contact info": None, "national id": "id_number", "ssn": "id_number",
              "credit card": "secret", "banking": "id_number", "financial": "pii", "credentials": "secret",
              "networking": "ipv4", "date of birth": "qi:dob", "health": "pii", "other": "pii"}


def classify_native(info_type: str | None, label: str | None, column: str) -> str | None:
    """`pii:<kind>` / `pii` comment for planning, or None when the label says not sensitive."""
    if (label or "").strip().lower() == "public":
        return None
    if info_type is None and label is None:
        return None
    kind = INFO_TYPES.get((info_type or "").strip().lower(), "pii")
    if kind is None:
        from .core import classify_name
        kind = classify_name("contact", column) or "pii"
    if kind.startswith("qi:"):
        return "pii:" + kind[3:]
    return f"pii:{kind}" if kind != "pii" else "pii"


def _mask_kind(fn: str | None) -> str | None:
    fn = (fn or "").lower()
    if fn.startswith("email("):
        return "pii:email"
    if fn.startswith(("partial(", "default(")):
        return "pii"
    return None  # random(): numeric, not seeded


def _connect(uri: str):
    import pymssql  # pip install pymssql
    u = urlparse(uri)
    return pymssql.connect(server=u.hostname or "127.0.0.1", port=u.port or 1433, user=unquote(u.username or ""),
                           password=unquote(u.password or ""), database=u.path.lstrip("/"), login_timeout=10,
                           read_only=True)


def seed_mssql(known: KnownValues, uri: str, connect: Callable[[], Any] | None = None,
               max_rows: int = 500_000) -> Report:
    conn = connect() if connect else _connect(uri)
    cur = conn.cursor()

    def rows(sql: str) -> list[tuple]:
        try:
            cur.execute(sql)
            return list(cur.fetchall())
        except Exception:  # an older server without the catalog view, or no permission
            return []

    q = lambda s: "[" + s.replace("]", "]]") + "]"
    tables: dict[tuple[str, str], dict[str, dict]] = {}
    for schema, table, col, typ, desc in rows(COLUMNS):
        tables.setdefault((schema, table), {})
        if typ.lower() in TEXT or typ.lower() in DATES and classify_quasi(col) == "dob":
            tables[(schema, table)][col] = {"json": False, "comment": desc}
    for schema, table, col, info_type, label in rows(CLASSIFICATIONS):
        tag = classify_native(info_type, label, col)
        if tag and col in tables.get((schema, table), {}):
            tables[(schema, table)][col]["comment"] = tag
    for schema, table, col, fn in rows(MASKS):
        tag = _mask_kind(fn)
        meta = tables.get((schema, table), {}).get(col)
        if tag and meta is not None and not (meta.get("comment") or "").startswith("pii"):
            meta["comment"] = tag
    keys, unique = {}, set()
    for schema, table, col, primary in rows(KEYS):
        if primary:
            keys[(schema, table)] = col
        unique.add((schema, table, col))
    name = lambda s, t: t if s == "dbo" else f"{s}.{t}"
    fks: dict[tuple[str, str], dict] = {}
    for schema, table, col, fschema, ftable in rows(FKS):
        fks.setdefault((schema, table), {})[col] = (name(fschema, ftable), (schema, table, col) in unique)

    def select(st: tuple[str, str], cols: list[str], limit: int):
        key = keys.get(st)
        key_expr = q(key) if key else "%%physloc%%"
        cur.execute(f"SELECT TOP ({int(limit)}) {key_expr} AS __key"
                    + "".join(", " + q(c) for c in cols) + f" FROM {q(st[0])}.{q(st[1])}")
        names = [d[0] for d in cur.description]
        for r in cur.fetchall():
            yield {k: _norm(v) for k, v in zip(names, r)}

    containers, by_name = [], {}
    for st, cols in tables.items():
        if not cols:
            continue
        fk = fks.get(st, {})
        c = Container(name(*st), "__key", cols, list(select(st, sorted(set(cols) | set(fk)), 200)), fk)
        containers.append(c)
        by_name[c.name] = st

    def fetch(c: Container, cols: list[str]):
        return select(by_name[c.name], sorted(set(cols) | set(c.fks)), max_rows)
    try:
        return run(known, containers, fetch)
    finally:
        conn.close()
