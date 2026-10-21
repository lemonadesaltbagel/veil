"""`veil mcp-db`: a read-only database tool for the agent (MCP over stdio).

Shell access to a database (`psql -c`, `sqlite3 db "..."`) makes veil escape real values
into command text. This tool removes that surface:

* the agent writes SQL with pseudonyms *inside string literals*
  (`WHERE email = 'user_ab12@example.test'`); every literal holding a pseudonym is
  replaced by a **bound parameter** carrying the real value -- the value is never SQL
  text, so there is nothing to escape. Pseudonyms outside a literal are refused;
* only reads: one statement, SELECT/WITH/EXPLAIN/SHOW/DESCRIBE/PRAGMA/VALUES, no
  write keywords outside literals, and a read-only connection or transaction;
* results come back pseudonymised (and pass the proxy's redaction and guard again on
  their way to the model).

MongoDB: `find` / `aggregate` / `count` with JSON filters; pseudonyms in string values
are restored structurally ($regex values are regex-escaped); $out, $merge, $where,
$function and $accumulator are refused.

    veil mcp-db postgresql://app@localhost/app      # or: veil mcp-db --source 1 (remembered, encrypted)
    claude mcp add veil-db --scope local -- veil mcp-db --source 1
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import time
from typing import Any
from urllib.parse import unquote, urlparse

PROTOCOL = "2025-06-18"
READ_FIRST = {"select", "with", "explain", "show", "describe", "desc", "pragma", "values"}
# Statements that write can't start a query (first-word check); these catch writes inside one:
# data-modifying CTEs (WITH x AS (DELETE ...)), SELECT ... INTO, FOR UPDATE, INTO OUTFILE.
WRITE_WORDS = re.compile(r"\b(insert|update|delete|merge|upsert|drop|alter|create|truncate|grant|revoke|"
                         r"attach|detach|vacuum|reindex|exec|execute|into|set|outfile|dumpfile)\b", re.I)
# PRAGMA x = v and PRAGMA x(v) change settings; only these read forms are allowed
READ_PRAGMA = re.compile(r"\s*pragma\s+(?:\w+\.)?(table_info|table_xinfo|index_list|index_info|index_xinfo|"
                         r"foreign_key_list|table_list|database_list|collation_list)\s*(\(\s*[\w.\"\[\]]*\s*\))?\s*$", re.I)
MONGO_FORBIDDEN = {"$out", "$merge", "$where", "$function", "$accumulator"}
MAX_ROWS = 500


class ToolError(Exception):
    """Shown to the model as the tool result (isError)."""


# -- SQL: literals -> parameters ------------------------------------------------

def _scan(sql: str):
    """Yield ("lit", start, end, content) for '...' literals, ("code", start, end, text) otherwise.
    Comments and "identifiers" are code (never parameterised)."""
    i, n, start = 0, len(sql), 0
    while i < n:
        c = sql[i]
        if c == "'":
            if start < i:
                yield "code", start, i, sql[start:i]
            j, buf = i + 1, []
            while j < n:
                if sql[j] == "'" and j + 1 < n and sql[j + 1] == "'":
                    buf.append("'"); j += 2; continue
                if sql[j] == "'":
                    break
                buf.append(sql[j]); j += 1
            if j >= n:
                raise ToolError("unterminated string literal")
            yield "lit", i, j + 1, "".join(buf)
            i = start = j + 1
            continue
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in '"`[':
            close = {'"': '"', "`": "`", "[": "]"}[c]
            j = sql.find(close, i + 1)
            i = n if j < 0 else j + 1
            continue
        i += 1
    if start < n:
        yield "code", start, n, sql[start:n]


def prepare_sql(veil, sql: str, paramstyle: str = "qmark") -> tuple[str, list[str]]:
    """(SQL with placeholders, real-value parameters). Raises ToolError on anything unsafe."""
    sql = sql.strip().rstrip(";").strip()
    if not sql:
        raise ToolError("empty query")
    parts = list(_scan(sql))
    code = " ".join(t for kind, _, _, t in parts if kind == "code")
    if ";" in code:
        raise ToolError("one statement per call")
    first = re.match(r"\s*\(*\s*(\w+)", code)
    if not first or first.group(1).lower() not in READ_FIRST:
        raise ToolError("read-only: SELECT / WITH / EXPLAIN / SHOW / DESCRIBE / PRAGMA / VALUES only")
    if first.group(1).lower() == "pragma" and not READ_PRAGMA.match(code):
        raise ToolError("read-only: only schema PRAGMAs (table_info, index_list, foreign_key_list, ...)")
    bad = WRITE_WORDS.search(re.sub(r"\bis\s+not\s+distinct\s+from\b", "", code, flags=re.I))
    if bad and not (bad.group(1).lower() == "set" and first.group(1).lower() == "show"):
        raise ToolError(f"read-only: `{bad.group(1)}` is not allowed")
    pattern = veil.token_pattern()
    out, params = [], []
    holder = "?" if paramstyle == "qmark" else "%s"
    for kind, a, b, text in parts:
        if kind == "code":
            if pattern and list(pattern.finditer(text)):
                raise ToolError("pseudonyms work only inside string literals, e.g. WHERE email = "
                                "'user_ab12@example.test' (veil binds them as parameters)")
            if veil.fragments(text):
                raise ToolError("part of a pseudonym outside a literal; quote whole pseudonyms")
            out.append(text.replace("%", "%%") if holder == "%s" else text)
        elif veil.fragments(text):
            raise ToolError("a string literal holds only part of a pseudonym: it can never match real data. "
                            "Use whole pseudonyms (LIKE patterns may wrap them: '%user_ab12%').")
        elif pattern and list(pattern.finditer(text)):
            out.append(holder)
            params.append(veil.rehydrate(text))
        else:
            out.append(sql[a:b].replace("%", "%%") if holder == "%s" else sql[a:b])
    return "".join(out), params


# -- databases ----------------------------------------------------------------------

class SQLSource:
    def __init__(self, uri: str):
        u = urlparse(uri)
        self.uri, self.kind = uri, u.scheme or "sqlite"
        if u.scheme in ("", "sqlite", "file") or len(u.scheme) == 1:
            import os, pathlib
            path = u.path if u.scheme in ("sqlite", "file") else uri
            self.conn = sqlite3.connect(pathlib.Path(os.path.abspath(path)).as_uri() + "?mode=ro", uri=True,
                                        check_same_thread=False)
            self.kind, self.paramstyle = "sqlite", "qmark"
            deadline = {"t": 0.0}
            self.conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline["t"] else 0, 10_000)
            self._deadline = deadline
        elif u.scheme in ("postgres", "postgresql"):
            import psycopg
            self.conn = psycopg.connect(uri, autocommit=True)
            self.conn.execute("SET default_transaction_read_only = on")
            self.conn.execute("SET statement_timeout = '30s'")
            self.kind, self.paramstyle = "postgres", "format"
        elif u.scheme in ("mysql", "mariadb"):
            import pymysql
            self.conn = pymysql.connect(host=u.hostname or "127.0.0.1", port=u.port or 3306,
                                        user=unquote(u.username or "root"), password=unquote(u.password or ""),
                                        database=u.path.lstrip("/"), autocommit=True, charset="utf8mb4")
            with self.conn.cursor() as c:
                c.execute("SET SESSION TRANSACTION READ ONLY")
            self.kind, self.paramstyle = "mysql", "format"
        elif u.scheme in ("mssql", "sqlserver"):
            from .sources.mssql import _connect
            self.conn = _connect(uri)
            self.kind, self.paramstyle = "mssql", "format"
        else:
            raise ToolError(f"unsupported SQL source {u.scheme}://")

    def run(self, sql: str, params: list, limit: int) -> tuple[list[str], list[tuple], bool]:
        if self.kind == "sqlite":
            self._deadline["t"] = time.monotonic() + 30
        cur = self.conn.cursor()
        try:
            cur.execute(sql, params)
            cols = [d[0] for d in cur.description or []]
            rows = cur.fetchmany(limit + 1) if cols else []
        finally:
            if self.kind == "mssql":
                self.conn.rollback()  # never keep anything a statement might have done
        return cols, [tuple(r) for r in rows[:limit]], len(rows) > limit

    def tables(self) -> list[str]:
        q = {"sqlite": "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY 1",
             "postgres": "SELECT table_schema || '.' || table_name FROM information_schema.tables "
                         "WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1",
             "mysql": "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY 1",
             "mssql": "SELECT s.name + '.' + t.name FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id ORDER BY 1"}
        return [r[0] for r in self.run(q[self.kind], [], 5000)[1]]

    def describe(self, table: str) -> list[tuple]:
        if self.kind == "sqlite":
            if not re.fullmatch(r"[\w.]+", table):
                raise ToolError("table name: letters, digits, _ and . only")
            return [(r[1], r[2], "" if r[3] else "null", "pk" if r[5] else "")
                    for r in self.conn.execute(f'PRAGMA table_info("{table}")').fetchall()]
        schema, _, name = table.rpartition(".")
        q = {"postgres": "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                         "WHERE table_name = %s AND (%s = '' OR table_schema = %s) ORDER BY ordinal_position",
             "mysql": "SELECT column_name, column_type, is_nullable FROM information_schema.columns "
                      "WHERE table_schema = DATABASE() AND table_name = %s AND %s = %s ORDER BY ordinal_position",
             "mssql": "SELECT c.name, ty.name, c.is_nullable FROM sys.columns c JOIN sys.types ty ON ty.user_type_id = c.user_type_id "
                      "WHERE c.object_id = OBJECT_ID(%s) AND %s = %s ORDER BY c.column_id"}
        args = [name, schema, schema] if self.kind == "postgres" else [table if self.kind == "mssql" else name, "", ""]
        return self.run(q[self.kind], args, 1000)[1]


class MongoSource:
    def __init__(self, uri: str):
        from pymongo import MongoClient
        u = urlparse(uri)
        self.client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        self.db = self.client[u.path.lstrip("/") or "test"]
        self.kind = "mongo"


def restore_filter(veil, node: Any, regex: bool = False) -> Any:
    """Pseudonyms in a Mongo filter/pipeline -> real values (structured, so no escaping;
    inside $regex the value is regex-escaped)."""
    if isinstance(node, dict):
        bad = MONGO_FORBIDDEN & set(node)
        if bad:
            raise ToolError(f"read-only: {sorted(bad)[0]} is not allowed")
        return {k: restore_filter(veil, v, regex=(k == "$regex")) for k, v in node.items()}
    if isinstance(node, list):
        return [restore_filter(veil, v, regex) for v in node]
    if isinstance(node, str):
        pattern = veil.token_pattern()
        if not pattern or not list(pattern.finditer(node)):
            return node
        if regex:
            return pattern.sub(lambda m: re.escape(veil.vault.value_for(m.group()) or m.group()), node)
        return veil.rehydrate(node)
    return node


# -- the MCP server -----------------------------------------------------------------

def _table(veil, cols: list[str], rows: list[tuple], more: bool) -> str:
    def cell(v):
        if v is None:
            return "NULL"
        if isinstance(v, (bytes, bytearray, memoryview)):
            return f"<{len(bytes(v))} bytes>"
        s = v if isinstance(v, str) else (json.dumps(v, default=str, ensure_ascii=False)
                                          if isinstance(v, (dict, list)) else str(v))
        return veil.redact(s, free_text=True).replace("\t", " ").replace("\n", "\\n")
    lines = ["\t".join(cols)] + ["\t".join(cell(v) for v in r) for r in rows]
    lines.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''}{', more rows not shown: add LIMIT/WHERE' if more else ''})")
    return "\n".join(lines)


class Server:
    def __init__(self, veil, source, name: str = "veil-db"):
        self.veil, self.source, self.name = veil, source, name
        self.calls = 0

    def tools(self) -> list[dict]:
        if isinstance(self.source, MongoSource):
            return [
                {"name": "collections", "description": "List the collections.", "inputSchema": {"type": "object", "properties": {}}},
                {"name": "find", "description": FIND_DOC, "inputSchema": {"type": "object", "properties": {
                    "collection": {"type": "string"}, "filter": {"type": "object"}, "projection": {"type": "object"},
                    "sort": {"type": "object"}, "limit": {"type": "integer"}}, "required": ["collection"]}},
                {"name": "aggregate", "description": "Run a read-only aggregation pipeline ($out/$merge/$where/"
                 "$function are refused). Pseudonyms in string values are matched against real data.",
                 "inputSchema": {"type": "object", "properties": {"collection": {"type": "string"},
                                 "pipeline": {"type": "array", "items": {"type": "object"}}},
                                 "required": ["collection", "pipeline"]}},
                {"name": "count", "description": "Count documents matching a filter.", "inputSchema": {"type": "object",
                 "properties": {"collection": {"type": "string"}, "filter": {"type": "object"}}, "required": ["collection"]}},
            ]
        return [
            {"name": "query", "description": QUERY_DOC, "inputSchema": {"type": "object", "properties": {
                "sql": {"type": "string"}, "limit": {"type": "integer", "description": f"max rows (default 100, max {MAX_ROWS})"}},
                "required": ["sql"]}},
            {"name": "list_tables", "description": "List tables and views.", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "describe_table", "description": "Columns of one table (name, type, nullable).",
             "inputSchema": {"type": "object", "properties": {"table": {"type": "string"}}, "required": ["table"]}},
        ]

    def call(self, name: str, args: dict) -> str:
        self.calls += 1
        if hasattr(self.veil.vault, "refresh"):
            self.veil.vault.refresh()
        limit = max(1, min(int(args.get("limit") or 100), MAX_ROWS))
        src = self.source
        if isinstance(src, MongoSource):
            coll = args.get("collection") or ""
            if name == "collections":
                return "\n".join(sorted(src.db.list_collection_names()))
            if not re.fullmatch(r"[\w.\-]+", coll) or coll.startswith("system."):
                raise ToolError("collection name: letters, digits, _ . - only")
            c = src.db[coll]
            if name == "find":
                docs = list(c.find(restore_filter(self.veil, args.get("filter") or {}), args.get("projection"),
                                   sort=list((args.get("sort") or {}).items()) or None, limit=limit + 1,
                                   max_time_ms=30_000))
            elif name == "aggregate":
                pipeline = restore_filter(self.veil, args.get("pipeline") or [])
                docs = list(c.aggregate(pipeline + [{"$limit": limit + 1}], maxTimeMS=30_000))
            elif name == "count":
                return str(c.count_documents(restore_filter(self.veil, args.get("filter") or {}), maxTimeMS=30_000))
            else:
                raise ToolError(f"unknown tool {name}")
            more = len(docs) > limit
            out = self.veil.redact_json(json.loads(json.dumps(docs[:limit], default=str, ensure_ascii=False)))
            return json.dumps(out, ensure_ascii=False, indent=1) + (f"\n(more than {limit} documents: narrow the filter)" if more else "")
        if name == "list_tables":
            return "\n".join(self.veil.redact(t) for t in src.tables())
        if name == "describe_table":
            rows = src.describe(str(args.get("table", "")))
            if not rows:
                raise ToolError("no such table (see list_tables)")
            return _table(self.veil, ["column", "type", "nullable", "key"][:len(rows[0])], rows, False)
        if name == "query":
            sql, params = prepare_sql(self.veil, str(args.get("sql", "")), "qmark" if src.paramstyle == "qmark" else "format")
            try:
                cols, rows, more = src.run(sql, params, limit)
            except ToolError:
                raise
            except Exception as e:  # database error: message pseudonymised (it may quote a value)
                raise ToolError(f"{type(e).__name__}: {self.veil.redact(str(e))[:500]}")
            return _table(self.veil, cols, rows, more)
        raise ToolError(f"unknown tool {name}")

    def handle(self, msg: dict) -> dict | None:
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:  # notification (initialized, cancelled): no reply
            return None
        if method == "initialize":
            result = {"protocolVersion": msg.get("params", {}).get("protocolVersion") or PROTOCOL,
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": self.name, "version": _version()},
                      "instructions": INSTRUCTIONS}
        elif method == "tools/list":
            result = {"tools": self.tools()}
        elif method == "tools/call":
            p = msg.get("params") or {}
            try:
                text, err = self.call(p.get("name", ""), p.get("arguments") or {}), False
            except ToolError as e:
                text, err = f"veil-db: {e}", True
            result = {"content": [{"type": "text", "text": text}], "isError": err}
        elif method == "ping":
            result = {}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def serve(self, stdin=None, stdout=None) -> None:
        stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            else:
                try:
                    reply = self.handle(msg)
                except Exception as e:  # never die on one bad call; never echo data
                    reply = {"jsonrpc": "2.0", "id": msg.get("id"),
                             "error": {"code": -32603, "message": f"internal error: {type(e).__name__}"}}
            if reply is not None:
                stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
                stdout.flush()


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("veil-proxy")
    except Exception:
        return "dev"


def open_source(uri: str):
    scheme = urlparse(uri).scheme
    return MongoSource(uri) if scheme in ("mongodb", "mongodb+srv") else SQLSource(uri)


INSTRUCTIONS = ("Read-only access to the project database through veil. Personal values appear as pseudonyms "
                "(user_ab12@example.test, First_Ab12 Last_Ab12). To filter by one, put the whole pseudonym inside a "
                "string literal exactly as you saw it; veil matches it against the real data.")
QUERY_DOC = ("Run one read-only SQL statement (SELECT/WITH/EXPLAIN/SHOW/DESCRIBE/PRAGMA). Results are pseudonymised. "
             "To filter by a person, quote the whole pseudonym as a string literal: "
             "WHERE email = 'user_ab12@example.test' or LIKE '%user_ab12%'; veil binds the real value as a parameter.")
FIND_DOC = ("Find documents (read-only). filter/projection/sort are MongoDB JSON; pseudonyms in string values "
            "are matched against the real data. Results are pseudonymised.")
