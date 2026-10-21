"""Automatic re-seeding: keep the known values in step with the data sources.

`veil seed` takes a snapshot; a customer added afterwards would only be caught by
patterns (emails, phones) and optional NER, not by the precise seeded matching.
So the proxy re-seeds in the background:

* every `interval` seconds it asks each remembered source for a cheap
  *fingerprint* (file mtimes, Postgres row-change statistics, MySQL table
  statistics, Redis' write counter, MongoDB op counters);
* when a fingerprint changes (or `full_every` seconds have passed) that source is
  re-seeded into a copy of the known values, which is then swapped in atomically,
  so requests never see a half-built set;
* the result is persisted (known.enc) so hook processes see it too;
* matcher and guard indexes are built in this thread before the swap, and the
  interval stretches to 10x the last re-seed's duration (1.2M values: ~6 s).

Sources are remembered encrypted (sources.enc): database URLs can carry passwords.
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlparse

import httpx

from .guard import seeded_index
from .sources import seed
from .sources.files import iter_files


def warm(known) -> None:
    """Build the matcher and guard indexes now, then exclude them from cyclic GC:
    millions of long-lived tuples made full collections pause requests ~90 ms.
    (Refcounting still frees them when a newer set replaces them.)"""
    known.matcher()
    seeded_index(known)
    gc.freeze()


def _digest(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, default=str).encode()).hexdigest()[:16]


def fingerprint(source: str) -> str:
    """Cheap 'did anything change?' value for a source. Raises if unreachable."""
    u = urlparse(source)
    if u.scheme in ("postgres", "postgresql"):
        import psycopg
        with psycopg.connect(source, connect_timeout=5) as c:
            row = c.execute("SELECT coalesce(sum(n_tup_ins + n_tup_upd + n_tup_del), 0), "
                            "coalesce(sum(n_live_tup), 0), count(*) FROM pg_stat_user_tables").fetchone()
        return _digest("pg", row)
    if u.scheme in ("mysql", "mariadb"):
        import pymysql
        c = pymysql.connect(host=u.hostname or "127.0.0.1", port=u.port or 3306, user=unquote(u.username or "root"),
                            password=unquote(u.password or ""), database=u.path.lstrip("/"), connect_timeout=5)
        try:
            with c.cursor() as cur:
                try:
                    cur.execute("SET SESSION information_schema_stats_expiry = 0")  # MySQL 8 caches stats for a day
                except Exception:
                    pass  # MariaDB: no such variable, no such cache
                cur.execute("SELECT SUM(TABLE_ROWS), MAX(UPDATE_TIME), COUNT(*), SUM(DATA_LENGTH) "
                            "FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()")
                return _digest("mysql", cur.fetchone())
        finally:
            c.close()
    if u.scheme == "snowflake":
        from .sources.warehouse import _snowflake_connect
        c = _snowflake_connect(source)
        try:
            cur = c.cursor()
            cur.execute("SELECT SUM(row_count), MAX(last_altered), COUNT(*) FROM information_schema.tables "
                        "WHERE table_schema <> 'INFORMATION_SCHEMA'")
            return _digest("snowflake", cur.fetchone())
        finally:
            c.close()
    if u.scheme == "bigquery":
        from .sources.warehouse import API, _bq_token
        project, datasets = u.hostname, [d for d in u.path.strip("/").split(",") if d]
        with httpx.Client(base_url=API, headers={"authorization": f"Bearer {_bq_token()}"}, timeout=60) as bq:
            if not datasets:
                datasets = [d["datasetReference"]["datasetId"]
                            for d in bq.get(f"/projects/{project}/datasets").json().get("datasets", [])]
            meta = []
            for ds in datasets:
                for t in bq.get(f"/projects/{project}/datasets/{ds}/tables").json().get("tables", []):
                    tid = t["tableReference"]["tableId"]
                    info = bq.get(f"/projects/{project}/datasets/{ds}/tables/{tid}").json()
                    meta.append((ds, tid, info.get("numRows"), info.get("lastModifiedTime")))
        return _digest("bigquery", meta)
    if u.scheme == "dynamodb":  # counts refresh every ~6 h; the hourly full re-seed covers the rest
        from .sources.dynamo import _client
        ddb, tables = _client(source)
        if not tables:
            tables = ddb.list_tables()["TableNames"]
        return _digest("dynamodb", [(t, ddb.describe_table(TableName=t)["Table"].get("ItemCount"),
                                     ddb.describe_table(TableName=t)["Table"].get("TableSizeBytes")) for t in tables])
    if u.scheme == "git":
        refs = subprocess.run(["git", "-C", source[4:] or ".", "for-each-ref", "--format=%(objectname)"],
                              capture_output=True, text=True, timeout=30).stdout
        return _digest("git", refs)
    if u.scheme.split("+")[0] in ("elasticsearch", "opensearch", "es"):
        from .sources.elastic import _client
        es, indices = _client(source)
        with es:
            r = es.get("/" + (",".join(indices) or "_all") + "/_stats/docs,indexing").json()
        t = (r.get("_all") or {}).get("primaries") or {}
        return _digest("es", (t.get("docs") or {}).get("count"), (t.get("indexing") or {}).get("index_total"),
                       (t.get("indexing") or {}).get("delete_total"))
    if u.scheme in ("mssql", "sqlserver"):
        from .sources.mssql import _connect
        c = _connect(source)
        try:
            cur = c.cursor()
            cur.execute("SELECT SUM(p.rows), COUNT(*) FROM sys.partitions p JOIN sys.tables t "
                        "ON t.object_id = p.object_id WHERE p.index_id IN (0, 1)")
            rows = cur.fetchone()
            try:  # write counters need VIEW SERVER STATE; row counts alone still catch inserts
                cur.execute("SELECT SUM(user_updates), MAX(last_user_update) FROM sys.dm_db_index_usage_stats "
                            "WHERE database_id = DB_ID()")
                writes = cur.fetchone()
            except Exception:
                writes = None
            return _digest("mssql", rows, writes)
        finally:
            c.close()
    if u.scheme in ("redis", "rediss"):
        import redis
        r = redis.Redis.from_url(source, socket_timeout=5)
        info = r.info("persistence")
        return _digest("redis", r.dbsize(), info.get("rdb_changes_since_last_save"), info.get("rdb_last_save_time"))
    if u.scheme in ("mongodb", "mongodb+srv"):
        from pymongo import MongoClient
        client = MongoClient(source, serverSelectionTimeoutMS=5000)
        db = client[u.path.lstrip("/") or "test"]
        try:
            ops = client.admin.command("serverStatus").get("opcounters", {})
            return _digest("mongo", ops.get("insert"), ops.get("update"), ops.get("delete"))
        except Exception:  # no serverStatus permission: fall back to collection sizes
            return _digest("mongo", sorted((n, db[n].estimated_document_count()) for n in db.list_collection_names()))
    path = u.path if u.scheme in ("sqlite", "file") else source
    if os.path.isfile(path) and path.endswith((".db", ".sqlite", ".sqlite3")):
        stats = [(p, os.stat(p).st_mtime_ns, os.stat(p).st_size) for p in (path, path + "-wal") if os.path.exists(p)]
        return _digest("sqlite", stats)
    files = sorted(iter_files([path]))
    return _digest("files", [(f, os.stat(f).st_mtime_ns, os.stat(f).st_size) for f in files])


class Reseeder(threading.Thread):
    def __init__(self, veil, sources: list[str], interval: float = 30, full_every: float = 3600,
                 save=None, log=sys.stderr, on_swap=None):
        super().__init__(daemon=True, name="veil-reseed")
        self.veil, self.sources, self.interval, self.full_every = veil, list(sources), interval, full_every
        self.save, self.log, self.on_swap = save, log, on_swap
        self.prints: dict[str, str] = {}
        self.last_full: dict[str, float] = {}
        self._stop = threading.Event()
        self.runs = 0
        self.last_seconds = 0.0  # duration of the last pass that re-seeded something

    def stop(self) -> None:
        self._stop.set()

    def check_once(self) -> int:
        """One pass over all sources. Returns how many new values were learned."""
        added_total, now = 0, time.monotonic()
        for src in self.sources:
            try:
                fp = fingerprint(src)
            except Exception as e:  # unreachable right now: keep the last snapshot, retry next pass
                print(f"[veil] reseed: {_label(src)} unreachable ({type(e).__name__})", file=self.log)
                continue
            first = src not in self.prints
            stale = now - self.last_full.get(src, 0) >= self.full_every
            if fp == self.prints.get(src) and not stale:
                continue
            started = time.monotonic()
            new = self.veil.known.copy()
            before = len(new)
            try:
                seed(new, src)
            except Exception as e:
                print(f"[veil] reseed: {_label(src)} failed ({type(e).__name__})", file=self.log)
                continue
            added = len(new) - before
            if added:
                warm(new)  # build the indexes here, not on the next request (seconds at 1M values)
                self.veil.known = new  # atomic swap
                added_total += added
                if self.on_swap:
                    self.on_swap()
            self.prints[src], self.last_full[src] = fp, now
            self.last_seconds = time.monotonic() - started
            if added or first:
                print(f"[veil] reseed: {_label(src)} +{added} values", file=self.log)
        if added_total and self.save:
            self.save(self.veil.known)
        self.runs += 1
        return added_total

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_once()
            except Exception as e:  # never let the thread die
                print(f"[veil] reseed error: {type(e).__name__}", file=self.log)
            # A big source under constant writes would otherwise re-seed back to back:
            # keep re-seeding under ~10% of one core.
            self._stop.wait(max(self.interval, 10 * self.last_seconds))


def _label(src: str) -> str:
    from .adopt import redact_uri
    return redact_uri(src) if "://" in src else os.path.basename(src.rstrip("/")) or src
