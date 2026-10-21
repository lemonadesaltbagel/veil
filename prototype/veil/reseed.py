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
* the result is persisted (known.enc) so hook processes see it too.

Sources are remembered encrypted (sources.enc): database URLs can carry passwords.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from urllib.parse import unquote, urlparse

from .sources import seed
from .sources.files import iter_files


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
            new = self.veil.known.copy()
            before = len(new)
            try:
                seed(new, src)
            except Exception as e:
                print(f"[veil] reseed: {_label(src)} failed ({type(e).__name__})", file=self.log)
                continue
            added = len(new) - before
            if added:
                self.veil.known = new  # atomic swap; matchers rebuild on the size change
                added_total += added
                if self.on_swap:
                    self.on_swap()
            self.prints[src], self.last_full[src] = fp, now
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
            self._stop.wait(self.interval)


def _label(src: str) -> str:
    from .adopt import redact_uri
    return redact_uri(src) if "://" in src else os.path.basename(src.rstrip("/")) or src
