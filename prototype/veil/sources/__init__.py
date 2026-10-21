"""Seed the known-value dictionary from the developer's own data sources.

    seed(known, "app.db")                                   # SQLite file
    seed(known, "postgresql://user:pw@localhost/app")
    seed(known, "mysql://user:pw@localhost:3306/app")
    seed(known, "mongodb://localhost:27017/app")
    seed(known, "redis://localhost:6379/0")
    seed(known, "fixtures/")                                # JSON / JSONL / CSV / Django fixtures
"""

from __future__ import annotations

import getpass
import os
import subprocess
from urllib.parse import unquote, urlparse

from ..detect import KnownValues
from .core import COLUMN_KINDS, Report, classify_name
from .files import seed_files
from .kv import seed_redis
from .mongo import seed_mongo
from .sql import seed_mysql, seed_postgres, seed_sqlite

__all__ = ["COLUMN_KINDS", "Report", "classify", "seed", "seed_environment", "seed_files", "seed_mongo", "seed_mysql",
           "seed_postgres", "seed_redis", "seed_sqlite"]


def classify(table: str, column: str) -> str | None:
    return classify_name(table, column)


def seed(known: KnownValues, uri: str) -> Report:
    u = urlparse(uri)
    if u.scheme in ("postgres", "postgresql"):
        return seed_postgres(known, uri)
    if u.scheme in ("mysql", "mariadb"):
        return seed_mysql(known, u.hostname or "127.0.0.1", unquote(u.username or "root"),
                          unquote(u.password or ""), u.path.lstrip("/"), u.port or 3306)
    if u.scheme.split("+")[0] in ("elasticsearch", "opensearch", "es"):
        from .elastic import seed_elasticsearch
        return seed_elasticsearch(known, uri)
    if u.scheme in ("mssql", "sqlserver"):
        from .mssql import seed_mssql
        return seed_mssql(known, uri)
    if u.scheme in ("redis", "rediss"):
        return seed_redis(known, uri)
    if u.scheme in ("mongodb", "mongodb+srv"):
        return seed_mongo(known, uri, u.path.lstrip("/") or "test")
    if u.scheme in ("", "sqlite", "file") or len(u.scheme) == 1:  # C:\data\app.db: a drive, not a scheme
        path = u.path if u.scheme in ("sqlite", "file") else uri
        if os.path.isdir(path) or not path.endswith((".db", ".sqlite", ".sqlite3")):
            return seed_files(known, [path])
        return seed_sqlite(known, path)
    raise ValueError(f"unsupported source: {u.scheme}://")


def seed_environment(known: KnownValues) -> list[str]:
    """The developer's own identity: OS user (leaks via /Users/<name> paths in the
    agent's system prompt) and git author name/email."""
    found = []
    for value, kind in [(getpass.getuser(), "username"),
                        (os.path.basename(os.path.expanduser("~")), "username")]:
        if value:
            known.add(value, kind, "env:developer")
            found.append(value)
    for key, kind in [("user.email", "email"), ("user.name", "name")]:
        try:
            value = subprocess.run(["git", "config", "--global", key], capture_output=True,
                                   text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            value = ""
        if value:
            known.add(value, kind, "env:developer")
            found.append(value)
    return found
