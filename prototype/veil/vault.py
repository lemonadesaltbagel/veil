"""Local mapping store: real value <-> token. Never leaves the machine.

On disk (schema v2) real values and groups are AES-256-GCM encrypted, bound to
their token; rows are found by a keyed hash of (kind, value). The key lives in
the OS keychain (see keys.py). In-memory vaults (tests, audits) use NullCipher.
A v1 plaintext vault is migrated in place and its plaintext table dropped.
"""

from __future__ import annotations

import os
import sqlite3
import threading

from .crypto import NullCipher
from .tokens import code, render

SCHEMA = """
CREATE TABLE IF NOT EXISTS entities_v2 (
    kind  TEXT NOT NULL,
    vkey  TEXT NOT NULL,            -- keyed hash of (kind, value)
    value BLOB NOT NULL,            -- sealed(value, aad=token)
    token TEXT NOT NULL UNIQUE,
    grp   BLOB,                     -- sealed(group, aad=token+"|grp")
    PRIMARY KEY (kind, vkey)
);
-- tokens from a previous token secret: still rehydrated, never issued again
CREATE TABLE IF NOT EXISTS retired (
    token TEXT PRIMARY KEY,
    value BLOB NOT NULL             -- sealed(value, aad=token)
);
"""


class Vault:
    def __init__(self, path: str = ":memory:", secret: bytes = b"veil-dev-secret", cipher=None):
        self.secret = secret
        self.cipher = cipher or NullCipher()
        if path != ":memory:" and not os.path.exists(path):
            open(path, "a").close()
            os.chmod(path, 0o600)
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")  # hooks + proxy share the file
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()
        self.version = 0  # bumped on insert; lets matchers cache compiled patterns
        self._by_token: dict[str, str] = {}
        self._by_value: dict[tuple[str, str], str] = {}
        self._group_of: dict[str, str | None] = {}
        self._migrate_v1()
        self._last_rowid = 0
        for token, blob in self._db.execute("SELECT token, value FROM retired"):
            self._by_token[token] = self.cipher.open(blob, token)
        self.refresh()

    def refresh(self) -> int:
        """Load rows other processes (hooks, other proxies) added since the last load."""
        rows = self._db.execute("SELECT rowid, kind, value, token, grp FROM entities_v2 WHERE rowid > ? "
                                "ORDER BY rowid", (self._last_rowid,)).fetchall()
        for rowid, kind, blob, token, grp in rows:
            value = self.cipher.open(blob, token)
            self._by_token[token] = value
            self._by_value[(kind, value)] = token
            self._group_of[token] = self.cipher.open(grp, token + "|grp") if grp is not None else None
            self._last_rowid = rowid
        if rows:
            self.version += 1
        return len(rows)

    def _migrate_v1(self) -> None:
        has_v1 = self._db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='entities'").fetchone()
        if not has_v1:
            return
        rows = self._db.execute("SELECT kind, value, token, grp FROM entities").fetchall()
        with self._db:
            for kind, value, token, grp in rows:
                try:
                    self._insert(kind, value, token, grp)
                except sqlite3.IntegrityError:
                    pass  # already migrated by another process
            self._db.execute("DROP TABLE entities")
        self._db.execute("VACUUM")  # don't leave plaintext pages behind in the file

    def _insert(self, kind: str, value: str, token: str, group: str | None) -> None:
        self._db.execute(
            "INSERT INTO entities_v2 (kind, vkey, value, token, grp) VALUES (?, ?, ?, ?, ?)",
            (kind, self.cipher.lookup(kind, value), self.cipher.seal(value, token), token,
             self.cipher.seal(group, token + "|grp") if group is not None else None))

    def token_for(self, kind: str, value: str, group: str | None = None) -> str:
        key = (kind, value)
        if key in self._by_value:
            return self._by_value[key]
        with self._lock:
            for _ in range(5):
                self.refresh()  # another process may have allocated it (or taken our token)
                if key in self._by_value:
                    return self._by_value[key]
                try:
                    return self._allocate(kind, value, group)
                except sqlite3.IntegrityError:
                    self._db.rollback()  # lost a race with another process: reload and retry
            raise RuntimeError("could not allocate token (persistent conflict)")

    def _allocate(self, kind: str, value: str, group: str | None) -> str:
        key = (kind, value)
        material = group or f"{kind}\x00{value}"
        token = None
        if group:
            # Same person, another value of the same kind (2nd email, alias):
            # keep the person's code and number the variant.
            base = code(self.secret, material, 4)
            for n in range(1, 50):
                t = render(kind, base, self.secret, n)
                owner = self._by_token.get(t)
                if owner is None:
                    token = t
                    break
                if self._group_of.get(t) != group:
                    break  # code collides with another person: fall through to rehash
        for attempt in range(64) if token is None else ():
            length = 4 + attempt // 8  # widen the code if collisions persist
            c = code(self.secret, material if attempt == 0 else f"{material}#{attempt}", length)
            token = render(kind, c, self.secret)
            if token not in self._by_token:
                break
        if token is None or token in self._by_token:  # pragma: no cover
            raise RuntimeError(f"could not allocate token for {kind}")
        self._insert(kind, value, token, group)
        self._db.commit()
        self._last_rowid = max(self._last_rowid, self._db.execute("SELECT last_insert_rowid()").fetchone()[0])
        self._by_token[token] = value
        self._by_value[key] = token
        self._group_of[token] = group
        self.version += 1
        return token

    def close(self) -> None:
        self._db.close()

    def retire_all(self, drop: bool = False) -> int:
        """Stop issuing the current tokens (a new token secret follows). Kept for
        rehydration unless `drop`. Returns how many tokens were affected."""
        with self._lock, self._db:
            n = self._db.execute("SELECT count(*) FROM entities_v2").fetchone()[0]
            if not drop:
                self._db.execute("INSERT OR REPLACE INTO retired (token, value) SELECT token, value FROM entities_v2")
            else:
                self._db.execute("DELETE FROM retired")
            self._db.execute("DELETE FROM entities_v2")
        self._by_value.clear()
        self._group_of.clear()
        if drop:
            self._by_token.clear()
        self._last_rowid = 0
        self.version += 1
        return n

    def value_for(self, token: str) -> str | None:
        if token not in self._by_token:
            self.refresh()
        return self._by_token.get(token)

    def is_token(self, s: str) -> bool:
        return s in self._by_token

    def tokens(self) -> dict[str, str]:
        return dict(self._by_token)
