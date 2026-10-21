"""Key rotation.

vault-key (at-rest encryption; pseudonyms unchanged):
  1. a new key is stored as `vault-key-next` (so a crash can never lose it);
  2. vault.db, known.enc and sources.enc are re-encrypted into new files, each
     row read with whichever key opens it, and swapped in;
  3. the new key becomes `vault-key`; `vault-key-next` is deleted.
  `state.load()` finishes an interrupted rotation (step 2 is idempotent).

token-secret (pseudonyms change: after a suspected leak of the secret, or a team
change): existing tokens are *retired* -- they still rehydrate, so conversations
in flight keep working, but redaction issues new tokens from the new secret.
`--drop-old` forgets them instead.
"""

from __future__ import annotations

import os
import secrets
import sqlite3

from cryptography.exceptions import InvalidTag

from .crypto import Cipher
from .keys import delete_key, peek_key, set_key
from .vault import SCHEMA

MARKER = "rotating"


def _open_any(ciphers: list[Cipher], blob: bytes, aad: str) -> str:
    for c in ciphers:
        try:
            return c.open(blob, aad)
        except InvalidTag:
            continue
    raise InvalidTag(f"no key opens {aad.split('|')[0][:12]}...")


def reencrypt(home: str, read_keys: list[bytes], write_key: bytes) -> dict:
    readers, w = [Cipher(k) for k in read_keys], Cipher(write_key)
    counts = {"vault_rows": 0, "retired": 0, "files": 0}
    vault = os.path.join(home, "vault.db")
    if os.path.exists(vault):
        src = sqlite3.connect(vault)
        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        src.executescript(SCHEMA)
        tmp = vault + ".rotating"
        if os.path.exists(tmp):
            os.remove(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        dst = sqlite3.connect(tmp)
        dst.executescript(SCHEMA)
        for kind, blob, token, grp in src.execute("SELECT kind, value, token, grp FROM entities_v2 ORDER BY rowid"):
            value = _open_any(readers, blob, token)
            group = _open_any(readers, grp, token + "|grp") if grp is not None else None
            dst.execute("INSERT INTO entities_v2 (kind, vkey, value, token, grp) VALUES (?, ?, ?, ?, ?)",
                        (kind, w.lookup(kind, value), w.seal(value, token), token,
                         w.seal(group, token + "|grp") if group is not None else None))
            counts["vault_rows"] += 1
        for token, blob in src.execute("SELECT token, value FROM retired"):
            dst.execute("INSERT INTO retired (token, value) VALUES (?, ?)",
                        (token, w.seal(_open_any(readers, blob, token), token)))
            counts["retired"] += 1
        dst.commit()
        dst.close()
        src.close()
        os.replace(tmp, vault)
        for side in ("-wal", "-shm"):
            if os.path.exists(vault + side):
                os.remove(vault + side)
    for name, aad in (("known.enc", "known"), ("sources.enc", "sources")):
        path = os.path.join(home, name)
        if os.path.exists(path):
            plain = _open_any(readers, open(path, "rb").read(), aad)
            tmp = path + ".rotating"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(w.seal(plain, aad))
            os.replace(tmp, path)
            counts["files"] += 1
    return counts


def rotate_vault_key(home: str) -> dict:
    old = peek_key("vault-key", home)
    if old is None:
        raise SystemExit("no vault key yet: nothing to rotate")
    if os.environ.get("VEIL_VAULT_KEY"):
        raise SystemExit("VEIL_VAULT_KEY comes from the environment, which veil can't change; "
                         "unset it to rotate a keychain/file key")
    new = secrets.token_bytes(32)
    marker = os.path.join(home, MARKER)
    open(marker, "w").close()  # tells state.load() to finish this if we die midway
    set_key("vault-key-next", home, new)
    counts = reencrypt(home, [old, new], new)
    set_key("vault-key", home, new)
    delete_key("vault-key-next", home)
    os.remove(marker)
    return counts


def finish_interrupted(home: str) -> bool:
    """Called on load (cheap: a marker file): complete a rotation that died midway."""
    marker = os.path.join(home, MARKER)
    if not os.path.exists(marker):
        return False
    nxt = peek_key("vault-key-next", home)
    if nxt is not None and not os.environ.get("VEIL_VAULT_KEY"):
        old = peek_key("vault-key", home)
        reencrypt(home, [k for k in (old, nxt) if k], nxt)
        set_key("vault-key", home, nxt)
        delete_key("vault-key-next", home)
    os.remove(marker)  # no next key: the rotation died before step 1, nothing changed
    return nxt is not None


def rotate_token_secret(home: str, vault, drop_old: bool = False) -> dict:
    if os.environ.get("VEIL_TOKEN_SECRET"):
        raise SystemExit("VEIL_TOKEN_SECRET is set in the environment: change it there")
    n = vault.retire_all(drop=drop_old)
    set_key("token-secret", home, secrets.token_bytes(32))
    return {"retired": 0 if drop_old else n, "dropped": n if drop_old else 0}
