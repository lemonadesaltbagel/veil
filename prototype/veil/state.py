"""On-disk state under $VEIL_HOME (default ~/.veil), all files mode 0600.

  vault.db   tokens + AES-GCM-encrypted real values (schema v2)
  known.enc  encrypted seed dictionary
  keys       in the OS keychain (keys.py); legacy plaintext files are migrated
"""

from __future__ import annotations

import json
import os

from .detect import KnownValues
from .engine import Veil
from .vault import Vault


def home() -> str:
    path = os.environ.get("VEIL_HOME", os.path.expanduser("~/.veil"))
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _private_write(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _key_material(h: str) -> tuple[bytes, bytes]:
    from .keys import get_key
    legacy = os.path.join(h, "secret")  # v1 kept the token secret in a plain file
    initial = open(legacy, "rb").read() if os.path.exists(legacy) else None
    token_secret = get_key("token-secret", h, initial)
    if initial is not None and token_secret == initial:
        os.remove(legacy)
    return get_key("vault-key", h), token_secret


def config() -> dict:
    path = os.path.join(home(), "config.json")
    return json.load(open(path)) if os.path.exists(path) else {}


def save_config(cfg: dict) -> None:
    _private_write(os.path.join(home(), "config.json"), json.dumps(cfg, indent=2).encode())


def load() -> Veil:
    from .crypto import Cipher
    from .detect import set_allowlist
    h = home()
    set_allowlist(config().get("allow", []))
    from .sources.core import set_hints
    set_hints(config().get("schema_hints", {}))
    from .rotate import finish_interrupted
    if finish_interrupted(h):
        import sys
        print("[veil] finished an interrupted vault-key rotation", file=sys.stderr)
    vault_key, token_secret = _key_material(h)
    cipher = Cipher(vault_key)
    known = KnownValues()
    enc_path, legacy = os.path.join(h, "known.enc"), os.path.join(h, "known.json")
    if os.path.exists(enc_path):
        rows = json.loads(cipher.open(open(enc_path, "rb").read(), "known"))
    elif os.path.exists(legacy):
        rows = json.load(open(legacy))
    else:
        rows = []
    quasi, qi = [], {}
    if isinstance(rows, dict):  # v2: {"rows": [...], "quasi": [...], "qi_people": {...}, "qi_groups": [...]}
        rows, quasi, qi = rows.get("rows", []), rows.get("quasi", []), rows
    for value, kind, group in rows:
        known.add(value, kind, group)
    for value, kind, count, group in quasi:
        known._quasi[value] = [kind, count, group]
    known._qi_groups = {g: i for i, g in enumerate(qi.get("qi_groups", []))}
    known._qi_people = {v: set(p) for v, p in qi.get("qi_people", {}).items()}
    veil = Veil(Vault(os.path.join(h, "vault.db"), token_secret, cipher), known)
    from .quasi import mode as quasi_mode
    veil.quasi_mode = quasi_mode(h)  # in-process hooks follow `veil quasi` too
    if os.path.exists(legacy):  # migrate v1 plaintext seed file
        save_known(known, cipher)
        os.remove(legacy)
    return veil


def save_known(known: KnownValues, cipher=None) -> None:
    from .crypto import Cipher
    h = home()
    cipher = cipher or Cipher(_key_material(h)[0])
    rows = [[v, k, g] for v, (k, g) in known._entries.items()]
    quasi = [[v, k, n, g] for v, (k, n, g) in known._quasi.items()]
    groups = [g for g, _ in sorted(known._qi_groups.items(), key=lambda kv: kv[1])]
    doc = {"rows": rows, "quasi": quasi, "qi_groups": groups,
           "qi_people": {v: sorted(p) for v, p in known._qi_people.items()}}
    _private_write(os.path.join(h, "known.enc"), cipher.seal(json.dumps(doc), "known"))


# -- remembered seed sources (encrypted: database URLs can carry passwords) --------------

def load_sources(cipher=None) -> list[str]:
    from .crypto import Cipher
    path = os.path.join(home(), "sources.enc")
    if not os.path.exists(path):
        return []
    cipher = cipher or Cipher(_key_material(home())[0])
    return json.loads(cipher.open(open(path, "rb").read(), "sources"))


def save_sources(sources: list[str], cipher=None) -> None:
    from .crypto import Cipher
    cipher = cipher or Cipher(_key_material(home())[0])
    _private_write(os.path.join(home(), "sources.enc"), cipher.seal(json.dumps(sources), "sources"))


def remember_sources(new: list[str], cipher=None) -> list[str]:
    import os.path as p
    norm = [s if "://" in s else p.abspath(s) for s in new]
    current = load_sources(cipher)
    merged = current + [s for s in norm if s not in current]
    if merged != current:
        save_sources(merged, cipher)
    return merged
