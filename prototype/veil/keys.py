"""Key material for the local vault.

Two 32-byte keys, both generated on first use:
  vault-key     encrypts real values at rest. Never leaves the machine.
  token-secret  HMAC key that derives pseudonyms. Share it across a team to get
                identical tokens everywhere (it reveals nothing without the vault).

Sources, in order:
  1. env  VEIL_VAULT_KEY / VEIL_TOKEN_SECRET (base64)       -- CI, containers, Linux
  2. macOS Keychain, service "veil" (VEIL_KEYCHAIN=path selects a keychain file);
     Linux Secret Service via `secret-tool` (GNOME Keyring, KWallet, KeePassXC...)
  3. fallback: $VEIL_HOME/keys/<name>, mode 0600, with a warning
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
import sys

SERVICE = "veil"
_warned = False


def _secret_service() -> bool:
    return sys.platform.startswith("linux") and bool(shutil.which("secret-tool")) \
        and os.environ.get("VEIL_SECRET_SERVICE", "1") != "0"


def _env_name(name: str) -> str:
    return "VEIL_" + name.upper().replace("-", "_")


def _keychain_args() -> list[str] | None:
    """[] = the default (login) keychain; [path] = a specific keychain file;
    None = keychain unavailable (VEIL_KEYCHAIN names a file that doesn't exist).
    Never fall through to the login keychain when a specific one was requested."""
    kc = os.environ.get("VEIL_KEYCHAIN")
    if not kc:
        return []
    return [kc] if os.path.exists(kc) else None


def _keychain_get(name: str) -> bytes | None:
    args = _keychain_args()
    if args is None:
        return None
    r = subprocess.run(["security", "find-generic-password", "-s", SERVICE, "-a", name, "-w", *args],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return base64.b64decode(r.stdout.strip())


def _keychain_put(name: str, key: bytes) -> bool:
    args = _keychain_args()
    if args is None:
        return False
    value = base64.b64encode(key).decode()
    if args:  # explicit keychain file (tests, dedicated keychains): argv form honours the path
        r = subprocess.run(["security", "add-generic-password", "-U", "-s", SERVICE, "-a", name, "-w", value, *args],
                           capture_output=True, text=True, timeout=30)
    else:     # default keychain: `security -i` reads the command from stdin, keeping the key out of argv/`ps`
        r = subprocess.run(["security", "-i"], input=f"add-generic-password -U -s {SERVICE} -a {name} -w {value}\n",
                           capture_output=True, text=True, timeout=30)
    return r.returncode == 0 and _keychain_get(name) == key


def _secret_tool_get(name: str) -> bytes | None:
    try:
        r = subprocess.run(["secret-tool", "lookup", "service", SERVICE, "account", name],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return base64.b64decode(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip() else None


def _secret_tool_put(name: str, key: bytes) -> bool:
    # the secret is read from stdin: never in argv
    try:
        r = subprocess.run(["secret-tool", "store", f"--label=veil {name}", "service", SERVICE, "account", name],
                           input=base64.b64encode(key).decode(), capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and _secret_tool_get(name) == key


def _file_key(home: str, name: str, create: bytes | None) -> bytes:
    global _warned
    d = os.path.join(home, "keys")
    os.makedirs(d, mode=0o700, exist_ok=True)
    path = os.path.join(d, name)
    if os.path.exists(path):
        return open(path, "rb").read()
    key = create or secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    if not _warned:
        print(f"[veil] warning: no OS keychain; keys stored in {d} (0600)", file=sys.stderr)
        _warned = True
    return key


def get_key(name: str, home: str, initial: bytes | None = None) -> bytes:
    """Return key `name`, creating it (from `initial`, e.g. a migrated legacy secret) if absent."""
    env = os.environ.get(_env_name(name))
    if env:
        return base64.b64decode(env)
    if sys.platform == "darwin" and shutil.which("security"):
        key = _keychain_get(name)
        if key:
            return key
        key = initial or secrets.token_bytes(32)
        if _keychain_put(name, key):
            return key
    elif _secret_service():
        key = _secret_tool_get(name)
        if key:
            return key
        key = initial or secrets.token_bytes(32)
        if _secret_tool_put(name, key):
            return key
    return _file_key(home, name, initial)


def set_key(name: str, home: str, key: bytes) -> str:
    """Replace key `name`. Returns where it was stored ('env' means: refused, env wins)."""
    if os.environ.get(_env_name(name)):
        return "env"
    if sys.platform == "darwin" and shutil.which("security") and _keychain_put(name, key):
        return "keychain"
    if _secret_service() and _secret_tool_put(name, key):
        return "secret-service"
    d = os.path.join(home, "keys")
    os.makedirs(d, mode=0o700, exist_ok=True)
    path = os.path.join(d, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return "file"


def peek_key(name: str, home: str) -> bytes | None:
    """Key `name` if it exists anywhere; never creates one."""
    env = os.environ.get(_env_name(name))
    if env:
        return base64.b64decode(env)
    if sys.platform == "darwin" and shutil.which("security"):
        key = _keychain_get(name)
        if key:
            return key
    elif _secret_service():
        key = _secret_tool_get(name)
        if key:
            return key
    path = os.path.join(home, "keys", name)
    return open(path, "rb").read() if os.path.exists(path) else None


def delete_key(name: str, home: str) -> None:
    if sys.platform == "darwin" and shutil.which("security") and _keychain_args() is not None:
        subprocess.run(["security", "delete-generic-password", "-s", SERVICE, "-a", name, *_keychain_args()],
                       capture_output=True, timeout=30)
    elif _secret_service():
        subprocess.run(["secret-tool", "clear", "service", SERVICE, "account", name], capture_output=True, timeout=30)
    path = os.path.join(home, "keys", name)
    if os.path.exists(path):
        os.remove(path)
