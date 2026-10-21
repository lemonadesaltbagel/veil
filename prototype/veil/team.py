"""Team mode.

* `veil team export` / `veil team join`: share the token secret (and the team's
  allowlist) so every teammate derives identical pseudonyms -- bug reports and
  transcripts mean the same thing on every machine. The vault key is never shared.
  A passphrase (scrypt + AES-GCM) protects the bundle in transit.
* `veil team managed-settings`: a `managed-settings.d/` drop-in that forces Claude
  Code through veil: the proxy URL pinned in managed `env`, `allowedProviders:
  ["customEndpoint"]` (admits only that exact pinned endpoint), optionally veil's
  hooks, optionally locked with `allowManagedHooksOnly`.
"""

from __future__ import annotations

import base64
import json
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PREFIX = "veil-team-v1:"
MANAGED_DIRS = {"darwin": "/Library/Application Support/ClaudeCode/managed-settings.d",
                "linux": "/etc/claude-code/managed-settings.d"}


def _kdf(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def export_bundle(token_secret: bytes, allow: list[str], passphrase: str | None = None) -> str:
    payload = json.dumps({"token_secret": base64.b64encode(token_secret).decode(), "allow": allow}).encode()
    if passphrase:
        salt, nonce = os.urandom(16), os.urandom(12)
        payload = b"E" + salt + nonce + AESGCM(_kdf(passphrase, salt)).encrypt(nonce, payload, b"veil-team")
    else:
        payload = b"P" + payload
    return PREFIX + base64.urlsafe_b64encode(payload).decode()


def import_bundle(bundle: str, passphrase: str | None = None) -> tuple[bytes, list[str]]:
    if not bundle.startswith(PREFIX):
        raise ValueError("not a veil team bundle")
    raw = base64.urlsafe_b64decode(bundle[len(PREFIX):])
    if raw[:1] == b"E":
        if not passphrase:
            raise ValueError("bundle is passphrase-protected")
        salt, nonce, ct = raw[1:17], raw[17:29], raw[29:]
        raw = AESGCM(_kdf(passphrase, salt)).decrypt(nonce, ct, b"veil-team")
    else:
        raw = raw[1:]
    data = json.loads(raw)
    return base64.b64decode(data["token_secret"]), list(data.get("allow", []))


def managed_settings(port: int, hooks: bool = True, lock_hooks: bool = False, display: str | None = None) -> dict:
    url = f"http://127.0.0.1:{port}"
    doc: dict = {"env": {"ANTHROPIC_BASE_URL": url, "NO_PROXY": "127.0.0.1,localhost"},
                 "allowedProviders": ["customEndpoint"]}
    if display == "tokens":
        # the proxy honours this header per request and it can't be loosened locally
        doc["env"]["ANTHROPIC_CUSTOM_HEADERS"] = "x-veil-display: tokens"
    if hooks:
        doc["hooks"] = {event: [{"matcher": "*", "hooks": [{"type": "command",
                                                            "command": f"veil-hook {kind} --port {port}"}]}]
                        for event, kind in (("PreToolUse", "pre"), ("PostToolUse", "post"))}
    if lock_hooks:
        doc["allowManagedHooksOnly"] = True
    return doc


def install_hint(path: str) -> str:
    target = MANAGED_DIRS.get(sys.platform, "C:\\\\Program Files\\\\ClaudeCode\\\\managed-settings.d")
    return (f'sudo mkdir -p "{target}" && sudo install -m 644 "{path}" "{target}/50-veil.json"\n'
            "# requires Claude Code v2.1.285+ for allowedProviders; every machine also needs the veil proxy\n"
            "# running on the pinned port (veil service install) and `veil-hook` on PATH if hooks are enabled")
