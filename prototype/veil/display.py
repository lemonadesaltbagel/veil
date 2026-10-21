"""Display mode: does the developer see real values or pseudonyms in the agent's answers?

Default `real`: the developer's terminal is inside the trust boundary, and a privacy
tool that makes answers unreadable gets switched off. Switch to `tokens` before a
screen share, a recording, or pasting answers into tickets/chat, or when developers
should not see the data (contractors, regulated data):

    veil display tokens        # takes effect on the next request, no restart
    veil display real

Strength order (strictest wins): `x-veil-display: tokens` request header (set via
Claude Code managed settings: ANTHROPIC_CUSTOM_HEADERS, cannot be loosened locally)
> proxy `--show-tokens` > VEIL_DISPLAY > `display` in $VEIL_HOME/config.json > real.
"""

from __future__ import annotations

import json
import os

MODES = ("real", "tokens")
HEADER = "x-veil-display"
_cache: dict = {"path": None, "mtime": None, "mode": "real"}


def configured_mode(home: str) -> str:
    env = os.environ.get("VEIL_DISPLAY", "").strip().lower()
    if env in MODES:
        return env
    path = os.path.join(home, "config.json")
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        return "real"
    if _cache["path"] != path or _cache["mtime"] != mtime:
        try:
            mode = json.load(open(path)).get("display", "real")
        except (OSError, ValueError):
            mode = "real"
        _cache.update(path=path, mtime=mtime, mode=mode if mode in MODES else "real")
    return _cache["mode"]


def resolve(headers, home: str, forced_tokens: bool = False) -> str:
    """Mode for one request. A header can only make it stricter, never looser."""
    hdr = ""
    for k, v in headers.items():
        if k.lower() == HEADER:
            hdr = str(v).strip().lower()
    if hdr == "tokens" or forced_tokens:
        return "tokens"
    return configured_mode(home)
