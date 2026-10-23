"""NO_PROXY entries that httpx can't parse.

httpx turns each NO_PROXY entry into a URL pattern when a client is created, and one entry it
can't parse makes every `httpx.Client()` raise, so veil would exit at startup. DeepSeek
Harness, for one, adds `[::1]` (an IPv6 address in brackets, which httpx doesn't recognise as an
address) for its child processes.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from typing import MutableMapping

KEYS = ("NO_PROXY", "no_proxy")
_BRACKETED = re.compile(r"\[([0-9A-Fa-f:.%]+)\](?::\d+)?")


def _pattern(host: str) -> str:
    """The URL pattern httpx builds for one NO_PROXY entry (httpx._utils.get_environment_proxies)."""
    if "://" in host:
        return host
    for cls, fmt in ((ipaddress.IPv4Address, "all://{}"), (ipaddress.IPv6Address, "all://[{}]")):
        try:
            cls(host.split("/")[0])
            return fmt.format(host)
        except ValueError:
            pass
    return f"all://{host}" if host.lower() == "localhost" else f"all://*{host}"


def _parses(host: str) -> bool:
    import httpx
    try:
        httpx.URL(_pattern(host))
        return True
    except Exception:
        return False


def normalize_no_proxy(environ: MutableMapping[str, str] = os.environ, log=sys.stderr) -> None:
    """Rewrite `[::1]` and `[::1]:port` to `::1`, and drop entries httpx would still reject."""
    for key in KEYS:
        value = environ.get(key)
        if not value:
            continue
        kept, dropped = [], []
        for host in (h.strip() for h in value.split(",")):
            if not host:
                continue
            m = _BRACKETED.fullmatch(host)
            host = m.group(1) if m else host
            if host == "*" or _parses(host):
                if host not in kept:
                    kept.append(host)
            else:
                dropped.append(host)
        if dropped and log:
            print(f"[veil] ignoring {key} entries that can't be parsed: {', '.join(dropped)}", file=log)
        environ[key] = ",".join(kept)
