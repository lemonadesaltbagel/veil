"""Fast Claude Code hook: forwards the hook event to the running veil proxy.

    python -m veil.hookclient pre|post [--port 8787] [--home ~/.veil]

Stdlib only (no vault load, no crypto import): ~30 ms instead of ~260 ms. If the
proxy is not reachable it falls back to the in-process hook (correct, slower).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request


def main(argv: list[str]) -> int:
    kind = argv[0] if argv else "post"
    port = int(argv[argv.index("--port") + 1]) if "--port" in argv else int(os.environ.get("VEIL_PORT", "8787"))
    if "--home" in argv:  # per-project vaults: the proxy on this port uses this home
        os.environ["VEIL_HOME"] = argv[argv.index("--home") + 1]
    raw = sys.stdin.read()
    home = os.environ.get("VEIL_HOME", os.path.expanduser("~/.veil"))
    try:
        secret = open(os.path.join(home, "hook.secret")).read().strip()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/veil/hook/{kind}", data=raw.encode(),
                                     headers={"content-type": "application/json", "x-veil-hook-secret": secret})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never via a system proxy
        with opener.open(req, timeout=10) as r:
            sys.stdout.write(r.read().decode())
        return 0
    except Exception:
        pass
    from . import state                    # fallback: proxy down -> do it in-process
    from .hooks import hook_response
    out = hook_response(state.load(), kind, json.loads(raw))
    if out:
        json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


def cli() -> int:  # console script `veil-hook pre|post [--port N]` (stable path for managed settings)
    return main(sys.argv[1:])
