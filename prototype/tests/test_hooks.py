"""Fast hooks: hook client -> proxy endpoint (secret + loopback only), with in-process fallback."""

import base64
import json
import os
import subprocess
import sys
import threading
import time

import httpx
from veil.proxy import LocalHTTPServer
import pytest

EVENT = {"tool_name": "Bash", "tool_input": {"command": "tail app.log"},
         "tool_response": {"stdout": "payment failed for leonekohler@surfeu.de", "stderr": "",
                           "interrupted": False, "isImage": False}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("VEIL_TOKEN_SECRET", base64.b64encode(b"t" * 32).decode())
    from veil import state
    v = state.load()
    v.known.add("leonekohler@surfeu.de", "email", "c:2")
    state.save_known(v.known, v.vault.cipher)
    return tmp_path


def _proxy():
    from veil import state
    from veil.anthropic import Policy
    from veil.proxy import make_handler
    srv = LocalHTTPServer(("127.0.0.1", 0), make_handler(state.load(), Policy(), "http://127.0.0.1:9",
                                                             httpx.Client(trust_env=False), log=open(os.devnull, "w")))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_client(kind, port, event=EVENT):
    t = time.perf_counter()
    p = subprocess.run([sys.executable, "-m", "veil.hookclient", kind, "--port", str(port)],
                       input=json.dumps(event), capture_output=True, text=True, env=os.environ.copy())
    return p.stdout, time.perf_counter() - t


def test_client_via_proxy_and_fallback(env):
    srv = _proxy()
    try:
        out, secs = _run_client("post", srv.server_port)
        assert "leonekohler" not in out and "user_" in json.loads(out)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        # vs ~0.26 s+ for the in-process hook with a large vault; Windows spawns processes slower
        assert secs < (0.6 if sys.platform == "win32" else 0.25), secs
    finally:
        srv.shutdown()
    out, _ = _run_client("post", 1)  # nothing listens on port 1 -> in-process fallback, same answer
    assert "user_" in json.loads(out)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def test_endpoint_requires_secret_and_loopback(env):
    srv = _proxy()
    url = f"http://127.0.0.1:{srv.server_port}/veil/hook/pre"
    c = httpx.Client(trust_env=False)
    try:
        assert c.post(url, json=EVENT).status_code == 403                                   # no secret
        assert c.post(url, json=EVENT, headers={"x-veil-hook-secret": "nope"}).status_code == 403
        secret = (env / "hook.secret").read_text().strip()
        assert c.post(url, json=EVENT, headers={"x-veil-hook-secret": secret, "host": "evil.example:80"}).status_code == 403
        assert c.post(url, json=EVENT, headers={"x-veil-hook-secret": secret}).status_code == 200
    finally:
        srv.shutdown()
