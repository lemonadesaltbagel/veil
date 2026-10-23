"""NO_PROXY entries httpx can't parse must not stop veil (DeepSeek Harness adds `[::1]`)."""

import io
import subprocess
import sys

import httpx
import pytest

from veil.netenv import normalize_no_proxy

DSH = "127.0.0.1,localhost,::1,[::1],127.0.0.1,localhost"


def test_bracketed_ipv6_breaks_httpx_and_normalizing_fixes_it(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", DSH)
    monkeypatch.setenv("no_proxy", DSH)                   # one variable on Windows: set both, delete neither
    with pytest.raises(httpx.InvalidURL):
        httpx.Client()                                    # what crashed `veil proxy` under dsh
    normalize_no_proxy()
    import os
    assert os.environ["NO_PROXY"] == "127.0.0.1,localhost,::1"
    httpx.Client().close()


def test_ports_wildcards_and_unparseable_entries():
    env = {"no_proxy": " [fe80::1]:8080 , *.corp.example ,, .example.org,10.0.0.0/8,http://x.io, x:y ",
           "NO_PROXY": "*"}
    log = io.StringIO()
    normalize_no_proxy(env, log)
    assert env["no_proxy"] == "fe80::1,*.corp.example,.example.org,10.0.0.0/8,http://x.io"
    assert env["NO_PROXY"] == "*"
    assert "x:y" in log.getvalue()


def test_veil_proxy_starts_with_dsh_no_proxy(tmp_path):
    import base64, os, socket, time
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    env = {**os.environ, "HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": DSH, "no_proxy": DSH,
           "VEIL_HOME": str(tmp_path), "VEIL_VAULT_KEY": base64.b64encode(b"v" * 32).decode(),
           "VEIL_TOKEN_SECRET": base64.b64encode(b"t" * 32).decode()}
    p = subprocess.Popen([sys.executable, "-m", "veil.cli", "proxy", "--port", str(port)], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 60
        while True:
            assert p.poll() is None, p.stderr.read()[-2000:]
            try:
                r = httpx.get(f"http://127.0.0.1:{port}/veil/health", timeout=1, trust_env=False)
                assert r.json()["ok"] is True
                break
            except httpx.TransportError:
                assert time.monotonic() < deadline, "veil proxy did not answer"
                time.sleep(0.2)
    finally:
        p.terminate(); p.wait(10)
