"""Display modes: real by default, switchable at runtime, enforceable via a managed header."""

import base64
import json

import httpx
import pytest

from veil import cli, state, team
from veil.detect import KnownValues
from veil.engine import Veil
from veil.vault import Vault
from veil_dev.testing import Recorder, start_mock_llm, start_proxy

REAL = "leonekohler@surfeu.de"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("VEIL_TOKEN_SECRET", base64.b64encode(b"t" * 32).decode())
    monkeypatch.delenv("VEIL_DISPLAY", raising=False)
    known = KnownValues(); known.add(REAL, "email", "c:2")
    veil = Veil(Vault(":memory:", b"s"), known)
    rec = Recorder()
    llm = start_mock_llm()
    px = start_proxy(veil, f"http://127.0.0.1:{llm.server_port}", rec)
    yield tmp_path, f"http://127.0.0.1:{px.server_port}", rec
    px.shutdown(); llm.shutdown()


def _ask(url, headers=None):
    body = {"model": "m", "max_tokens": 50, "stream": True, "messages": [{"role": "user", "content": f"check {REAL}"}],
            "tools": [{"name": "Bash", "description": "x", "input_schema": {"type": "object"}}]}
    with httpx.Client(trust_env=False) as c:
        r = c.post(url + "/v1/messages", json=body, headers=headers or {})
    return "".join(json.loads(l[6:]).get("delta", {}).get("text", "") for l in r.text.splitlines() if l.startswith("data: "))


def test_runtime_switch_and_managed_header(setup):
    home, url, rec = setup
    assert REAL in _ask(url)                                   # default: real
    state.save_config({"display": "tokens"})                   # `veil display tokens`, no restart
    shown = _ask(url)
    assert REAL not in shown and "@example.test" in shown
    assert REAL not in _ask(url, {"x-veil-display": "real"})   # a header can't loosen config
    state.save_config({"display": "real"})
    assert REAL not in _ask(url, {"x-veil-display": "tokens"})  # managed header forces pseudonyms
    assert REAL in _ask(url)
    assert all("x-veil-display" not in json.dumps(e["headers"]).lower() for e in rec.exchanges)  # never forwarded


def test_reveal_and_share_invert_each_other(setup, capsys, monkeypatch):
    home, _, _ = setup
    v = state.load(); v.known.add(REAL, "email", "c:2"); state.save_known(v.known, v.vault.cipher)
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(f"customer {REAL} paid twice"))
    cli.main(["share"]); shared = capsys.readouterr().out
    assert REAL not in shared and "@example.test" in shared
    monkeypatch.setattr("sys.stdin", io.StringIO(shared))
    cli.main(["reveal"]); assert capsys.readouterr().out == f"customer {REAL} paid twice"
    cli.main(["display", "tokens"]); assert "display: tokens" in capsys.readouterr().out
    assert state.config()["display"] == "tokens"


def test_managed_settings_can_enforce_tokens():
    doc = team.managed_settings(8787, display="tokens")
    assert doc["env"]["ANTHROPIC_CUSTOM_HEADERS"] == "x-veil-display: tokens"
    assert "ANTHROPIC_CUSTOM_HEADERS" not in team.managed_settings(8787)["env"]
